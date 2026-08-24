"""Tests for the CapAuth signature verifier.

Exercises canonical payload construction and round-trip sign/verify
using the PGPy backend. Skips if PGPy is unavailable.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from capauth.authentik.verifier import (
    canonical_claims_payload,
    canonical_nonce_payload,
    check_origin,
    fingerprint_from_armor,
    payload_version,
    verify_claims_signature,
    verify_nonce_signature,
)
from tests.conftest import TEST_EMAIL, TEST_NAME, TEST_PASSPHRASE, _requires_crypto

# Shared cross-impl test vector — the SAME fixture is asserted by the PHP and JS
# suites so the canonical bytes never drift between languages.
_VECTOR_PATH = Path(__file__).parent / "fixtures" / "canonical_nonce_v2_vector.json"
VECTOR = json.loads(_VECTOR_PATH.read_text())


@_requires_crypto
class TestCanonicalPayloads:
    def test_nonce_payload_is_deterministic(self):
        """Same inputs always produce the same canonical nonce bytes."""
        p1 = canonical_nonce_payload(
            "uuid-1", "abc=", "2026-02-24T12:00:00Z", "svc.io", "2026-02-24T12:01:00Z"
        )
        p2 = canonical_nonce_payload(
            "uuid-1", "abc=", "2026-02-24T12:00:00Z", "svc.io", "2026-02-24T12:01:00Z"
        )
        assert p1 == p2

    def test_nonce_payload_contains_header(self):
        """Legacy (origin-less) canonical nonce payload starts with the V1 header."""
        payload = canonical_nonce_payload("n", "c", "t", "s", "e")
        assert payload.startswith(b"CAPAUTH_NONCE_V1")

    def test_nonce_payload_v2_header_when_origin_present(self):
        """Supplying an origin emits the V2 header."""
        payload = canonical_nonce_payload("n", "c", "t", "s", "e", origin="https://x.io")
        assert payload.startswith(b"CAPAUTH_NONCE_V2")

    def test_nonce_payload_v2_origin_line_position(self):
        """The origin line sits between client_nonce and timestamp."""
        payload = canonical_nonce_payload(
            "n", "c", "ts", "svc", "exp", origin="https://x.io"
        ).decode()
        lines = payload.split("\n")
        assert lines[0] == "CAPAUTH_NONCE_V2"
        assert lines[1] == "nonce=n"
        assert lines[2] == "client_nonce=c"
        assert lines[3] == "origin=https://x.io"
        assert lines[4] == "timestamp=ts"
        assert lines[5] == "service=svc"
        assert lines[6] == "expires=exp"

    def test_cross_impl_vector_v2(self):
        """Python output must match the shared cross-impl V2 test vector bytes."""
        f = VECTOR["fields"]
        payload = canonical_nonce_payload(
            f["nonce"],
            f["client_nonce"],
            f["timestamp"],
            f["service"],
            f["expires"],
            origin=f["origin"],
        )
        assert payload.decode("utf-8") == VECTOR["expected_v2"]

    def test_cross_impl_vector_v1(self):
        """Legacy V1 output must match the shared cross-impl V1 test vector bytes."""
        f = VECTOR["fields"]
        payload = canonical_nonce_payload(
            f["nonce"],
            f["client_nonce"],
            f["timestamp"],
            f["service"],
            f["expires"],
        )
        assert payload.decode("utf-8") == VECTOR["expected_v1"]

    def test_payload_version_dispatch(self):
        """payload_version() dispatches V1/V2 on the header line."""
        v1 = canonical_nonce_payload("n", "c", "t", "s", "e")
        v2 = canonical_nonce_payload("n", "c", "t", "s", "e", origin="https://x.io")
        assert payload_version(v1) == "V1"
        assert payload_version(v2) == "V2"
        assert payload_version(b"GARBAGE\nfoo=bar") is None


@_requires_crypto
class TestOriginBinding:
    """Tier-A origin assertion + migration semantics (no crypto needed)."""

    ALLOWED = "https://cloud.example.org"

    def test_matching_origin_accepts(self):
        ok, err = check_origin(self.ALLOWED, self.ALLOWED)
        assert ok and err == ""

    def test_phishing_origin_rejected(self):
        ok, err = check_origin("https://evil.example", self.ALLOWED)
        assert not ok and err == "invalid_origin"

    def test_origin_match_is_case_and_slash_insensitive(self):
        ok, _ = check_origin("HTTPS://Cloud.Example.ORG/", self.ALLOWED)
        assert ok

    def test_origin_match_against_list(self):
        ok, _ = check_origin("https://b.example", ["https://a.example", "https://b.example"])
        assert ok

    def test_v1_accepted_when_binding_not_required(self):
        ok, err = check_origin(None, self.ALLOWED, require_origin_binding=False)
        assert ok and err == ""

    def test_v1_rejected_when_binding_required(self):
        ok, err = check_origin(None, self.ALLOWED, require_origin_binding=True)
        assert not ok and err == "v1_rejected"

    def test_claims_payload_is_deterministic(self):
        """Same claims always produce the same bytes regardless of dict ordering."""
        claims = {"name": "Chef", "email": "chef@x.io", "groups": ["a", "b"]}
        p1 = canonical_claims_payload("FP" * 20, "nonce-uuid", claims)
        p2 = canonical_claims_payload("FP" * 20, "nonce-uuid", claims)
        assert p1 == p2

    def test_claims_payload_contains_header(self):
        """Canonical claims payload starts with the protocol header."""
        payload = canonical_claims_payload("FP" * 20, "nonce-uuid", {})
        assert payload.startswith(b"CAPAUTH_CLAIMS_V1")

    def test_claims_payload_sorts_keys(self):
        """Claims JSON in payload uses sorted keys."""
        claims_1 = {"z_field": "z", "a_field": "a"}
        claims_2 = {"a_field": "a", "z_field": "z"}
        p1 = canonical_claims_payload("FP" * 20, "nonce", claims_1)
        p2 = canonical_claims_payload("FP" * 20, "nonce", claims_2)
        assert p1 == p2


@_requires_crypto
class TestSignVerify:
    @pytest.fixture
    def key_bundle(self, pgpy_backend):
        from capauth.models import Algorithm

        return pgpy_backend.generate_keypair(
            TEST_NAME, TEST_EMAIL, TEST_PASSPHRASE, Algorithm.RSA4096
        )

    def test_nonce_signature_round_trip(self, pgpy_backend, key_bundle):
        """A nonce signature verifies against the matching public key."""
        payload = canonical_nonce_payload("uuid", "echo=", "ts", "svc", "exp")
        sig = pgpy_backend.sign(payload, key_bundle.private_armor, TEST_PASSPHRASE)
        assert verify_nonce_signature(payload, sig, key_bundle.public_armor)

    def test_detached_nonce_signature_works_without_optional_gnupg(
        self, pgpy_backend, key_bundle, monkeypatch
    ):
        """A valid detached signature does not depend on python-gnupg."""
        import pgpy

        payload = canonical_nonce_payload("uuid", "echo=", "ts", "svc", "exp")
        private_key, _ = pgpy.PGPKey.from_blob(key_bundle.private_armor)
        with private_key.unlock(TEST_PASSPHRASE):
            signature = str(private_key.sign(payload))

        monkeypatch.setitem(sys.modules, "gnupg", None)
        assert verify_nonce_signature(payload, signature, key_bundle.public_armor)

    def test_detached_nonce_signature_rejects_tamper_and_wrong_key(
        self, pgpy_backend, key_bundle, monkeypatch
    ):
        """The native fallback still binds the exact payload and signer key."""
        import pgpy

        from capauth.models import Algorithm

        payload = canonical_nonce_payload("uuid", "echo=", "ts", "svc", "exp")
        private_key, _ = pgpy.PGPKey.from_blob(key_bundle.private_armor)
        with private_key.unlock(TEST_PASSPHRASE):
            signature = str(private_key.sign(payload))
        other_bundle = pgpy_backend.generate_keypair(
            "Other", "other@x.io", TEST_PASSPHRASE, Algorithm.RSA4096
        )

        monkeypatch.setitem(sys.modules, "gnupg", None)
        assert not verify_nonce_signature(
            payload + b"\ntampered", signature, key_bundle.public_armor
        )
        assert not verify_nonce_signature(payload, signature, other_bundle.public_armor)
        assert not verify_nonce_signature(payload, "not armor", key_bundle.public_armor)

    def test_nonce_signature_tampered_payload_fails(self, pgpy_backend, key_bundle):
        """A tampered payload fails signature verification."""
        payload = canonical_nonce_payload("uuid", "echo=", "ts", "svc", "exp")
        sig = pgpy_backend.sign(payload, key_bundle.private_armor, TEST_PASSPHRASE)
        tampered = payload + b"\ntampered"
        assert not verify_nonce_signature(tampered, sig, key_bundle.public_armor)

    def test_nonce_signature_wrong_key_fails(self, pgpy_backend, key_bundle):
        """A signature verifies only against the signing key, not another key."""
        from capauth.models import Algorithm

        other_bundle = pgpy_backend.generate_keypair(
            "Other", "other@x.io", TEST_PASSPHRASE, Algorithm.RSA4096
        )
        payload = canonical_nonce_payload("uuid", "echo=", "ts", "svc", "exp")
        sig = pgpy_backend.sign(payload, key_bundle.private_armor, TEST_PASSPHRASE)
        assert not verify_nonce_signature(payload, sig, other_bundle.public_armor)

    def test_v2_nonce_signature_round_trip(self, pgpy_backend, key_bundle):
        """A V2 (origin-bound) nonce signature verifies against the matching key."""
        payload = canonical_nonce_payload(
            "uuid", "echo=", "ts", "svc", "exp", origin="https://real.example"
        )
        sig = pgpy_backend.sign(payload, key_bundle.private_armor, TEST_PASSPHRASE)
        assert verify_nonce_signature(payload, sig, key_bundle.public_armor)

    def test_v2_origin_tamper_breaks_signature(self, pgpy_backend, key_bundle):
        """Flipping the signed origin invalidates the signature (the point of V2)."""
        signed = canonical_nonce_payload(
            "uuid", "echo=", "ts", "svc", "exp", origin="https://real.example"
        )
        sig = pgpy_backend.sign(signed, key_bundle.private_armor, TEST_PASSPHRASE)
        # A proxy that rewrites the origin to evil.example must break the sig.
        tampered = canonical_nonce_payload(
            "uuid", "echo=", "ts", "svc", "exp", origin="https://evil.example"
        )
        assert not verify_nonce_signature(tampered, sig, key_bundle.public_armor)

    def test_phishing_relay_origin_rejected_end_to_end(self, pgpy_backend, key_bundle):
        """End-to-end: a signature over origin=evil is rejected by the origin check
        even though the PGP signature itself is valid for that (evil) payload."""
        # User is phished onto evil.example; their client signs origin=evil.
        evil_payload = canonical_nonce_payload(
            "uuid", "echo=", "ts", "svc", "exp", origin="https://evil.example"
        )
        sig = pgpy_backend.sign(evil_payload, key_bundle.private_armor, TEST_PASSPHRASE)
        # The signature is cryptographically valid for the evil payload...
        assert verify_nonce_signature(evil_payload, sig, key_bundle.public_armor)
        # ...but the RP (origin=real) rejects on the origin assertion.
        ok, err = check_origin("https://evil.example", "https://real.example")
        assert not ok and err == "invalid_origin"
        # A signature over the real origin is accepted by the same RP.
        ok2, _ = check_origin("https://real.example", "https://real.example")
        assert ok2

    def test_claims_signature_round_trip(self, pgpy_backend, key_bundle):
        """A claims signature verifies against the matching public key."""
        claims = {"name": "Chef", "email": "chef@x.io"}
        payload = canonical_claims_payload(key_bundle.fingerprint, "nonce-uuid", claims)
        sig = pgpy_backend.sign(payload, key_bundle.private_armor, TEST_PASSPHRASE)
        assert verify_claims_signature(payload, sig, key_bundle.public_armor)

    def test_claims_signature_tampered_claims_fails(self, pgpy_backend, key_bundle):
        """Tampered claims fail signature verification."""
        claims = {"name": "Chef"}
        payload = canonical_claims_payload(key_bundle.fingerprint, "nonce-uuid", claims)
        sig = pgpy_backend.sign(payload, key_bundle.private_armor, TEST_PASSPHRASE)
        tampered_claims = {"name": "Hacker"}
        tampered_payload = canonical_claims_payload(
            key_bundle.fingerprint, "nonce-uuid", tampered_claims
        )
        assert not verify_claims_signature(tampered_payload, sig, key_bundle.public_armor)

    def test_fingerprint_from_armor_returns_correct_fp(self, pgpy_backend, key_bundle):
        """fingerprint_from_armor extracts the same fingerprint as key generation."""
        extracted = fingerprint_from_armor(key_bundle.public_armor)
        assert extracted is not None
        assert extracted.upper() == key_bundle.fingerprint.upper()

    def test_fingerprint_from_armor_invalid_input_returns_none(self):
        """Invalid armor returns None without raising."""
        result = fingerprint_from_armor("this is not a pgp key")
        assert result is None
