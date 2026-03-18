"""Tests for the CapAuth signature verifier.

Exercises canonical payload construction and round-trip sign/verify
using the PGPy backend. Skips if PGPy is unavailable.
"""

from __future__ import annotations

import pytest

from tests.conftest import TEST_EMAIL, TEST_NAME, TEST_PASSPHRASE, _requires_crypto
from capauth.authentik.verifier import (
    canonical_claims_payload,
    canonical_nonce_payload,
    fingerprint_from_armor,
    verify_claims_signature,
    verify_nonce_signature,
)


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
        """Canonical nonce payload starts with the protocol header."""
        payload = canonical_nonce_payload("n", "c", "t", "s", "e")
        assert payload.startswith(b"CAPAUTH_NONCE_V1")

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
