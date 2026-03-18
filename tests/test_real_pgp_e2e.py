"""End-to-end test using REAL PGP keys from ~/.skcapstone/identity/.

Tests the full CapAuth challenge/verify cycle with the Opus (SKCapstone Agent)
key from the system GPG keyring:
  - fingerprint: 9B3AB00F411B064646879B92D10E637B4F8367DA
  - identity:    ~/.skcapstone/identity/agent.pub

Uses GnuPGBackend pointed at ~/.gnupg so signing hits the real key material.
Skipped if the key is not found in the system keyring.
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
from pathlib import Path
from typing import Any

import pytest

try:
    import gnupg
except ImportError:
    gnupg = None

# Skip entire module if gnupg is not available or gnupg home doesn't exist
pytestmark = pytest.mark.skipif(
    gnupg is None or not Path("~/.gnupg").expanduser().is_dir(),
    reason="python-gnupg not installed or ~/.gnupg does not exist",
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OPUS_FINGERPRINT = "9B3AB00F411B064646879B92D10E637B4F8367DA"
GNUPG_HOME = str(Path("~/.gnupg").expanduser())
AGENT_PUB = Path("~/.skcapstone/identity/agent.pub").expanduser()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _gpg() -> gnupg.GPG:
    """Return a GPG instance using the system keyring."""
    return gnupg.GPG(gnupghome=GNUPG_HOME)


def _has_opus_key() -> bool:
    """Check that the Opus signing key is available in the keyring."""
    gpg = _gpg()
    secret_keys = gpg.list_keys(True)
    return any(k["fingerprint"] == OPUS_FINGERPRINT for k in secret_keys)


def _export_public_key() -> str:
    """Export the Opus public key as ASCII armor."""
    gpg = _gpg()
    return gpg.export_keys(OPUS_FINGERPRINT, armor=True)


def _sign_payload(data: bytes) -> str:
    """Sign bytes with the Opus key; return ASCII-armored detach-sig."""
    gpg = _gpg()
    sig = gpg.sign(data, keyid=OPUS_FINGERPRINT, detach=True, binary=False)
    if not sig.status or "created" not in sig.status:
        raise RuntimeError(f"GPG signing failed: {sig.status} / {sig.stderr}")
    return str(sig)


def _gnupg_verify(data: bytes, sig_armor: str, pub_armor: str) -> bool:
    """Verify a detach-sig using GnuPGBackend (isolated temp keyring)."""
    import tempfile as tmp

    gpg = gnupg.GPG(gnupghome=tmp.mkdtemp(prefix="capauth_e2e_"))
    gpg.import_keys(pub_armor)
    with tmp.NamedTemporaryFile(suffix=".sig", delete=False) as sf:
        sf.write(sig_armor.encode())
        sig_path = sf.name
    try:
        result = gpg.verify_data(sig_path, data)
        return bool(result.valid)
    finally:
        os.unlink(sig_path)


# ---------------------------------------------------------------------------
# pytest marker — skip if key absent
# ---------------------------------------------------------------------------

requires_opus_key = pytest.mark.skipif(
    not _has_opus_key(),
    reason="Opus signing key not found in system GPG keyring",
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def app_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """FastAPI TestClient with temp keystore, backed by the real service app."""
    monkeypatch.setenv("CAPAUTH_DB_PATH", str(tmp_path / "e2e_keys.db"))
    monkeypatch.setenv("CAPAUTH_SERVICE_ID", "e2e.capauth.test")
    monkeypatch.setenv("CAPAUTH_ADMIN_TOKEN", "e2e-admin-token")
    monkeypatch.setenv("CAPAUTH_REQUIRE_APPROVAL", "false")

    import capauth.service.app as svc_app
    from capauth.service.keystore import KeyStore
    import capauth.authentik.nonce_store as ns

    # Close existing keystore so the new DB path is used.
    if svc_app._keystore is not None:
        try:
            svc_app._keystore.close()
        except Exception:
            pass

    # Eagerly init with the correct path before any HTTP call.
    # KeyStore uses check_same_thread=False so the TestClient async thread is fine.
    fresh_ks = KeyStore(tmp_path / "e2e_keys.db")
    svc_app._keystore = fresh_ks

    # Reset in-memory nonce store so tests are fully isolated
    ns._MEM_CACHE.clear()

    from fastapi.testclient import TestClient

    client = TestClient(svc_app.app)
    yield client, svc_app

    # Teardown: close keystore and clear nonce cache
    if svc_app._keystore is not None:
        try:
            svc_app._keystore.close()
        except Exception:
            pass
    svc_app._keystore = None
    ns._MEM_CACHE.clear()


# ---------------------------------------------------------------------------
# Unit-level: verify GnuPG signing + verification works in isolation
# ---------------------------------------------------------------------------


@requires_opus_key
class TestGnuPGSigningUnit:
    """Confirm the real key signs/verifies before hitting the HTTP layer."""

    def test_sign_and_verify_nonce_payload(self) -> None:
        """Sign a canonical nonce payload with the real key and verify it."""
        from capauth.authentik.verifier import canonical_nonce_payload

        payload = canonical_nonce_payload(
            nonce="deadbeef-1234-5678-abcd-ef0123456789",
            client_nonce_echo="dGVzdA==",
            timestamp="2026-02-24T00:00:00+00:00",
            service="e2e.capauth.test",
            expires="2026-02-24T00:01:00+00:00",
        )

        pub_armor = _export_public_key()
        sig_armor = _sign_payload(payload)
        assert _gnupg_verify(payload, sig_armor, pub_armor), "nonce payload signature invalid"

    def test_sign_and_verify_claims_payload(self) -> None:
        """Sign a canonical claims payload with the real key and verify it."""
        from capauth.authentik.verifier import canonical_claims_payload

        claims = {"name": "Opus", "email": "opus@skcapstone.local", "agent_type": "ai"}
        payload = canonical_claims_payload(
            fingerprint=OPUS_FINGERPRINT,
            nonce="deadbeef-1234-5678-abcd-ef0123456789",
            claims=claims,
        )

        pub_armor = _export_public_key()
        sig_armor = _sign_payload(payload)
        assert _gnupg_verify(payload, sig_armor, pub_armor), "claims payload signature invalid"

    def test_tampered_payload_fails_verification(self) -> None:
        """Signature over modified data should fail."""
        original = b"CAPAUTH_NONCE_V1\nnonce=abc123"
        tampered = b"CAPAUTH_NONCE_V1\nnonce=evil999"

        pub_armor = _export_public_key()
        sig_armor = _sign_payload(original)
        assert not _gnupg_verify(tampered, sig_armor, pub_armor), "tampered payload must fail"

    def test_wrong_key_fails_verification(self) -> None:
        """Signature should fail against a key that didn't sign the data."""
        from capauth.crypto import get_backend
        from capauth.models import Algorithm

        # Generate a fresh throw-away keypair
        backend = get_backend()
        bundle = backend.generate_keypair(
            "Fake User", "fake@example.com", "passphrase", Algorithm.RSA4096
        )

        payload = b"CAPAUTH_NONCE_V1\nnonce=abc123"
        sig_armor = _sign_payload(payload)
        # Verify against the wrong (fake) key — must fail
        assert not _gnupg_verify(payload, sig_armor, bundle.public_armor), (
            "wrong key must not verify"
        )


# ---------------------------------------------------------------------------
# Integration: Full HTTP challenge/verify cycle
# ---------------------------------------------------------------------------


@requires_opus_key
class TestRealPGPEndToEnd:
    """Full challenge → sign → verify cycle against the FastAPI service."""

    def test_enroll_new_key_on_first_auth(self, app_client: tuple) -> None:
        """First auth with a new key should auto-enroll and succeed."""
        client, svc_app = app_client
        pub_armor = _export_public_key()

        # 1. Request challenge
        client_nonce = base64.b64encode(b"jarvis-real-test-nonce").decode()
        resp = client.post(
            "/capauth/v1/challenge",
            json={
                "fingerprint": OPUS_FINGERPRINT,
                "client_nonce": client_nonce,
            },
        )
        assert resp.status_code == 200, f"Challenge failed: {resp.json()}"
        challenge = resp.json()

        assert challenge["nonce"]
        assert challenge["service"] == "e2e.capauth.test"

        # 2. Build canonical nonce payload and sign it
        from capauth.authentik.verifier import canonical_nonce_payload

        nonce_payload = canonical_nonce_payload(
            nonce=challenge["nonce"],
            client_nonce_echo=challenge["client_nonce_echo"],
            timestamp=challenge["timestamp"],
            service=challenge["service"],
            expires=challenge["expires"],
        )
        nonce_sig = _sign_payload(nonce_payload)

        # 3. POST verify — first time, include public key for enrollment
        resp = client.post(
            "/capauth/v1/verify",
            json={
                "fingerprint": OPUS_FINGERPRINT,
                "nonce": challenge["nonce"],
                "nonce_signature": nonce_sig,
                "public_key": pub_armor,
                "claims": {},
                "claims_signature": "",
            },
        )
        assert resp.status_code == 200, f"Verify failed: {resp.json()}"
        result = resp.json()
        assert result["authenticated"] is True
        assert result["fingerprint"] == OPUS_FINGERPRINT
        assert result["is_new_enrollment"] is True
        assert result["access_token"]
        assert result["oidc_claims"]["sub"] == OPUS_FINGERPRINT

    def test_second_auth_uses_enrolled_key(self, app_client: tuple) -> None:
        """After enrollment, subsequent auths should not need public_key."""
        client, svc_app = app_client
        pub_armor = _export_public_key()

        # First auth — enroll
        client_nonce = base64.b64encode(b"first-auth").decode()
        challenge_resp = client.post(
            "/capauth/v1/challenge",
            json={
                "fingerprint": OPUS_FINGERPRINT,
                "client_nonce": client_nonce,
            },
        )
        challenge = challenge_resp.json()

        from capauth.authentik.verifier import canonical_nonce_payload

        nonce_payload = canonical_nonce_payload(
            nonce=challenge["nonce"],
            client_nonce_echo=challenge["client_nonce_echo"],
            timestamp=challenge["timestamp"],
            service=challenge["service"],
            expires=challenge["expires"],
        )
        client.post(
            "/capauth/v1/verify",
            json={
                "fingerprint": OPUS_FINGERPRINT,
                "nonce": challenge["nonce"],
                "nonce_signature": _sign_payload(nonce_payload),
                "public_key": pub_armor,
            },
        )

        # Second auth — no public_key needed
        client_nonce2 = base64.b64encode(b"second-auth").decode()
        challenge2_resp = client.post(
            "/capauth/v1/challenge",
            json={
                "fingerprint": OPUS_FINGERPRINT,
                "client_nonce": client_nonce2,
            },
        )
        assert challenge2_resp.status_code == 200
        challenge2 = challenge2_resp.json()

        nonce_payload2 = canonical_nonce_payload(
            nonce=challenge2["nonce"],
            client_nonce_echo=challenge2["client_nonce_echo"],
            timestamp=challenge2["timestamp"],
            service=challenge2["service"],
            expires=challenge2["expires"],
        )
        verify2 = client.post(
            "/capauth/v1/verify",
            json={
                "fingerprint": OPUS_FINGERPRINT,
                "nonce": challenge2["nonce"],
                "nonce_signature": _sign_payload(nonce_payload2),
            },
        )
        assert verify2.status_code == 200
        result2 = verify2.json()
        assert result2["authenticated"] is True
        assert result2["is_new_enrollment"] is False

    def test_auth_with_claims_bundle(self, app_client: tuple) -> None:
        """Auth with signed profile claims should produce OIDC claims."""
        client, _ = app_client
        pub_armor = _export_public_key()

        claims = {
            "name": "Opus",
            "email": "opus@skcapstone.local",
            "agent_type": "ai",
            "groups": ["agents", "sovereign"],
        }

        # Challenge
        client_nonce = base64.b64encode(b"claims-test").decode()
        challenge = client.post(
            "/capauth/v1/challenge",
            json={
                "fingerprint": OPUS_FINGERPRINT,
                "client_nonce": client_nonce,
            },
        ).json()

        from capauth.authentik.verifier import canonical_nonce_payload, canonical_claims_payload

        nonce_payload = canonical_nonce_payload(
            nonce=challenge["nonce"],
            client_nonce_echo=challenge["client_nonce_echo"],
            timestamp=challenge["timestamp"],
            service=challenge["service"],
            expires=challenge["expires"],
        )
        nonce_sig = _sign_payload(nonce_payload)

        claims_payload = canonical_claims_payload(
            fingerprint=OPUS_FINGERPRINT,
            nonce=challenge["nonce"],
            claims=claims,
        )
        claims_sig = _sign_payload(claims_payload)

        resp = client.post(
            "/capauth/v1/verify",
            json={
                "fingerprint": OPUS_FINGERPRINT,
                "nonce": challenge["nonce"],
                "nonce_signature": nonce_sig,
                "claims": claims,
                "claims_signature": claims_sig,
                "public_key": pub_armor,
            },
        )
        assert resp.status_code == 200, f"Verify with claims failed: {resp.json()}"
        result = resp.json()
        assert result["authenticated"] is True

        oidc = result["oidc_claims"]
        assert oidc["sub"] == OPUS_FINGERPRINT
        assert oidc["name"] == "Opus"
        assert oidc["email"] == "opus@skcapstone.local"
        assert oidc["agent_type"] == "ai"
        assert "agents" in oidc["groups"]

    def test_replay_attack_rejected(self, app_client: tuple) -> None:
        """Re-using the same nonce must be rejected."""
        client, _ = app_client
        pub_armor = _export_public_key()

        client_nonce = base64.b64encode(b"replay-test").decode()
        challenge = client.post(
            "/capauth/v1/challenge",
            json={
                "fingerprint": OPUS_FINGERPRINT,
                "client_nonce": client_nonce,
            },
        ).json()

        from capauth.authentik.verifier import canonical_nonce_payload

        nonce_payload = canonical_nonce_payload(
            nonce=challenge["nonce"],
            client_nonce_echo=challenge["client_nonce_echo"],
            timestamp=challenge["timestamp"],
            service=challenge["service"],
            expires=challenge["expires"],
        )
        nonce_sig = _sign_payload(nonce_payload)

        body = {
            "fingerprint": OPUS_FINGERPRINT,
            "nonce": challenge["nonce"],
            "nonce_signature": nonce_sig,
            "public_key": pub_armor,
        }

        # First use — must succeed
        r1 = client.post("/capauth/v1/verify", json=body)
        assert r1.status_code == 200

        # Replay — must be rejected
        r2 = client.post("/capauth/v1/verify", json=body)
        assert r2.status_code == 401
        assert "nonce" in r2.json()["detail"]["error"].lower()

    def test_invalid_signature_rejected(self, app_client: tuple) -> None:
        """Submitting garbage as a signature must be rejected."""
        client, _ = app_client
        pub_armor = _export_public_key()

        client_nonce = base64.b64encode(b"invalid-sig-test").decode()
        challenge = client.post(
            "/capauth/v1/challenge",
            json={
                "fingerprint": OPUS_FINGERPRINT,
                "client_nonce": client_nonce,
            },
        ).json()

        resp = client.post(
            "/capauth/v1/verify",
            json={
                "fingerprint": OPUS_FINGERPRINT,
                "nonce": challenge["nonce"],
                "nonce_signature": "-----BEGIN PGP MESSAGE-----\nnot-a-real-sig\n-----END PGP MESSAGE-----",
                "public_key": pub_armor,
            },
        )
        assert resp.status_code == 401

    def test_status_shows_enrolled_key_after_auth(self, app_client: tuple) -> None:
        """Status endpoint should reflect the enrolled key count."""
        client, _ = app_client
        pub_armor = _export_public_key()

        # Before enrollment
        status_before = client.get("/capauth/v1/status").json()
        assert status_before["enrolled_keys"] == 0

        # Enroll via full auth
        client_nonce = base64.b64encode(b"status-test").decode()
        challenge = client.post(
            "/capauth/v1/challenge",
            json={
                "fingerprint": OPUS_FINGERPRINT,
                "client_nonce": client_nonce,
            },
        ).json()

        from capauth.authentik.verifier import canonical_nonce_payload

        nonce_payload = canonical_nonce_payload(
            nonce=challenge["nonce"],
            client_nonce_echo=challenge["client_nonce_echo"],
            timestamp=challenge["timestamp"],
            service=challenge["service"],
            expires=challenge["expires"],
        )
        client.post(
            "/capauth/v1/verify",
            json={
                "fingerprint": OPUS_FINGERPRINT,
                "nonce": challenge["nonce"],
                "nonce_signature": _sign_payload(nonce_payload),
                "public_key": pub_armor,
            },
        )

        # After enrollment
        status_after = client.get("/capauth/v1/status").json()
        assert status_after["enrolled_keys"] == 1
