"""Tests for CapAuth Verification Service — keystore and endpoints."""

from __future__ import annotations

from pathlib import Path

import pytest

from capauth.service.keystore import KeyStore


@pytest.fixture
def keystore(tmp_path: Path) -> KeyStore:
    """Create a keystore with a temp database."""
    return KeyStore(db_path=tmp_path / "test_keys.db")


FAKE_FP = "A" * 40
FAKE_ARMOR = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfake\n-----END PGP PUBLIC KEY BLOCK-----"


class TestKeyStore:
    """Tests for the SQLite key store."""

    def test_enroll_and_get(self, keystore: KeyStore) -> None:
        """Enrolling a key should make it retrievable."""
        enrolled = keystore.enroll(FAKE_FP, FAKE_ARMOR)
        assert enrolled.fingerprint == FAKE_FP
        assert enrolled.approved is True

        retrieved = keystore.get(FAKE_FP)
        assert retrieved is not None
        assert retrieved.fingerprint == FAKE_FP

    def test_get_nonexistent(self, keystore: KeyStore) -> None:
        """Looking up a missing key returns None."""
        assert keystore.get("B" * 40) is None

    def test_enroll_unapproved(self, keystore: KeyStore) -> None:
        """Keys can be enrolled as pending approval."""
        enrolled = keystore.enroll(FAKE_FP, FAKE_ARMOR, approved=False)
        assert enrolled.approved is False

        retrieved = keystore.get(FAKE_FP)
        assert retrieved is not None
        assert retrieved.approved is False

    def test_approve(self, keystore: KeyStore) -> None:
        """Pending keys can be approved."""
        keystore.enroll(FAKE_FP, FAKE_ARMOR, approved=False)
        assert keystore.approve(FAKE_FP) is True

        retrieved = keystore.get(FAKE_FP)
        assert retrieved is not None
        assert retrieved.approved is True

    def test_approve_nonexistent(self, keystore: KeyStore) -> None:
        """Approving a missing key returns False."""
        assert keystore.approve("C" * 40) is False

    def test_revoke(self, keystore: KeyStore) -> None:
        """Revoking a key should remove it."""
        keystore.enroll(FAKE_FP, FAKE_ARMOR)
        assert keystore.revoke(FAKE_FP) is True
        assert keystore.get(FAKE_FP) is None

    def test_revoke_nonexistent(self, keystore: KeyStore) -> None:
        """Revoking a missing key returns False."""
        assert keystore.revoke("D" * 40) is False

    def test_list_keys(self, keystore: KeyStore) -> None:
        """Listing keys should return all enrolled."""
        keystore.enroll("A" * 40, FAKE_ARMOR)
        keystore.enroll("B" * 40, FAKE_ARMOR)
        assert len(keystore.list_keys()) == 2

    def test_list_approved_only(self, keystore: KeyStore) -> None:
        """Filtering approved-only should exclude pending."""
        keystore.enroll("A" * 40, FAKE_ARMOR, approved=True)
        keystore.enroll("B" * 40, FAKE_ARMOR, approved=False)
        approved = keystore.list_keys(approved_only=True)
        assert len(approved) == 1
        assert approved[0].fingerprint == "A" * 40

    def test_update_last_auth(self, keystore: KeyStore) -> None:
        """Recording auth should update last_auth timestamp."""
        keystore.enroll(FAKE_FP, FAKE_ARMOR)
        keystore.update_last_auth(FAKE_FP)
        retrieved = keystore.get(FAKE_FP)
        assert retrieved is not None
        assert retrieved.last_auth is not None

    def test_count(self, keystore: KeyStore) -> None:
        """Count should reflect enrolled keys."""
        assert keystore.count() == 0
        keystore.enroll(FAKE_FP, FAKE_ARMOR)
        assert keystore.count() == 1

    def test_effective_fingerprint(self, keystore: KeyStore) -> None:
        """Linked keys should report primary fingerprint."""
        enrolled = keystore.enroll(FAKE_FP, FAKE_ARMOR)
        assert enrolled.effective_fingerprint == FAKE_FP

    def test_case_insensitive_lookup(self, keystore: KeyStore) -> None:
        """Fingerprints are stored uppercase regardless of input case."""
        keystore.enroll("a" * 40, FAKE_ARMOR)
        assert keystore.get("A" * 40) is not None


class TestServiceEndpoints:
    """Tests for the FastAPI endpoints using TestClient."""

    @pytest.fixture(autouse=True)
    def setup_app(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Configure the app with a temp database."""
        monkeypatch.setenv("CAPAUTH_DB_PATH", str(tmp_path / "service_test.db"))
        monkeypatch.setenv("CAPAUTH_ADMIN_TOKEN", "test-admin-token")
        monkeypatch.setenv("CAPAUTH_SERVICE_ID", "test.capauth.local")
        monkeypatch.setenv("CAPAUTH_JWT_SECRET", "test-jwt-secret-deterministic")

        # Reset the keystore singleton (close if open, then re-init)
        import capauth.service.app as svc_app
        from capauth.service.keystore import KeyStore
        if svc_app._keystore is not None:
            try:
                svc_app._keystore.close()
            except Exception:
                pass
        svc_app._keystore = KeyStore(tmp_path / "service_test.db")

        from fastapi.testclient import TestClient
        self.client = TestClient(svc_app.app)

    def test_status(self) -> None:
        """Status endpoint should return service info."""
        resp = self.client.get("/capauth/v1/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["service"] == "test.capauth.local"
        assert data["healthy"] is True

    def test_challenge_valid_fingerprint(self) -> None:
        """Challenge should succeed with a valid 40-char fingerprint."""
        resp = self.client.post("/capauth/v1/challenge", json={
            "fingerprint": "A" * 40,
            "client_nonce": "dGVzdA==",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "nonce" in data
        assert data["service"] == "test.capauth.local"

    def test_challenge_invalid_fingerprint(self) -> None:
        """Challenge should reject short fingerprints."""
        resp = self.client.post("/capauth/v1/challenge", json={
            "fingerprint": "short",
            "client_nonce": "dGVzdA==",
        })
        assert resp.status_code == 400

    def test_verify_unknown_fingerprint(self) -> None:
        """Verify should reject unknown fingerprints without a public key."""
        resp = self.client.post("/capauth/v1/verify", json={
            "fingerprint": "B" * 40,
            "nonce": "fake-nonce",
            "nonce_signature": "fake-sig",
        })
        assert resp.status_code == 401

    def test_oidc_discovery(self) -> None:
        """OIDC discovery should return a valid document."""
        resp = self.client.get("/.well-known/openid-configuration")
        assert resp.status_code == 200
        data = resp.json()
        assert "capauth_pgp" in data["token_endpoint_auth_methods_supported"]
        assert "openid" in data["scopes_supported"]

    def test_oidc_discovery_forgejo_required_fields(self) -> None:
        """OIDC discovery document should satisfy Forgejo's autodiscovery requirements."""
        resp = self.client.get("/.well-known/openid-configuration")
        assert resp.status_code == 200
        data = resp.json()
        # Fields required by Forgejo's OIDC client
        assert "issuer" in data
        assert "authorization_endpoint" in data
        assert "token_endpoint" in data
        assert "userinfo_endpoint" in data
        assert "jwks_uri" in data
        assert "response_types_supported" in data
        assert "code" in data["response_types_supported"]
        assert "subject_types_supported" in data
        assert "public" in data["subject_types_supported"]
        assert "id_token_signing_alg_values_supported" in data
        assert "HS256" in data["id_token_signing_alg_values_supported"]
        assert "scopes_supported" in data
        assert "claims_supported" in data
        assert "sub" in data["claims_supported"]
        assert "email" in data["claims_supported"]
        # Additional fields Forgejo expects
        assert "end_session_endpoint" in data
        assert "grant_types_supported" in data
        assert "code_challenge_methods_supported" in data

    def test_jwks_endpoint(self) -> None:
        """JWKS endpoint should return a parseable document."""
        resp = self.client.get("/.well-known/jwks.json")
        assert resp.status_code == 200
        data = resp.json()
        assert "keys" in data
        assert isinstance(data["keys"], list)

    def test_userinfo_no_token(self) -> None:
        """Userinfo endpoint should reject requests without bearer token."""
        resp = self.client.get("/capauth/v1/userinfo")
        assert resp.status_code == 401

    def test_userinfo_valid_token(self) -> None:
        """Userinfo endpoint should return claims for a valid JWT."""
        import jwt as pyjwt
        import time
        import capauth.service.app as svc_app
        svc_app.JWT_SECRET = "test-jwt-secret-deterministic"

        now = int(time.time())
        payload = {
            "sub": "A" * 40,
            "iss": "test.capauth.local",
            "iat": now,
            "exp": now + 3600,
            "amr": ["pgp"],
            "capauth_fingerprint": "A" * 40,
            "name": "Test User",
        }
        token = pyjwt.encode(payload, "test-jwt-secret-deterministic", algorithm="HS256")

        resp = self.client.get("/capauth/v1/userinfo", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["sub"] == "A" * 40
        assert data["name"] == "Test User"
        assert "pgp" in data["amr"]

    def test_logout_endpoint(self) -> None:
        """Logout endpoint should return success (no-op)."""
        resp = self.client.get("/capauth/v1/logout")
        assert resp.status_code == 200
        assert resp.json()["logged_out"] is True

    def test_admin_list_keys_no_token(self) -> None:
        """Admin endpoints should reject requests without token."""
        resp = self.client.get("/capauth/v1/keys")
        assert resp.status_code == 403

    def test_admin_list_keys_with_token(self) -> None:
        """Admin endpoints should work with valid token."""
        resp = self.client.get(
            "/capauth/v1/keys",
            headers={"Authorization": "Bearer test-admin-token"},
        )
        assert resp.status_code == 200
        assert resp.json() == []

    def test_admin_approve_nonexistent(self) -> None:
        """Approving a missing key should 404."""
        resp = self.client.post(
            "/capauth/v1/keys/approve",
            json={"fingerprint": "C" * 40},
            headers={"Authorization": "Bearer test-admin-token"},
        )
        assert resp.status_code == 404


class TestJWTTokens:
    """Tests for JWT access token generation and introspection."""

    @pytest.fixture(autouse=True)
    def setup_app(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Configure app with deterministic JWT secret."""
        monkeypatch.setenv("CAPAUTH_DB_PATH", str(tmp_path / "jwt_test.db"))
        monkeypatch.setenv("CAPAUTH_SERVICE_ID", "jwt.capauth.test")
        monkeypatch.setenv("CAPAUTH_JWT_SECRET", "test-deterministic-jwt-secret-32x")

        import capauth.service.app as svc_app
        from capauth.service.keystore import KeyStore
        if svc_app._keystore is not None:
            try:
                svc_app._keystore.close()
            except Exception:
                pass
        svc_app._keystore = KeyStore(tmp_path / "jwt_test.db")
        # Force JWT_SECRET to pick up the monkeypatched env var
        svc_app.JWT_SECRET = "test-deterministic-jwt-secret-32x"
        svc_app.SERVICE_ID = "jwt.capauth.test"

        from fastapi.testclient import TestClient
        self.client = TestClient(svc_app.app)
        self.svc_app = svc_app

    def _make_jwt(self, sub: str = "A" * 40, exp_offset: int = 3600) -> str:
        """Generate a test JWT directly."""
        import jwt as pyjwt
        import time
        now = int(time.time())
        payload = {
            "sub": sub,
            "iss": "jwt.capauth.test",
            "iat": now,
            "exp": now + exp_offset,
            "amr": ["pgp"],
            "capauth_fingerprint": sub,
        }
        return pyjwt.encode(payload, "test-deterministic-jwt-secret-32x", algorithm="HS256")

    def test_token_info_valid_token(self) -> None:
        """Valid JWT should return active=true with correct claims."""
        token = self._make_jwt("A" * 40)
        resp = self.client.get(f"/capauth/v1/token-info?token={token}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["active"] is True
        assert data["sub"] == "A" * 40
        assert data["iss"] == "jwt.capauth.test"
        assert "pgp" in data["amr"]
        assert data["capauth_fingerprint"] == "A" * 40

    def test_token_info_expired_token(self) -> None:
        """Expired JWT should return active=false with token_expired error."""
        token = self._make_jwt("B" * 40, exp_offset=-1)  # already expired
        resp = self.client.get(f"/capauth/v1/token-info?token={token}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["active"] is False
        assert data["error"] == "token_expired"

    def test_token_info_garbage_token(self) -> None:
        """Garbage token string should return active=false."""
        resp = self.client.get("/capauth/v1/token-info?token=not-a-real-jwt")
        assert resp.status_code == 200
        data = resp.json()
        assert data["active"] is False
        assert data["error"].startswith("invalid_token")

    def test_token_info_wrong_secret(self) -> None:
        """Token signed with wrong secret should return active=false."""
        import jwt as pyjwt
        import time
        payload = {"sub": "C" * 40, "iss": "test", "iat": int(time.time()), "exp": int(time.time()) + 3600}
        bad_token = pyjwt.encode(payload, "wrong-secret", algorithm="HS256")
        resp = self.client.get(f"/capauth/v1/token-info?token={bad_token}")
        assert resp.status_code == 200
        assert resp.json()["active"] is False

    def test_oidc_callback_missing_code(self) -> None:
        """Callback with no code and no error should return 400."""
        resp = self.client.get("/capauth/v1/callback")
        assert resp.status_code == 400

    def test_oidc_callback_error_param(self) -> None:
        """Callback with error param should return 400 HTML with error details."""
        resp = self.client.get("/capauth/v1/callback?error=access_denied&error_description=User+cancelled")
        assert resp.status_code == 400
        assert "access_denied" in resp.text
        assert "User cancelled" in resp.text

    def test_oidc_callback_no_client_config(self) -> None:
        """Callback with code but no OIDC client configured returns 501."""
        import capauth.service.app as svc_app
        original_id = svc_app.AUTHENTIK_CLIENT_ID
        svc_app.AUTHENTIK_CLIENT_ID = ""
        try:
            resp = self.client.get("/capauth/v1/callback?code=testcode")
            assert resp.status_code == 501
        finally:
            svc_app.AUTHENTIK_CLIENT_ID = original_id

    def test_oidc_callback_token_exchange_success(self) -> None:
        """Callback with valid code triggers token exchange and returns CapAuth JWT."""
        import time
        import jwt as pyjwt
        from unittest.mock import AsyncMock, MagicMock, patch

        fake_oidc_cfg = {
            "token_endpoint": "https://sso.example.com/token",
            "userinfo_endpoint": "https://sso.example.com/userinfo",
        }
        fake_token_resp = MagicMock()
        fake_token_resp.raise_for_status = MagicMock()
        fake_token_resp.json.return_value = {
            "access_token": "upstream-access-token",
            "id_token": "upstream-id-token",
        }
        fake_userinfo_resp = MagicMock()
        fake_userinfo_resp.raise_for_status = MagicMock()
        fake_userinfo_resp.json.return_value = {
            "sub": "user123",
            "name": "SmilinTux",
            "email": "admin@smilintux.org",
            "groups": ["admins"],
        }

        import capauth.service.app as svc_app
        original_id = svc_app.AUTHENTIK_CLIENT_ID
        original_secret = svc_app.AUTHENTIK_CLIENT_SECRET
        svc_app.AUTHENTIK_CLIENT_ID = "test-client-id"
        svc_app.AUTHENTIK_CLIENT_SECRET = "test-client-secret"

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=fake_token_resp)
        mock_client.get = AsyncMock(return_value=fake_userinfo_resp)

        try:
            with patch("capauth.service.app._get_oidc_config", AsyncMock(return_value=fake_oidc_cfg)), \
                 patch("httpx.AsyncClient", return_value=mock_client):
                resp = self.client.get("/capauth/v1/callback?code=authcode123")

            assert resp.status_code == 200
            assert "SmilinTux" in resp.text
            assert "admin@smilintux.org" in resp.text
            assert "admins" in resp.text
        finally:
            svc_app.AUTHENTIK_CLIENT_ID = original_id
            svc_app.AUTHENTIK_CLIENT_SECRET = original_secret

    def test_access_token_is_valid_jwt(self) -> None:
        """Access token returned by /verify should be a decodable JWT."""
        import jwt as pyjwt

        # Enroll a key manually
        FAKE_FP = "D" * 40
        FAKE_PUB = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfake\n-----END PGP PUBLIC KEY BLOCK-----"
        self.svc_app._keystore.enroll(FAKE_FP, FAKE_PUB, approved=True)

        # Issue a challenge
        import capauth.authentik.nonce_store as ns
        ns._MEM_CACHE.clear()
        nonce_record = ns.issue(FAKE_FP, client_nonce_echo="dGVzdA==")
        nonce_id = nonce_record["nonce"]

        # Inject a fake verify that bypasses sig check by patching verify_auth_response
        import capauth.service.app as svc_app
        from unittest.mock import patch

        fake_claims = {"sub": FAKE_FP, "capauth_fingerprint": FAKE_FP, "amr": ["pgp"]}
        with patch("capauth.service.app.verify_auth_response", return_value=(True, "", fake_claims)):
            resp = self.client.post("/capauth/v1/verify", json={
                "fingerprint": FAKE_FP,
                "nonce": nonce_id,
                "nonce_signature": "fake-will-be-patched",
                "public_key": FAKE_PUB,
            })

        assert resp.status_code == 200
        result = resp.json()
        token = result["access_token"]

        # Must be a proper JWT
        decoded = pyjwt.decode(
            token,
            "test-deterministic-jwt-secret-32x",
            algorithms=["HS256"],
        )
        assert decoded["sub"] == FAKE_FP
        assert decoded["iss"] == "jwt.capauth.test"
        assert "pgp" in decoded["amr"]
