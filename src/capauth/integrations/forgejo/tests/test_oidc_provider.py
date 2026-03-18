"""Tests for the Forgejo OIDC provider FastAPI router."""

from __future__ import annotations

import time
from typing import Any

import jwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from capauth.integrations.forgejo.auth_flow import ForgejoAuthFlow
from capauth.integrations.forgejo.config import ForgejoConfig
from capauth.integrations.forgejo.oidc_provider import build_router

SECRET = "test-secret-that-is-32-bytes-!!"
FINGERPRINT = "B" * 40
REDIRECT_URI = "https://git.example.com/user/oauth2/capauth/callback"
STATE = "test-oauth-state-xyz"


@pytest.fixture
def config() -> ForgejoConfig:
    return ForgejoConfig(
        capauth_base_url="https://auth.example.com",
        capauth_jwt_secret=SECRET,
        forgejo_base_url="https://git.example.com",
        client_id="capauth",
        client_secret="any",
        auth_code_ttl=120,
    )


@pytest.fixture
def app(config: ForgejoConfig) -> FastAPI:
    flow = ForgejoAuthFlow(config)
    router = build_router(flow, config)
    application = FastAPI()
    application.include_router(router, prefix="/forgejo")
    return application


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app, raise_server_exceptions=True)


def _make_jwt(config: ForgejoConfig, fingerprint: str = FINGERPRINT, **extra: Any) -> str:
    now = int(time.time())
    payload = {
        "sub": fingerprint,
        "iss": config.capauth_base_url,
        "iat": now,
        "exp": now + 3600,
        "capauth_fingerprint": fingerprint,
        **extra,
    }
    return jwt.encode(payload, config.capauth_jwt_secret, algorithm="HS256")


# ---------------------------------------------------------------------------
# OIDC discovery
# ---------------------------------------------------------------------------


class TestOIDCDiscovery:
    def test_discovery_document(self, client: TestClient) -> None:
        resp = client.get("/forgejo/.well-known/openid-configuration")
        assert resp.status_code == 200
        doc = resp.json()
        assert doc["issuer"] == "https://auth.example.com"
        assert "/forgejo/authorize" in doc["authorization_endpoint"]
        assert "/forgejo/token" in doc["token_endpoint"]
        assert "/forgejo/userinfo" in doc["userinfo_endpoint"]
        assert "S256" in doc["code_challenge_methods_supported"]
        assert "capauth_fingerprint" in doc["claims_supported"]


# ---------------------------------------------------------------------------
# Authorization endpoint
# ---------------------------------------------------------------------------


class TestAuthorizeEndpoint:
    def test_renders_signing_page(self, client: TestClient) -> None:
        resp = client.get(
            "/forgejo/authorize",
            params={
                "response_type": "code",
                "client_id": "capauth",
                "redirect_uri": REDIRECT_URI,
                "state": STATE,
                "scope": "openid profile email",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 200
        assert "CapAuth" in resp.text
        assert STATE in resp.text

    def test_missing_state_returns_400(self, client: TestClient) -> None:
        resp = client.get(
            "/forgejo/authorize",
            params={"response_type": "code", "client_id": "capauth"},
        )
        assert resp.status_code == 400

    def test_wrong_response_type_returns_400(self, client: TestClient) -> None:
        resp = client.get(
            "/forgejo/authorize",
            params={"response_type": "token", "client_id": "capauth", "state": STATE},
        )
        assert resp.status_code == 400

    def test_unknown_client_returns_400(self, client: TestClient) -> None:
        resp = client.get(
            "/forgejo/authorize",
            params={
                "response_type": "code",
                "client_id": "evil",
                "state": STATE,
                "redirect_uri": REDIRECT_URI,
            },
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# authorize/complete
# ---------------------------------------------------------------------------


class TestAuthorizeComplete:
    def _start_session(self, client: TestClient) -> None:
        client.get(
            "/forgejo/authorize",
            params={
                "response_type": "code",
                "client_id": "capauth",
                "redirect_uri": REDIRECT_URI,
                "state": STATE,
            },
        )

    def test_complete_ok(self, client: TestClient, config: ForgejoConfig) -> None:
        self._start_session(client)
        token = _make_jwt(config)
        resp = client.post(
            "/forgejo/authorize/complete",
            json={
                "state": STATE,
                "fingerprint": FINGERPRINT,
                "access_token": token,
                "oidc_claims": {"name": "Bob", "email": "bob@example.com"},
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "redirect_to" in body
        assert "code=" in body["redirect_to"]
        assert f"state={STATE}" in body["redirect_to"]

    def test_complete_missing_session_returns_400(
        self, client: TestClient, config: ForgejoConfig
    ) -> None:
        token = _make_jwt(config)
        resp = client.post(
            "/forgejo/authorize/complete",
            json={"state": "bad-state", "fingerprint": FINGERPRINT, "access_token": token},
        )
        assert resp.status_code == 400

    def test_complete_invalid_token_returns_401(self, client: TestClient) -> None:
        self._start_session(client)
        resp = client.post(
            "/forgejo/authorize/complete",
            json={"state": STATE, "fingerprint": FINGERPRINT, "access_token": "not-a-jwt"},
        )
        assert resp.status_code == 401

    def test_complete_fingerprint_mismatch_returns_401(
        self, client: TestClient, config: ForgejoConfig
    ) -> None:
        self._start_session(client)
        # JWT says CCCC... but we claim BBBB...
        token = _make_jwt(config, fingerprint="C" * 40)
        resp = client.post(
            "/forgejo/authorize/complete",
            json={"state": STATE, "fingerprint": FINGERPRINT, "access_token": token},
        )
        assert resp.status_code == 401

    def test_complete_missing_fields_returns_400(self, client: TestClient) -> None:
        resp = client.post("/forgejo/authorize/complete", json={})
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Token endpoint
# ---------------------------------------------------------------------------


class TestTokenEndpoint:
    def _get_code(self, client: TestClient, config: ForgejoConfig) -> str:
        """Run the authorize → complete flow and extract the auth code."""
        client.get(
            "/forgejo/authorize",
            params={
                "response_type": "code",
                "client_id": "capauth",
                "redirect_uri": REDIRECT_URI,
                "state": STATE,
            },
        )
        token = _make_jwt(config)
        resp = client.post(
            "/forgejo/authorize/complete",
            json={
                "state": STATE,
                "fingerprint": FINGERPRINT,
                "access_token": token,
                "oidc_claims": {},
            },
        )
        redirect_to: str = resp.json()["redirect_to"]
        # Parse code from redirect_to URL
        from urllib.parse import parse_qs, urlparse

        qs = parse_qs(urlparse(redirect_to).query)
        return qs["code"][0]

    def test_token_exchange_ok(self, client: TestClient, config: ForgejoConfig) -> None:
        code = self._get_code(client, config)
        resp = client.post(
            "/forgejo/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": "capauth",
                "client_secret": "any",
            },
        )
        assert resp.status_code == 200
        tokens = resp.json()
        assert "access_token" in tokens
        assert tokens["token_type"] == "Bearer"
        assert "id_token" in tokens

    def test_token_invalid_code(self, client: TestClient) -> None:
        resp = client.post(
            "/forgejo/token",
            data={"grant_type": "authorization_code", "code": "invalid", "client_id": "capauth"},
        )
        assert resp.status_code == 400

    def test_token_wrong_grant_type(self, client: TestClient) -> None:
        resp = client.post(
            "/forgejo/token",
            data={"grant_type": "client_credentials", "client_id": "capauth"},
        )
        assert resp.status_code == 400

    def test_token_missing_code(self, client: TestClient) -> None:
        resp = client.post(
            "/forgejo/token",
            data={"grant_type": "authorization_code", "client_id": "capauth"},
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# UserInfo endpoint
# ---------------------------------------------------------------------------


class TestUserInfoEndpoint:
    def test_userinfo_ok(self, client: TestClient, config: ForgejoConfig) -> None:
        token = _make_jwt(config, name="Alice", email="alice@example.com", groups=["admins"])
        resp = client.get("/forgejo/userinfo", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        claims = resp.json()
        assert claims["sub"] == FINGERPRINT
        assert claims["name"] == "Alice"
        assert claims["email_verified"] is True
        # iat/exp stripped
        assert "iat" not in claims
        assert "exp" not in claims

    def test_userinfo_missing_bearer(self, client: TestClient) -> None:
        resp = client.get("/forgejo/userinfo")
        assert resp.status_code == 401

    def test_userinfo_invalid_token(self, client: TestClient) -> None:
        resp = client.get("/forgejo/userinfo", headers={"Authorization": "Bearer bad-token"})
        assert resp.status_code == 401

    def test_userinfo_expired_token(self, client: TestClient, config: ForgejoConfig) -> None:
        expired = jwt.encode(
            {"sub": FINGERPRINT, "exp": int(time.time()) - 10, "capauth_fingerprint": FINGERPRINT},
            config.capauth_jwt_secret,
            algorithm="HS256",
        )
        resp = client.get("/forgejo/userinfo", headers={"Authorization": f"Bearer {expired}"})
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------


class TestLogoutEndpoint:
    def test_logout_returns_ok(self, client: TestClient) -> None:
        resp = client.get("/forgejo/logout")
        assert resp.status_code == 200
        assert resp.json()["logged_out"] is True
