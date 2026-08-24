"""Endpoint-level security tests for the hardened OIDC browser flow."""

from __future__ import annotations

import base64
import hashlib
import sqlite3
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import jwt as pyjwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from capauth.service.oidc.clients import ClientRegistry, OIDCClient
from capauth.service.oidc.provider import build_oidc_router
from capauth.service.oidc.signing_key import SigningKey
from capauth.service.oidc.store import AuthCodeStore

ISSUER = "https://capauth.test"
CLIENT_ID = "authentik"
SECRET = "client-secret"
REDIRECT = "https://authentik.test/callback"
FINGERPRINT = "A" * 40
VERIFIER = "verifier-string-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
CHALLENGE = (
    base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).rstrip(b"=").decode()
)
STATE = "state-0123456789abcdef"
NONCE = "nonce-0123456789abcdef"


@pytest.fixture
def hardened(monkeypatch, tmp_path):
    monkeypatch.setenv("CAPAUTH_OIDC_ISSUER", ISSUER)
    signing_key = SigningKey(tmp_path / "signing.pem")
    registry = ClientRegistry(
        [
            OIDCClient(
                client_id=CLIENT_ID,
                client_secret=SECRET,
                redirect_uris=[REDIRECT],
                scopes=["openid", "profile", "email"],
            )
        ]
    )
    store = AuthCodeStore(tmp_path / "state.db")
    router = build_oidc_router(signing_key=signing_key, clients=registry, store=store)

    import capauth.authentik.nonce_store as nonce_store
    import capauth.authentik.stage as stage
    import capauth.authentik.verifier as verifier
    import capauth.service.app as app

    monkeypatch.setattr(
        nonce_store,
        "peek",
        lambda nonce: {
            "nonce": nonce,
            "client_nonce_echo": "echo",
            "issued_at": "2026-08-24T00:00:00Z",
            "expires_at": "2026-08-24T00:05:00Z",
        },
    )
    monkeypatch.setattr(
        stage,
        "verify_auth_response",
        lambda **kwargs: (
            True,
            "",
            {"sub": kwargs["fingerprint"], "amr": ["pgp"], "email": "a@example.test"},
        ),
    )
    monkeypatch.setattr(verifier, "fingerprint_from_armor", lambda _armor: FINGERPRINT)

    class FakeKeyStore:
        key = SimpleNamespace(public_key_armor="PUBLIC", approved=True)
        unavailable = False

        def get(self, _fingerprint):
            if self.unavailable:
                raise sqlite3.OperationalError("offline")
            return self.key

        def update_last_auth(self, _fingerprint):
            if self.unavailable:
                raise sqlite3.OperationalError("offline")

    keystore = FakeKeyStore()
    monkeypatch.setattr(app, "get_keystore", lambda: keystore)
    monkeypatch.setattr(app, "SERVICE_ID", "capauth.test")
    web = FastAPI()
    web.include_router(router, prefix="/oidc")
    return SimpleNamespace(
        client=TestClient(web),
        router=router,
        store=store,
        signing_key=signing_key,
        registry=registry,
        keystore=keystore,
        path=tmp_path / "state.db",
    )


def _authorization_params(**overrides):
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT,
        "scope": "openid profile email",
        "state": STATE,
        "nonce": NONCE,
        "code_challenge": CHALLENGE,
        "code_challenge_method": "S256",
        "issuer": ISSUER,
    }
    params.update(overrides)
    return params


def _begin(client: TestClient, **overrides) -> str:
    response = client.get("/oidc/authorize", params=_authorization_params(**overrides))
    assert response.status_code == 200, response.text
    return response.text.split('REQUEST_ID = "', 1)[1].split('"', 1)[0]


def _complete(client: TestClient, request_id: str):
    return client.post(
        "/oidc/complete",
        json={
            "request_id": request_id,
            "fingerprint": FINGERPRINT,
            "nonce": "pgp-challenge",
            "nonce_signature": "signature",
        },
    )


def _code(response) -> str:
    body = response.json()
    assert "code" not in body
    return parse_qs(urlsplit(body["redirect_to"]).query)["code"][0]


def _tokens(client: TestClient, code: str):
    return client.post(
        "/oidc/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "client_id": CLIENT_ID,
            "client_secret": SECRET,
            "code_verifier": VERIFIER,
        },
    )


@pytest.mark.parametrize(
    ("override", "detail"),
    [
        ({"state": ""}, "invalid_state"),
        ({"nonce": ""}, "invalid_nonce"),
        ({"code_challenge": ""}, "invalid_code_challenge"),
        ({"code_challenge_method": "plain"}, "unsupported code_challenge_method"),
        ({"redirect_uri": "https://evil.test/callback"}, "invalid redirect_uri"),
        ({"issuer": "https://other.test"}, "invalid_issuer"),
        ({"scope": "profile"}, "invalid_scope"),
        ({"scope": "openid admin"}, "invalid_scope"),
        ({"scope": "openid openid"}, "invalid_scope"),
    ],
)
def test_authorization_boundary_is_mandatory_and_exact(hardened, override, detail):
    response = hardened.client.get("/oidc/authorize", params=_authorization_params(**override))
    assert response.status_code == 400
    assert response.json()["detail"] == detail


def test_first_seen_and_unapproved_identities_never_receive_code(hardened):
    hardened.keystore.key = None
    unknown = _complete(hardened.client, _begin(hardened.client))
    assert unknown.status_code == 401
    assert unknown.json()["detail"] == "unknown_fingerprint"

    hardened.keystore.key = SimpleNamespace(public_key_armor="PUBLIC", approved=False)
    unapproved = _complete(hardened.client, _begin(hardened.client))
    assert unapproved.status_code == 403
    assert unapproved.json()["detail"] == "fingerprint_not_approved"
    assert hardened.store.pending_codes == 0


def test_durable_code_exchanges_after_router_restart_and_cannot_replay(hardened):
    code = _code(_complete(hardened.client, _begin(hardened.client)))
    restarted = FastAPI()
    restarted.include_router(
        build_oidc_router(
            signing_key=hardened.signing_key,
            clients=hardened.registry,
            store=AuthCodeStore(hardened.path),
        ),
        prefix="/oidc",
    )
    restarted_client = TestClient(restarted)
    first = _tokens(restarted_client, code)
    assert first.status_code == 200, first.text
    assert _tokens(restarted_client, code).status_code == 400


def test_missing_redirect_burns_code_and_does_not_leak_binding_reason(hardened):
    code = _code(_complete(hardened.client, _begin(hardened.client)))
    bad = hardened.client.post(
        "/oidc/token",
        data={
            "code": code,
            "client_id": CLIENT_ID,
            "client_secret": SECRET,
            "code_verifier": VERIFIER,
        },
    )
    assert bad.status_code == 400
    assert bad.json()["detail"] == "invalid_grant"
    assert _tokens(hardened.client, code).status_code == 400


def test_access_token_is_bounded_and_logout_revokes_currentness(hardened):
    token_response = _tokens(
        hardened.client, _code(_complete(hardened.client, _begin(hardened.client)))
    )
    assert token_response.status_code == 200, token_response.text
    body = token_response.json()
    assert 1 <= body["expires_in"] <= 300
    for encoded in (body["id_token"], body["access_token"]):
        claims = pyjwt.decode(encoded, options={"verify_signature": False})
        assert 1 <= claims["exp"] - claims["iat"] <= 300
    headers = {"Authorization": f"Bearer {body['access_token']}"}
    assert hardened.client.get("/oidc/userinfo", headers=headers).status_code == 200
    logout = hardened.client.post("/oidc/logout", headers=headers)
    assert logout.status_code == 200
    assert logout.json() == {"revoked": True}
    assert hardened.client.get("/oidc/userinfo", headers=headers).status_code == 401


def test_revoked_enrollment_invalidates_an_existing_access_token(hardened):
    body = _tokens(
        hardened.client, _code(_complete(hardened.client, _begin(hardened.client)))
    ).json()
    hardened.keystore.key = None
    response = hardened.client.get(
        "/oidc/userinfo", headers={"Authorization": f"Bearer {body['access_token']}"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "enrollment_not_current"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("iss", "https://other.test"),
        ("aud", "other-client"),
        ("sub", "B" * 40),
        ("scope", "openid admin"),
        ("exp", 9_999_999_999),
    ],
)
def test_signed_access_token_binding_mutations_deny(hardened, field, value):
    body = _tokens(
        hardened.client, _code(_complete(hardened.client, _begin(hardened.client)))
    ).json()
    claims = pyjwt.decode(body["access_token"], options={"verify_signature": False})
    claims[field] = value
    mutated = pyjwt.encode(
        claims,
        hardened.signing_key.private_pem,
        algorithm=hardened.signing_key.ALGORITHM,
        headers={"kid": hardened.signing_key.kid},
    )
    response = hardened.client.get(
        "/oidc/userinfo", headers={"Authorization": f"Bearer {mutated}"}
    )
    assert response.status_code == 401


def test_outages_remain_distinct_and_fail_closed(hardened, monkeypatch):
    request_id = _begin(hardened.client)
    hardened.keystore.unavailable = True
    enrollment = _complete(hardened.client, request_id)
    assert (enrollment.status_code, enrollment.json()["detail"]) == (
        503,
        "enrollment_unavailable",
    )
    hardened.keystore.unavailable = False

    def unavailable():
        raise sqlite3.OperationalError("offline")

    monkeypatch.setattr(hardened.store, "_connect", unavailable)
    state = _complete(hardened.client, request_id)
    assert (state.status_code, state.json()["detail"]) == (503, "state_unavailable")


def test_token_currentness_outage_is_not_reported_as_auth_denial(hardened, monkeypatch):
    body = _tokens(
        hardened.client, _code(_complete(hardened.client, _begin(hardened.client)))
    ).json()

    def unavailable():
        raise sqlite3.OperationalError("offline")

    monkeypatch.setattr(hardened.store, "_connect", unavailable)
    response = hardened.client.get(
        "/oidc/userinfo", headers={"Authorization": f"Bearer {body['access_token']}"}
    )
    assert (response.status_code, response.json()["detail"]) == (
        503,
        "currentness_unavailable",
    )


def test_authorization_rate_limit_is_enforced(hardened):
    for _ in range(30):
        assert (
            hardened.client.get("/oidc/authorize", params=_authorization_params()).status_code
            == 200
        )
    response = hardened.client.get("/oidc/authorize", params=_authorization_params())
    assert (response.status_code, response.json()["detail"]) == (429, "rate_limited")


def test_signer_and_ttl_configuration_outages_deny_distinctly(hardened, monkeypatch):
    import capauth.service.oidc.provider as provider

    code = _code(_complete(hardened.client, _begin(hardened.client)))
    with monkeypatch.context() as scoped:
        scoped.setattr(
            provider.pyjwt,
            "encode",
            lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("offline")),
        )
        signer = _tokens(hardened.client, code)
    assert (signer.status_code, signer.json()["detail"]) == (503, "signer_unavailable")


def test_token_ttl_above_five_minutes_fails_closed(hardened, monkeypatch):
    code = _code(_complete(hardened.client, _begin(hardened.client)))
    monkeypatch.setenv("CAPAUTH_OIDC_ACCESS_TOKEN_TTL", "301")
    response = _tokens(hardened.client, code)
    assert (response.status_code, response.json()["detail"]) == (
        503,
        "configuration_unavailable",
    )
