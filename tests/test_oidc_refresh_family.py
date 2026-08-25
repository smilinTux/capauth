"""Security boundary tests for the SKDashboard refresh-family contract."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import replace
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from capauth.pairing import EnrollmentMode, approve, enroll_device, revoke
from capauth.service.oidc.clients import ClientRegistry, OIDCClient
from capauth.service.oidc.provider import (
    SESSION_POLICY_VERSION,
    SKDASHBOARD_AUDIENCE,
    SKDASHBOARD_SCOPES,
    build_oidc_router,
)
from capauth.service.oidc.signing_key import SigningKey
from capauth.service.oidc.store import AuthCodeStore, InvalidGrantError
from capauth.tokens import TokenSigningError, issue_token

SUBJECT = "A" * 40
SECRET = "dashboard-secret"
REDIRECT = "https://dashboard.test/auth/callback"
VERIFIER = "verifier-string-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
CHALLENGE = (
    base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).rstrip(b"=").decode()
)


def _family(store: AuthCodeStore):
    return store.create_refresh_family(
        subject=SUBJECT,
        client_id=SKDASHBOARD_AUDIENCE,
        audience=SKDASHBOARD_AUDIENCE,
        scope=" ".join(SKDASHBOARD_SCOPES),
        policy_version=SESSION_POLICY_VERSION,
    )


def test_refresh_family_rotates_once_and_replay_revokes_successor(tmp_path):
    path = tmp_path / "state.db"
    first = _family(AuthCodeStore(path))
    assert first.token.encode() not in path.read_bytes()

    successor = AuthCodeStore(path).rotate_refresh_token(
        AuthCodeStore(path).inspect_refresh_token(first.token)
    )
    assert successor.generation == 1
    assert successor.token != first.token
    assert successor.token.encode() not in path.read_bytes()

    with pytest.raises(InvalidGrantError, match="replayed"):
        AuthCodeStore(path).inspect_refresh_token(first.token)
    with pytest.raises(InvalidGrantError, match="inactive"):
        AuthCodeStore(path).inspect_refresh_token(successor.token)


def test_refresh_rotation_rejects_client_substitution_and_revokes_family(tmp_path):
    store = AuthCodeStore(tmp_path / "state.db")
    first = _family(store)
    grant = store.inspect_refresh_token(first.token)
    with pytest.raises(InvalidGrantError, match="conflict"):
        store.rotate_refresh_token(replace(grant, client_id="other-client"))
    with pytest.raises(InvalidGrantError, match="inactive"):
        store.inspect_refresh_token(first.token)


@pytest.fixture
def refresh_app(monkeypatch, tmp_path, stub_token_signing):
    monkeypatch.setenv("CAPAUTH_OIDC_ISSUER", "https://capauth.test")
    monkeypatch.setenv("CAPAUTH_HOME", str(tmp_path))
    registry = ClientRegistry(
        [
            OIDCClient(
                client_id=SKDASHBOARD_AUDIENCE,
                client_secret=SECRET,
                redirect_uris=[REDIRECT],
                scopes=["openid", *SKDASHBOARD_SCOPES],
            )
        ]
    )
    store = AuthCodeStore(tmp_path / "state.db")

    import capauth.service.app as service_app
    import capauth.service.oidc.provider as provider

    monkeypatch.setattr(
        service_app,
        "get_keystore",
        lambda: SimpleNamespace(get=lambda _subject: SimpleNamespace(approved=True)),
    )
    monkeypatch.setattr(provider, "mint_audience_token", lambda *_a, **_k: object())
    monkeypatch.setattr(provider, "export_token", lambda _token: '{"signed":"audience"}')

    policy_subject = f"device:{SUBJECT.lower()}"
    enrollment = enroll_device(
        "PUBLIC-KEY",
        list(SKDASHBOARD_SCOPES),
        mode=EnrollmentMode.TOFU,
        base_dir=tmp_path,
        subject=policy_subject,
    )
    device = approve(enrollment.enrollment_id, "operator@chef.skworld.io", base_dir=tmp_path)
    issue_token(
        home=tmp_path,
        subject=policy_subject,
        capabilities=list(SKDASHBOARD_SCOPES),
        ttl_hours=1,
        sign=True,
    )
    app = FastAPI()
    app.include_router(
        build_oidc_router(
            signing_key=SigningKey(tmp_path / "signing.pem"),
            clients=registry,
            store=store,
        ),
        prefix="/oidc",
    )
    return SimpleNamespace(client=TestClient(app), store=store, device=device, home=tmp_path)


def _refresh(client: TestClient, token: str):
    return client.post(
        "/oidc/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": token,
            "client_id": SKDASHBOARD_AUDIENCE,
            "client_secret": SECRET,
        },
    )


def _authorization_code(store: AuthCodeStore, scope: str):
    request = store.create_login_request(
        SKDASHBOARD_AUDIENCE,
        REDIRECT,
        scope,
        "state-0123456789abcdef",
        CHALLENGE,
        "S256",
        "nonce-0123456789abcdef",
    )
    return store.complete_login_request(request.request_id, SUBJECT, {})[1].code


def test_canonical_policy_grant_exchanges_once_and_keeps_id_token(refresh_app):
    """A canonical policy grant authorizes the raw-fingerprint OIDC record once."""
    code = _authorization_code(
        refresh_app.store, "openid skdashboard.read skdashboard.events.read"
    )
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT,
        "client_id": SKDASHBOARD_AUDIENCE,
        "client_secret": SECRET,
        "code_verifier": VERIFIER,
    }
    response = refresh_app.client.post("/oidc/token", data=form)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["id_token"]
    assert body["refresh_token"]
    assert body["scope"].split() == list(SKDASHBOARD_SCOPES)
    assert refresh_app.store.inspect_refresh_token(body["refresh_token"]).subject == SUBJECT
    assert refresh_app.client.post("/oidc/token", data=form).status_code == 400


def test_oidc_approval_does_not_replace_policy_enrollment(refresh_app):
    revoke(refresh_app.device.device_id, "qualification", base_dir=refresh_app.home)
    code = _authorization_code(
        refresh_app.store, "openid skdashboard.read skdashboard.events.read"
    )

    response = refresh_app.client.post(
        "/oidc/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "client_id": SKDASHBOARD_AUDIENCE,
            "client_secret": SECRET,
            "code_verifier": VERIFIER,
        },
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "grant_not_current"


def test_refresh_endpoint_returns_only_exact_bounded_authority(refresh_app):
    first = _family(refresh_app.store)
    response = _refresh(refresh_app.client, first.token)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["expires_in"] == 300
    assert body["scope"].split() == list(SKDASHBOARD_SCOPES)
    assert body["refresh_token"] != first.token
    assert base64.urlsafe_b64decode(body["access_token"]).decode() == '{"signed":"audience"}'

    assert _refresh(refresh_app.client, first.token).status_code == 400
    assert _refresh(refresh_app.client, body["refresh_token"]).status_code == 400


def test_policy_and_signer_fail_closed_without_consuming_refresh(refresh_app, monkeypatch):
    import capauth.service.oidc.provider as provider

    first = _family(refresh_app.store)
    monkeypatch.setattr(provider, "decide", lambda *_a, **_k: SimpleNamespace(allow=False))
    denied = _refresh(refresh_app.client, first.token)
    assert denied.status_code == 403
    assert refresh_app.store.inspect_refresh_token(first.token).generation == 0

    monkeypatch.setattr(provider, "decide", lambda *_a, **_k: SimpleNamespace(allow=True))
    monkeypatch.setattr(
        provider,
        "mint_audience_token",
        lambda *_a, **_k: (_ for _ in ()).throw(TokenSigningError("locked")),
    )
    unavailable = _refresh(refresh_app.client, first.token)
    assert unavailable.status_code == 503
    assert unavailable.json()["detail"] == "signer_unavailable"
    assert refresh_app.store.inspect_refresh_token(first.token).generation == 0


def test_refresh_revocation_is_family_wide_and_idempotent(refresh_app):
    first = _family(refresh_app.store)
    successor = _refresh(refresh_app.client, first.token).json()["refresh_token"]
    revoked = refresh_app.client.post(
        "/oidc/revoke",
        data={"token": successor, "token_type_hint": "refresh_token"},
    )
    assert revoked.status_code == 200
    assert revoked.json() == {"revoked": True}
    assert _refresh(refresh_app.client, successor).status_code == 400
    assert refresh_app.client.post(
        "/oidc/revoke", data={"token": "unknown", "token_type_hint": "refresh_token"}
    ).json() == {"revoked": True}
