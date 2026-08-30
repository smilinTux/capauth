"""Unit tests for the CapAuth OIDC/OAuth2 Identity Provider (Track-2 spike).

Covers:
* Discovery document shape + endpoint URLs
* JWKS publication (RSA public key) and RS256 sign/verify roundtrip
* The full Authorization Code + PKCE flow with the PGP verify step MOCKED
  (we are not testing PGP crypto here — that's covered by test_real_pgp_e2e.py
  and test_verifier.py — only the OIDC plumbing).
* Token endpoint: client auth, PKCE enforcement, RS256 ID token verifiable
  against the published JWKS, ``nonce``/``aud``/``sub`` binding.
* UserInfo: Bearer access token -> claims.
"""

from __future__ import annotations

import base64
import hashlib
from urllib.parse import parse_qs, urlsplit

import jwt as pyjwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from capauth.service.oidc.clients import ClientRegistry, OIDCClient
from capauth.service.oidc.passkey import PasskeyStoreUnavailableError
from capauth.service.oidc.provider import build_oidc_router, discovery_document
from capauth.service.oidc.signing_key import SigningKey
from capauth.service.oidc.store import AuthCodeStore, verify_pkce

ISSUER = "https://capauth.test"
CLIENT_ID = "authentik"
CLIENT_SECRET = "super-secret"
REDIRECT_URI = "https://authentik.test/source/oauth/callback/capauth/"
TEST_FP = "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"
DEFAULT_VERIFIER = "verifier-string-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
VALID_STATE = "state-0123456789abcdef"
VALID_NONCE = "nonce-0123456789abcdef"


@pytest.fixture
def signing_key(tmp_path) -> SigningKey:
    """A fresh RSA signing key persisted under tmp_path."""
    return SigningKey(path=tmp_path / "oidc_signing_key.pem")


@pytest.fixture
def client_registry() -> ClientRegistry:
    return ClientRegistry(
        [
            OIDCClient(
                client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET,
                redirect_uris=[REDIRECT_URI],
                name="Authentik",
            )
        ]
    )


@pytest.fixture
def oidc_app(monkeypatch, signing_key, client_registry, tmp_path):
    """A minimal FastAPI app mounting only the OIDC router, with PGP mocked."""
    monkeypatch.setenv("CAPAUTH_OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("CAPAUTH_WEBAUTHN_RP_ID", "capauth.test")
    monkeypatch.setenv("CAPAUTH_PASSKEY_DATA_DIR", str(tmp_path / "passkeys"))

    store = AuthCodeStore(path=tmp_path / "oidc-state.db")
    router = build_oidc_router(signing_key=signing_key, clients=client_registry, store=store)

    # Mock the PGP verify path. provider._verify_pgp lazily imports these symbols
    # from their source modules, so patching them there is sufficient — no real
    # crypto runs. "GOOD-SIG" => verified identity; anything else => failure.
    import capauth.authentik.nonce_store as ns_mod
    import capauth.authentik.stage as stage_mod
    import capauth.authentik.verifier as ver_mod

    monkeypatch.setattr(
        stage_mod,
        "verify_auth_response",
        lambda **kw: (
            (
                True,
                "",
                {
                    "sub": kw["fingerprint"],
                    "capauth_fingerprint": kw["fingerprint"],
                    "amr": ["pgp"],
                    "name": "Test Sovereign",
                    "preferred_username": "Test Sovereign",
                    "email": "sovereign@capauth.test",
                    "email_verified": False,
                    "groups": ["sovereign", "admins"],
                },
            )
            if kw["nonce_signature_armor"] == "GOOD-SIG"
            else (False, "invalid_nonce_signature", {})
        ),
    )
    monkeypatch.setattr(
        ns_mod,
        "peek",
        lambda nonce_id: {
            "nonce": nonce_id,
            "client_nonce_echo": "echo==",
            "issued_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "2030-01-01T00:00:00+00:00",
        },
    )
    monkeypatch.setattr(ver_mod, "fingerprint_from_armor", lambda armor: TEST_FP)

    # Fake keystore: known fp already enrolled (no public_key needed).
    class _FakeKey:
        public_key_armor = "PUBKEY"
        approved = True

    class _FakeKS:
        def get(self, fp):
            return _FakeKey()

        def enroll(self, *a, **k):
            return None

        def update_last_auth(self, fp):
            return None

    import capauth.service.app as app_mod

    monkeypatch.setattr(app_mod, "get_keystore", lambda: _FakeKS())
    monkeypatch.setattr(app_mod, "SERVICE_ID", "capauth.test")

    fastapi_app = FastAPI()
    fastapi_app.include_router(router, prefix="/oidc")
    return TestClient(fastapi_app), router


def test_discovery_document_shape():
    doc = discovery_document(ISSUER)
    assert doc["issuer"] == ISSUER
    assert doc["authorization_endpoint"] == f"{ISSUER}/oidc/authorize"
    assert doc["token_endpoint"] == f"{ISSUER}/oidc/token"
    assert doc["userinfo_endpoint"] == f"{ISSUER}/oidc/userinfo"
    assert doc["jwks_uri"] == f"{ISSUER}/oidc/jwks.json"
    assert "code" in doc["response_types_supported"]
    assert "authorization_code" in doc["grant_types_supported"]
    assert "RS256" in doc["id_token_signing_alg_values_supported"]
    assert "S256" in doc["code_challenge_methods_supported"]
    assert doc["code_challenge_methods_supported"] == ["S256"]
    assert "none" not in doc["token_endpoint_auth_methods_supported"]
    assert doc["revocation_endpoint"] == f"{ISSUER}/oidc/revoke"
    assert set(["openid", "profile", "email", "groups"]).issubset(doc["scopes_supported"])


def test_discovery_endpoint(oidc_app):
    client, _ = oidc_app
    resp = client.get("/oidc/.well-known/openid-configuration")
    assert resp.status_code == 200
    assert resp.json()["issuer"] == ISSUER


def test_jwks_endpoint_publishes_rsa_key(oidc_app, signing_key):
    client, _ = oidc_app
    resp = client.get("/oidc/jwks.json")
    assert resp.status_code == 200
    keys = resp.json()["keys"]
    assert len(keys) == 1
    jwk = keys[0]
    assert jwk["kty"] == "RSA"
    assert jwk["use"] == "sig"
    assert jwk["alg"] == "RS256"
    assert jwk["kid"] == signing_key.kid
    assert jwk["n"] and jwk["e"]


def test_signing_key_sign_verify_roundtrip(signing_key):
    payload = {"sub": TEST_FP, "iss": ISSUER, "exp": 9999999999, "iat": 1}
    token = pyjwt.encode(
        payload, signing_key.private_pem, algorithm="RS256", headers={"kid": signing_key.kid}
    )
    decoded = pyjwt.decode(token, signing_key.public_pem, algorithms=["RS256"])
    assert decoded["sub"] == TEST_FP
    # Wrong key must fail.
    other = SigningKey(path=signing_key.path.parent / "other.pem")
    with pytest.raises(pyjwt.InvalidSignatureError):
        pyjwt.decode(token, other.public_pem, algorithms=["RS256"])


def test_signing_key_persists_kid(tmp_path):
    p = tmp_path / "k.pem"
    k1 = SigningKey(path=p)
    k2 = SigningKey(path=p)  # reload from disk
    assert k1.kid == k2.kid
    assert k1.public_pem == k2.public_pem


def test_verify_pkce_s256():
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    assert verify_pkce(verifier, challenge, "S256") is True
    assert verify_pkce("wrong", challenge, "S256") is False


def test_verify_pkce_rejects_plain_absent_and_short():
    assert verify_pkce("abc", "abc", "plain") is False
    assert verify_pkce("abc", "xyz", "plain") is False
    assert verify_pkce("", "", "S256") is False


def test_authorize_unknown_client(oidc_app):
    client, _ = oidc_app
    resp = client.get(
        "/oidc/authorize",
        params={"client_id": "nope", "redirect_uri": REDIRECT_URI, "state": "s"},
    )
    assert resp.status_code == 400


def test_authorize_bad_redirect_uri(oidc_app):
    client, _ = oidc_app
    resp = client.get(
        "/oidc/authorize",
        params={"client_id": CLIENT_ID, "redirect_uri": "https://evil.test/cb", "state": "s"},
    )
    assert resp.status_code == 400


def test_authorize_renders_login_page(oidc_app):
    client, router = oidc_app
    resp = client.get(
        "/oidc/authorize",
        params={
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid profile email groups",
            "state": VALID_STATE,
            "nonce": VALID_NONCE,
            "code_challenge": "a" * 43,
            "code_challenge_method": "S256",
        },
    )
    assert resp.status_code == 200
    assert "Sign in with CapAuth" in resp.text
    assert router.store.pending_requests == 1


def test_login_page_documents_exact_signing_contract(oidc_app):
    client, _router = oidc_app
    resp = client.get(
        "/oidc/authorize",
        params={
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid profile email groups",
            "state": VALID_STATE,
            "nonce": VALID_NONCE,
            "code_challenge": "a" * 43,
            "code_challenge_method": "S256",
        },
    )

    assert resp.status_code == 200
    assert ">Sign in with a passkey<" in resp.text
    assert "Recommended after one PGP-proven enrollment" in resp.text
    assert 'currentPayload=["CAPAUTH_NONCE_V1", "nonce="+ch.nonce' in resp.text
    assert '"client_nonce="+ch.client_nonce_echo' in resp.text
    assert '"timestamp="+ch.timestamp' in resp.text
    assert '"service="+ch.service' in resp.text
    assert '"expires="+ch.expires' in resp.text
    assert "gpg --armor --sign" in resp.text
    assert "gpg --armor --detach-sign" in resp.text
    assert "capauth sign --nonce" not in resp.text
    assert "Sign on this device (key in your bunker)" in resp.text
    assert "Sign from another device (QR)" in resp.text


def test_passkey_enrollment_page_documents_exact_signing_contract(oidc_app):
    client, _router = oidc_app

    response = client.get("/oidc/passkey/enroll")

    assert response.status_code == 200
    assert 'currentPayload=["CAPAUTH_NONCE_V1", "nonce="+ch.nonce' in response.text
    assert '"client_nonce="+ch.client_nonce_echo' in response.text
    assert '"timestamp="+ch.timestamp' in response.text
    assert '"service="+ch.service' in response.text
    assert '"expires="+ch.expires' in response.text
    assert "gpg --armor --sign" in response.text
    assert "gpg --armor --detach-sign" in response.text
    assert 'maxlength="64"' in response.text
    assert "Create passkey with this device" in response.text
    assert "Checking this browser for a CapAuth identity" in response.text
    assert 'localStorage.getItem("capauth_bunker_fp")' in response.text
    assert 'localStorage.getItem("capauth_bunker_envelope")' in response.text
    assert '<details id="manual-enrollment">' in response.text
    assert "Advanced: sign a fresh challenge manually" in response.text
    assert "/bunker/" in response.text


def test_ip_issuer_passkey_preflight_denies_before_pgp_verification(oidc_app, monkeypatch):
    client, _router = oidc_app
    monkeypatch.setenv("CAPAUTH_OIDC_ISSUER", "https://100.81.238.58:8420")
    monkeypatch.setenv("CAPAUTH_WEBAUTHN_RP_ID", "100.81.238.58")
    calls = []

    import capauth.authentik.stage as stage_mod

    monkeypatch.setattr(
        stage_mod,
        "verify_auth_response",
        lambda **kwargs: calls.append(kwargs) or (True, "", {}),
    )

    response = client.post(
        "/oidc/passkey/register/begin",
        json={
            "fingerprint": TEST_FP,
            "nonce": "sentinel-nonce",
            "nonce_signature": "sentinel-signature",
        },
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "passkey_rp_unavailable"}
    assert calls == []


def test_passkey_directory_does_not_redirect_oidc_state(
    monkeypatch, tmp_path, signing_key, client_registry
):
    capauth_home = tmp_path / "capauth-home"
    passkey_dir = tmp_path / "passkey-only"
    monkeypatch.setenv("SKCAPSTONE_HOME", str(capauth_home))
    monkeypatch.delenv("CAPAUTH_DATA_DIR", raising=False)
    monkeypatch.delenv("CAPAUTH_OIDC_STATE_DB", raising=False)
    monkeypatch.setenv("CAPAUTH_PASSKEY_DATA_DIR", str(passkey_dir))
    monkeypatch.setenv("CAPAUTH_OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("CAPAUTH_WEBAUTHN_RP_ID", "capauth.test")

    router = build_oidc_router(signing_key=signing_key, clients=client_registry)

    assert router.passkeys._path == passkey_dir / "passkeys.json"
    assert router.store.path != passkey_dir / "oidc_state.db"


def test_shared_data_directory_cannot_enable_passkey_store(
    monkeypatch, tmp_path, signing_key, client_registry
):
    shared_dir = tmp_path / "shared-service-state"
    monkeypatch.setenv("CAPAUTH_DATA_DIR", str(shared_dir))
    monkeypatch.delenv("CAPAUTH_PASSKEY_DATA_DIR", raising=False)
    monkeypatch.setenv("CAPAUTH_OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("CAPAUTH_WEBAUTHN_RP_ID", "capauth.test")

    router = build_oidc_router(signing_key=signing_key, clients=client_registry)

    assert router.store.path == shared_dir / "oidc_state.db"
    with pytest.raises(PasskeyStoreUnavailableError):
        router.passkeys.preflight()


def test_passkey_registration_persistence_failure_is_unavailable(oidc_app, monkeypatch):
    client, router = oidc_app

    def unavailable(_ticket, _credential):
        raise PasskeyStoreUnavailableError("disk unavailable")

    monkeypatch.setattr(router.passkeys, "complete_registration", unavailable)
    response = client.post(
        "/oidc/passkey/register/complete",
        json={"ticket": "valid-ticket", "credential": {"id": "credential"}},
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "passkey_state_unavailable"}


def _start_login(client, router, *, challenge="", method="S256", nonce=VALID_NONCE):
    """Hit /authorize and pull the request_id out of the rendered page."""
    resp = client.get(
        "/oidc/authorize",
        params={
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid profile email groups",
            "state": VALID_STATE,
            "nonce": nonce,
            "code_challenge": challenge
            or base64.urlsafe_b64encode(hashlib.sha256(DEFAULT_VERIFIER.encode()).digest())
            .rstrip(b"=")
            .decode(),
            "code_challenge_method": method,
        },
    )
    assert resp.status_code == 200
    # request_id is embedded as: const REQUEST_ID = "...";
    marker = 'REQUEST_ID = "'
    rid = resp.text.split(marker, 1)[1].split('"', 1)[0]
    return rid


def _code(response) -> str:
    return parse_qs(urlsplit(response.json()["redirect_to"]).query)["code"][0]


def test_full_authorization_code_pkce_flow(oidc_app, signing_key):
    client, router = oidc_app

    verifier = "verifier-string-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )

    rid = _start_login(client, router, challenge=challenge, method="S256")

    # Complete PGP login (mocked GOOD-SIG).
    comp = client.post(
        "/oidc/complete",
        json={
            "request_id": rid,
            "fingerprint": TEST_FP,
            "nonce": "pgp-nonce-uuid",
            "nonce_signature": "GOOD-SIG",
        },
    )
    assert comp.status_code == 200, comp.text
    data = comp.json()
    assert data["redirect_to"].startswith(REDIRECT_URI + "?")
    assert f"state={VALID_STATE}" in data["redirect_to"]
    code = _code(comp)

    # Exchange code for tokens with PKCE verifier.
    tok = client.post(
        "/oidc/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code_verifier": verifier,
        },
    )
    assert tok.status_code == 200, tok.text
    tokens = tok.json()
    assert tokens["token_type"] == "Bearer"
    id_token = tokens["id_token"]

    # ID token must verify against the published JWKS public key, RS256.
    header = pyjwt.get_unverified_header(id_token)
    assert header["alg"] == "RS256"
    assert header["kid"] == signing_key.kid
    claims = pyjwt.decode(
        id_token, signing_key.public_pem, algorithms=["RS256"], audience=CLIENT_ID
    )
    assert claims["sub"] == TEST_FP
    assert claims["iss"] == ISSUER
    assert claims["aud"] == CLIENT_ID
    assert claims["nonce"] == VALID_NONCE
    assert claims["amr"] == ["pgp"]
    assert claims["email"] == "sovereign@capauth.test"
    assert "admins" in claims["groups"]

    # UserInfo with the access token.
    ui = client.get(
        "/oidc/userinfo",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert ui.status_code == 200, ui.text
    info = ui.json()
    assert info["sub"] == TEST_FP
    assert info["email"] == "sovereign@capauth.test"
    # iss/exp/nonce are stripped from userinfo.
    assert "nonce" not in info


def test_token_rejects_bad_pkce(oidc_app):
    client, router = oidc_app
    verifier = "verifier-string-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    rid = _start_login(client, router, challenge=challenge)
    comp = client.post(
        "/oidc/complete",
        json={
            "request_id": rid,
            "fingerprint": TEST_FP,
            "nonce": "x",
            "nonce_signature": "GOOD-SIG",
        },
    )
    code = _code(comp)

    resp = client.post(
        "/oidc/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code_verifier": "WRONG-VERIFIER",
            "redirect_uri": REDIRECT_URI,
        },
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "invalid_grant"


def test_token_rejects_bad_client_secret(oidc_app):
    client, router = oidc_app
    rid = _start_login(client, router)
    comp = client.post(
        "/oidc/complete",
        json={
            "request_id": rid,
            "fingerprint": TEST_FP,
            "nonce": "x",
            "nonce_signature": "GOOD-SIG",
        },
    )
    code = _code(comp)
    resp = client.post(
        "/oidc/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": CLIENT_ID,
            "client_secret": "WRONG",
        },
    )
    assert resp.status_code == 401


def test_code_is_single_use(oidc_app):
    client, router = oidc_app
    rid = _start_login(client, router)
    comp = client.post(
        "/oidc/complete",
        json={
            "request_id": rid,
            "fingerprint": TEST_FP,
            "nonce": "x",
            "nonce_signature": "GOOD-SIG",
        },
    )
    code = _code(comp)
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": DEFAULT_VERIFIER,
    }
    assert client.post("/oidc/token", data=form).status_code == 200
    # Replay must fail.
    assert client.post("/oidc/token", data=form).status_code == 400


def test_complete_rejects_bad_pgp_signature(oidc_app):
    client, router = oidc_app
    rid = _start_login(client, router)
    resp = client.post(
        "/oidc/complete",
        json={"request_id": rid, "fingerprint": TEST_FP, "nonce": "x", "nonce_signature": "BAD"},
    )
    assert resp.status_code == 401


def test_complete_rejects_unknown_request(oidc_app):
    client, _ = oidc_app
    resp = client.post(
        "/oidc/complete",
        json={
            "request_id": "nope",
            "fingerprint": TEST_FP,
            "nonce": "x",
            "nonce_signature": "GOOD-SIG",
        },
    )
    assert resp.status_code == 400


def test_userinfo_requires_bearer(oidc_app):
    client, _ = oidc_app
    assert client.get("/oidc/userinfo").status_code == 401


def test_client_registry_from_env(monkeypatch):
    monkeypatch.setenv(
        "CAPAUTH_OIDC_CLIENTS_JSON",
        '[{"client_id":"ak","client_secret":"s","redirect_uris":["https://a/cb"],"name":"AK"}]',
    )
    reg = ClientRegistry()
    assert "ak" in reg
    c = reg.get("ak")
    assert c.name == "AK"
    assert c.redirect_uri_allowed("https://a/cb")
    assert not c.redirect_uri_allowed("https://a/other")
    assert c.secret_matches("s")
    assert not c.secret_matches("x")


def test_public_client_is_not_accepted_by_confidential_endpoint():
    c = OIDCClient(client_id="pub", client_secret="", redirect_uris=["https://a/cb"])
    assert c.secret_matches("") is False
    assert c.secret_matches("anything") is False
