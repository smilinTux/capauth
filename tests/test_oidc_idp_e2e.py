"""End-to-end OIDC IdP test with REAL PGP signing (no crypto mocked).

Generates a throwaway PGP keypair via the PGPy backend, then drives the full
Authorization Code + PKCE flow through the live CapAuth service app:

    /capauth/v1/challenge  -> sign canonical CAPAUTH_NONCE_V1 payload
    /oidc/authorize        -> login request
    /oidc/complete         -> real verify_auth_response -> auth code
    /oidc/token            -> RS256 ID token (verified vs JWKS)
    /oidc/userinfo         -> claims

This proves the spike works against the real verifier + keystore, not just the
OIDC plumbing. Skipped if PGPy crypto is unavailable on this interpreter.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

try:
    from capauth.crypto import get_backend
    from capauth.models import Algorithm, CryptoBackendType

    _HAS_CRYPTO = True
except ImportError:  # pragma: no cover
    _HAS_CRYPTO = False

import jwt as pyjwt

pytestmark = pytest.mark.skipif(not _HAS_CRYPTO, reason="PGPy crypto unavailable")

ISSUER = "https://capauth-e2e.test"
CLIENT_ID = "authentik"
CLIENT_SECRET = "e2e-secret"
REDIRECT_URI = "https://authentik-e2e.test/source/oauth/callback/capauth/"


@pytest.fixture
def e2e_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Live service app with a temp keystore + a single static OIDC client."""
    monkeypatch.setenv("CAPAUTH_DB_PATH", str(tmp_path / "e2e_oidc.db"))
    monkeypatch.setenv("CAPAUTH_SERVICE_ID", "capauth-e2e.test")
    monkeypatch.setenv("CAPAUTH_OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("CAPAUTH_OIDC_SIGNING_KEY_PATH", str(tmp_path / "signing.pem"))
    monkeypatch.setenv("CAPAUTH_OIDC_STATE_DB", str(tmp_path / "oidc_state.db"))
    monkeypatch.setenv(
        "CAPAUTH_OIDC_CLIENTS_JSON",
        f'[{{"client_id":"{CLIENT_ID}","client_secret":"{CLIENT_SECRET}",'
        f'"redirect_uris":["{REDIRECT_URI}"],"name":"Authentik"}}]',
    )

    # Build a fresh app instance so env-driven OIDC router/clients are picked up.
    import importlib

    import capauth.service.app as svc_app

    importlib.reload(svc_app)

    import capauth.authentik.nonce_store as ns
    from capauth.service.keystore import KeyStore

    svc_app._keystore = KeyStore(tmp_path / "e2e_oidc.db")
    ns._MEM_CACHE.clear()

    from fastapi.testclient import TestClient

    client = TestClient(svc_app.app)
    router = svc_app._oidc_router
    yield client, router, svc_app._keystore

    svc_app._keystore = None
    ns._MEM_CACHE.clear()
    # Restore the module to its env-free default for other tests.
    importlib.reload(svc_app)


def test_full_oidc_flow_with_real_pgp(e2e_client):
    client, router, keystore = e2e_client
    backend = get_backend(CryptoBackendType.PGPY)
    bundle = backend.generate_keypair("E2E", "e2e@capauth.test", "pp", Algorithm.RSA4096)
    fingerprint = bundle.fingerprint.upper()
    keystore.enroll(fingerprint, bundle.public_armor, approved=True)

    # 1. PKCE pair
    verifier = "pkce-verifier-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )

    # 2. /oidc/authorize -> request_id
    auth = client.get(
        "/oidc/authorize",
        params={
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid profile email",
            "state": "state-0123456789abcdef",
            "nonce": "nonce-0123456789abcdef",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    assert auth.status_code == 200, auth.text
    rid = auth.text.split('REQUEST_ID = "', 1)[1].split('"', 1)[0]

    # 3. Get a real PGP challenge nonce and sign the canonical payload.
    ch = client.post(
        "/capauth/v1/challenge",
        json={"fingerprint": fingerprint, "client_nonce": base64.b64encode(b"cn").decode()},
    ).json()

    from capauth.authentik.verifier import canonical_nonce_payload

    payload = canonical_nonce_payload(
        nonce=ch["nonce"],
        client_nonce_echo=ch["client_nonce_echo"],
        timestamp=ch["timestamp"],
        service=ch["service"],
        expires=ch["expires"],
    )
    sig = backend.sign(payload, bundle.private_armor, "pp")

    # 4. /oidc/complete with the real signature for the approved enrollment.
    comp = client.post(
        "/oidc/complete",
        json={
            "request_id": rid,
            "fingerprint": fingerprint,
            "nonce": ch["nonce"],
            "nonce_signature": sig,
        },
    )
    assert comp.status_code == 200, comp.text
    code = parse_qs(urlsplit(comp.json()["redirect_to"]).query)["code"][0]
    assert "state=state-0123456789abcdef" in comp.json()["redirect_to"]

    # 5. /oidc/token
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

    # 6. Verify the ID token against the published JWKS public key.
    jwks = client.get("/oidc/jwks.json").json()
    assert jwks["keys"][0]["kid"] == router.signing_key.kid
    claims = pyjwt.decode(
        tokens["id_token"],
        router.signing_key.public_pem,
        algorithms=["RS256"],
        audience=CLIENT_ID,
    )
    assert claims["sub"] == fingerprint
    assert claims["iss"] == ISSUER
    assert claims["nonce"] == "nonce-0123456789abcdef"
    assert claims["amr"] == ["pgp"]

    # 7. userinfo
    ui = client.get(
        "/oidc/userinfo",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert ui.status_code == 200, ui.text
    assert ui.json()["sub"] == fingerprint
