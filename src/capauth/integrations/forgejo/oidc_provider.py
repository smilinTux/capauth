"""Forgejo-specific OIDC provider endpoints.

This FastAPI router supplements the core CapAuth service with endpoints that
handle the full Forgejo authorization code flow including the interactive PGP
signing UI.

Mount it inside the main CapAuth FastAPI application:

.. code-block:: python

    from capauth.integrations.forgejo.oidc_provider import build_router
    from capauth.integrations.forgejo.auth_flow import ForgejoAuthFlow
    from capauth.integrations.forgejo.config import ForgejoConfig

    config = ForgejoConfig.from_env()
    flow = ForgejoAuthFlow(config)
    app.include_router(build_router(flow, config), prefix="/forgejo")

Endpoints
---------
GET  /forgejo/authorize          OAuth2 authorization endpoint (Forgejo redirects here)
POST /forgejo/token              Token exchange endpoint (code → JWT)
GET  /forgejo/userinfo           UserInfo endpoint (JWT → claims)
GET  /forgejo/.well-known/openid-configuration   OIDC discovery override for Forgejo
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional
from urllib.parse import urlencode

import jwt as pyjwt
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from .auth_flow import ForgejoAuthFlow
from .config import ForgejoConfig

logger = logging.getLogger("capauth.forgejo.oidc")

_SIGN_PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>CapAuth — Sign to log in to Forgejo</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#f1f5f9;
          display:flex;align-items:center;justify-content:center;min-height:100vh;padding:1rem}}
    .card{{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:2rem;
           max-width:480px;width:100%}}
    h1{{font-size:1.4rem;color:#38bdf8;margin-bottom:.5rem}}
    p{{color:#94a3b8;font-size:.9rem;margin-bottom:1.2rem;line-height:1.5}}
    label{{display:block;font-size:.8rem;color:#94a3b8;margin-bottom:.3rem}}
    input,textarea{{width:100%;background:#0f172a;border:1px solid #334155;border-radius:8px;
                    color:#f1f5f9;padding:.6rem .8rem;font-size:.9rem;margin-bottom:1rem;
                    font-family:monospace}}
    textarea{{min-height:120px;resize:vertical}}
    button{{width:100%;background:#0ea5e9;color:#fff;border:none;border-radius:8px;
            padding:.75rem;font-size:1rem;cursor:pointer;font-weight:600}}
    button:hover{{background:#38bdf8}}
    .nonce-box{{background:#0f172a;border:1px solid #334155;border-radius:8px;
                padding:.75rem;margin-bottom:1rem;font-family:monospace;font-size:.8rem;
                color:#38bdf8;word-break:break-all}}
    .error{{color:#f87171;font-size:.85rem;margin-top:.5rem;display:none}}
    .step{{color:#64748b;font-size:.75rem;margin-bottom:.3rem}}
  </style>
</head>
<body>
<div class="card">
  <h1>CapAuth — Passwordless Login</h1>
  <p>Sign the challenge below with your PGP key to log in to <strong>{forgejo_url}</strong>.</p>

  <div class="step">Step 1 — Your PGP fingerprint</div>
  <label for="fp">Fingerprint (40 hex chars)</label>
  <input id="fp" type="text" maxlength="40" placeholder="ABCDEF1234..." autocomplete="off"/>

  <div class="step">Step 2 — Challenge nonce</div>
  <div class="nonce-box" id="nonce-display">Loading challenge…</div>

  <div class="step">Step 3 — Paste your PGP signature</div>
  <label for="sig">PGP Signature (ASCII armor)</label>
  <textarea id="sig" placeholder="-----BEGIN PGP SIGNATURE-----&#10;...&#10;-----END PGP SIGNATURE-----"></textarea>

  <button onclick="submit()">Verify &amp; Log In</button>
  <div class="error" id="err"></div>

  <p style="margin-top:1rem;font-size:.75rem;color:#475569">
    Using the CapAuth browser extension? It will fill the signature automatically.<br/>
    CLI: <code>capauth sign --nonce &lt;nonce&gt;</code>
  </p>
</div>

<script>
const STATE = "{state}";
const CAPAUTH_BASE = "{capauth_base}";
let currentNonce = null;

async function fetchChallenge(fp) {{
  const r = await fetch(CAPAUTH_BASE + "/capauth/v1/challenge", {{
    method: "POST",
    headers: {{"Content-Type": "application/json"}},
    body: JSON.stringify({{
      capauth_version: "1.0",
      fingerprint: fp,
      client_nonce: btoa(crypto.getRandomValues(new Uint8Array(16))),
      requested_service: "{service_id}"
    }})
  }});
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}}

document.getElementById("fp").addEventListener("blur", async function() {{
  const fp = this.value.trim().toUpperCase().replace(/\\s/g, "");
  if (fp.length !== 40) return;
  try {{
    const ch = await fetchChallenge(fp);
    currentNonce = ch.nonce;
    document.getElementById("nonce-display").textContent = ch.nonce;
  }} catch(e) {{
    document.getElementById("nonce-display").textContent = "Error: " + e.message;
  }}
}});

async function submit() {{
  const fp = document.getElementById("fp").value.trim().toUpperCase().replace(/\\s/g, "");
  const sig = document.getElementById("sig").value.trim();
  const err = document.getElementById("err");
  err.style.display = "none";

  if (!fp || fp.length !== 40) {{ err.textContent = "Invalid fingerprint."; err.style.display="block"; return; }}
  if (!currentNonce) {{ err.textContent = "No challenge loaded — blur the fingerprint field first."; err.style.display="block"; return; }}
  if (!sig) {{ err.textContent = "Paste your PGP signature."; err.style.display="block"; return; }}

  const r = await fetch(CAPAUTH_BASE + "/capauth/v1/verify", {{
    method: "POST",
    headers: {{"Content-Type": "application/json"}},
    body: JSON.stringify({{
      capauth_version: "1.0",
      fingerprint: fp,
      nonce: currentNonce,
      nonce_signature: sig,
      claims: {{}}
    }})
  }});

  if (!r.ok) {{
    const body = await r.json().catch(() => ({{}}));
    err.textContent = body.error_description || body.error || "Verification failed.";
    err.style.display = "block";
    return;
  }}

  const data = await r.json();
  // Exchange access_token for auth code via the Forgejo flow callback
  const cbr = await fetch(CAPAUTH_BASE + "/forgejo/authorize/complete", {{
    method: "POST",
    headers: {{"Content-Type": "application/json"}},
    body: JSON.stringify({{
      state: STATE,
      fingerprint: fp,
      access_token: data.access_token,
      oidc_claims: data.oidc_claims
    }})
  }});
  if (!cbr.ok) {{
    const body = await cbr.json().catch(() => ({{}}));
    err.textContent = body.detail || "Flow completion failed.";
    err.style.display = "block";
    return;
  }}
  const cbdata = await cbr.json();
  window.location.href = cbdata.redirect_to;
}}
</script>
</body>
</html>
"""


def build_router(flow: ForgejoAuthFlow, config: ForgejoConfig) -> APIRouter:
    """Build the FastAPI router for Forgejo OIDC endpoints.

    Parameters
    ----------
    flow:
        A ``ForgejoAuthFlow`` instance (holds session/code stores).
    config:
        Runtime configuration.

    Returns
    -------
    APIRouter
        Mount at prefix ``/forgejo`` in the parent FastAPI app.
    """
    router = APIRouter(tags=["forgejo-oidc"])

    # ------------------------------------------------------------------
    # OIDC discovery override — points Forgejo at Forgejo-specific endpoints
    # ------------------------------------------------------------------

    @router.get("/.well-known/openid-configuration", summary="Forgejo OIDC discovery")
    async def forgejo_oidc_discovery() -> dict[str, Any]:
        """OIDC discovery document tailored for Forgejo.

        Forgejo fetches this at startup via the configured
        ``OPENID_CONNECT_AUTO_DISCOVERY_URL`` setting.
        """
        base = config.capauth_base_url
        return {
            "issuer": base,
            "authorization_endpoint": f"{base}/forgejo/authorize",
            "token_endpoint": f"{base}/forgejo/token",
            "userinfo_endpoint": f"{base}/forgejo/userinfo",
            "jwks_uri": f"{base}/.well-known/jwks.json",
            "end_session_endpoint": f"{base}/forgejo/logout",
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["HS256"],
            "userinfo_signing_alg_values_supported": ["none"],
            "scopes_supported": ["openid", "profile", "email", "groups"],
            "claims_supported": [
                "sub", "iss", "iat", "exp",
                "name", "preferred_username", "email", "email_verified",
                "picture", "groups", "locale",
                "capauth_fingerprint", "amr",
            ],
            "grant_types_supported": ["authorization_code"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_post",
                "client_secret_basic",
            ],
            "code_challenge_methods_supported": ["S256", "plain"],
        }

    # ------------------------------------------------------------------
    # Authorization endpoint — Forgejo redirects here to start login
    # ------------------------------------------------------------------

    @router.get("/authorize", response_class=HTMLResponse, summary="Start PGP auth flow")
    async def authorize(
        response_type: str = "code",
        client_id: str = "",
        redirect_uri: str = "",
        scope: str = "openid profile email",
        state: str = "",
        code_challenge: str = "",
        code_challenge_method: str = "S256",
    ) -> HTMLResponse:
        """Authorization endpoint.

        Forgejo redirects the user here.  We create an auth session and serve
        the interactive PGP signing page.
        """
        if response_type != "code":
            raise HTTPException(status_code=400, detail="Only response_type=code is supported")
        if not state:
            raise HTTPException(status_code=400, detail="state parameter is required")

        try:
            flow.create_session(
                state=state,
                redirect_uri=redirect_uri,
                client_id=client_id,
                scope=scope,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

        html = _SIGN_PAGE_TEMPLATE.format(
            state=state,
            capauth_base=config.capauth_base_url,
            forgejo_url=config.forgejo_base_url,
            service_id=config.capauth_base_url.split("//")[-1],
        )
        return HTMLResponse(content=html)

    # ------------------------------------------------------------------
    # Flow completion — called by the JS signing page after verify succeeds
    # ------------------------------------------------------------------

    @router.post("/authorize/complete", summary="Complete PGP auth and issue code")
    async def authorize_complete(request: Request) -> dict[str, Any]:
        """Called by the browser signing page after /capauth/v1/verify succeeds.

        Body JSON:
        - state: OAuth2 state from the session
        - fingerprint: verified PGP fingerprint
        - access_token: CapAuth JWT from /verify (proves identity)
        - oidc_claims: OIDC claims from /verify response
        """
        body = await request.json()
        state: str = body.get("state", "")
        fingerprint: str = body.get("fingerprint", "")
        access_token: str = body.get("access_token", "")
        oidc_claims: dict[str, Any] = body.get("oidc_claims", {})

        if not state or not fingerprint or not access_token:
            raise HTTPException(status_code=400, detail="state, fingerprint, and access_token required")

        # Validate the CapAuth JWT to confirm identity
        try:
            payload = pyjwt.decode(
                access_token,
                config.capauth_jwt_secret,
                algorithms=["HS256"],
                options={"require": ["sub", "exp"]},
            )
        except pyjwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="CapAuth token expired")
        except pyjwt.InvalidTokenError as exc:
            raise HTTPException(status_code=401, detail=f"Invalid CapAuth token: {exc}")

        token_fp: str = payload.get("capauth_fingerprint", payload.get("sub", ""))
        if token_fp.upper() != fingerprint.upper():
            raise HTTPException(status_code=401, detail="Token fingerprint mismatch")

        session = flow.get_session(state)
        if session is None:
            raise HTTPException(status_code=400, detail="No pending session for this state")

        # Merge fingerprint into claims
        claims = dict(oidc_claims)
        claims["capauth_fingerprint"] = fingerprint
        claims.setdefault("sub", fingerprint)

        try:
            code = flow.issue_auth_code(state=state, fingerprint=fingerprint, claims=claims)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

        redirect_uri = session.redirect_uri
        params = urlencode({"code": code, "state": state})
        redirect_to = f"{redirect_uri}?{params}"

        logger.info("Auth code issued for fingerprint=%s...", fingerprint[:8])
        return {"redirect_to": redirect_to, "code": code}

    # ------------------------------------------------------------------
    # Token endpoint — Forgejo POSTs the code here to get a JWT
    # ------------------------------------------------------------------

    @router.post("/token", summary="Exchange auth code for JWT")
    async def token_endpoint(
        grant_type: str = Form(default="authorization_code"),
        code: str = Form(default=""),
        redirect_uri: str = Form(default=""),
        client_id: str = Form(default=""),
        client_secret: str = Form(default=""),
        code_verifier: str = Form(default=""),
    ) -> dict[str, Any]:
        """OAuth2 token endpoint.

        Forgejo's backend posts the authorization code here after the user
        completes the PGP signing flow.
        """
        if grant_type != "authorization_code":
            raise HTTPException(status_code=400, detail="unsupported_grant_type")
        if not code:
            raise HTTPException(status_code=400, detail="code is required")

        try:
            tokens = flow.exchange_code(
                code=code,
                client_id=client_id or config.client_id,
                client_secret=client_secret,
                redirect_uri=redirect_uri,
                code_verifier=code_verifier,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

        logger.info("Token issued for code exchange (client=%s)", client_id)
        return tokens

    # ------------------------------------------------------------------
    # UserInfo endpoint — Forgejo calls this with the bearer JWT
    # ------------------------------------------------------------------

    @router.get("/userinfo", summary="Return OIDC claims from JWT")
    async def userinfo_endpoint(request: Request) -> dict[str, Any]:
        """OIDC userinfo endpoint.

        Forgejo calls this with the access_token to get user claims and
        create/update the Forgejo user account.
        """
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Bearer token required")

        token = auth[len("Bearer "):]
        try:
            payload = pyjwt.decode(
                token,
                config.capauth_jwt_secret,
                algorithms=["HS256"],
                options={"require": ["sub", "exp"]},
            )
        except pyjwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="token_expired")
        except pyjwt.InvalidTokenError as exc:
            raise HTTPException(status_code=401, detail=f"invalid_token: {exc}")

        # Return stable userinfo claims — Forgejo maps these to the user record
        claims = {k: v for k, v in payload.items() if k not in ("iat", "exp")}
        claims.setdefault("email_verified", True)
        return claims

    # ------------------------------------------------------------------
    # Logout — stateless no-op
    # ------------------------------------------------------------------

    @router.get("/logout", summary="OIDC end-session (no-op)")
    async def logout_endpoint() -> dict[str, Any]:
        """CapAuth JWTs are stateless.  Forgejo-side logout is a no-op here."""
        return {"logged_out": True}

    return router
