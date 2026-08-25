"""CapAuth Verification Service — FastAPI application.

Endpoints:
    POST /capauth/v1/challenge  — Issue a signed challenge nonce
    POST /capauth/v1/verify     — Verify signed response, return OIDC claims
    GET  /capauth/v1/status     — Service health and key count
    GET  /capauth/v1/keys       — List enrolled keys (admin)
    POST /capauth/v1/keys/approve — Approve a pending key (admin)
    POST /capauth/v1/keys/revoke  — Revoke an enrolled key (admin)
    GET  /capauth/v1/callback   — OAuth2/OIDC callback from upstream IdP (Authentik)

Any OIDC-consuming application can use this service for passwordless
PGP authentication. Nextcloud, Forgejo, Immich, custom apps — all
talk to this single service.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional

import httpx
import jwt
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, Field

from .. import integration as _integration
from .. import resolve_capauth_home
from ..authentik.nonce_store import issue, peek
from ..authentik.stage import build_challenge, verify_auth_response
from ..authentik.verifier import fingerprint_from_armor
from ..authz import Decision as AuthzDecision
from ..authz import decide as authz_decide
from .bunker import BunkerBroker, BunkerCapacityError, build_pairing_uri
from .keystore import KeyStore
from .oidc import build_oidc_router
from .oidc.provider import discovery_document as _oidc_discovery_document
from .push import PushRegistry

logger = logging.getLogger("capauth.service")

SERVICE_ID = os.environ.get("CAPAUTH_SERVICE_ID", "capauth.local")
SERVER_KEY_ARMOR = os.environ.get("CAPAUTH_SERVER_KEY_ARMOR", "")
SERVER_KEY_PASSPHRASE = os.environ.get("CAPAUTH_SERVER_KEY_PASSPHRASE", "")
REQUIRE_APPROVAL = os.environ.get("CAPAUTH_REQUIRE_APPROVAL", "false").lower() == "true"
DB_PATH = os.environ.get("CAPAUTH_DB_PATH", "")
ADMIN_TOKEN = os.environ.get("CAPAUTH_ADMIN_TOKEN", "")

# Authorization decide endpoint (POST /v1/authz/decide). A dedicated service
# credential, SEPARATE from ADMIN_TOKEN so a trusted subapp backend (skgateway)
# that needs the PDP never also holds key approve/revoke power (least privilege).
# Fail closed: when this is empty the endpoint is DISABLED (503), so it is never
# an open oracle by default. See the SKWorld Authorization Standard section 1.
AUTHZ_TOKEN = os.environ.get("CAPAUTH_AUTHZ_TOKEN", "")
# Injectable storage root for the PDP fact lookups (pairing devices + capability
# tokens). Empty means use the real ~/.skcapstone registry (the PDP default).
# Tests point this at a tmp_path so the endpoint stays hermetic.
AUTHZ_BASE_DIR = os.environ.get("CAPAUTH_AUTHZ_BASE_DIR", "")

# Upstream OIDC provider (Authentik) for the OAuth2 callback flow
AUTHENTIK_CLIENT_ID = os.environ.get("AUTHENTIK_CLIENT_ID", "")
AUTHENTIK_CLIENT_SECRET = os.environ.get("AUTHENTIK_CLIENT_SECRET", "")
AUTHENTIK_OIDC_DISCOVERY = os.environ.get(
    "AUTHENTIK_OIDC_DISCOVERY",
    "https://sso.skstack01.douno.it/application/o/capauth-skstack01/.well-known/openid-configuration",
)

# JWT signing secret — auto-generated per process if not set.
# In production, set CAPAUTH_JWT_SECRET to a stable secret so tokens
# survive service restarts.
_JWT_SECRET_DEFAULT = secrets.token_hex(32)
JWT_SECRET = os.environ.get("CAPAUTH_JWT_SECRET", _JWT_SECRET_DEFAULT)
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_SECONDS = 3600


@asynccontextmanager
async def _lifespan(application: FastAPI):  # type: ignore[type-arg]
    """Register capauth with the skcapstone fleet on service start."""
    _integration.ensure_schedule()
    _integration.register_self()
    yield


app = FastAPI(
    title="CapAuth Verification Service",
    description="Passwordless PGP authentication for any application",
    version="1.0.0",
    lifespan=_lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# OIDC/OAuth2 Identity Provider (Track-2: CapAuth as its own IdP / Authentik
# OAuth Source). Mounted at /oidc. The discovery doc is also aliased at the
# service root (/.well-known/oidc-idp-configuration) so generic clients that
# only know the issuer can autodiscover. See docs/CAPAUTH_OIDC_IDP.md.
# ---------------------------------------------------------------------------
_oidc_router = build_oidc_router()
app.include_router(_oidc_router, prefix="/oidc")


@app.get("/.well-known/oidc-idp-configuration")
async def oidc_idp_discovery_alias() -> dict[str, Any]:
    """Root-level alias of the CapAuth OIDC IdP discovery document.

    The canonical discovery URL is ``/oidc/.well-known/openid-configuration``
    (issuer is the service base; configure Authentik with that URL). This alias
    avoids colliding with the legacy consumer-facing
    ``/.well-known/openid-configuration`` document already served below.
    """
    return _oidc_discovery_document()


_keystore: Optional[KeyStore] = None


def get_keystore() -> KeyStore:
    """Lazy-initialize the key store singleton."""
    global _keystore
    if _keystore is None:
        db_path = Path(DB_PATH) if DB_PATH else None
        _keystore = KeyStore(db_path)
    return _keystore


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------


class ChallengeRequest(BaseModel):
    """Client request for a challenge nonce."""

    capauth_version: str = "1.0"
    fingerprint: str = Field(description="Client's 40 (v4) or 64 (v6) hex PGP fingerprint")
    client_nonce: str = Field(description="Base64-encoded random client nonce")
    requested_service: str = Field(default="", description="Service hostname hint")


class ChallengeResponse(BaseModel):
    """Server challenge nonce response."""

    capauth_version: str = "1.0"
    nonce: str
    client_nonce_echo: str
    timestamp: str
    service: str
    expires: str
    server_signature: str = ""
    server_public_key: str = ""


class VerifyRequest(BaseModel):
    """Client's signed authentication response."""

    capauth_version: str = "1.0"
    fingerprint: str = Field(description="Client's PGP fingerprint")
    nonce: str = Field(description="Challenge nonce UUID")
    nonce_signature: str = Field(description="PGP signature over canonical nonce payload")
    claims: dict[str, Any] = Field(default_factory=dict, description="Client-asserted claims")
    claims_signature: str = Field(default="", description="PGP signature over claims")
    public_key: str = Field(default="", description="ASCII-armored public key (for enrollment)")


class VerifyResponse(BaseModel):
    """Successful authentication response with OIDC claims."""

    authenticated: bool = True
    fingerprint: str
    oidc_claims: dict[str, Any]
    access_token: str = Field(default="", description="Opaque session token")
    token_type: str = "capauth"
    expires_in: int = 3600
    is_new_enrollment: bool = False


class ErrorResponse(BaseModel):
    """Error response."""

    error: str
    error_description: str = ""
    capauth_version: str = "1.0"


class StatusResponse(BaseModel):
    """Service health status."""

    service: str
    version: str = "1.0.0"
    enrolled_keys: int
    require_approval: bool
    healthy: bool = True


class TokenInfoResponse(BaseModel):
    """JWT token introspection response."""

    active: bool
    sub: str = ""
    iss: str = ""
    iat: int = 0
    exp: int = 0
    amr: list[str] = []
    capauth_fingerprint: str = ""
    error: str = ""


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.post("/capauth/v1/challenge", response_model=ChallengeResponse)
async def challenge_endpoint(req: ChallengeRequest) -> dict[str, Any]:
    """Issue a signed challenge nonce for authentication.

    The client must sign this nonce with their PGP private key
    and POST it back to /verify within the TTL window.
    """
    if not req.fingerprint or len(req.fingerprint) not in (40, 64):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_fingerprint",
                "error_description": "Provide a 40 (v4) or 64 (v6) hex fingerprint.",
            },
        )

    challenge = build_challenge(
        fingerprint=req.fingerprint,
        client_nonce_b64=req.client_nonce,
        service_id=SERVICE_ID,
        server_key_armor=SERVER_KEY_ARMOR,
        server_key_passphrase=SERVER_KEY_PASSPHRASE,
    )

    # Reason: include server public key so clients can verify server identity
    if SERVER_KEY_ARMOR:
        from ..crypto import get_backend

        try:
            backend = get_backend()
            challenge["server_public_key"] = backend.fingerprint_from_armor(SERVER_KEY_ARMOR)
        except Exception:
            pass

    return challenge


@app.post("/capauth/v1/verify")
async def verify_endpoint(req: VerifyRequest) -> dict[str, Any]:
    """Verify a signed CapAuth response and return OIDC claims.

    This is the core authentication endpoint. On success, returns
    OIDC-compatible claims derived from the client's signed assertions.
    """
    ks = get_keystore()

    if not all([req.fingerprint, req.nonce, req.nonce_signature]):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_request",
                "error_description": "fingerprint, nonce, nonce_signature required.",
            },
        )

    public_key_armor = req.public_key

    # Resolve public key: from request body (enrollment) or from keystore
    existing = ks.get(req.fingerprint)
    if not public_key_armor and existing:
        public_key_armor = existing.public_key_armor
    elif not public_key_armor and not existing:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "unknown_fingerprint",
                "error_description": "Fingerprint not enrolled. Include public_key.",
            },
        )

    # Verify fingerprint matches submitted key
    if public_key_armor:
        derived_fp = fingerprint_from_armor(public_key_armor)
        if derived_fp and derived_fp.upper() != req.fingerprint.upper():
            raise HTTPException(
                status_code=401,
                detail={
                    "error": "invalid_fingerprint",
                    "error_description": "public_key does not match claimed fingerprint.",
                },
            )

    # Handle new enrollment
    is_new = existing is None
    if is_new:
        if REQUIRE_APPROVAL:
            ks.enroll(req.fingerprint, public_key_armor, approved=False)
            raise HTTPException(
                status_code=403,
                detail={
                    "status": "enrollment_pending",
                    "error_description": "New key requires admin approval.",
                },
            )
        ks.enroll(req.fingerprint, public_key_armor, approved=True)
        logger.info("New CapAuth key enrolled: %s", req.fingerprint[:8])

    # Check approval
    key_record = ks.get(req.fingerprint)
    if key_record and not key_record.approved:
        raise HTTPException(
            status_code=403,
            detail={
                "status": "enrollment_pending",
                "error_description": "Key pending admin approval.",
            },
        )

    # Reconstruct challenge context from the nonce store
    nonce_record = peek(req.nonce)
    if nonce_record is None:
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_nonce", "error_description": "Nonce not found or expired."},
        )

    challenge_ctx = {
        "nonce": nonce_record["nonce"],
        "client_nonce_echo": nonce_record.get("client_nonce_echo", ""),
        "timestamp": nonce_record["issued_at"],
        "service": SERVICE_ID,
        "expires": nonce_record["expires_at"],
    }

    success, error_code, oidc_claims = verify_auth_response(
        fingerprint=req.fingerprint,
        nonce_id=req.nonce,
        nonce_signature_armor=req.nonce_signature,
        claims=req.claims,
        claims_signature_armor=req.claims_signature,
        public_key_armor=public_key_armor,
        challenge_context=challenge_ctx,
    )

    if not success:
        _integration.alert(
            "verify_failed",
            {"fingerprint": req.fingerprint[:8], "error_code": error_code},
            level="warn",
        )
        raise HTTPException(
            status_code=401,
            detail={"error": error_code, "capauth_version": "1.0"},
        )

    ks.update_last_auth(req.fingerprint)

    now = int(time.time())
    jwt_payload = {
        "sub": req.fingerprint,
        "iss": SERVICE_ID,
        "iat": now,
        "exp": now + JWT_EXPIRY_SECONDS,
        "amr": ["pgp"],
        "capauth_fingerprint": req.fingerprint,
    }
    access_token = jwt.encode(jwt_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    return VerifyResponse(
        fingerprint=req.fingerprint,
        oidc_claims=oidc_claims,
        access_token=access_token,
        is_new_enrollment=is_new,
    ).model_dump()


@app.get("/capauth/v1/status", response_model=StatusResponse)
async def status_endpoint() -> dict[str, Any]:
    """Service health check and statistics."""
    ks = get_keystore()
    return StatusResponse(
        service=SERVICE_ID,
        enrolled_keys=ks.count(),
        require_approval=REQUIRE_APPROVAL,
    ).model_dump()


@app.get("/capauth/v1/token-info", response_model=TokenInfoResponse)
async def token_info_endpoint(token: str) -> dict[str, Any]:
    """Validate a CapAuth JWT and return its decoded claims.

    Pass the access_token as a query parameter: ?token=<jwt>

    Returns ``active: false`` for expired, invalid, or tampered tokens.
    Never raises an HTTP error for invalid tokens — callers should inspect
    the ``active`` field.
    """
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            options={"require": ["sub", "iss", "iat", "exp"]},
        )
        return TokenInfoResponse(
            active=True,
            sub=payload.get("sub", ""),
            iss=payload.get("iss", ""),
            iat=payload.get("iat", 0),
            exp=payload.get("exp", 0),
            amr=payload.get("amr", []),
            capauth_fingerprint=payload.get("capauth_fingerprint", ""),
        ).model_dump()
    except jwt.ExpiredSignatureError:
        return TokenInfoResponse(active=False, error="token_expired").model_dump()
    except jwt.InvalidTokenError as exc:
        return TokenInfoResponse(active=False, error=f"invalid_token: {exc}").model_dump()


def _check_admin(request: Request) -> None:
    """Verify admin authorization via bearer token."""
    if not ADMIN_TOKEN:
        raise HTTPException(
            status_code=501, detail="Admin API not configured. Set CAPAUTH_ADMIN_TOKEN."
        )
    auth = request.headers.get("Authorization", "")
    if auth != f"Bearer {ADMIN_TOKEN}":
        raise HTTPException(status_code=403, detail="Invalid admin token.")


@app.get("/capauth/v1/keys")
async def list_keys(request: Request, approved_only: bool = False) -> list[dict[str, Any]]:
    """List enrolled keys (admin only)."""
    _check_admin(request)
    ks = get_keystore()
    keys = ks.list_keys(approved_only=approved_only)
    return [
        {
            "fingerprint": k.fingerprint,
            "enrolled_at": k.enrolled_at,
            "last_auth": k.last_auth,
            "approved": k.approved,
            "linked_to": k.linked_to,
        }
        for k in keys
    ]


class KeyActionRequest(BaseModel):
    """Request to approve or revoke a key."""

    fingerprint: str


@app.post("/capauth/v1/keys/approve")
async def approve_key(req: KeyActionRequest, request: Request) -> dict[str, Any]:
    """Approve a pending key enrollment (admin only)."""
    _check_admin(request)
    ks = get_keystore()
    if ks.approve(req.fingerprint):
        return {"approved": True, "fingerprint": req.fingerprint}
    raise HTTPException(status_code=404, detail="Key not found.")


@app.post("/capauth/v1/keys/revoke")
async def revoke_key(req: KeyActionRequest, request: Request) -> dict[str, Any]:
    """Revoke an enrolled key (admin only)."""
    _check_admin(request)
    ks = get_keystore()
    if ks.revoke(req.fingerprint):
        return {"revoked": True, "fingerprint": req.fingerprint}
    raise HTTPException(status_code=404, detail="Key not found.")


# ---------------------------------------------------------------------------
# Authorization decision endpoint (POST /v1/authz/decide)
#
# The platform's ONE decision point (capauth.authz.decide) exposed over HTTP so
# a NON-Python subapp backend (skgateway, Node) delegates the allow/deny instead
# of porting the PDP (two PDPs drift). SKWorld Authorization Standard section 1;
# design detail spec 2026-08-06 L1.8.
#
# This is a THIN wrapper: it authenticates the CALLER (a trusted service
# credential), then calls decide() against the SAME token store. It does not
# authenticate the SUBJECT: the caller is a PEP that has already authenticated
# its subject and passes that already-authenticated identity here (exactly the
# in-process contract). The audit obligation decide() returns is passed straight
# back in the response so the calling PEP honors it the same way an in-process
# caller does.
#
# GATING (conservative, security-adjacent): a dedicated bearer service
# credential CAPAUTH_AUTHZ_TOKEN, distinct from the admin token (least
# privilege). Unset -> the endpoint is DISABLED (503), so it is never an open
# oracle that lets an anonymous internet caller probe arbitrary
# (subject, capability) pairs. Operators MUST additionally bind/restrict the
# service to loopback/tailnet at the network layer (the standard's
# "loopback/tailnet only"); the bearer credential is the application-layer gate.
# ---------------------------------------------------------------------------


def _check_authz_caller(request: Request) -> None:
    """Gate the decide endpoint to trusted service callers only.

    Mirrors ``_check_admin`` but with its OWN credential so an authz caller
    never inherits admin (key approve/revoke) power. Fails closed: when
    ``CAPAUTH_AUTHZ_TOKEN`` is unset the endpoint is disabled entirely.
    """
    if not AUTHZ_TOKEN:
        raise HTTPException(
            status_code=503,
            detail="Authz decide endpoint not configured. Set CAPAUTH_AUTHZ_TOKEN.",
        )
    auth = request.headers.get("Authorization", "")
    if auth != f"Bearer {AUTHZ_TOKEN}":
        raise HTTPException(status_code=403, detail="Invalid authz service token.")


class AuthzDecideRequest(BaseModel):
    """A PEP's request to the one PDP: may ``subject`` exercise ``capability``?

    ``subject`` is the caller-side ALREADY-AUTHENTICATED identity (e.g. an fqid);
    this endpoint does not re-authenticate it. ``resource`` / ``context`` mirror
    ``capauth.authz.decide`` (a ``trust_signal`` in context is advisory only and
    never gates the decision).
    """

    subject: str = Field(description="Already-authenticated subject identity (e.g. an fqid)")
    capability: str = Field(description="Requested capability, e.g. 'skgateway.infer'")
    resource: Optional[dict] = Field(default=None, description="Action target; recorded on audit")
    context: Optional[dict] = Field(
        default=None, description="Advisory context; never gates allow"
    )


@app.post("/v1/authz/decide", response_model=AuthzDecision)
async def authz_decide_endpoint(req: AuthzDecideRequest, request: Request) -> AuthzDecision:
    """Return the PDP allow/deny for ``(subject, capability, resource, context)``.

    Thin wrapper over ``capauth.authz.decide`` (the ONE decision point). Fails
    closed on every uncertainty: a bad caller credential is refused before any
    decision runs; a blank subject/capability is a 400; and any PDP error is
    returned as a DENY rather than a 500 so a fault never accidentally allows.
    """
    _check_authz_caller(request)

    # Fail closed on structurally-present-but-empty input. (Entirely missing
    # fields are rejected by pydantic with 422 before we get here.)
    subject = (req.subject or "").strip()
    capability = (req.capability or "").strip()
    if not subject or not capability:
        raise HTTPException(status_code=400, detail="subject and capability are required.")

    base_dir = Path(AUTHZ_BASE_DIR) if AUTHZ_BASE_DIR else None
    try:
        decision = authz_decide(
            subject,
            capability,
            req.resource,
            req.context,
            base_dir=base_dir,
        )
    except Exception as exc:  # pragma: no cover - defensive; PDP is pure + fail-closed
        logger.warning(
            "authz decide error for subject=%s capability=%s: %s", subject, capability, exc
        )
        return AuthzDecision(allow=False, reason=f"pdp error: {exc}", obligations=[])

    logger.info(
        "authz.decide subject=%s capability=%s -> %s",
        subject,
        capability,
        "allow" if decision.allow else "deny",
    )
    return decision


# ---------------------------------------------------------------------------
# OIDC Discovery (for apps that autodiscover)
# ---------------------------------------------------------------------------


@app.get("/.well-known/openid-configuration")
async def oidc_discovery() -> dict[str, Any]:
    """OIDC discovery document compatible with Forgejo, Immich, Grafana, etc.

    CapAuth uses a non-standard PGP challenge-response flow rather than the
    standard OAuth authorization code flow.  The endpoints below map the
    OIDC terminology onto CapAuth concepts so that auto-discovery works:

      authorization_endpoint → /capauth/v1/challenge  (issue challenge nonce)
      token_endpoint         → /capauth/v1/verify     (exchange signed nonce for JWT)
      userinfo_endpoint      → /capauth/v1/userinfo   (return claims from JWT)
    """
    base = os.environ.get(
        "CAPAUTH_BASE_URL",
        os.environ.get("CAPAUTH_OIDC_ISSUER", f"https://{SERVICE_ID}"),
    ).rstrip("/")
    return {
        "issuer": base,
        "authorization_endpoint": f"{base}/capauth/v1/challenge",
        "token_endpoint": f"{base}/capauth/v1/verify",
        "userinfo_endpoint": f"{base}/capauth/v1/userinfo",
        "jwks_uri": f"{base}/.well-known/jwks.json",
        "end_session_endpoint": f"{base}/capauth/v1/logout",
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["HS256"],
        "userinfo_signing_alg_values_supported": ["none"],
        "scopes_supported": ["openid", "profile", "email", "groups"],
        "claims_supported": [
            "sub",
            "iss",
            "iat",
            "exp",
            "name",
            "preferred_username",
            "email",
            "email_verified",
            "picture",
            "groups",
            "locale",
            "zoneinfo",
            "capauth_fingerprint",
            "agent_type",
            "amr",
        ],
        "grant_types_supported": ["authorization_code"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic",
            "capauth_pgp",
        ],
        "code_challenge_methods_supported": ["S256", "plain"],
    }


@app.get("/.well-known/jwks.json")
async def jwks_endpoint() -> dict[str, Any]:
    """JWKS endpoint — returns an empty key set for HS256.

    CapAuth uses HMAC-SHA256 (HS256) JWTs with a server-side secret,
    not RSA/EC public-key signing.  JWKS is not applicable to symmetric
    algorithms, but the endpoint is required by OIDC autodiscovery.

    Note for Forgejo:  Forgejo's OIDC client validates the JWKS URI exists
    and returns a parseable document.  Since HS256 tokens are validated
    internally (not by consumers), the key set is intentionally empty.
    """
    return {"keys": []}


@app.get("/capauth/v1/userinfo")
async def userinfo_endpoint(request: Request) -> dict[str, Any]:
    """OIDC userinfo endpoint — returns claims for a valid JWT bearer token.

    Forgejo and other OIDC consumers call this after receiving an access_token
    to get the full set of user claims.

    Authorization: Bearer <access_token>
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail={"error": "missing_token", "error_description": "Bearer token required."},
        )
    token = auth[len("Bearer ") :]
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            options={"require": ["sub", "iss", "iat", "exp"]},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail={"error": "token_expired"})
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail={"error": f"invalid_token: {exc}"})

    # Return all claims from the JWT payload as userinfo
    return {k: v for k, v in payload.items() if k not in ("iat", "exp", "iss")}


@app.get("/capauth/v1/logout")
async def logout_endpoint() -> dict[str, Any]:
    """OIDC end-session endpoint (no-op for CapAuth).

    CapAuth JWTs are stateless; logout means discarding the token client-side.
    This endpoint satisfies OIDC autodiscovery without doing anything server-side.
    """
    return {"logged_out": True}


# ---------------------------------------------------------------------------
# OAuth2 Callback — receives the authorization code from Authentik after
# the user completes the upstream OIDC flow, exchanges it for tokens, and
# returns the CapAuth session token to the originating client.
# ---------------------------------------------------------------------------

# In-memory cache for the OIDC discovery document (TTL = 1 hour)
_oidc_discovery_cache: dict[str, Any] = {}
_oidc_discovery_fetched_at: float = 0.0
_OIDC_CACHE_TTL = 3600.0


async def _get_oidc_config() -> dict[str, Any]:
    """Fetch and cache the upstream OIDC discovery document.

    Returns:
        dict: Parsed OIDC discovery document from the upstream provider.
    """
    global _oidc_discovery_cache, _oidc_discovery_fetched_at
    now = time.time()
    if _oidc_discovery_cache and (now - _oidc_discovery_fetched_at) < _OIDC_CACHE_TTL:
        return _oidc_discovery_cache
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(AUTHENTIK_OIDC_DISCOVERY)
        resp.raise_for_status()
        _oidc_discovery_cache = resp.json()
        _oidc_discovery_fetched_at = now
    return _oidc_discovery_cache


@app.get("/capauth/v1/callback", response_class=HTMLResponse)
async def oidc_callback(
    request: Request, code: str = "", error: str = "", error_description: str = ""
) -> Any:
    """OAuth2 authorization code callback from the upstream IdP (Authentik).

    After the user authenticates with Authentik, the browser is redirected here
    with an authorization code. This endpoint exchanges the code for tokens,
    extracts the identity, and presents the CapAuth session token to the user.

    Query params (from IdP redirect):
        code: Authorization code to exchange for tokens.
        error: OAuth2 error code if authorization failed.
        error_description: Human-readable error message.

    Returns:
        HTMLResponse: Simple page with the CapAuth session token or error details.
    """
    if error:
        return HTMLResponse(
            content=f"""
            <html><body style="font-family:monospace;padding:2em;background:#0f172a;color:#f1f5f9">
            <h2 style="color:#dc2626">CapAuth: Authorization Failed</h2>
            <p><b>Error:</b> {error}</p>
            <p><b>Details:</b> {error_description}</p>
            </body></html>
            """,
            status_code=400,
        )

    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code.")

    if not AUTHENTIK_CLIENT_ID or not AUTHENTIK_CLIENT_SECRET:
        raise HTTPException(
            status_code=501,
            detail="Upstream OIDC not configured. Set AUTHENTIK_CLIENT_ID and AUTHENTIK_CLIENT_SECRET.",
        )

    base_url = os.environ.get("CAPAUTH_BASE_URL", f"https://{SERVICE_ID}")
    redirect_uri = f"{base_url}/capauth/v1/callback"

    try:
        oidc_cfg = await _get_oidc_config()
        token_endpoint = oidc_cfg["token_endpoint"]
        userinfo_endpoint = oidc_cfg["userinfo_endpoint"]
    except Exception as exc:
        logger.error("Failed to fetch OIDC discovery: %s", exc)
        raise HTTPException(status_code=502, detail=f"OIDC discovery failed: {exc}")

    # Exchange authorization code for tokens
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            token_resp = await client.post(
                token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": AUTHENTIK_CLIENT_ID,
                    "client_secret": AUTHENTIK_CLIENT_SECRET,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            token_resp.raise_for_status()
            token_data = token_resp.json()
        except httpx.HTTPStatusError as exc:
            logger.error(
                "Token exchange failed: %s %s", exc.response.status_code, exc.response.text
            )
            raise HTTPException(
                status_code=502, detail=f"Token exchange failed: {exc.response.status_code}"
            )
        except Exception as exc:
            logger.error("Token exchange error: %s", exc)
            raise HTTPException(status_code=502, detail=f"Token exchange error: {exc}")

        upstream_access_token = token_data.get("access_token", "")
        id_token = token_data.get("id_token", "")

        # Fetch userinfo from upstream
        try:
            userinfo_resp = await client.get(
                userinfo_endpoint,
                headers={"Authorization": f"Bearer {upstream_access_token}"},
            )
            userinfo_resp.raise_for_status()
            userinfo = userinfo_resp.json()
        except Exception as exc:
            logger.warning("Userinfo fetch failed, using id_token claims only: %s", exc)
            # Fall back to decoding id_token without verification for claims
            try:
                userinfo = (
                    jwt.decode(id_token, options={"verify_signature": False}) if id_token else {}
                )
            except Exception:
                userinfo = {}

    # Build a CapAuth session token from the upstream identity
    upstream_sub = userinfo.get("sub", userinfo.get("preferred_username", "unknown"))
    upstream_email = userinfo.get("email", "")
    upstream_name = userinfo.get("name", userinfo.get("preferred_username", upstream_sub))
    upstream_groups = userinfo.get("groups", [])

    now = int(time.time())
    jwt_payload = {
        "sub": upstream_sub,
        "iss": SERVICE_ID,
        "iat": now,
        "exp": now + JWT_EXPIRY_SECONDS,
        "amr": ["oidc", "authentik"],
        "name": upstream_name,
        "email": upstream_email,
        "groups": upstream_groups,
        "upstream_provider": "authentik",
        "capauth_version": "1.0",
    }
    capauth_token = jwt.encode(jwt_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    logger.info("OIDC callback: issued CapAuth token for upstream sub=%s", upstream_sub[:16])

    # Present the token — in a real browser extension / app, this page would
    # post the token back to the originating window via postMessage.
    return HTMLResponse(
        content=f"""
        <!DOCTYPE html>
        <html>
        <head>
          <title>CapAuth — Authenticated</title>
          <style>
            body {{font-family:monospace;padding:2em;background:#0f172a;color:#f1f5f9;max-width:700px;margin:auto}}
            h2 {{color:#10b981}} .token {{background:#1e293b;padding:1em;border-radius:8px;word-break:break-all;font-size:0.85em;border:1px solid #334155}}
            .label {{color:#94a3b8;font-size:0.8em;margin-top:1em}} .success {{color:#10b981;font-size:1.1em}}
          </style>
        </head>
        <body>
          <h2>CapAuth: Authentication Successful</h2>
          <p class="success">Authenticated via Authentik as <b>{upstream_name}</b></p>
          <p class="label">CapAuth Session Token (copy this):</p>
          <div class="token" id="token">{capauth_token}</div>
          <p class="label">Identity: {upstream_sub}</p>
          <p class="label">Email: {upstream_email}</p>
          <p class="label">Groups: {", ".join(upstream_groups) if upstream_groups else "none"}</p>
          <p class="label" style="margin-top:2em;color:#475569">
            This token expires in {JWT_EXPIRY_SECONDS // 60} minutes.
            Use it as: <code>Authorization: Bearer &lt;token&gt;</code>
          </p>
          <script>
            // Auto-copy token for browser extension integration
            if (window.opener) {{
              window.opener.postMessage({{capauth_token: "{capauth_token}", sub: "{upstream_sub}"}}, "*");
            }}
          </script>
        </body>
        </html>
        """,
        status_code=200,
    )


# ---------------------------------------------------------------------------
# QR Login — mobile scans QR, signs challenge, desktop polls for result
# ---------------------------------------------------------------------------


class QRChallengeResponse(BaseModel):
    """QR code challenge payload for mobile scanning."""

    capauth_qr: str = "1.0"
    nonce: str
    service: str
    callback: str = Field(description="URL the mobile device POSTs the signed response to")
    expires: str
    qr_data_url: str = Field(default="", description="Base64 data:image/png QR code")


class QRStatusResponse(BaseModel):
    """Polling response for desktop waiting on mobile auth."""

    status: str = Field(description="pending | authenticated | expired")
    access_token: str = ""
    fingerprint: str = ""
    oidc_claims: dict[str, Any] = Field(default_factory=dict)
    expires_in: int = 0


# In-memory store for QR auth results (nonce -> VerifyResponse data)
_qr_results: dict[str, dict[str, Any]] = {}


@app.post("/capauth/v1/qr-challenge", response_model=QRChallengeResponse)
async def qr_challenge_endpoint(request: Request) -> dict[str, Any]:
    """Generate a QR code containing a challenge nonce for mobile scanning.

    The desktop browser calls this to get a QR code. The QR encodes a
    JSON payload with the nonce and callback URL. The phone scans it,
    signs the challenge with its PGP key, and POSTs back to the callback.

    No fingerprint is required upfront — the mobile device provides it.
    """
    # Issue a nonce with a placeholder fingerprint (mobile will provide its own)
    nonce_record = issue(fingerprint="QR_PENDING", client_nonce_echo="")
    nonce_id = nonce_record["nonce"]

    base_url = os.environ.get("CAPAUTH_BASE_URL", f"https://{SERVICE_ID}")
    callback = f"{base_url}/capauth/v1/qr-verify/{nonce_id}"

    qr_payload = {
        "capauth_qr": "1.0",
        "nonce": nonce_id,
        "service": SERVICE_ID,
        "callback": callback,
        "expires": nonce_record["expires_at"],
    }

    # Generate QR code as data URL
    qr_data_url = ""
    try:
        import base64
        import io

        import segno

        qr = segno.make(json.dumps(qr_payload), error="m")
        buf = io.BytesIO()
        qr.save(buf, kind="png", scale=6, dark="#7C3AED", light="#0f0f1a")
        b64 = base64.b64encode(buf.getvalue()).decode()
        qr_data_url = f"data:image/png;base64,{b64}"
    except ImportError:
        logger.warning("segno not installed — QR data URL unavailable")

    return QRChallengeResponse(
        nonce=nonce_id,
        service=SERVICE_ID,
        callback=callback,
        expires=nonce_record["expires_at"],
        qr_data_url=qr_data_url,
    ).model_dump()


@app.get("/capauth/v1/qr-status/{nonce_id}", response_model=QRStatusResponse)
async def qr_status_endpoint(nonce_id: str) -> dict[str, Any]:
    """Poll for QR login completion.

    The desktop browser calls this repeatedly after displaying the QR code.
    Returns ``pending`` until the mobile device completes the auth flow,
    then returns the JWT and claims.
    """
    # Check if mobile has completed authentication
    if nonce_id in _qr_results:
        result = _qr_results.pop(nonce_id)
        return QRStatusResponse(
            status="authenticated",
            access_token=result["access_token"],
            fingerprint=result["fingerprint"],
            oidc_claims=result.get("oidc_claims", {}),
            expires_in=result.get("expires_in", JWT_EXPIRY_SECONDS),
        ).model_dump()

    # Check if the nonce still exists / hasn't expired
    nonce_record = peek(nonce_id)
    if nonce_record is None:
        return QRStatusResponse(status="expired").model_dump()

    return QRStatusResponse(status="pending").model_dump()


@app.get("/capauth/v1/qr-login", response_class=HTMLResponse)
async def qr_login_page(request: Request) -> HTMLResponse:
    """Serve the QR login page for desktop browsers.

    Displays a QR code and polls for mobile authentication completion.
    Once the mobile device scans and signs, the page auto-redirects or
    shows the authenticated session.
    """
    base_url = os.environ.get("CAPAUTH_BASE_URL", f"https://{SERVICE_ID}")
    redirect_to = request.query_params.get("redirect", "")

    return HTMLResponse(
        content=f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CapAuth — Mobile Login</title>
  <style>
    :root {{
      --bg: #0f0f1a; --card: #1a1a35; --accent: #7C3AED;
      --cyan: #00e5ff; --text: #e2e8f0; --muted: #64748b;
      --success: #10b981; --error: #ef4444;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: var(--bg); color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh; padding: 20px;
    }}
    .card {{
      background: var(--card); border: 1px solid rgba(124,58,237,0.2);
      border-radius: 16px; padding: 40px; text-align: center;
      max-width: 420px; width: 100%;
      box-shadow: 0 8px 40px rgba(0,0,0,0.4);
    }}
    .shield {{ margin-bottom: 16px; }}
    h1 {{ font-size: 22px; color: #a78bfa; margin-bottom: 6px; }}
    .subtitle {{ color: var(--muted); font-size: 13px; margin-bottom: 28px; }}
    #qr-container {{
      background: var(--bg); border: 2px solid rgba(124,58,237,0.3);
      border-radius: 12px; padding: 20px; margin: 0 auto 24px;
      display: inline-block;
    }}
    #qr-img {{ display: block; border-radius: 8px; }}
    #qr-fallback {{
      color: var(--muted); font-size: 12px;
      font-family: monospace; word-break: break-all;
      max-width: 280px; margin: 8px auto 0;
    }}
    .status {{
      display: flex; align-items: center; justify-content: center;
      gap: 8px; margin-top: 20px; font-size: 14px;
    }}
    .dot {{
      width: 8px; height: 8px; border-radius: 50%;
      animation: pulse 1.2s infinite;
    }}
    .dot.pending {{ background: #f59e0b; }}
    .dot.success {{ background: var(--success); animation: none; }}
    .dot.error {{ background: var(--error); animation: none; }}
    @keyframes pulse {{
      0%,100% {{ opacity: 1; }} 50% {{ opacity: 0.3; }}
    }}
    .timer {{ color: var(--muted); font-size: 12px; margin-top: 8px; }}
    .result {{
      background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.3);
      border-radius: 8px; padding: 16px; margin-top: 20px; text-align: left;
      font-size: 13px; display: none;
    }}
    .result .fp {{
      font-family: monospace; color: var(--cyan); font-size: 11px;
      word-break: break-all;
    }}
    .instructions {{
      color: var(--muted); font-size: 12px; margin-top: 20px; line-height: 1.6;
    }}
    .instructions ol {{ text-align: left; padding-left: 20px; }}
    .btn {{
      background: var(--accent); color: #fff; border: none;
      border-radius: 8px; padding: 12px 24px; font-size: 14px;
      font-weight: 600; cursor: pointer; margin-top: 16px;
      display: none;
    }}
    .btn:hover {{ background: #6d28d9; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="shield">
      <svg width="40" height="40" viewBox="0 0 24 24" fill="none">
        <path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z"
              fill="#7C3AED" opacity="0.3"/>
        <path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z"
              stroke="#a78bfa" stroke-width="1.5" fill="none"/>
        <path d="M10 12l2 2 4-4" stroke="#00e5ff" stroke-width="2"
              stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    </div>
    <h1>CapAuth Mobile Login</h1>
    <p class="subtitle">Scan with your phone to sign in with PGP</p>

    <div id="qr-container">
      <img id="qr-img" alt="QR Code" width="240" height="240"/>
      <div id="qr-fallback"></div>
    </div>

    <div class="status">
      <div class="dot pending" id="status-dot"></div>
      <span id="status-text">Waiting for mobile scan...</span>
    </div>
    <div class="timer" id="timer"></div>

    <div class="result" id="result">
      <div style="color:var(--success);font-weight:600;margin-bottom:8px;">
        Authenticated
      </div>
      <div>Fingerprint:</div>
      <div class="fp" id="result-fp"></div>
    </div>

    <button class="btn" id="btn-continue" onclick="handleRedirect()">Continue</button>

    <div class="instructions">
      <ol>
        <li>Open CapAuth on your phone</li>
        <li>Scan this QR code</li>
        <li>Approve the PGP signature</li>
        <li>You're in — no password needed</li>
      </ol>
    </div>
  </div>

  <script>
    const BASE = "{base_url}";
    const REDIRECT = "{redirect_to}";
    let nonceId = null;
    let pollTimer = null;
    let expiresAt = null;

    async function initQR() {{
      try {{
        const resp = await fetch(BASE + "/capauth/v1/qr-challenge", {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: "{{}}",
        }});
        const data = await resp.json();
        nonceId = data.nonce;
        expiresAt = new Date(data.expires);

        if (data.qr_data_url) {{
          document.getElementById("qr-img").src = data.qr_data_url;
        }} else {{
          document.getElementById("qr-img").style.display = "none";
          document.getElementById("qr-fallback").textContent =
            JSON.stringify({{ nonce: data.nonce, service: data.service, callback: data.callback }});
        }}

        pollTimer = setInterval(pollStatus, 2000);
        updateTimer();
        setInterval(updateTimer, 1000);
      }} catch (e) {{
        setStatus("error", "Failed to generate QR: " + e.message);
      }}
    }}

    async function pollStatus() {{
      if (!nonceId) return;
      try {{
        const resp = await fetch(BASE + "/capauth/v1/qr-status/" + nonceId);
        const data = await resp.json();

        if (data.status === "authenticated") {{
          clearInterval(pollTimer);
          setStatus("success", "Authenticated");
          document.getElementById("result").style.display = "block";
          document.getElementById("result-fp").textContent = data.fingerprint;

          if (REDIRECT) {{
            document.getElementById("btn-continue").style.display = "inline-block";
            setTimeout(handleRedirect, 2000);
          }}

          // Notify browser extension
          if (window.opener) {{
            window.opener.postMessage({{
              capauth_token: data.access_token,
              fingerprint: data.fingerprint
            }}, "*");
          }}
        }} else if (data.status === "expired") {{
          clearInterval(pollTimer);
          setStatus("error", "QR expired — refresh to try again");
        }}
      }} catch (e) {{
        // Network hiccup — keep polling
      }}
    }}

    function setStatus(type, text) {{
      const dot = document.getElementById("status-dot");
      dot.className = "dot " + type;
      document.getElementById("status-text").textContent = text;
    }}

    function updateTimer() {{
      if (!expiresAt) return;
      const remaining = Math.max(0, Math.floor((expiresAt - Date.now()) / 1000));
      if (remaining <= 0) {{
        document.getElementById("timer").textContent = "Expired";
        return;
      }}
      const m = Math.floor(remaining / 60);
      const s = remaining % 60;
      document.getElementById("timer").textContent =
        "Expires in " + m + ":" + String(s).padStart(2, "0");
    }}

    function handleRedirect() {{
      if (REDIRECT) window.location.href = REDIRECT;
    }}

    initQR();
  </script>
</body>
</html>"""
    )


@app.post("/capauth/v1/qr-verify/{nonce_id}")
async def qr_verify_endpoint(nonce_id: str, req: VerifyRequest) -> dict[str, Any]:
    """Mobile device submits signed challenge for QR login.

    This is the callback URL encoded in the QR code. The mobile device
    signs the challenge nonce with its PGP key and POSTs here. On success,
    the result is stored so the polling desktop can retrieve it.
    """
    ks = get_keystore()

    if not all([req.fingerprint, req.nonce_signature]):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_request",
                "error_description": "fingerprint and nonce_signature required.",
            },
        )

    # Override the nonce from the URL path
    req.nonce = nonce_id

    public_key_armor = req.public_key

    # Resolve public key
    existing = ks.get(req.fingerprint)
    if not public_key_armor and existing:
        public_key_armor = existing.public_key_armor
    elif not public_key_armor and not existing:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "unknown_fingerprint",
                "error_description": "Fingerprint not enrolled. Include public_key.",
            },
        )

    # Verify fingerprint matches submitted key
    if public_key_armor:
        derived_fp = fingerprint_from_armor(public_key_armor)
        if derived_fp and derived_fp.upper() != req.fingerprint.upper():
            raise HTTPException(
                status_code=401,
                detail={
                    "error": "invalid_fingerprint",
                    "error_description": "public_key does not match fingerprint.",
                },
            )

    # Handle new enrollment
    is_new = existing is None
    if is_new:
        if REQUIRE_APPROVAL:
            ks.enroll(req.fingerprint, public_key_armor, approved=False)
            raise HTTPException(
                status_code=403,
                detail={
                    "status": "enrollment_pending",
                    "error_description": "New key requires admin approval.",
                },
            )
        ks.enroll(req.fingerprint, public_key_armor, approved=True)
        logger.info("QR login: new key enrolled: %s", req.fingerprint[:8])

    # Check approval
    key_record = ks.get(req.fingerprint)
    if key_record and not key_record.approved:
        raise HTTPException(
            status_code=403,
            detail={"status": "enrollment_pending"},
        )

    # For QR flow, the nonce was issued with fingerprint="QR_PENDING".
    # We need to peek and verify without the fingerprint check in consume().
    nonce_record = peek(nonce_id)
    if nonce_record is None:
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_nonce", "error_description": "Nonce not found or expired."},
        )

    challenge_ctx = {
        "nonce": nonce_record["nonce"],
        "client_nonce_echo": nonce_record.get("client_nonce_echo", ""),
        "timestamp": nonce_record["issued_at"],
        "service": SERVICE_ID,
        "expires": nonce_record["expires_at"],
    }

    success, error_code, oidc_claims = verify_auth_response(
        fingerprint=req.fingerprint,
        nonce_id=nonce_id,
        nonce_signature_armor=req.nonce_signature,
        claims=req.claims,
        claims_signature_armor=req.claims_signature,
        public_key_armor=public_key_armor,
        challenge_context=challenge_ctx,
    )

    if not success:
        raise HTTPException(
            status_code=401,
            detail={"error": error_code, "capauth_version": "1.0"},
        )

    ks.update_last_auth(req.fingerprint)

    now = int(time.time())
    jwt_payload = {
        "sub": req.fingerprint,
        "iss": SERVICE_ID,
        "iat": now,
        "exp": now + JWT_EXPIRY_SECONDS,
        "amr": ["pgp", "qr"],
        "capauth_fingerprint": req.fingerprint,
    }
    access_token = jwt.encode(jwt_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    # Store result for desktop polling
    result_data = {
        "authenticated": True,
        "fingerprint": req.fingerprint,
        "oidc_claims": oidc_claims,
        "access_token": access_token,
        "expires_in": JWT_EXPIRY_SECONDS,
        "is_new_enrollment": is_new,
    }
    _qr_results[nonce_id] = result_data

    return result_data


# ---------------------------------------------------------------------------
# CapAuth Bunker — NIP-46-style remote signer (SPIKE)
#
# The phone holds the PGP key; the desktop relays the canonical CAPAUTH_NONCE_V2
# payload over this broker for the phone to sign. The broker only relays — it
# never sees the private key. See bunker.py for the protocol + hardening notes.
# ---------------------------------------------------------------------------

# Persist approved pairing sessions so they survive a service restart (clients
# do NOT have to re-pair). Only session id + pairing secret + TTL + replay guard
# are written (mode 0600), never key material. Set CAPAUTH_BUNKER_STORE="" to
# opt back into pure in-memory (non-persistent) sessions.
_bunker_store_default = str(resolve_capauth_home() / "service" / "bunker_sessions.json")
_bunker_store = os.environ.get("CAPAUTH_BUNKER_STORE", _bunker_store_default) or None
_bunker = BunkerBroker(
    max_sessions=int(os.environ.get("CAPAUTH_BUNKER_MAX_SESSIONS", "500")),
    store_path=_bunker_store,
)
_push = PushRegistry(data_dir=os.environ.get("CAPAUTH_DATA_DIR", "/data"))

# Simple in-memory sliding-window rate limiter for POST /bunker/session, keyed by
# client IP. Defaults: 10 new sessions / 60s / IP. Tune via env. This is a DoS
# backstop for the single-process broker — not a substitute for edge rate limits.
_BUNKER_RL_MAX = int(os.environ.get("CAPAUTH_BUNKER_RL_MAX", "10"))
_BUNKER_RL_WINDOW = float(os.environ.get("CAPAUTH_BUNKER_RL_WINDOW", "60"))
_bunker_rl: dict[str, list[float]] = {}


def _bunker_rate_ok(client_ip: str) -> bool:
    now = time.time()
    hits = [t for t in _bunker_rl.get(client_ip, []) if now - t < _BUNKER_RL_WINDOW]
    if len(hits) >= _BUNKER_RL_MAX:
        _bunker_rl[client_ip] = hits
        return False
    hits.append(now)
    _bunker_rl[client_ip] = hits
    return True


def _bunker_auth_ok(request: Request) -> bool:
    """Optional bearer auth on /bunker/session. Open when the env is unset."""
    token = os.environ.get("CAPAUTH_BUNKER_AUTH_TOKEN", "")
    if not token:
        return True
    header = request.headers.get("authorization", "")
    return header.startswith("Bearer ") and secrets.compare_digest(header[7:], token)


# Directory holding the phone-signer PWA static assets.
_PHONE_SIGNER_DIR = Path(__file__).resolve().parent.parent.parent.parent / "phone-signer"


def _broker_host(request: Optional["Request"] = None) -> str:
    """Resolve the broker host advertised in the pairing URI.

    Resolution order:
      1. The request's own (forwarded) host IF it is in the allow-list
         ``CAPAUTH_BUNKER_HOSTS`` (comma-separated). This lets the SAME service
         serve multiple transports — the Cloudflare tunnel AND a Tailscale Funnel
         — each producing *native* pairing URIs (so the funnel is a true
         independent transport, usable even when CF is down). The allow-list
         prevents a client from spoofing an arbitrary Host into the pairing URI.
      2. ``CAPAUTH_BUNKER_HOST`` — a forced override / default.
      3. ``CAPAUTH_BASE_URL`` host, then ``SERVICE_ID``.
    """
    allowed = [
        h.strip() for h in os.environ.get("CAPAUTH_BUNKER_HOSTS", "").split(",") if h.strip()
    ]
    if request is not None and allowed:
        cand = (
            (request.headers.get("x-forwarded-host") or request.headers.get("host") or "")
            .split(",")[0]
            .strip()
        )
        if cand in allowed:
            return cand
    explicit = os.environ.get("CAPAUTH_BUNKER_HOST", "")
    if explicit:
        return explicit
    base = os.environ.get("CAPAUTH_BASE_URL", "")
    if base:
        from urllib.parse import urlparse

        netloc = urlparse(base).netloc
        if netloc:
            return netloc
    return SERVICE_ID


def _relay_ws_url(host: str) -> str:
    """Build the wss:// relay URL the phone connects to."""
    scheme = "ws" if host.startswith("localhost") or host.startswith("127.") else "wss"
    return f"{scheme}://{host}/bunker/ws"


class BunkerSessionResponse(BaseModel):
    """Pairing session creation response (returned to the desktop client)."""

    session_id: str
    pairing_secret: str
    broker_host: str
    relay_ws_url: str
    pairing_uri: str
    qr_data_url: str = ""
    expires_in: int = 300


@app.post("/bunker/session", response_model=BunkerSessionResponse)
async def bunker_create_session(request: Request) -> dict[str, Any]:
    """Create a remote-signer pairing session and return the pairing URI + QR.

    The desktop client calls this, renders the QR, and connects to the relay as
    ``role=client``. The phone scans the QR (``capauth-bunker://...``), connects
    as ``role=signer``, and both receive a ``paired`` event.

    Guarded by an optional bearer token (``CAPAUTH_BUNKER_AUTH_TOKEN``), a
    per-IP rate limit, and a global session cap.
    """
    if not _bunker_auth_ok(request):
        raise HTTPException(status_code=401, detail="unauthorized")
    client_ip = request.client.host if request.client else "unknown"
    if not _bunker_rate_ok(client_ip):
        raise HTTPException(status_code=429, detail="rate limited; try again shortly")
    try:
        created = _bunker.create_session()
    except BunkerCapacityError:
        raise HTTPException(status_code=503, detail="broker at capacity; retry later")
    host = _broker_host(request)
    relay = _relay_ws_url(host)
    uri = build_pairing_uri(host, created["session_id"], created["pairing_secret"], relay)

    qr_data_url = ""
    try:
        import base64
        import io

        import segno

        qr = segno.make(uri, error="m")
        buf = io.BytesIO()
        qr.save(buf, kind="png", scale=6, dark="#7C3AED", light="#0f0f1a")
        qr_data_url = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
    except ImportError:
        logger.warning("segno not installed — bunker QR data URL unavailable")

    return BunkerSessionResponse(
        session_id=created["session_id"],
        pairing_secret=created["pairing_secret"],
        broker_host=host,
        relay_ws_url=relay,
        pairing_uri=uri,
        qr_data_url=qr_data_url,
    ).model_dump()


@app.websocket("/bunker/ws")
async def bunker_ws(websocket: WebSocket) -> None:
    """WebSocket relay endpoint for the bunker protocol.

    Query params:
        session: the pairing session id.
        role: ``client`` (desktop) or ``signer`` (phone).
        key: the pairing secret.

    The broker validates the session + pairing secret, registers the peer, emits
    ``paired`` when both sides are present, then relays ``sign_request`` /
    ``sign_response`` / ``approve`` / ``reject`` messages between them. The
    relayed payload is opaque to the broker.
    """
    session_id = websocket.query_params.get("session", "")
    role = websocket.query_params.get("role", "")
    pairing_secret = websocket.query_params.get("key", "")

    await websocket.accept()

    err = await _bunker.join(session_id, role, pairing_secret, websocket)
    if err is not None:
        await websocket.send_json({"type": "error", "code": err})
        await websocket.close(code=4400)
        return

    try:
        while True:
            message = await websocket.receive_json()
            relay_err = await _bunker.relay(session_id, role, message)
            if relay_err is not None:
                await websocket.send_json(
                    {"type": "error", "code": relay_err, "ref": message.get("id", "")}
                )
    except WebSocketDisconnect:
        pass
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("bunker ws error (%s/%s): %s", session_id, role, exc)
    finally:
        await _bunker.leave(session_id, role)


# The PWA is iterated on live; an intermediary (Cloudflare) caches .js for hours
# by default, which masks deployed fixes AND poisons an installed service worker.
# Serve every PWA asset no-cache so the edge + browser always revalidate. (The
# correctness-critical files — sw.js, app.js — must never be served stale.)
_PWA_NO_CACHE = {"Cache-Control": "no-cache, no-store, must-revalidate"}


# --- Web Push (background approval prompts) --------------------------------
# Registered BEFORE the /bunker/{asset:path} catch-all so these aren't captured
# as static assets.


class PushSubscribeRequest(BaseModel):
    fingerprint: str
    subscription: dict


class PushNotifyRequest(BaseModel):
    fingerprint: str
    url: str = ""
    title: str = "CapAuth sign-in request"
    body: str = "Tap to review and approve a sign-in on your phone."


@app.get("/bunker/vapid")
async def bunker_vapid() -> dict[str, str]:
    """Return the VAPID application-server key for pushManager.subscribe."""
    return {"publicKey": _push.application_server_key()}


@app.post("/bunker/subscribe")
async def bunker_subscribe(req: PushSubscribeRequest) -> dict[str, Any]:
    """Register a phone's Web Push subscription under its PGP fingerprint."""
    try:
        _push.subscribe(req.fingerprint, req.subscription)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"ok": True, "subscriptions": _push.subscription_count(req.fingerprint)}


@app.post("/bunker/notify")
async def bunker_notify(req: PushNotifyRequest, request: Request) -> dict[str, Any]:
    """Push a sign-in approval prompt to a fingerprint's subscribed phone(s).

    Same auth + rate-limit posture as session creation (push can be abused to
    spam). The desktop pairing flow calls this so a backgrounded phone wakes.
    """
    if not _bunker_auth_ok(request):
        raise HTTPException(status_code=401, detail="unauthorized")
    client_ip = request.client.host if request.client else "unknown"
    if not _bunker_rate_ok(client_ip):
        raise HTTPException(status_code=429, detail="rate limited; try again shortly")
    payload = {"title": req.title, "body": req.body, "url": req.url}
    return _push.notify(req.fingerprint, payload)


@app.get("/bunker/", response_class=HTMLResponse)
@app.get("/bunker/signer", response_class=HTMLResponse)
async def phone_signer_page() -> Any:
    """Serve the phone-signer PWA entry page (mobile-friendly)."""
    index = _PHONE_SIGNER_DIR / "index.html"
    if index.exists():
        return FileResponse(str(index), media_type="text/html", headers=_PWA_NO_CACHE)
    raise HTTPException(status_code=404, detail="phone-signer PWA not bundled")


@app.get("/bunker/{asset:path}")
async def phone_signer_asset(asset: str) -> Any:
    """Serve a phone-signer PWA static asset (manifest, service worker, js, css).

    Path-traversal guarded: the resolved path must stay within its asset root.
    """
    asset_root = _PHONE_SIGNER_DIR.resolve()
    target = (asset_root / asset).resolve()
    if not target.is_file():
        asset_root = (Path(__file__).parent / "oidc" / "static" / "bunker").resolve()
        target = (asset_root / asset).resolve()
    try:
        target.relative_to(asset_root)
    except ValueError:
        raise HTTPException(status_code=403, detail="forbidden")
    if not target.is_file():
        raise HTTPException(status_code=404, detail="not found")
    # Vendored third-party libs (e.g. openpgp.min.js) are content-stable + large
    # — cache them long so the 540KB OpenPGP bundle isn't refetched every load.
    # App code stays no-cache so fixes always propagate.
    headers = (
        {"Cache-Control": "public, max-age=604800, immutable"}
        if asset.startswith("vendor/")
        else _PWA_NO_CACHE
    )
    return FileResponse(str(target), headers=headers)
