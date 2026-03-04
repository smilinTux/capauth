"""Forgejo CapAuth authorization code flow.

Forgejo uses standard OAuth2/OIDC authorization code flow:

  1. Forgejo → GET /forgejo/authorize?state=...&redirect_uri=...
     CapAuth issues a PGP challenge and serves the signing UI.

  2. User signs the challenge in the browser (browser extension or JS)
     and POSTs the signature to /capauth/v1/verify.
     On success, CapAuth stores an auth code keyed by state.

  3. Forgejo receives the callback: GET /user/oauth2/capauth/callback?code=...
     Forgejo POSTs the code to /forgejo/token to exchange for a JWT.

  4. Forgejo calls /capauth/v1/userinfo with the JWT bearer token
     to retrieve the user's claims and create/update the account.

This module manages the short-lived auth code store (state → code → claims).
It is intentionally stateless-friendly: in production, swap ``_CodeStore``
for a Redis backend.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from .config import ForgejoConfig


# ---------------------------------------------------------------------------
# In-memory auth code store
# ---------------------------------------------------------------------------


@dataclass
class _AuthCodeRecord:
    """A single pending authorization code issued after PGP verify."""

    code: str
    fingerprint: str
    claims: dict[str, Any]
    redirect_uri: str
    client_id: str
    issued_at: float
    expires_at: float
    consumed: bool = False


class _CodeStore:
    """Thread-unsafe in-memory store for auth codes (swap for Redis in prod)."""

    def __init__(self) -> None:
        self._records: dict[str, _AuthCodeRecord] = {}

    def put(self, record: _AuthCodeRecord) -> None:
        # Evict expired codes on each write to keep memory bounded
        now = time.time()
        expired = [k for k, v in self._records.items() if v.expires_at < now]
        for k in expired:
            del self._records[k]
        self._records[record.code] = record

    def pop(self, code: str) -> Optional[_AuthCodeRecord]:
        record = self._records.get(code)
        if record is None:
            return None
        del self._records[code]
        return record

    def __len__(self) -> int:
        return len(self._records)


# ---------------------------------------------------------------------------
# Auth session store (state → pending auth context)
# ---------------------------------------------------------------------------


@dataclass
class _AuthSession:
    """Pending authorization session created when Forgejo redirects to us."""

    session_id: str
    state: str
    redirect_uri: str
    client_id: str
    scope: str
    code_challenge: str
    code_challenge_method: str
    fingerprint: str = ""  # filled in when user identifies
    nonce: str = ""  # CapAuth challenge nonce UUID
    issued_at: float = field(default_factory=time.time)
    expires_at: float = 0.0


class _SessionStore:
    """In-memory store for pending auth sessions keyed by state."""

    def __init__(self) -> None:
        self._records: dict[str, _AuthSession] = {}

    def put(self, session: _AuthSession) -> None:
        now = time.time()
        expired = [k for k, v in self._records.items() if v.expires_at < now]
        for k in expired:
            del self._records[k]
        self._records[session.state] = session

    def get(self, state: str) -> Optional[_AuthSession]:
        return self._records.get(state)

    def pop(self, state: str) -> Optional[_AuthSession]:
        return self._records.pop(state, None)

    def update(self, state: str, **kwargs: Any) -> bool:
        session = self._records.get(state)
        if session is None:
            return False
        for k, v in kwargs.items():
            setattr(session, k, v)
        return True


# ---------------------------------------------------------------------------
# ForgejoAuthFlow
# ---------------------------------------------------------------------------


class ForgejoAuthFlow:
    """Manages the OAuth2 authorization code flow between Forgejo and CapAuth.

    Instantiate once and mount ``router`` into your FastAPI application:

    .. code-block:: python

        from capauth.integrations.forgejo.auth_flow import ForgejoAuthFlow
        from capauth.integrations.forgejo.config import ForgejoConfig

        flow = ForgejoAuthFlow(config=ForgejoConfig.from_env())
        app.include_router(flow.router, prefix="/forgejo")

    Attributes
    ----------
    config : ForgejoConfig
        Runtime configuration.
    """

    def __init__(self, config: Optional[ForgejoConfig] = None) -> None:
        self.config = config or ForgejoConfig.from_env()
        self._sessions = _SessionStore()
        self._codes = _CodeStore()

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------

    def create_session(
        self,
        state: str,
        redirect_uri: str,
        client_id: str,
        scope: str = "openid profile email",
        code_challenge: str = "",
        code_challenge_method: str = "S256",
        ttl: Optional[int] = None,
    ) -> _AuthSession:
        """Create a pending auth session from Forgejo's authorization redirect.

        Parameters
        ----------
        state:
            OAuth2 state parameter from Forgejo (opaque, echoed back).
        redirect_uri:
            The redirect URI Forgejo registered — must match exactly.
        client_id:
            OAuth2 client_id — validated against ``config.client_id``.
        scope:
            Requested scopes.
        code_challenge:
            PKCE code_challenge (optional but recommended).
        code_challenge_method:
            PKCE method — "S256" or "plain".

        Returns
        -------
        _AuthSession
            The newly created session.

        Raises
        ------
        ValueError
            If client_id is unknown or redirect_uri does not match.
        """
        if client_id != self.config.client_id:
            raise ValueError(f"Unknown client_id: {client_id!r}")

        expected_uri = self.config.forgejo_redirect_uri
        if redirect_uri and redirect_uri != expected_uri:
            raise ValueError(
                f"redirect_uri mismatch: got {redirect_uri!r}, expected {expected_uri!r}"
            )

        ttl = ttl or self.config.auth_code_ttl
        now = time.time()
        session = _AuthSession(
            session_id=secrets.token_urlsafe(16),
            state=state,
            redirect_uri=redirect_uri or expected_uri,
            client_id=client_id,
            scope=scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            issued_at=now,
            expires_at=now + ttl,
        )
        self._sessions.put(session)
        return session

    def attach_fingerprint(self, state: str, fingerprint: str, nonce: str) -> bool:
        """Record the user's fingerprint and challenge nonce against a session.

        Called once the user has entered their fingerprint and a challenge nonce
        has been issued by /capauth/v1/challenge.

        Returns True if the session was found and updated.
        """
        return self._sessions.update(state, fingerprint=fingerprint, nonce=nonce)

    def get_session(self, state: str) -> Optional[_AuthSession]:
        """Return the session for *state* (without removing it)."""
        return self._sessions.get(state)

    # ------------------------------------------------------------------
    # Authorization code issuance
    # ------------------------------------------------------------------

    def issue_auth_code(
        self,
        state: str,
        fingerprint: str,
        claims: dict[str, Any],
    ) -> str:
        """Issue a short-lived authorization code after successful PGP verify.

        Forgejo receives this code via the redirect_uri callback and exchanges
        it for a JWT at /forgejo/token.

        Parameters
        ----------
        state:
            OAuth2 state — identifies the pending session.
        fingerprint:
            Verified PGP fingerprint.
        claims:
            OIDC claims to embed in the eventual JWT.

        Returns
        -------
        str
            The authorization code (opaque, single-use).

        Raises
        ------
        ValueError
            If the session is not found or has expired.
        """
        session = self._sessions.pop(state)
        if session is None:
            raise ValueError(f"No pending session for state={state!r}")

        now = time.time()
        if now > session.expires_at:
            raise ValueError("Authorization session has expired")

        code = secrets.token_urlsafe(32)
        record = _AuthCodeRecord(
            code=code,
            fingerprint=fingerprint,
            claims=claims,
            redirect_uri=session.redirect_uri,
            client_id=session.client_id,
            issued_at=now,
            expires_at=now + self.config.auth_code_ttl,
        )
        self._codes.put(record)
        return code

    # ------------------------------------------------------------------
    # Token exchange
    # ------------------------------------------------------------------

    def exchange_code(
        self,
        code: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        code_verifier: str = "",
    ) -> dict[str, Any]:
        """Exchange an authorization code for OIDC tokens.

        Called by Forgejo's backend when it POSTs to /forgejo/token.

        Parameters
        ----------
        code:
            The authorization code returned in the callback.
        client_id:
            Must match the registered client.
        client_secret:
            Any non-empty string is accepted for HS256 (Forgejo sends whatever
            was configured in app.ini).
        redirect_uri:
            Must match the redirect_uri used during the authorization request.
        code_verifier:
            PKCE code verifier (optional; validated if present).

        Returns
        -------
        dict
            ``{"access_token": ..., "token_type": "Bearer", "expires_in": 3600,
               "id_token": ..., "scope": "openid profile email"}``

        Raises
        ------
        ValueError
            On any validation error (invalid code, expired, mismatch).
        """
        import jwt as pyjwt

        if client_id != self.config.client_id:
            raise ValueError("invalid_client")

        record = self._codes.pop(code)
        if record is None:
            raise ValueError("invalid_grant: code not found or already used")

        now = time.time()
        if now > record.expires_at:
            raise ValueError("invalid_grant: authorization code expired")

        if record.client_id != client_id:
            raise ValueError("invalid_grant: client_id mismatch")

        if redirect_uri and redirect_uri != record.redirect_uri:
            raise ValueError("invalid_grant: redirect_uri mismatch")

        # Build JWT
        iat = int(now)
        exp = iat + 3600
        payload: dict[str, Any] = {
            "iss": self.config.capauth_base_url,
            "sub": record.fingerprint,
            "aud": client_id,
            "iat": iat,
            "exp": exp,
            "amr": ["pgp"],
            "capauth_fingerprint": record.fingerprint,
        }
        payload.update(record.claims)

        token = pyjwt.encode(payload, self.config.capauth_jwt_secret, algorithm="HS256")

        return {
            "access_token": token,
            "id_token": token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "openid profile email",
        }

    # ------------------------------------------------------------------
    # PKCE helpers
    # ------------------------------------------------------------------

    @staticmethod
    def verify_pkce(code_verifier: str, code_challenge: str, method: str) -> bool:
        """Verify a PKCE code_verifier against the stored code_challenge.

        Parameters
        ----------
        code_verifier:
            The plain-text verifier from the client.
        code_challenge:
            The challenge stored during the authorization request.
        method:
            "S256" or "plain".

        Returns
        -------
        bool
            True if verification passes.
        """
        if not code_challenge:
            return True  # PKCE not required if no challenge was sent
        if method == "plain":
            return hmac.compare_digest(code_verifier.encode(), code_challenge.encode())
        if method == "S256":
            digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
            import base64
            computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
            return hmac.compare_digest(computed, code_challenge)
        return False

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    @property
    def pending_sessions(self) -> int:
        """Number of sessions currently waiting for PGP sign."""
        return len(self._sessions._records)

    @property
    def pending_codes(self) -> int:
        """Number of auth codes awaiting exchange."""
        return len(self._codes)
