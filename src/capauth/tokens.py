"""
Capability token issuance and verification.

CapAuth tokens are PGP-signed JSON payloads that grant specific
permissions to agents or services. They are self-contained,
cryptographically verifiable, and don't require a central authority.

Token types:
    - AgentToken: proves identity, grants access to agent runtime
    - CapabilityToken: grants specific permissions (read memory, push sync, etc.)
    - DelegationToken: allows one agent to act on behalf of another

The issuer signs with their CapAuth PGP key. Any holder can verify
with the issuer's public key. No server required.

This module was moved verbatim from skcapstone into capauth (kernel track M1):
capauth is the L0 identity/authz core, and tokens belong with it. The old
skcapstone.tokens re-export shim was retired (CR-3.6); callers import from
capauth.tokens directly. The portable-export envelope key stays "skcapstone_token"
so tokens already issued in the wild still import.
"""

from __future__ import annotations

import hashlib
import json
import logging
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from .agent_identity import resolve_agent_identity

logger = logging.getLogger("capauth.tokens")

#: Standard default scopes per audience for the ergonomic mint wrapper.
#:
#: These are the audience-scoped grants a subapp's dataplane accepts (distinct
#: from the PDP capabilities in :data:`capauth.provisioning.SKCHAT_SCOPES`). The
#: ``skchat`` entry mirrors what skchat's dataplane honours: read + send chat,
#: join calls, join spaces. Callers may always override with an explicit
#: ``scopes`` list.
#:
#: Grounding for each entry (source of truth is the subapp's manifest / adapter):
#:
#: * ``skchat`` - what skchat's dataplane honours (read + send chat, join calls,
#:   join spaces). Left exactly as originally defined.
#: * ``skcode`` - the ``auth.scopes`` block of skcode's SKWorld module manifest
#:   (``skharness.manifest.skcode_module_manifest`` -> ``["skcode.stream",
#:   "skcode.inject", "skcode.dispatch"]``). This is the grounded source of truth.
#: * ``skcomms`` / ``skos`` / ``skmemory`` - PROVISIONAL. These subapps do not yet
#:   publish an SKWorld module manifest with an ``auth.scopes`` block, and their
#:   operator adapters expose only the control-plane facet (conditions + actions),
#:   not dataplane audience scopes. Each gets a minimal read-only default
#:   (``<app>.read``) so the ergonomic mint helper succeeds for their audiences
#:   without an explicit scopes arg. Tighten/expand these to a real
#:   ``<app>.<verb>`` set once each subapp declares its manifest auth block;
#:   callers needing more can always pass an explicit ``scopes`` list.
AUDIENCE_SCOPES: dict[str, list[str]] = {
    "skchat": ["chat.read", "chat.send", "calls.join", "spaces.join"],
    # Grounded: skcode manifest auth.scopes (skharness.manifest).
    "skcode": ["skcode.stream", "skcode.inject", "skcode.dispatch"],
    # Provisional: minimal read scope until a manifest auth block exists.
    "skcomms": ["skcomms.read"],
    "skos": ["skos.read"],
    "skmemory": ["skmemory.read"],
}


class TokenType(str, Enum):
    """Types of capability tokens."""

    AGENT = "agent"
    CAPABILITY = "capability"
    DELEGATION = "delegation"


class Capability(str, Enum):
    """Granular permissions that can be granted via token."""

    MEMORY_READ = "memory:read"
    MEMORY_WRITE = "memory:write"
    SYNC_PUSH = "sync:push"
    SYNC_PULL = "sync:pull"
    IDENTITY_VERIFY = "identity:verify"
    IDENTITY_SIGN = "identity:sign"
    TRUST_READ = "trust:read"
    TRUST_WRITE = "trust:write"
    AUDIT_READ = "audit:read"
    AGENT_STATUS = "agent:status"
    AGENT_CONNECT = "agent:connect"
    TOKEN_ISSUE = "token:issue"
    ALL = "*"


class TokenPayload(BaseModel):
    """The signed content of a capability token.

    This is the JSON structure that gets PGP-signed.
    It's self-describing and independently verifiable.
    """

    token_id: str = Field(description="Unique token identifier (SHA-256 hash)")
    token_type: TokenType = Field(description="What kind of token this is")
    issuer: str = Field(description="PGP fingerprint of the issuer")
    subject: str = Field(description="Who/what this token is for (fingerprint or name)")
    capabilities: list[str] = Field(
        default_factory=list, description="List of granted capabilities"
    )
    issued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = Field(
        default=None, description="When the token expires (None = no expiry)"
    )
    not_before: Optional[datetime] = Field(
        default=None, description="Token not valid before this time"
    )
    metadata: dict = Field(
        default_factory=dict, description="Additional claims (agent name, platform, etc.)"
    )
    audience: Optional[str] = Field(
        default=None,
        description=(
            "The audience (subapp id) this token is scoped to. None means an "
            "unscoped legacy token. Additive and backward-compatible: tokens "
            "issued before this field existed load with audience=None."
        ),
    )

    @property
    def is_expired(self) -> bool:
        """Check if the token has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    @property
    def is_active(self) -> bool:
        """Check if the token is currently valid (time-wise)."""
        now = datetime.now(timezone.utc)
        if self.expires_at and now > self.expires_at:
            return False
        if self.not_before and now < self.not_before:
            return False
        return True

    def has_capability(self, cap: str) -> bool:
        """Check if this token grants a specific capability.

        Args:
            cap: The capability string to check (e.g., 'memory:read').

        Returns:
            True if the capability is granted (or ALL is granted).
        """
        return Capability.ALL.value in self.capabilities or cap in self.capabilities

    def has_scope(self, scope: str) -> bool:
        """Check if this token grants a specific scope.

        Audience-scoped tokens carry their granted scopes in ``capabilities``
        (e.g. ``chat.read``, ``skcode.stream``). This mirrors
        :meth:`has_capability` and honours the ``*`` wildcard.

        Args:
            scope: The scope string to check (e.g. 'chat.send').

        Returns:
            True if the scope is granted (or ALL is granted).
        """
        return self.has_capability(scope)


class SignedToken(BaseModel):
    """A complete token with its PGP signature."""

    payload: TokenPayload
    signature: Optional[str] = Field(
        default=None, description="PGP detached signature (ASCII-armored)"
    )
    verified: bool = Field(default=False, description="Whether signature has been verified")


def issue_token(
    home: Path,
    subject: str,
    capabilities: list[str],
    token_type: TokenType = TokenType.CAPABILITY,
    ttl_hours: Optional[int] = 24,
    metadata: Optional[dict] = None,
    sign: bool = True,
) -> SignedToken:
    """Issue a new capability token signed by the agent's CapAuth key.

    Args:
        home: Agent home directory (~/.skcapstone).
        subject: Who the token is for (fingerprint, name, or email).
        capabilities: List of capability strings to grant.
        token_type: Type of token to issue.
        ttl_hours: Hours until expiry (None = no expiry).
        metadata: Additional claims to embed.
        sign: Whether to PGP-sign the token.

    Returns:
        SignedToken with the payload and optional signature.
    """
    issuer_fp = _get_issuer_fingerprint(home)
    now = datetime.now(timezone.utc)

    payload = TokenPayload(
        token_id="",
        token_type=token_type,
        issuer=issuer_fp,
        subject=subject,
        capabilities=capabilities,
        issued_at=now,
        expires_at=now + timedelta(hours=ttl_hours) if ttl_hours else None,
        metadata=metadata or {},
    )

    payload.token_id = _compute_token_id(payload)

    token = SignedToken(payload=payload)

    if sign:
        signature = _pgp_sign_payload(payload, home)
        if signature:
            token.signature = signature
            token.verified = True

    _store_token(home, token)
    logger.info("Issued token %s for %s (%s)", payload.token_id[:12], subject, token_type.value)
    return token


def verify_token(token: SignedToken, home: Optional[Path] = None) -> bool:
    """Verify a token's signature and validity.

    Args:
        token: The signed token to verify.
        home: Agent home for accessing the keyring.

    Returns:
        True if the token is valid and signature checks out.
    """
    if not token.payload.is_active:
        logger.warning(
            "Token %s is not active (expired or not yet valid)", token.payload.token_id[:12]
        )
        return False

    # Revocation gate (CR-3.4 P2): a revoked token must fail verification even
    # with a valid, in-window signature. Historically only the PDP consulted the
    # revocation list; a bare verify_token / verify_audience_token (the skchat
    # accept path) affirmed a revoked token. This closes that asymmetry: a
    # revoked token is now rejected everywhere verify_token affirms.
    #
    # ``is_revoked`` needs a home to locate the revocation file, so resolve the
    # default home when the caller did not pass one (the audience accept path
    # calls with ``home=None``). Guarded so a revocation-list read error never
    # crashes verification; a non-revoked token is unaffected.
    try:
        revocation_home = home
        if revocation_home is None:
            from . import resolve_capauth_home

            revocation_home = resolve_capauth_home()
        if is_revoked(revocation_home, token.payload.token_id):
            logger.warning("Token %s is revoked", token.payload.token_id[:12])
            return False
    except Exception:  # noqa: BLE001 - never let a revocation read crash verify
        logger.debug("revocation check errored for %s", token.payload.token_id[:12])

    if token.signature:
        verified = _pgp_verify_signature(token.payload, token.signature, home)
        token.verified = verified
        return verified

    logger.warning("Token %s has no signature", token.payload.token_id[:12])
    return False


def mint_audience_token(
    home: Path,
    subject: str,
    audience: str,
    scopes: list[str],
    *,
    ttl_hours: int = 1,
    metadata: Optional[dict] = None,
    sign: bool = True,
) -> SignedToken:
    """Mint a short-lived, audience-scoped capability token.

    This is the M1+ / R4.2 audience-mint surface. The SKWorld shell mints one
    of these per mounted subapp so a pane only ever holds a token for its own
    audience and scopes (containment). The token's ``audience`` is set to the
    subapp id from the manifest (``auth.audience``, e.g. ``"skchat"``) and its
    ``capabilities`` are the granted ``scopes`` (a subset of the manifest's
    declared ``auth.scopes``). Tokens are short-lived by default (1 hour) since
    the shell re-mints; a compromised pane is contained.

    The signing and storage path is delegated to :func:`issue_token`, so there
    is a single crypto path (no duplicated signing logic).

    Args:
        home: Agent home directory (~/.skcapstone).
        subject: The human/session identity the token is minted for.
        audience: The subapp id the token is scoped to (e.g. "skchat").
        scopes: The granted scope strings (become ``capabilities``).
        ttl_hours: Hours until expiry (default 1; the shell re-mints).
        metadata: Additional claims to embed.
        sign: Whether to PGP-sign the token.

    Returns:
        A :class:`SignedToken` whose payload has ``audience`` set and
        ``token_type`` = CAPABILITY.
    """
    issuer_fp = _get_issuer_fingerprint(home)
    now = datetime.now(timezone.utc)

    payload = TokenPayload(
        token_id="",
        token_type=TokenType.CAPABILITY,
        issuer=issuer_fp,
        subject=subject,
        capabilities=list(scopes),
        issued_at=now,
        expires_at=now + timedelta(hours=ttl_hours) if ttl_hours else None,
        metadata=metadata or {},
        audience=audience,
    )

    payload.token_id = _compute_token_id(payload)

    token = SignedToken(payload=payload)

    if sign:
        signature = _pgp_sign_payload(payload, home)
        if signature:
            token.signature = signature
            token.verified = True

    _store_token(home, token)
    logger.info(
        "Minted audience token %s for %s (audience=%s, scopes=%s)",
        payload.token_id[:12],
        subject,
        audience,
        ",".join(scopes),
    )
    return token


def mint_agent_audience_token(
    agent: Optional[str] = None,
    audience: str = "skchat",
    scopes: Optional[list[str]] = None,
    *,
    ttl_hours: int = 1,
    home: Optional[Path] = None,
    sign: bool = True,
    metadata: Optional[dict] = None,
) -> SignedToken:
    """Mint an audience-scoped token for an agent using its resolved identity.

    Operator-ergonomic wrapper over :func:`mint_audience_token`. Instead of
    hand-supplying a subject, a signing home, and the audience's standard scopes,
    this resolves them for you:

    * **subject** comes from :func:`capauth.resolve_agent_identity`. The
      resolved ``fqid`` (``<agent>@<operator>.<realm>``) is used because that is
      the subject the PDP / skchat dataplane sees; it falls back to the
      ``capauth_uri`` wire identity when no ``cluster.json`` yields an fqid.
    * **home** defaults to :func:`capauth.resolve_capauth_home` when not given.
    * **scopes** default to :data:`AUDIENCE_SCOPES` for the audience (for
      ``skchat``: ``chat.read``/``chat.send``/``calls.join``/``spaces.join``).
      An explicit ``scopes`` list always overrides the default.

    Args:
        agent: Short agent name; ``None`` resolves the active agent (SKAGENT).
        audience: The subapp id the token is scoped to (default ``"skchat"``).
        scopes: Explicit granted scopes; ``None`` uses the audience default.
        ttl_hours: Hours until expiry (default 1; the shell re-mints).
        home: CapAuth home; ``None`` resolves via ``resolve_capauth_home()``.
        sign: Whether to PGP-sign the token.
        metadata: Additional claims to embed.

    Returns:
        A :class:`SignedToken` scoped to ``audience`` with the resolved subject.

    Raises:
        ValueError: If ``scopes`` is None and ``audience`` has no default entry.
    """
    if scopes is not None:
        granted = list(scopes)
    else:
        default = AUDIENCE_SCOPES.get(audience)
        if default is None:
            raise ValueError(
                f"no default scopes for audience {audience!r}; pass an explicit scopes list"
            )
        granted = list(default)

    ident = resolve_agent_identity(agent)
    subject = ident.fqid or ident.capauth_uri

    if home is not None:
        resolved_home = Path(home).expanduser()
    else:
        from . import resolve_capauth_home

        resolved_home = resolve_capauth_home()

    return mint_audience_token(
        resolved_home,
        subject,
        audience,
        granted,
        ttl_hours=ttl_hours,
        metadata=metadata,
        sign=sign,
    )


def verify_audience_token(
    token: SignedToken,
    audience: str,
    *,
    home: Optional[Path] = None,
) -> bool:
    """Verify a token AND that it is scoped to the expected audience.

    This is :func:`verify_token` (signature + time validity) plus an audience
    match. It fails closed: a signature/validity failure, an audience mismatch,
    or an unscoped token (``audience is None``) when an audience is required all
    return False.

    Args:
        token: The signed token to verify.
        audience: The audience the token must be scoped to.
        home: Agent home for accessing the keyring.

    Returns:
        True only if the signature/validity checks pass AND the token's
        ``audience`` equals ``audience``.
    """
    if token.payload.audience != audience:
        logger.warning(
            "Token %s audience mismatch (have=%r, want=%r)",
            token.payload.token_id[:12],
            token.payload.audience,
            audience,
        )
        return False

    return verify_token(token, home)


def has_scope(token: SignedToken, scope: str) -> bool:
    """Check whether a signed token grants a given scope.

    Convenience wrapper over :meth:`TokenPayload.has_scope` (honours the ``*``
    wildcard). Does NOT verify the signature; callers that need trust should
    pair this with :func:`verify_audience_token`.

    Args:
        token: The signed token to inspect.
        scope: The scope string to check (e.g. 'chat.send').

    Returns:
        True if the token's scopes include ``scope`` (or ALL).
    """
    return token.payload.has_scope(scope)


def revoke_token(home: Path, token_id: str) -> bool:
    """Revoke a previously issued token.

    Adds the token ID to the revocation list. Revoked tokens
    fail verification even if their signature is valid.

    Args:
        home: Agent home directory.
        token_id: The token ID to revoke.

    Returns:
        True if the token was found and revoked.
    """
    revocation_file = home / "security" / "revoked-tokens.json"
    revoked = _load_revocation_list(revocation_file)

    if token_id in revoked:
        return True

    revoked[token_id] = {
        "revoked_at": datetime.now(timezone.utc).isoformat(),
        "reason": "manual_revocation",
    }

    revocation_file.parent.mkdir(parents=True, exist_ok=True)
    revocation_file.write_text(json.dumps(revoked, indent=2), encoding="utf-8")
    logger.info("Revoked token %s", token_id[:12])
    return True


def is_revoked(home: Path, token_id: str) -> bool:
    """Check if a token has been revoked.

    Args:
        home: Agent home directory.
        token_id: The token ID to check.

    Returns:
        True if the token is on the revocation list.
    """
    revocation_file = home / "security" / "revoked-tokens.json"
    revoked = _load_revocation_list(revocation_file)
    return token_id in revoked


def list_tokens(home: Path) -> list[SignedToken]:
    """List all issued tokens.

    Args:
        home: Agent home directory.

    Returns:
        List of all stored tokens.
    """
    token_dir = home / "security" / "tokens"
    if not token_dir.exists():
        return []

    tokens = []
    for f in sorted(token_dir.iterdir()):
        if f.suffix == ".json":
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                token = SignedToken(
                    payload=TokenPayload(**data["payload"]),
                    signature=data.get("signature"),
                    verified=data.get("verified", False),
                )
                tokens.append(token)
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                logger.warning("Failed to load token %s: %s", f.name, exc)
    return tokens


def export_token(token: SignedToken) -> str:
    """Export a token as a portable JSON string.

    Args:
        token: The token to export.

    Returns:
        JSON string suitable for sharing.
    """
    return json.dumps(
        {
            "skcapstone_token": "1.0",
            "payload": token.payload.model_dump(mode="json"),
            "signature": token.signature,
        },
        indent=2,
        default=str,
    )


def import_token(token_json: str) -> SignedToken:
    """Import a token from a JSON string.

    Args:
        token_json: JSON string from export_token().

    Returns:
        The reconstructed SignedToken.

    Raises:
        ValueError: If the JSON is not a valid token.
    """
    try:
        data = json.loads(token_json)
        if "skcapstone_token" not in data:
            raise ValueError("Not an SKCapstone token")
        return SignedToken(
            payload=TokenPayload(**data["payload"]),
            signature=data.get("signature"),
            verified=False,
        )
    except (json.JSONDecodeError, KeyError) as exc:
        raise ValueError(f"Invalid token format: {exc}") from exc


# --- Private helpers ---


def _get_issuer_fingerprint(home: Path) -> str:
    """Get the agent's PGP fingerprint for signing tokens."""
    identity_file = home / "identity" / "identity.json"
    if identity_file.exists():
        try:
            data = json.loads(identity_file.read_text(encoding="utf-8"))
            fp = data.get("fingerprint")
            if fp:
                return fp
        except (json.JSONDecodeError, OSError):
            pass
    return "unknown"


def _compute_token_id(payload: TokenPayload) -> str:
    """Compute a deterministic token ID from the payload content.

    The ``audience`` field is folded into the hash ONLY when it is set. Legacy
    tokens (``audience=None``) therefore hash to exactly the same id they did
    before the field existed, keeping the change fully backward-compatible.
    """
    content_fields = {
        "issuer": payload.issuer,
        "subject": payload.subject,
        "capabilities": sorted(payload.capabilities),
        "issued_at": payload.issued_at.isoformat(),
        "type": payload.token_type.value,
    }
    if payload.audience is not None:
        content_fields["audience"] = payload.audience
    content = json.dumps(content_fields, sort_keys=True)
    return hashlib.sha256(content.encode()).hexdigest()


def _pgp_sign_payload(payload: TokenPayload, home: Path) -> Optional[str]:
    """PGP-sign a token payload using the agent's CapAuth key."""
    if not shutil.which("gpg"):
        logger.warning("gpg not found - token will be unsigned")
        return None

    issuer_fp = _get_issuer_fingerprint(home)
    payload_json = payload.model_dump_json()

    # Attempt order matters. The plain invocation lets gpg-agent mediate, which
    # is what actually works for a normal key. The loopback+empty-passphrase
    # form is kept ONLY as a fallback for a genuinely passphrase-less key in an
    # environment with no usable agent (CI containers, cold bootstrap).
    #
    # It used to be the ONLY form, and that silently broke signing everywhere:
    # forcing `--passphrase "" --pinentry-mode loopback` makes gpg refuse an
    # agent-managed key with "No passphrase given" instead of consulting the
    # agent. Every token this fleet ever issued came out unsigned as a result,
    # regardless of which key was configured, and nothing noticed because
    # issue_token treats a signing failure as a warning and stores the token
    # anyway. Verified 2026-08-14: same key, same payload, plain form rc=0,
    # loopback form rc=2.
    base = [
        "gpg",
        "--batch",
        "--yes",
        "--armor",
        "--detach-sign",
        "--local-user",
        issuer_fp,
    ]
    attempts = [base, base + ["--passphrase", "", "--pinentry-mode", "loopback"]]

    last_err = ""
    for cmd in attempts:
        try:
            result = subprocess.run(
                cmd,
                input=payload_json,
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout
            last_err = result.stderr.strip()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            last_err = str(exc)

    logger.warning("GPG signing failed for %s: %s", issuer_fp, last_err)
    return None


def _pgp_verify_signature(
    payload: TokenPayload,
    signature: str,
    home: Optional[Path] = None,
) -> bool:
    """Verify a PGP detached signature against a token payload."""
    if not shutil.which("gpg"):
        return False

    import tempfile

    payload_json = payload.model_dump_json()

    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sig", delete=False) as sig_file:
            sig_file.write(signature)
            sig_path = sig_file.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as data_file:
            data_file.write(payload_json)
            data_path = data_file.name

        result = subprocess.run(
            ["gpg", "--batch", "--verify", sig_path, data_path],
            capture_output=True,
            text=True,
            timeout=15,
        )

        Path(sig_path).unlink(missing_ok=True)
        Path(data_path).unlink(missing_ok=True)

        return result.returncode == 0
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        logger.warning("GPG verify error: %s", exc)
    return False


def _store_token(home: Path, token: SignedToken) -> None:
    """Persist a token to disk."""
    token_dir = home / "security" / "tokens"
    token_dir.mkdir(parents=True, exist_ok=True)

    token_file = token_dir / f"{token.payload.token_id[:16]}.json"
    data = {
        "payload": token.payload.model_dump(mode="json"),
        "signature": token.signature,
        "verified": token.verified,
    }
    token_file.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def _load_revocation_list(revocation_file: Path) -> dict:
    """Load the token revocation list."""
    if not revocation_file.exists():
        return {}
    try:
        return json.loads(revocation_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


__all__ = [
    "TokenType",
    "Capability",
    "TokenPayload",
    "SignedToken",
    "issue_token",
    "verify_token",
    "AUDIENCE_SCOPES",
    "mint_audience_token",
    "mint_agent_audience_token",
    "verify_audience_token",
    "has_scope",
    "revoke_token",
    "is_revoked",
    "list_tokens",
    "export_token",
    "import_token",
]
