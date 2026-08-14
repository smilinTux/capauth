"""Hybrid post-quantum signatures for capauth CAPABILITY TOKENS (CR-3.7 token leg).

Additive and opt-in, mirroring :mod:`capauth.pqc_identity` (the challenge/DID
surface). It lets an issuer attach a hybrid Ed25519 + ML-DSA-65 signature
(FIPS 204) ALONGSIDE the existing classical PGP token signature, so a verifier
can require both legs (quantum-resistant capability tokens) while classical-only
verifiers keep working unchanged.

What this does NOT touch (read this)
------------------------------------
* It does NOT migrate the ROOT PGP identity key, and it does NOT open the gated
  Sequoia root ceremony (that is the separate CR-3.7 / T3 decision, human-gated
  behind ``CAPAUTH_ALLOW_T3_COMPOSITE_ROOT``). The hybrid leg uses a per-agent
  ML-DSA-65 + Ed25519 key that is SEPARATE from, and never derived from, the PGP
  key.
* It does NOT change :func:`capauth.tokens.issue_token` /
  :func:`capauth.tokens.verify_token`. Their behavior and a classical token's
  exported bytes are byte-identical to before this module existed. The hybrid
  path is entered ONLY by calling :func:`issue_token_hybrid` /
  :func:`verify_token_hybrid`.

Construction
------------
The hybrid leg reuses the vetted ``skcomms.pqsig`` composite primitive (the
single source of the wire format and the "both legs required" AND gate); capauth
composes it rather than re-implementing the lattice math. The hybrid signature
covers ``payload.model_dump_json().encode("utf-8")`` -- the EXACT bytes the
classical PGP leg signs (:func:`capauth.tokens._pgp_sign_payload`), so both legs
bind an identical token payload.
"""

from __future__ import annotations

import base64
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from .tokens import (
    SignedToken,
    TokenPayload,
    TokenType,
    _compute_token_id,
    _get_issuer_fingerprint,
    _pgp_sign_payload,
    _pgp_verify_signature,
    _store_token,
    is_revoked,
    verify_token,
)

logger = logging.getLogger("capauth.pqc_tokens")

HYBRID_SIG_SUITE = "mldsa65-ed25519-v2"


class HybridSigUnavailable(RuntimeError):  # noqa: N818 - public name, keep stable
    """Raised when the hybrid-signature primitive (skcomms.pqsig) is missing."""


def _pqsig():
    """Import ``skcomms.pqsig`` lazily; raise loudly if unavailable.

    capauth composes skcomms' vetted primitive rather than re-implementing it. A
    missing backend is a hard error, never a silent downgrade to classical (the
    caller chooses the classical path by using :func:`capauth.tokens.issue_token`).
    """
    try:
        from skcomms import pqsig  # type: ignore
    except Exception as exc:  # noqa: BLE001 - re-raise as the public error
        raise HybridSigUnavailable(
            "hybrid token signing needs skcomms.pqsig (Ed25519 + ML-DSA-65). "
            "Install skcomms + liboqs-python. capauth composes this primitive; it "
            "never re-implements the lattice math. The classical PGP token path is "
            f"unaffected. ({exc})"
        ) from exc
    return pqsig


def issue_token_hybrid(
    home: Path,
    subject: str,
    capabilities: list[str],
    *,
    token_type: TokenType = TokenType.CAPABILITY,
    ttl_hours: Optional[int] = 24,
    metadata: Optional[dict] = None,
    audience: Optional[str] = None,
    hybrid_keypair=None,
    agent: str = "",
) -> SignedToken:
    """Issue a capability token carrying BOTH a classical PGP leg and a hybrid leg.

    The classical PGP ``signature`` is produced exactly as
    :func:`capauth.tokens.issue_token` does (so a classical verifier is satisfied;
    a missing/unusable signing key leaves it unsigned, same as ``issue_token``),
    and an Ed25519 + ML-DSA-65 composite is ALSO attached over the SAME payload
    bytes. The PGP root key is untouched, and the T3 root gate is never opened.

    Args:
        home: Agent home directory (~/.skcapstone).
        subject: Who the token is for.
        capabilities: Capability/scope strings to grant.
        token_type: Token type (default CAPABILITY).
        ttl_hours: Hours until expiry (None = no expiry).
        metadata: Additional claims to embed.
        audience: Optional audience (subapp id) to scope the token to.
        hybrid_keypair: A ``skcomms.pqsig`` keypair. If None, one is loaded/created
            for ``agent``.
        agent: Agent id for hybrid key persistence (required if no keypair).

    Returns:
        A :class:`SignedToken` with ``sig_suite`` and the hybrid fields populated.

    Raises:
        HybridSigUnavailable: if the hybrid primitive is missing.
        ValueError: if neither ``hybrid_keypair`` nor ``agent`` is given.
    """
    pqsig = _pqsig()
    if hybrid_keypair is None:
        if not agent:
            raise ValueError("issue_token_hybrid needs a hybrid_keypair or an agent id")
        hybrid_keypair = pqsig.load_or_create_signer_keypair(agent)

    now = datetime.now(timezone.utc)
    payload = TokenPayload(
        token_id="",
        token_type=token_type,
        issuer=_get_issuer_fingerprint(home),
        subject=subject,
        capabilities=list(capabilities),
        issued_at=now,
        expires_at=now + timedelta(hours=ttl_hours) if ttl_hours else None,
        metadata=metadata or {},
        audience=audience,
    )
    payload.token_id = _compute_token_id(payload)

    token = SignedToken(payload=payload)

    # Classical PGP leg -- unchanged path (may be None if no usable key, exactly
    # as issue_token treats a signing failure).
    signature = _pgp_sign_payload(payload, home)
    if signature:
        token.signature = signature
        token.verified = True

    # Hybrid leg over the SAME bytes the classical leg signs.
    data = payload.model_dump_json().encode("utf-8")
    composite = pqsig.hybrid_sign(data, hybrid_keypair.ed25519_priv, hybrid_keypair.mldsa_priv)
    token.sig_suite = HYBRID_SIG_SUITE
    token.hybrid_signature = base64.b64encode(composite).decode("ascii")
    token.hybrid_ed25519_pub = base64.b64encode(hybrid_keypair.ed25519_pub).decode("ascii")
    token.hybrid_mldsa_pub = base64.b64encode(hybrid_keypair.mldsa_pub).decode("ascii")

    _store_token(home, token)
    logger.info(
        "Issued hybrid token %s for %s (%s)",
        payload.token_id[:12],
        subject,
        token_type.value,
    )
    return token


def verify_token_hybrid(
    token: SignedToken,
    home: Optional[Path] = None,
    *,
    require_hybrid: bool = False,
) -> bool:
    """Verify a token, accepting classical OR hybrid (either-or), like the challenge path.

    Transition policy (additive):
      * A classical-only token (``not token.is_hybrid``) verifies EXACTLY as
        :func:`capauth.tokens.verify_token` -- byte-for-byte unchanged.
      * A hybrid token must pass its time/revocation gates, its classical PGP leg
        WHEN one is present (defence in depth during transition), AND the hybrid
        Ed25519 + ML-DSA-65 composite. A hybrid token with no classical signature
        (a post-quantum-only token) is validated by its hybrid leg alone.
      * ``require_hybrid=True`` rejects a classical-only token (prevents a silent
        downgrade once a peer is known hybrid-capable).

    Returns True iff the token verifies under the negotiated policy.
    """
    if require_hybrid and not token.is_hybrid:
        logger.warning(
            "Token %s is classical-only but hybrid was required (possible downgrade)",
            token.payload.token_id[:12],
        )
        return False

    if not token.is_hybrid:
        return verify_token(token, home)

    if not token.payload.is_active:
        logger.warning("Token %s is not active", token.payload.token_id[:12])
        return False

    # Revocation gate, mirroring verify_token: a revoked token fails even with a
    # valid, in-window signature. Never let a revocation-list read crash verify.
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

    # Classical leg, only when present (defence in depth during transition).
    if token.signature and not _pgp_verify_signature(token.payload, token.signature, home):
        logger.warning("Token %s classical leg failed", token.payload.token_id[:12])
        return False

    # Hybrid leg over the SAME bytes the classical leg signs. A malformed or
    # tampered composite is a verification FAILURE, never a crash into the caller.
    pqsig = _pqsig()
    data = token.payload.model_dump_json().encode("utf-8")
    try:
        composite = base64.b64decode(token.hybrid_signature)
        ed_pub = base64.b64decode(token.hybrid_ed25519_pub)
        mldsa_pub = base64.b64decode(token.hybrid_mldsa_pub)
        verified = bool(pqsig.hybrid_verify(data, composite, ed_pub, mldsa_pub))
    except Exception:  # noqa: BLE001 - malformed/tampered composite is a failure
        logger.warning("Token %s hybrid leg failed to verify", token.payload.token_id[:12])
        return False

    token.verified = verified
    return verified


__all__ = [
    "HYBRID_SIG_SUITE",
    "HybridSigUnavailable",
    "issue_token_hybrid",
    "verify_token_hybrid",
]
