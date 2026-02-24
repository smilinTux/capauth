"""
PMA (Private Membership Association) membership management.

Implements the Fiducia Communitatis membership flow:
  1. Requestor creates and signs a membership request
  2. Steward reviews, countersigns, and issues a membership claim
  3. Anyone can verify a claim offline using the steward's public key

Membership claims are PGP-signed JSON documents stored in
~/.capauth/pma/. No central server, no API -- just cryptography
and files that sync via Syncthing or any transport.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from .exceptions import CapAuthError
from .profile import DEFAULT_CAPAUTH_DIR

logger = logging.getLogger("capauth.pma")

PMA_DIR = "pma"
REQUESTS_DIR = "requests"
CLAIMS_DIR = "claims"


class PMACapability(BaseModel):
    """A capability granted by PMA membership.

    Attributes:
        name: Capability identifier (e.g. pma:member, pma:steward).
        granted_at: When the capability was granted.
        expires_at: Optional expiration time.
    """

    name: str
    granted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None

    @property
    def is_expired(self) -> bool:
        """Check if this capability has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at


class MembershipRequest(BaseModel):
    """A signed request to join the PMA.

    Created by the requestor and sent to a steward for review.

    Attributes:
        request_id: Unique identifier for this request.
        requestor_name: Display name of the person/agent requesting.
        requestor_fingerprint: PGP fingerprint of the requestor.
        requestor_type: human or ai.
        reason: Why they want to join.
        requestor_signature: PGP signature over the request body.
    """

    request_id: str = Field(default_factory=lambda: str(uuid4()))
    requestor_name: str
    requestor_fingerprint: str
    requestor_type: str = "human"
    reason: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    requestor_signature: Optional[str] = None


class MembershipClaim(BaseModel):
    """A steward-signed membership claim.

    This is the proof of PMA membership. Created when a steward
    approves a request. Contains the requestor's identity, granted
    capabilities, and the steward's countersignature.

    Attributes:
        claim_id: Unique identifier for this claim.
        member_name: The member's name.
        member_fingerprint: The member's PGP fingerprint.
        member_type: human or ai.
        steward_name: Name of the approving steward.
        steward_fingerprint: PGP fingerprint of the steward.
        capabilities: List of granted PMA capabilities.
        request_id: Link to the original request.
        steward_signature: PGP signature by the steward.
    """

    claim_id: str = Field(default_factory=lambda: str(uuid4()))
    member_name: str
    member_fingerprint: str
    member_type: str = "human"
    steward_name: str
    steward_fingerprint: str
    capabilities: list[PMACapability] = Field(default_factory=list)
    request_id: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    revoked: bool = False
    revoked_at: Optional[datetime] = None
    steward_signature: Optional[str] = None


def _pma_dir(base: Optional[Path] = None) -> Path:
    """Get or create the PMA directory.

    Args:
        base: Override capauth home.

    Returns:
        Path to the PMA directory.
    """
    base = base or DEFAULT_CAPAUTH_DIR
    d = base / PMA_DIR
    d.mkdir(parents=True, exist_ok=True)
    return d


def create_request(
    name: str,
    fingerprint: str,
    entity_type: str = "human",
    reason: str = "",
    base_dir: Optional[Path] = None,
    passphrase: Optional[str] = None,
) -> MembershipRequest:
    """Create a signed PMA membership request.

    Args:
        name: Requestor's display name.
        fingerprint: Requestor's PGP fingerprint.
        entity_type: "human" or "ai".
        reason: Why they want to join.
        base_dir: CapAuth home directory.
        passphrase: Passphrase for signing (optional).

    Returns:
        The created MembershipRequest.
    """
    base = base_dir or DEFAULT_CAPAUTH_DIR
    request = MembershipRequest(
        requestor_name=name,
        requestor_fingerprint=fingerprint,
        requestor_type=entity_type,
        reason=reason,
    )

    if passphrase:
        request = _sign_request(request, base, passphrase)

    requests_dir = _pma_dir(base) / REQUESTS_DIR
    requests_dir.mkdir(parents=True, exist_ok=True)
    path = requests_dir / f"{request.request_id}.json"
    path.write_text(request.model_dump_json(indent=2), encoding="utf-8")

    logger.info("Created membership request %s for %s", request.request_id[:8], name)
    return request


def approve_request(
    request: MembershipRequest,
    steward_name: str,
    steward_fingerprint: str,
    capabilities: Optional[list[str]] = None,
    base_dir: Optional[Path] = None,
    passphrase: Optional[str] = None,
) -> MembershipClaim:
    """Approve a membership request and issue a signed claim.

    Args:
        request: The membership request to approve.
        steward_name: Name of the approving steward.
        steward_fingerprint: PGP fingerprint of the steward.
        capabilities: List of capability names to grant.
            Defaults to ["pma:member"].
        base_dir: CapAuth home directory.
        passphrase: Steward's passphrase for signing.

    Returns:
        The issued MembershipClaim.
    """
    base = base_dir or DEFAULT_CAPAUTH_DIR
    cap_names = capabilities or ["pma:member"]
    caps = [PMACapability(name=c) for c in cap_names]

    claim = MembershipClaim(
        member_name=request.requestor_name,
        member_fingerprint=request.requestor_fingerprint,
        member_type=request.requestor_type,
        steward_name=steward_name,
        steward_fingerprint=steward_fingerprint,
        capabilities=caps,
        request_id=request.request_id,
    )

    if passphrase:
        claim = _sign_claim(claim, base, passphrase)

    claims_dir = _pma_dir(base) / CLAIMS_DIR
    claims_dir.mkdir(parents=True, exist_ok=True)
    path = claims_dir / f"{claim.claim_id}.json"
    path.write_text(claim.model_dump_json(indent=2), encoding="utf-8")

    logger.info(
        "Approved membership for %s (claim %s) by steward %s",
        request.requestor_name,
        claim.claim_id[:8],
        steward_name,
    )
    return claim


def verify_claim(
    claim: MembershipClaim,
    steward_pubkey_armor: Optional[str] = None,
    base_dir: Optional[Path] = None,
) -> bool:
    """Verify a membership claim's validity.

    Checks that:
      1. The claim is not revoked
      2. All capabilities are current (not expired)
      3. The steward signature is valid (if pubkey provided)

    Args:
        claim: The membership claim to verify.
        steward_pubkey_armor: ASCII-armored public key of the steward.
        base_dir: CapAuth home directory.

    Returns:
        True if the claim is valid.
    """
    if claim.revoked:
        logger.info("Claim %s is revoked", claim.claim_id[:8])
        return False

    expired_caps = [c for c in claim.capabilities if c.is_expired]
    if expired_caps:
        logger.info("Claim %s has expired capabilities", claim.claim_id[:8])
        return False

    if steward_pubkey_armor and claim.steward_signature:
        try:
            from .crypto import get_backend
            from .models import CryptoBackendType

            backend = get_backend(CryptoBackendType.PGPY)
            claim_copy = claim.model_copy()
            claim_copy.steward_signature = None
            claim_bytes = claim_copy.model_dump_json(indent=2).encode("utf-8")
            if not backend.verify(claim_bytes, claim.steward_signature, steward_pubkey_armor):
                logger.info("Claim %s has invalid steward signature", claim.claim_id[:8])
                return False
        except Exception as exc:
            logger.warning("Signature verification failed: %s", exc)
            return False

    return True


def revoke_claim(
    claim_id: str,
    base_dir: Optional[Path] = None,
) -> bool:
    """Revoke a membership claim.

    Args:
        claim_id: ID of the claim to revoke.
        base_dir: CapAuth home directory.

    Returns:
        True if the claim was found and revoked.
    """
    base = base_dir or DEFAULT_CAPAUTH_DIR
    claims_dir = _pma_dir(base) / CLAIMS_DIR

    for f in claims_dir.glob("*.json"):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            if data.get("claim_id") == claim_id or f.stem == claim_id:
                claim = MembershipClaim.model_validate(data)
                claim.revoked = True
                claim.revoked_at = datetime.now(timezone.utc)
                f.write_text(claim.model_dump_json(indent=2), encoding="utf-8")
                logger.info("Revoked claim %s", claim_id[:8])
                return True
        except (json.JSONDecodeError, Exception):
            continue

    return False


def get_membership_status(
    base_dir: Optional[Path] = None,
) -> dict:
    """Get the current PMA membership status.

    Args:
        base_dir: CapAuth home directory.

    Returns:
        Dict with membership info: is_member, claims, capabilities.
    """
    base = base_dir or DEFAULT_CAPAUTH_DIR
    claims_dir = _pma_dir(base) / CLAIMS_DIR
    requests_dir = _pma_dir(base) / REQUESTS_DIR

    claims: list[MembershipClaim] = []
    if claims_dir.exists():
        for f in sorted(claims_dir.glob("*.json")):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                claims.append(MembershipClaim.model_validate(data))
            except (json.JSONDecodeError, Exception):
                continue

    active_claims = [c for c in claims if not c.revoked]
    all_caps: set[str] = set()
    for c in active_claims:
        for cap in c.capabilities:
            if not cap.is_expired:
                all_caps.add(cap.name)

    pending_requests = 0
    if requests_dir.exists():
        pending_requests = sum(1 for _ in requests_dir.glob("*.json"))

    return {
        "is_member": bool(active_claims),
        "active_claims": len(active_claims),
        "total_claims": len(claims),
        "revoked_claims": len(claims) - len(active_claims),
        "capabilities": sorted(all_caps),
        "pending_requests": pending_requests,
        "steward": active_claims[0].steward_name if active_claims else None,
    }


def load_claims(base_dir: Optional[Path] = None) -> list[MembershipClaim]:
    """Load all membership claims from disk.

    Args:
        base_dir: CapAuth home directory.

    Returns:
        List of MembershipClaim objects.
    """
    base = base_dir or DEFAULT_CAPAUTH_DIR
    claims_dir = _pma_dir(base) / CLAIMS_DIR
    claims: list[MembershipClaim] = []

    if not claims_dir.exists():
        return claims

    for f in sorted(claims_dir.glob("*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            claims.append(MembershipClaim.model_validate(data))
        except (json.JSONDecodeError, Exception):
            continue

    return claims


def load_requests(base_dir: Optional[Path] = None) -> list[MembershipRequest]:
    """Load all pending membership requests from disk.

    Args:
        base_dir: CapAuth home directory.

    Returns:
        List of MembershipRequest objects.
    """
    base = base_dir or DEFAULT_CAPAUTH_DIR
    requests_dir = _pma_dir(base) / REQUESTS_DIR
    requests: list[MembershipRequest] = []

    if not requests_dir.exists():
        return requests

    for f in sorted(requests_dir.glob("*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            requests.append(MembershipRequest.model_validate(data))
        except (json.JSONDecodeError, Exception):
            continue

    return requests


def _sign_request(
    request: MembershipRequest,
    base: Path,
    passphrase: str,
) -> MembershipRequest:
    """Sign a request with the requestor's private key.

    Args:
        request: The request to sign.
        base: CapAuth home directory.
        passphrase: Private key passphrase.

    Returns:
        The request with signature populated.
    """
    try:
        from .profile import load_profile
        from .crypto import get_backend

        profile = load_profile(base)
        backend = get_backend(profile.crypto_backend)
        priv_armor = Path(profile.key_info.private_key_path).read_text(encoding="utf-8")

        request.requestor_signature = None
        body = request.model_dump_json(indent=2).encode("utf-8")
        sig = backend.sign(body, priv_armor, passphrase)
        request.requestor_signature = sig
    except Exception as exc:
        logger.warning("Could not sign request: %s", exc)

    return request


def _sign_claim(
    claim: MembershipClaim,
    base: Path,
    passphrase: str,
) -> MembershipClaim:
    """Sign a claim with the steward's private key.

    Args:
        claim: The claim to sign.
        base: CapAuth home directory.
        passphrase: Private key passphrase.

    Returns:
        The claim with steward_signature populated.
    """
    try:
        from .profile import load_profile
        from .crypto import get_backend

        profile = load_profile(base)
        backend = get_backend(profile.crypto_backend)
        priv_armor = Path(profile.key_info.private_key_path).read_text(encoding="utf-8")

        claim.steward_signature = None
        body = claim.model_dump_json(indent=2).encode("utf-8")
        sig = backend.sign(body, priv_armor, passphrase)
        claim.steward_signature = sig
    except Exception as exc:
        logger.warning("Could not sign claim: %s", exc)

    return claim
