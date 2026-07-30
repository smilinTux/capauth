"""Operator provisioning: enroll + tokenize a subject so the authz PDP allows it.

``capauth.authz.decide`` allows a subject only when it has an enrolled
``DeviceRecord`` of sufficient mode AND an active token granting the capability.
This helper provisions BOTH in one call, so an operator can enroll the live
subjects (agents, operators) that skchat's PEP decides on. That turns the authz
shadow measurement from a uniform deny-all into meaningful data: provisioned
subjects agree with the legacy allow, and the divergence log shows exactly which
subjects still need provisioning.

Pure orchestration over the shipped pairing + token surfaces; storage root is
injectable so tests never touch the real ``~/.skcapstone``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from .pairing import approve, enroll_device
from .pairing.store import default_base_dir
from .tokens import issue_token

#: The default scopes a skchat subject is provisioned with (send/inbox/prekey).
SKCHAT_SCOPES = ["skchat.send", "skchat.inbox", "skchat.prekey"]


def provision_subject(
    subject: str,
    scopes: Optional[list[str]] = None,
    *,
    mode: str = "verified",
    pubkey: Optional[str] = None,
    ttl_hours: int = 720,
    approver: str = "operator",
    sign: bool = True,
    base_dir: Optional[Path] = None,
) -> dict:
    """Provision one subject so the PDP will allow its scopes.

    Enrolls a ``DeviceRecord`` at ``mode`` (default verified, the strongest, which
    satisfies every seeded skchat rule) and issues a capability token granting
    ``scopes`` (default the three skchat capabilities). Both land under the same
    ``base_dir`` the PDP reads.

    Args:
        subject: The subject identity the PDP will see (e.g. an fqid).
        scopes: Capabilities to grant; defaults to the skchat scopes.
        mode: Enrollment mode for the device (verified | attested | tofu).
        pubkey: The subject's public key; defaults to the subject string (the PDP
            keys on subject + mode, not the pubkey, so a placeholder is fine when
            the real key is not to hand).
        ttl_hours: Token lifetime (default 30 days).
        approver: Recorded as the device's approver.
        sign: PGP-sign the token if a key is available (degrades to unsigned; the
            PDP checks capability/active/revoked, not the signature).
        base_dir: Injectable storage root (defaults to ~/.skcapstone).

    Returns:
        A summary dict: subject, device_id, token_id, mode, scopes.
    """
    granted = list(scopes) if scopes is not None else list(SKCHAT_SCOPES)
    base = Path(base_dir).expanduser() if base_dir is not None else default_base_dir()

    enrollment = enroll_device(
        pubkey or subject, granted, mode=mode, subject=subject, base_dir=base
    )
    device = approve(enrollment.enrollment_id, approver, base_dir=base)
    token = issue_token(base, subject, granted, ttl_hours=ttl_hours, sign=sign)

    return {
        "subject": subject,
        "device_id": device.device_id,
        "token_id": token.payload.token_id,
        "mode": device.mode.value,
        "scopes": granted,
    }


__all__ = ["provision_subject", "SKCHAT_SCOPES"]
