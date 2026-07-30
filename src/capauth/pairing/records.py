"""Records and enrollment modes for the CapAuth pairing kernel (spine M2).

The pairing kernel promotes skchat's shipped trust-bootstrap code
(``pairing_gate.py``, ``guest_accept.py``, ``join_routes.py``) into a clean L0
domain package. Nothing here invents new behavior: the three enrollment modes
are exactly the trust postures skchat already ships, made first-class on the
records so downstream authz can require a minimum mode per capability.

Mode mapping (ratified by Chef, 2026-07-30; spec 3.4 part 2):

* ``verified``  capauth challenge-response / a self-signed FQID assertion
                (``join_routes.authorize_sovereign``: a valid self-signature
                over the claimed identity is proof of key ownership). Strongest.
* ``attested``  an operator signature over the device key
                (``guest_accept`` Mode B: ``operator_attestation_payload`` /
                ``verify_operator_attestation``). The device inherits trust
                from a vouching operator.
* ``tofu``      pin-on-first-use (``guest_accept`` Mode C: the
                ``admitted_peers`` TOFU pin store). Weakest: the first key seen
                is pinned.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _new_id() -> str:
    return str(uuid.uuid4())


class EnrollmentMode(str, Enum):
    """How a device's key was trusted at enrollment time.

    Ordered by strength (see :data:`MODE_SEVERITY`): a ``verified`` device is
    strictly stronger than ``attested``, which is strictly stronger than
    ``tofu``. Downstream authz can require a minimum mode per capability.
    """

    #: Capauth challenge-response / self-signed FQID assertion (join_routes).
    VERIFIED = "verified"
    #: Operator signature over the key (guest_accept Mode B).
    ATTESTED = "attested"
    #: Pin-on-first-use (guest_accept Mode C TOFU pin store).
    TOFU = "tofu"


#: Severity ordering: higher wins. verified > attested > tofu.
MODE_SEVERITY: dict[str, int] = {
    EnrollmentMode.TOFU.value: 1,
    EnrollmentMode.ATTESTED.value: 2,
    EnrollmentMode.VERIFIED.value: 3,
}


def mode_severity(mode: "EnrollmentMode | str") -> int:
    """The numeric severity of an enrollment mode (higher = stronger).

    Args:
        mode: An :class:`EnrollmentMode` or its string value.

    Returns:
        int: 3 for verified, 2 for attested, 1 for tofu.

    Raises:
        ValueError: If ``mode`` is not a known enrollment mode.
    """
    key = mode.value if isinstance(mode, EnrollmentMode) else str(mode)
    try:
        return MODE_SEVERITY[key]
    except KeyError as exc:
        raise ValueError(f"unknown enrollment mode: {mode!r}") from exc


def mode_satisfies(record_mode: "EnrollmentMode | str", minimum: "EnrollmentMode | str") -> bool:
    """Whether ``record_mode`` meets or exceeds a required ``minimum`` mode.

    This is the helper downstream authz uses to enforce a minimum trust mode
    per capability (e.g. an ordering flow may require ``attested`` or better, so
    a ``tofu`` device is refused while a ``verified`` device passes).

    Args:
        record_mode: The mode a :class:`DeviceRecord` actually carries.
        minimum: The minimum mode a capability requires.

    Returns:
        bool: True iff ``record_mode`` is at least as strong as ``minimum``.
    """
    return mode_severity(record_mode) >= mode_severity(minimum)


class Enrollment(BaseModel):
    """A pending device enrollment, awaiting operator approval.

    Created by :func:`capauth.pairing.enroll_device`. Carries the presented
    public key, the scopes the device requested, the enrollment mode, and (when
    the enrollment came through an operator pairing window) the window/nonce
    linkage that gated it. Mode-specific evidence rides the optional fields:
    ``attestation`` + ``operator_pubkey`` for ``attested``, ``proof`` for a
    ``verified`` self-signed assertion.
    """

    enrollment_id: str = Field(default_factory=_new_id, description="Unique pending-enroll id")
    pubkey: str = Field(description="The device's presented public key (ASCII-armored)")
    fingerprint: str = Field(default="", description="Fingerprint derived from the pubkey")
    requested_scopes: list[str] = Field(
        default_factory=list, description="Scopes the device asked for"
    )
    mode: EnrollmentMode = Field(description="Trust posture this enrollment was made under")
    subject: Optional[str] = Field(
        default=None, description="Who the device belongs to (identity/handle); None = derive"
    )
    created_at: datetime = Field(default_factory=_now)
    # Window linkage (present when an operator pairing window gated the enroll).
    window_id: Optional[str] = Field(default=None, description="Pairing window this rode through")
    nonce: Optional[str] = Field(default=None, description="Window nonce presented at enroll")
    # Mode-specific evidence (additive; absent for tofu).
    operator_id: Optional[str] = Field(
        default=None, description="Vouching operator id (attested mode)"
    )
    operator_pubkey: Optional[str] = Field(
        default=None, description="Vouching operator public key (attested mode)"
    )
    attestation: Optional[str] = Field(
        default=None, description="Operator signature over the device key (attested mode)"
    )
    proof: Optional[str] = Field(
        default=None, description="Self-signed assertion / challenge proof (verified mode)"
    )


class DeviceRecord(BaseModel):
    """An approved, paired device.

    Produced by :func:`capauth.pairing.approve`. This is the durable record of a
    device's standing. It carries its enrollment ``mode`` so that
    :func:`mode_satisfies` can gate capabilities, and a ``revoked`` flag (with a
    reason/timestamp) so revocation is a state transition, never a delete.
    """

    device_id: str = Field(description="Stable id for this device")
    subject: str = Field(description="Who the device belongs to (identity/handle)")
    pubkey: str = Field(description="The device's public key (ASCII-armored)")
    fingerprint: str = Field(default="", description="Fingerprint derived from the pubkey")
    mode: EnrollmentMode = Field(description="Trust posture this device was approved under")
    scopes: list[str] = Field(default_factory=list, description="Granted scopes")
    approved_by: str = Field(description="Approver identity (operator/agent that approved)")
    approved_at: datetime = Field(default_factory=_now)
    enrollment_id: Optional[str] = Field(
        default=None, description="The pending enrollment this device was approved from"
    )
    revoked: bool = Field(default=False, description="Whether this device has been revoked")
    revoked_reason: Optional[str] = Field(default=None, description="Why it was revoked")
    revoked_at: Optional[datetime] = Field(default=None, description="When it was revoked")

    def satisfies(self, minimum: "EnrollmentMode | str") -> bool:
        """True iff this (non-revoked) device meets a minimum mode.

        A revoked device satisfies nothing.
        """
        if self.revoked:
            return False
        return mode_satisfies(self.mode, minimum)


__all__ = [
    "EnrollmentMode",
    "MODE_SEVERITY",
    "mode_severity",
    "mode_satisfies",
    "Enrollment",
    "DeviceRecord",
]
