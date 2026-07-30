"""The pairing kernel public API (spec 3.4 part 1, M0-frozen surface).

One pairing kernel, two front doors (skchat and skcode-hostd delegate here; that
delegation, the call-site conversion, is a deliberate later step behind the
``SKCHAT_PAIRING_KERNEL`` shadow flag and is NOT part of this package).

Frozen API:

* ``enroll_device(pubkey, requested_scopes, *, mode) -> Enrollment``
* ``approve(enrollment_id, approver_ident) -> DeviceRecord``
* ``revoke(device_id, reason)``
* ``list_devices(subject=None) -> list[DeviceRecord]``
* ``open_window(...)`` (re-exported from :mod:`capauth.pairing.window`)

Every function takes an additive keyword-only ``base_dir`` so tests inject a
``tmp_path`` root and never touch the real ``~/.skcapstone`` registry. The frozen
positional/keyword parameters above are untouched.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from capauth.exceptions import CapAuthError

from .records import DeviceRecord, Enrollment, EnrollmentMode
from .store import PairingStore, fingerprint_for
from .window import PairingWindow


class PairingError(CapAuthError):
    """Raised when a pairing operation is refused (bad window, unknown id, ...)."""


def _coerce_mode(mode: EnrollmentMode | str) -> EnrollmentMode:
    if isinstance(mode, EnrollmentMode):
        return mode
    try:
        return EnrollmentMode(mode)
    except ValueError as exc:
        raise PairingError(f"unknown enrollment mode: {mode!r}") from exc


def enroll_device(
    pubkey: str,
    requested_scopes: list[str],
    *,
    mode: EnrollmentMode | str,
    base_dir: Optional[Path] = None,
    subject: Optional[str] = None,
    window: Optional[PairingWindow] = None,
    window_nonce: Optional[str] = None,
    operator_id: Optional[str] = None,
    operator_pubkey: Optional[str] = None,
    attestation: Optional[str] = None,
    proof: Optional[str] = None,
) -> Enrollment:
    """Register a pending device enrollment (M0-frozen entry point).

    Promotes the skchat accept path: when an operator pairing ``window`` is
    supplied, the enroll is gated by the PairingGate semantics (rate limit ->
    window open -> nonce match -> accept cap) exactly as ``/pair/accept`` is,
    and a successful enroll consumes one window accept. Without a window the
    enroll is ungated (the tailnet-local path, unchanged behavior).

    Mode-specific evidence rides the optional kwargs:
    ``operator_pubkey`` + ``attestation`` for ``attested`` (guest_accept Mode B),
    ``proof`` for a ``verified`` self-signed assertion (join_routes). ``tofu``
    needs none.

    Args:
        pubkey: The device's presented public key (ASCII-armored).
        requested_scopes: Scopes the device asks for.
        mode: ``verified`` | ``attested`` | ``tofu`` (or the enum).
        base_dir: Injectable storage root (defaults to ``~/.skcapstone``).
        subject: Who the device belongs to; defaults to its fingerprint.
        window: An open :class:`PairingWindow` to gate this enroll.
        window_nonce: The nonce presented against ``window``.
        operator_id: Vouching operator id (attested).
        operator_pubkey: Vouching operator public key (attested).
        attestation: Operator signature over the device key (attested).
        proof: Self-signed assertion / challenge proof (verified).

    Returns:
        Enrollment: The persisted pending enrollment.

    Raises:
        PairingError: If the window gate refuses the attempt.
    """
    resolved_mode = _coerce_mode(mode)
    store = PairingStore(base_dir)

    window_id: Optional[str] = None
    nonce: Optional[str] = window_nonce
    if window is not None:
        ok, reason = window.check(window_nonce)
        if not ok:
            raise PairingError(f"pairing window refused enrollment: {reason}")
        window.consume()
        window_id = window.window_id
        nonce = window_nonce

    fingerprint = fingerprint_for(pubkey)
    enrollment = Enrollment(
        pubkey=pubkey,
        fingerprint=fingerprint,
        requested_scopes=list(requested_scopes or []),
        mode=resolved_mode,
        subject=subject or (fingerprint or None),
        window_id=window_id,
        nonce=nonce,
        operator_id=operator_id,
        operator_pubkey=operator_pubkey,
        attestation=attestation,
        proof=proof,
    )
    store.save_enrollment(enrollment)
    return enrollment


def approve(
    enrollment_id: str,
    approver_ident: str,
    *,
    base_dir: Optional[Path] = None,
) -> DeviceRecord:
    """Approve a pending enrollment into a durable :class:`DeviceRecord`.

    The device record is persisted into the peer registry as a versioned
    sidecar on the subject's v1 peer record (existing fields untouched). The
    pending enrollment is consumed (single-use).

    Args:
        enrollment_id: The pending enrollment to approve.
        approver_ident: The operator/agent approving (recorded as ``approved_by``).
        base_dir: Injectable storage root.

    Returns:
        DeviceRecord: The approved, persisted device.

    Raises:
        PairingError: If no such pending enrollment exists.
    """
    store = PairingStore(base_dir)
    enrollment = store.load_enrollment(enrollment_id)
    if enrollment is None:
        raise PairingError(f"no pending enrollment: {enrollment_id}")

    subject = enrollment.subject or enrollment.fingerprint or enrollment.enrollment_id
    device = DeviceRecord(
        device_id=enrollment.enrollment_id,
        subject=subject,
        pubkey=enrollment.pubkey,
        fingerprint=enrollment.fingerprint,
        mode=enrollment.mode,
        scopes=list(enrollment.requested_scopes),
        approved_by=approver_ident,
        enrollment_id=enrollment.enrollment_id,
    )
    store.upsert_device(device)
    store.delete_enrollment(enrollment_id)
    return device


def revoke(
    device_id: str,
    reason: str,
    *,
    base_dir: Optional[Path] = None,
) -> DeviceRecord:
    """Revoke an approved device (a state transition, never a delete).

    Sets ``revoked`` on the sidecar with the reason and a timestamp; the v1 peer
    fields are left untouched. A revoked device satisfies no minimum mode.

    Args:
        device_id: The device to revoke.
        reason: Why it is being revoked.
        base_dir: Injectable storage root.

    Returns:
        DeviceRecord: The updated, revoked device.

    Raises:
        PairingError: If no device with that id exists.
    """
    store = PairingStore(base_dir)
    found = store.find_device(device_id)
    if found is None:
        raise PairingError(f"no such device: {device_id}")
    _path, _record, device = found
    device.revoked = True
    device.revoked_reason = reason
    device.revoked_at = datetime.now(timezone.utc)
    store.upsert_device(device)
    return device


def list_devices(
    subject: Optional[str] = None,
    *,
    base_dir: Optional[Path] = None,
    include_revoked: bool = True,
) -> list[DeviceRecord]:
    """List approved devices, optionally filtered to a single ``subject``.

    Args:
        subject: If given, only devices belonging to this subject.
        base_dir: Injectable storage root.
        include_revoked: When False, drop revoked devices.

    Returns:
        list[DeviceRecord]: Matching devices (newest approval first).
    """
    store = PairingStore(base_dir)
    devices = [d for _path, d in store.iter_devices()]
    if subject is not None:
        wanted = subject.strip().lower()
        devices = [d for d in devices if (d.subject or "").strip().lower() == wanted]
    if not include_revoked:
        devices = [d for d in devices if not d.revoked]
    devices.sort(key=lambda d: d.approved_at, reverse=True)
    return devices


__all__ = [
    "PairingError",
    "enroll_device",
    "approve",
    "revoke",
    "list_devices",
]
