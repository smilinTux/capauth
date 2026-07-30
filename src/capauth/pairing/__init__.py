"""CapAuth pairing kernel (spine M2): device enrollment, modes, and windows.

The one pairing kernel for the SKWorld platform. It promotes skchat's shipped
trust-bootstrap code into a clean L0 domain package, preserving real semantics
rather than inventing new behavior:

* the operator pairing window (time-boxed nonce + accept cap + rate limit) from
  ``skchat.pairing_gate.PairingGate`` -> :class:`PairingWindow` / :func:`open_window`;
* three first-class enrollment MODES (ratified by Chef, 2026-07-30):
  ``verified`` (capauth challenge-response / self-signed FQID assertion,
  ``join_routes``), ``attested`` (operator signature over the key,
  ``guest_accept`` Mode B), ``tofu`` (pin-on-first-use, ``guest_accept`` Mode C);
* a device standing model (:class:`DeviceRecord`) that carries its mode so
  downstream authz can require a minimum via :func:`mode_satisfies`.

Storage keeps the ``~/.skcapstone/peers/`` v1 record shape VERBATIM; mode /
enrollment metadata rides a versioned ``pairing`` sidecar. The storage root is
injectable (``base_dir=``) so tests never touch the real registry.

This package is additive and standalone: skchat / skcomms / skcode call-site
conversion (delegating to this kernel behind the ``SKCHAT_PAIRING_KERNEL`` shadow
flag) is a deliberate later step and lives in those repos, not here.
"""

from __future__ import annotations

from .kernel import PairingError, approve, enroll_device, list_devices, revoke
from .records import (
    MODE_SEVERITY,
    DeviceRecord,
    Enrollment,
    EnrollmentMode,
    mode_satisfies,
    mode_severity,
)
from .store import (
    SIDECAR_KEY,
    SIDECAR_VERSION,
    PairingStore,
    default_base_dir,
    fingerprint_for,
)
from .window import PairingWindow, open_window

__all__ = [
    # kernel API (M0-frozen)
    "enroll_device",
    "approve",
    "revoke",
    "list_devices",
    "open_window",
    "PairingError",
    # records + modes
    "EnrollmentMode",
    "Enrollment",
    "DeviceRecord",
    "MODE_SEVERITY",
    "mode_severity",
    "mode_satisfies",
    # window
    "PairingWindow",
    # storage
    "PairingStore",
    "SIDECAR_KEY",
    "SIDECAR_VERSION",
    "default_base_dir",
    "fingerprint_for",
]
