"""CapAuth authorization kernel (spine M3): the deterministic ``decide`` PDP.

This module is the Policy Decision Point (PDP) for the SKWorld platform. It
answers exactly one question, deterministically, from cryptographic facts:

    given an already-AUTHENTICATED subject, is this subject ALLOWED to exercise
    this capability on this resource?

It is the second half of skchat's shipped ``dataplane_auth.py``. Today
``CapAuthValidator._verify_capauth_credential`` does BOTH jobs at once:
authentication (an operator JWT or a signed FQID assertion proves who the caller
is) AND the allow decision (a valid credential is treated as allowed).
``decide`` extracts ONLY the allow-decision half. Authentication stays in skchat:
the PEP authenticates the caller, yields a subject fqid, and then calls
``decide(subject, capability, resource, context)``. This package does NOT wire
that call site; the skchat PEP split and the ``SKCHAT_AUTHZ_PDP`` shadow/enforce
staging are a deliberate later step in the skchat repo (spec 3.5 parts 2-4).

Determinism from cryptographic facts only
-----------------------------------------
The decision is a pure function of three stored, cryptographic facts about the
subject plus the request:

1. **Enrollment mode** of the subject's device(s), from
   :mod:`capauth.pairing` (``DeviceRecord`` / :func:`mode_satisfies`). A
   capability may require a minimum mode (e.g. ``skchat.send`` requires
   ``verified``); a ``tofu`` device is refused where ``verified`` is required.
2. **Granted capabilities** carried on the subject's capability tokens, from the
   M1-moved :mod:`capauth.tokens` (capability chains included:
   ``Capability.ALL`` -- the ``"*"`` grant -- grants everything), gated by each
   token's ``is_active`` (expiry / not-before) and revocation state.
3. The **requested capability** and **resource**.

Hard rule (spec 4.2): FEB / emotional state NEVER gates the allow decision.
This module imports nothing from cloud9 and never consults a trust/FEB signal to
flip allow or deny. If a ``trust_signal`` rides in ``context`` it is recorded on
the audit obligation as ADVISORY metadata only, and is never read by any
allow/deny branch.

Fail closed
-----------
Every uncertainty denies: an unknown subject (no enrolled device), a missing /
expired / revoked token, an insufficient enrollment mode, and an unknown
capability all return ``allow=False`` with a clear ``reason``.

Obligations
-----------
Every decision (allow OR deny) emits an AUDIT obligation so the caller writes it
to the existing security audit surface. This module performs NO audit I/O
itself; it returns the audit record as an obligation for the PEP to honor.

Storage is injectable
----------------------
``decide(..., base_dir=...)`` roots both fact lookups (pairing devices and
capability tokens) under one injectable directory, matching the pairing / tokens
pattern, so tests run fully hermetic against a ``tmp_path`` and never touch the
real ``~/.skcapstone`` registry.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from .pairing import (
    DeviceRecord,
    EnrollmentMode,
    default_base_dir,
    list_devices,
    mode_satisfies,
)
from .tokens import Capability, SignedToken, is_revoked, list_tokens

#: Obligation kind for the audit record every decision emits.
OBLIGATION_AUDIT = "audit"


# --------------------------------------------------------------------------- #
# Result / obligation records
# --------------------------------------------------------------------------- #
class Obligation(BaseModel):
    """A side effect the PEP must honor after acting on a :class:`Decision`.

    The PDP never performs I/O; it returns obligations for the caller to carry
    out. The only obligation this kernel emits today is the AUDIT record
    (``kind == "audit"``), whose ``data`` is the append-ready audit entry.
    """

    kind: str = Field(description="Obligation kind (e.g. 'audit')")
    data: dict = Field(default_factory=dict, description="Obligation payload")


class Decision(BaseModel):
    """The result of :func:`decide`: a deterministic allow/deny with a reason.

    ``obligations`` always carries at least one AUDIT obligation (allow OR deny)
    so the caller records the decision on the security audit surface.
    """

    allow: bool = Field(description="Whether the subject is permitted")
    reason: str = Field(description="Human-readable justification, stable per branch")
    obligations: list[Obligation] = Field(
        default_factory=list, description="Side effects the PEP must honor (>= the audit entry)"
    )


# --------------------------------------------------------------------------- #
# Capability rules
# --------------------------------------------------------------------------- #
class CapabilityRule(BaseModel):
    """The requirements a capability places on a subject.

    A capability is granted only when BOTH hold:

    * the subject carries an active, non-revoked token granting
      ``required_capability`` (or the ``Capability.ALL`` ``"*"`` chain), and
    * the subject has at least one non-revoked device whose enrollment mode
      satisfies ``minimum_mode``.
    """

    capability: str = Field(description="The capability name callers request")
    required_capability: str = Field(
        description="The token capability string that must be granted (chains via Capability.ALL)"
    )
    minimum_mode: EnrollmentMode = Field(
        description="Weakest enrollment mode a subject's device may carry"
    )
    description: str = Field(default="", description="Why this rule exists")


# The seeded skchat capability rules (spec 3.5). skchat's PEP passes exactly
# these three capabilities with ``resource = {peer/thread}``. The gradient is by
# sensitivity: reading your inbox is the least sensitive (tofu is enough),
# publishing a prekey bundle binds key material to your identity (attested), and
# sending messages acts AS the subject identity on the wire (verified, matching
# skchat's shipped "valid operator JWT / self-signed FQID assertion" posture).
#
# ``decide`` is written general (subject / capability / resource / context) so
# skcode.dispatch and other surfaces slot in later by adding rows here; only the
# skchat rows are seeded now.
_SKCHAT_RULES: tuple[CapabilityRule, ...] = (
    CapabilityRule(
        capability="skchat.send",
        required_capability="skchat.send",
        minimum_mode=EnrollmentMode.VERIFIED,
        description="Send a message AS the subject identity; most sensitive.",
    ),
    CapabilityRule(
        capability="skchat.prekey",
        required_capability="skchat.prekey",
        minimum_mode=EnrollmentMode.ATTESTED,
        description="Publish a prekey bundle bound to the subject's identity.",
    ),
    CapabilityRule(
        capability="skchat.inbox",
        required_capability="skchat.inbox",
        minimum_mode=EnrollmentMode.TOFU,
        description="Read the subject's own inbox; least sensitive.",
    ),
)

#: The default, process-wide capability rule table, keyed by capability name.
DEFAULT_RULES: dict[str, CapabilityRule] = {rule.capability: rule for rule in _SKCHAT_RULES}


# --------------------------------------------------------------------------- #
# The PDP
# --------------------------------------------------------------------------- #
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _audit_obligation(
    *,
    subject: str,
    capability: str,
    resource: Optional[dict],
    allow: bool,
    reason: str,
    context: Optional[dict],
) -> Obligation:
    """Build the AUDIT obligation emitted for every decision.

    A ``trust_signal`` present in ``context`` is copied onto the audit record as
    ADVISORY metadata ONLY. It is recorded for observability and never read by
    any allow/deny branch (spec 4.2: FEB / emotional state never gates allow).
    """
    advisory: dict = {}
    if context and "trust_signal" in context:
        advisory["trust_signal"] = context["trust_signal"]
    return Obligation(
        kind=OBLIGATION_AUDIT,
        data={
            "event": "authz.decide",
            "subject": subject,
            "capability": capability,
            "resource": resource or {},
            "decision": "allow" if allow else "deny",
            "reason": reason,
            "advisory": advisory,  # never a determinant; observability only
            "timestamp": _now().isoformat(),
        },
    )


def _deny(subject, capability, resource, reason, context) -> Decision:
    return Decision(
        allow=False,
        reason=reason,
        obligations=[
            _audit_obligation(
                subject=subject,
                capability=capability,
                resource=resource,
                allow=False,
                reason=reason,
                context=context,
            )
        ],
    )


def _allow(subject, capability, resource, reason, context) -> Decision:
    return Decision(
        allow=True,
        reason=reason,
        obligations=[
            _audit_obligation(
                subject=subject,
                capability=capability,
                resource=resource,
                allow=True,
                reason=reason,
                context=context,
            )
        ],
    )


def _strongest_mode(devices: list[DeviceRecord]) -> Optional[EnrollmentMode]:
    """The strongest enrollment mode among non-revoked devices, or None."""
    live = [d for d in devices if not d.revoked]
    if not live:
        return None
    # verified > attested > tofu; mode_satisfies gives us the ordering.
    strongest = live[0].mode
    for d in live[1:]:
        if mode_satisfies(d.mode, strongest):
            strongest = d.mode
    return strongest


def _subject_tokens(subject: str, home: Path) -> list[SignedToken]:
    """All stored tokens whose payload subject matches ``subject``."""
    wanted = subject.strip().lower()
    return [t for t in list_tokens(home) if (t.payload.subject or "").strip().lower() == wanted]


def decide(
    subject: str,
    capability: str,
    resource: Optional[dict] = None,
    context: Optional[dict] = None,
    *,
    base_dir: Optional[Path] = None,
    rules: Optional[dict[str, CapabilityRule]] = None,
) -> Decision:
    """Decide whether ``subject`` may exercise ``capability`` on ``resource``.

    Deterministic from cryptographic facts only (enrollment mode + granted
    capability tokens). Authentication is NOT done here (the PEP authenticates
    the caller and yields ``subject`` before calling this). Fails closed on every
    uncertainty. Emits an AUDIT obligation on every decision.

    Args:
        subject: The already-authenticated subject identity (e.g. an fqid).
        capability: The requested capability (e.g. ``"skchat.send"``).
        resource: The target of the action (e.g. a peer / thread dict). Recorded
            on the audit obligation; not itself a determinant in the seeded rules.
        context: Optional request context. A ``trust_signal`` here is ADVISORY
            only and never gates allow (spec 4.2); it is copied to the audit
            record for observability.
        base_dir: Injectable storage root for BOTH pairing devices and capability
            tokens (defaults to ``~/.skcapstone``). Tests inject ``tmp_path``.
        rules: Override the capability rule table (defaults to
            :data:`DEFAULT_RULES`, the seeded skchat rules).

    Returns:
        Decision: ``allow`` + ``reason`` + ``obligations`` (>= the audit entry).
    """
    home = Path(base_dir).expanduser() if base_dir is not None else default_base_dir()
    rule_table = rules if rules is not None else DEFAULT_RULES

    # 1. Unknown capability -> fail closed.
    rule = rule_table.get(capability)
    if rule is None:
        return _deny(
            subject,
            capability,
            resource,
            f"unknown capability: {capability!r}",
            context,
        )

    # 2. Unknown subject (no enrolled, non-revoked device) -> fail closed.
    devices = list_devices(subject, base_dir=home, include_revoked=True)
    mode = _strongest_mode(devices)
    if mode is None:
        return _deny(
            subject,
            capability,
            resource,
            "unknown subject: no enrolled device",
            context,
        )

    # 3. Insufficient enrollment mode -> fail closed.
    if not mode_satisfies(mode, rule.minimum_mode):
        return _deny(
            subject,
            capability,
            resource,
            (
                f"insufficient enrollment mode: device is {mode.value!r}, "
                f"{capability} requires at least {rule.minimum_mode.value!r}"
            ),
            context,
        )

    # 4. Token facts. A granting token must be present, active, and not revoked.
    tokens = _subject_tokens(subject, home)
    granting = [t for t in tokens if t.payload.has_capability(rule.required_capability)]
    if not granting:
        return _deny(
            subject,
            capability,
            resource,
            f"no token grants capability {rule.required_capability!r}",
            context,
        )

    usable = [
        t
        for t in granting
        if t.payload.is_active and not is_revoked(home, t.payload.token_id)
    ]
    if not usable:
        # A grant exists but every one is expired / not-yet-valid / revoked.
        return _deny(
            subject,
            capability,
            resource,
            f"token granting {rule.required_capability!r} is expired, not-yet-valid, or revoked",
            context,
        )

    # 5. All cryptographic facts satisfied -> allow.
    granted_all = any(
        t.payload.has_capability(Capability.ALL.value)
        and Capability.ALL.value in t.payload.capabilities
        for t in usable
    )
    reason = (
        f"granted: subject enrolled {mode.value} (>= {rule.minimum_mode.value}) with an active "
        + ("Capability.ALL token" if granted_all else f"token granting {rule.required_capability}")
    )
    return _allow(subject, capability, resource, reason, context)


__all__ = [
    "decide",
    "Decision",
    "Obligation",
    "CapabilityRule",
    "DEFAULT_RULES",
    "OBLIGATION_AUDIT",
]
