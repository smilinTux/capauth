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
The decision is a pure function of four stored, cryptographic facts about the
subject plus the request:

1. **Enrollment mode** of the subject's device(s), from
   :mod:`capauth.pairing` (``DeviceRecord`` / :func:`mode_satisfies`). A
   capability may require a minimum mode (e.g. ``skchat.send`` requires
   ``verified``); a ``tofu`` device is refused where ``verified`` is required.
2. **Granted capabilities** carried on the subject's capability tokens, from the
   M1-moved :mod:`capauth.tokens` (capability chains included:
   ``Capability.ALL`` -- the ``"*"`` grant -- grants everything), gated by each
   token's ``is_active`` (expiry / not-before) and revocation state.
3. **The token's signature**, via :func:`capauth.tokens.signature_verifies`: a
   valid OpenPGP signature over the token's exact payload bytes, made by the key
   the payload names as its issuer. Fact 2 alone is only "a file exists in the
   store"; the token store is Syncthing-replicated, so without this fact any
   principal who can write a file into it could mint itself any capability. The
   trust anchor is the verifier's local gpg keyring (``~/.gnupg``), which is
   outside the replicated store.

   Two failure shapes here are kept apart on purpose, because they are
   different operator problems: a token that was **never signed** at all
   (``is unsigned: no signature is present``) versus a token that carries a
   signature which **does not verify** against its declared issuer
   (``carries a signature that does not verify...``, covering tamper, wrong
   signer, or an unreachable key). A genuinely unsigned token MAY be granted
   for a bounded window under an explicit, logged, time-boxed operator flag,
   ``CAPAUTH_LEGACY_UNSIGNED_GRACE_UNTIL`` (an ISO-8601 UTC deadline); a token
   with a signature that fails verification is NEVER graced, regardless of
   that flag, because it may be tampered rather than merely legacy. See
   :func:`_legacy_unsigned_grace_deadline`.
4. The **requested capability** and **resource**.

This kernel does NOT decide whether an issuer is *authorized* to grant a given
capability. A token is pinned to the issuer it declares, but any key in the
local keyring can be an issuer; a trusted-issuer allowlist is a separate,
fleet-wide policy decision that is deliberately not made here.

Hard rule (spec 4.2): FEB / emotional state NEVER gates the allow decision.
This module imports nothing from cloud9 and never consults a trust/FEB signal to
flip allow or deny. If a ``trust_signal`` rides in ``context`` it is recorded on
the audit obligation as ADVISORY metadata only, and is never read by any
allow/deny branch.

Fail closed
-----------
Every uncertainty denies: an unknown subject (no enrolled device), a missing /
expired / revoked token, an unsigned token or one whose signature does not
verify, an insufficient enrollment mode, and an unknown capability all return
``allow=False`` with a clear ``reason``. Unreachable key material is an
uncertainty like any other: if the issuer's key is absent from the keyring, or
gpg is unavailable, the signature cannot be established (``signature_verifies``
returns ``False``) and the request is DENIED rather than waved through, with the
same "does not verify" reason as a tampered signature (this kernel cannot tell
"the key is missing" apart from "the signature is bad" -- both are "cannot be
established" -- but it CAN and does tell either of those apart from "no
signature was ever attached").

The one deliberate, narrow exception is
``CAPAUTH_LEGACY_UNSIGNED_GRACE_UNTIL``: unconfigured (the default), malformed,
or expired all mean deny, exactly like every other uncertainty. Only an
explicit, well-formed, still-future ISO-8601 deadline in that env var allows a
token with NO signature at all through, and every such grant is logged at
WARNING and says so in its own ``reason`` string. It never applies to a token
that carries a signature which fails to verify.

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

import logging
import os
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
from .tokens import Capability, SignedToken, is_revoked, list_tokens, signature_verifies

logger = logging.getLogger("capauth.authz")

#: Obligation kind for the audit record every decision emits.
OBLIGATION_AUDIT = "audit"

#: Env var naming an explicit, time-boxed grace window for genuinely unsigned
#: (never-attempted) tokens. See :func:`_legacy_unsigned_grace_deadline`.
#: Unconfigured, unparseable, or expired all mean the same thing: deny.
LEGACY_UNSIGNED_GRACE_ENV = "CAPAUTH_LEGACY_UNSIGNED_GRACE_UNTIL"


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
    # --- Five new capabilities (SKWorld Authorization Model L2.2, 2026-08-06). --
    # Each gates a CLASS of action at one sensitivity tier (read=tofu,
    # write=attested, act=verified), mirroring the gradient the three rows above
    # already encode. Additive: the three shipped rules are untouched.
    CapabilityRule(
        capability="skchat.status",
        required_capability="skchat.status",
        minimum_mode=EnrollmentMode.TOFU,
        description=(
            "Read operational metadata (daemon status, peers, adapters, webrtc "
            "info, agent state); a disclosure class distinct from message content."
        ),
    ),
    CapabilityRule(
        capability="skchat.media.write",
        required_capability="skchat.media.write",
        minimum_mode=EnrollmentMode.ATTESTED,
        description=(
            "Upload attachment bytes bound to the subject. Attested, not verified: "
            "storing bytes does not by itself emit to the wire (the referencing "
            "send is the verified step)."
        ),
    ),
    CapabilityRule(
        capability="skchat.voice",
        required_capability="skchat.voice",
        minimum_mode=EnrollmentMode.ATTESTED,
        description="Run STT/TTS compute on the subject's behalf (transcribe, voice loop).",
    ),
    CapabilityRule(
        capability="skchat.groups",
        required_capability="skchat.groups",
        minimum_mode=EnrollmentMode.VERIFIED,
        description=(
            "Mutate shared group state (create groups, membership, group calls); "
            "verified because it changes OTHER subjects' memberships."
        ),
    ),
    CapabilityRule(
        capability="skchat.calls",
        required_capability="skchat.calls",
        minimum_mode=EnrollmentMode.VERIFIED,
        description=(
            "Ring peers, join calls, and mint LiveKit access tokens as the "
            "identity; verified and operationally distinct from messaging."
        ),
    ),
)

# The skgateway capability rules (SKWorld Authorization Model L1.8). skgateway is
# the ONE non-Python PEP: it authenticates locally, then calls this PDP over
# ``POST /v1/authz/decide`` (it does not port ``decide``). Two capabilities, at
# the tiers the design doc assigns:
#
#   * ``skgateway.infer``  -> ATTESTED. Running an inference proxies compute AS
#     the subject (spends the subject's budget, reaches paid cloud backends). It
#     is a write-class "spend compute as yourself" action, the same tier as
#     ``skchat.voice`` (run STT/TTS compute on the subject's behalf): storing/
#     spending on the subject's behalf, but not itself mutating shared state or
#     other subjects' records the way a verified action does.
#   * ``skgateway.admin`` -> VERIFIED. The /admin surface mutates the model
#     catalog / advertise allowlist / routing, i.e. it changes what the WHOLE
#     fleet is offered and how traffic is steered. That is an act/admin-class
#     change affecting other subjects, so it takes the verified floor (matching
#     ``skchat.groups`` / ``skchat.calls``).
_SKGATEWAY_RULES: tuple[CapabilityRule, ...] = (
    CapabilityRule(
        capability="skgateway.infer",
        required_capability="skgateway.infer",
        minimum_mode=EnrollmentMode.ATTESTED,
        description=(
            "Proxy an inference request AS the subject (spends the subject's "
            "budget, may reach paid cloud backends); write-class compute-spend."
        ),
    ),
    CapabilityRule(
        capability="skgateway.admin",
        required_capability="skgateway.admin",
        minimum_mode=EnrollmentMode.VERIFIED,
        description=(
            "Mutate the gateway model catalog / advertise allowlist / routing; "
            "verified because it changes what the whole fleet is offered."
        ),
    ),
)

# The skcode capability rules (SKWorld Authorization Model L1.8; CR-6.2 pre-inject
# security review, C3). skcode-hostd is the RCE surface: dispatch spawns a NEW
# coding-agent session (arbitrary command execution) and inject drives keystrokes
# into a running session's PTY. Both act AS the subject with the widest possible
# blast radius, so both take the VERIFIED floor, matching ``skchat.groups`` /
# ``skchat.calls`` (act-class). Previously ``skcode.dispatch`` existed only as a
# ``rules=`` injection at the daemon call site and ``skcode.inject`` had no PDP row
# at all (it was scope-only); seeding both here makes "the authz map is complete"
# a shared PDP fact instead of a per-callsite detail. ``skcode.stream`` stays
# scope-only (a read/view capability with no PDP decision), so it is deliberately
# NOT seeded here.
_SKCODE_RULES: tuple[CapabilityRule, ...] = (
    CapabilityRule(
        capability="skcode.dispatch",
        required_capability="skcode.dispatch",
        minimum_mode=EnrollmentMode.VERIFIED,
        description=(
            "Spawn a NEW agent session (RCE): arbitrary command execution AS the "
            "subject; the most sensitive capability, verified only."
        ),
    ),
    CapabilityRule(
        capability="skcode.inject",
        required_capability="skcode.inject",
        minimum_mode=EnrollmentMode.VERIFIED,
        description=(
            "Send operator keystrokes into a running agent session's PTY (RCE): "
            "drives a live agent AS the subject; verified only."
        ),
    ),
)

# The skdashboard fleet-suggestion-engine capability rules (card 640698fa).
# skdashboard.queue_authz calls this PDP to authorize queuing an AI run against
# a work item's suggestion. Two capabilities, at the tiers the existing gradient
# (read=tofu, write=attested, act=verified) already assigns:
#
#   * ``agentrun.queue`` -> ATTESTED. Queuing a propose/dry-run run spends
#     compute AS the subject (an ai-runner job is scheduled on their behalf) but
#     produces no side effect beyond a proposal for a human to later act on --
#     the same write/compute-spend tier as ``skgateway.infer`` (proxy inference
#     AS the subject) and ``skchat.voice`` (run STT/TTS compute on the subject's
#     behalf).
#   * ``agentrun.execute`` -> VERIFIED. Queuing an EXECUTE run produces a draft
#     with real side-effect potential (the run can touch shared state once
#     applied), an act-class change matching ``skchat.groups`` / ``skchat.calls``
#     and the ``skcode.dispatch`` / ``skcode.inject`` RCE rows: all four take the
#     verified floor because they act AS the subject with consequences beyond
#     the requester alone.
_AGENTRUN_RULES: tuple[CapabilityRule, ...] = (
    CapabilityRule(
        capability="agentrun.queue",
        required_capability="agentrun.queue",
        minimum_mode=EnrollmentMode.ATTESTED,
        description=(
            "Queue a propose/dry-run AI run on a work item; spends compute AS "
            "the subject but only proposes, matching skgateway.infer / "
            "skchat.voice's write/compute-spend tier."
        ),
    ),
    CapabilityRule(
        capability="agentrun.execute",
        required_capability="agentrun.execute",
        minimum_mode=EnrollmentMode.VERIFIED,
        description=(
            "Queue an EXECUTE AI run that produces a draft with real "
            "side-effect potential; act-class, matching skchat.groups / "
            "skchat.calls and skcode.dispatch / skcode.inject."
        ),
    ),
)

# The change-management capability rules (card fe10c9d8; design doc
# 2026-08-13-change-management-cab-ai-arch.md section 7). These gate the
# ITIL change state machine end to end: raising a change, attaching a CI
# verdict, CAB voting, scheduling the deploy window, and the deploy itself.
# Tier gradient, same read=tofu/write=attested/act=verified pattern as every
# other namespace here:
#
#   * ``change.propose``  -> ATTESTED. Creates a fleet-change record
#     (write-class), matching ``skchat.prekey`` / ``agentrun.queue``.
#   * ``change.validate`` -> ATTESTED. Runs CI and attaches a verdict to the
#     change (compute-spend/write-class), same tier as ``change.propose``.
#   * ``change.cab_vote`` -> VERIFIED. Acts as an identity on the one gate
#     that authorizes fleet mutation; this is the fix for today's
#     unauthenticated free-text CAB vote agent field (design doc section 7,
#     "no-self-approval" layer 1). Verified only, matching ``skchat.groups``
#     / ``skchat.calls`` / ``skcode.dispatch``.
#   * ``change.schedule`` -> VERIFIED. Decides WHEN the fleet mutates;
#     act-class, same floor as the CAB vote.
#   * ``change.deploy``   -> VERIFIED. Merges + deploys: the widest blast
#     radius in the system. Verified only (and, per the design doc, further
#     flag-gated + human-arm-gated at the PEP; this PDP row is the identity
#     floor, not the whole gate).
_CHANGE_RULES: tuple[CapabilityRule, ...] = (
    CapabilityRule(
        capability="change.propose",
        required_capability="change.propose",
        minimum_mode=EnrollmentMode.ATTESTED,
        description="Raise/draft a fleet-change record; write-class.",
    ),
    CapabilityRule(
        capability="change.validate",
        required_capability="change.validate",
        minimum_mode=EnrollmentMode.ATTESTED,
        description="Attach a CI verdict to a change; compute-spend/write-class.",
    ),
    CapabilityRule(
        capability="change.cab_vote",
        required_capability="change.cab_vote",
        minimum_mode=EnrollmentMode.VERIFIED,
        description=(
            "Cast a CAB vote on a change; acts as an identity on the gate that "
            "authorizes fleet mutation, verified only (fixes anonymous voting)."
        ),
    ),
    CapabilityRule(
        capability="change.schedule",
        required_capability="change.schedule",
        minimum_mode=EnrollmentMode.VERIFIED,
        description="Schedule the deploy window (ASAP or a future window); act-class.",
    ),
    CapabilityRule(
        capability="change.deploy",
        required_capability="change.deploy",
        minimum_mode=EnrollmentMode.VERIFIED,
        description=(
            "Execute the approved + scheduled change for real; the one merge "
            "authority in the system, verified only and the highest floor."
        ),
    ),
)

#: The default, process-wide capability rule table, keyed by capability name.
#: The seeded skchat rows plus the skgateway rows (L1.8) plus the skcode RCE rows
#: (CR-6.2 C3) plus the skdashboard agentrun rows (card 640698fa) plus the
#: change-management rows (card fe10c9d8). Additive: every prior row is
#: untouched; new subapps append their own ``<subapp>.*`` namespace here.
DEFAULT_RULES: dict[str, CapabilityRule] = {
    rule.capability: rule
    for rule in (
        *_SKCHAT_RULES,
        *_SKGATEWAY_RULES,
        *_SKCODE_RULES,
        *_AGENTRUN_RULES,
        *_CHANGE_RULES,
    )
}


# --------------------------------------------------------------------------- #
# The PDP
# --------------------------------------------------------------------------- #
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _legacy_unsigned_grace_deadline() -> tuple[Optional[datetime], Optional[str]]:
    """The still-future deadline of an explicit legacy-unsigned-token grace, if any.

    Reads :data:`LEGACY_UNSIGNED_GRACE_ENV`
    (``CAPAUTH_LEGACY_UNSIGNED_GRACE_UNTIL``), an operator-set ISO-8601
    timestamp marking when tolerance for genuinely unsigned tokens (never
    signed at all, as opposed to signed-but-invalid) expires. This exists
    because signature verification landed on a fleet where other nodes
    (Syncthing peers not yet updated, or holding tokens issued by a since-
    retired key) may still carry unsigned tokens; a bare hard flip with no
    migration window could lock every one of those nodes out the moment they
    pull this code. The flag is the deliberate, bounded alternative to that.

    Fails closed on every ambiguity, matching the rest of this module:

    * unset or blank -> no grace (``(None, raw)``);
    * not a valid ISO-8601 timestamp -> logged and ignored, no grace;
    * a valid timestamp that has already passed -> no grace (the window is
      over; the flag is not re-armed by leaving a stale value in place).

    A naive (timezone-less) timestamp is treated as UTC, since that is what
    every other timestamp in this module already is.

    Returns:
        A ``(deadline, raw)`` pair. ``deadline`` is the parsed, timezone-aware
        UTC cutoff, or ``None`` when there is no live grace window. ``raw`` is
        the unparsed env value (or ``None``), kept only so callers can include
        it in a log line or reason string.
    """
    raw = os.environ.get(LEGACY_UNSIGNED_GRACE_ENV)
    if raw is None or not raw.strip():
        return None, raw

    try:
        deadline = datetime.fromisoformat(raw.strip())
    except ValueError:
        logger.warning(
            "%s=%r is not a valid ISO-8601 timestamp; ignoring it (unsigned tokens still deny)",
            LEGACY_UNSIGNED_GRACE_ENV,
            raw,
        )
        return None, raw

    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=timezone.utc)

    if _now() >= deadline:
        return None, raw

    return deadline, raw


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
    capability tokens + a verifying signature on the granting token).
    Authentication is NOT done here (the PEP authenticates the caller and yields
    ``subject`` before calling this). Fails closed on every uncertainty,
    including key material that cannot be reached to verify a signature. Emits
    an AUDIT obligation on every decision.

    A granting token must ALSO carry a signature that verifies (see the module
    docstring, fact 3). Two denial shapes are reported with distinct reasons: a
    token that was never signed denies with ``"... is unsigned: no signature is
    present"``; a token that carries a signature which fails to verify (tamper,
    wrong signer, unreachable key, unattributable issuer) denies with ``"...
    carries a signature that does not verify against its declared issuer"``.
    An unsigned token MAY be granted instead, under an explicit, logged,
    time-boxed legacy exception: see ``CAPAUTH_LEGACY_UNSIGNED_GRACE_UNTIL`` /
    :func:`_legacy_unsigned_grace_deadline`. That exception never applies to a
    signature that was attempted and failed to verify.

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
        t for t in granting if t.payload.is_active and not is_revoked(home, t.payload.token_id)
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

    # 5. Signature fact. A token file sitting in the store proves only that
    # SOMETHING wrote a file. The store is Syncthing-replicated, so "can write
    # into the store" is a far wider set of principals than one box, and until
    # this gate existed a plain unsigned JSON file granted whatever capabilities
    # it named -- including the skcode RCE pair.
    #
    # Two failure shapes are kept apart deliberately (see the module
    # docstring): a token that never carried a signature at all, versus a
    # token that carries one that does not verify (tamper, wrong signer,
    # unreachable key, unattributable issuer). They are different operator
    # problems and get different deny reasons. When a capability's candidate
    # tokens include both shapes, the invalid-signature reason wins: an
    # attempted-and-failed signature is the more urgent case to surface, since
    # it may be tampering rather than merely an unmigrated token.
    verified = [t for t in usable if signature_verifies(t)]
    if not verified:
        unsigned = [t for t in usable if not (t.signature and t.signature.strip())]
        invalid = [t for t in usable if t.signature and t.signature.strip()]

        if invalid:
            return _deny(
                subject,
                capability,
                resource,
                (
                    f"token granting {rule.required_capability!r} carries a signature "
                    f"that does not verify against its declared issuer"
                ),
                context,
            )

        # Every candidate token is genuinely unsigned. Fail closed UNLESS an
        # explicit, well-formed, still-future grace deadline is configured.
        # Unconfigured (the default), malformed, or expired all deny, same as
        # every other uncertainty in this function.
        deadline, raw_deadline = _legacy_unsigned_grace_deadline()
        if deadline is not None:
            granted_all = any(
                t.payload.has_capability(Capability.ALL.value)
                and Capability.ALL.value in t.payload.capabilities
                for t in unsigned
            )
            logger.warning(
                "LEGACY GRACE: granting %r to %r on an UNSIGNED token under %s=%s "
                "(expires %s); this token must be re-issued signed before then",
                capability,
                subject,
                LEGACY_UNSIGNED_GRACE_ENV,
                raw_deadline,
                deadline.isoformat(),
            )
            reason = (
                f"granted under LEGACY GRACE ({LEGACY_UNSIGNED_GRACE_ENV}={raw_deadline}, "
                f"expires {deadline.isoformat()}): subject enrolled {mode.value} "
                f"(>= {rule.minimum_mode.value}) with an active but UNSIGNED "
                + (
                    "Capability.ALL token"
                    if granted_all
                    else f"token granting {rule.required_capability}"
                )
                + " -- this token must be re-issued signed before the grace expires"
            )
            return _allow(subject, capability, resource, reason, context)

        return _deny(
            subject,
            capability,
            resource,
            f"token granting {rule.required_capability!r} is unsigned: no signature is present",
            context,
        )

    # 6. Capability, enrollment mode, token validity, and signature all check
    # out -> allow. Note what this does NOT assert: that the issuer was
    # AUTHORIZED to grant this capability. The signature is pinned to the
    # issuer the payload declares, and the trust anchor is the local gpg keyring
    # (outside the replicated store), but a trusted-issuer allowlist is a
    # separate fleet-wide policy this kernel does not yet carry.
    granted_all = any(
        t.payload.has_capability(Capability.ALL.value)
        and Capability.ALL.value in t.payload.capabilities
        for t in verified
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
