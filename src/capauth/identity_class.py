"""Identity classes: a structural ceiling on what a KIND of identity may ever do.

Card fc6500cb (SKWorld node-roles epic). This module answers a question the
capability-token model deliberately does not: not "does this subject hold the
grant today?" but "is this subject the KIND of thing that may hold it at all?".

Why a class layer exists at all
-------------------------------
:func:`capauth.authz.decide` is a grant checker. A node that simply has no
``token:issue`` grant is safe only for as long as nobody issues it one. The
moment an operator fat-fingers a mint, or a wildcard (``Capability.ALL``) token
lands in the Syncthing-replicated store under a node's subject, that node can
mint tokens for the whole fleet. "Not granted today" is a state; "may never be
granted" is a property. This module supplies the property.

An :class:`IdentityClass` is therefore a CEILING, not a grant:

* ``forbidden_capabilities`` can never be exercised by a subject of this class,
  no matter what token the subject holds. The ``node`` class forbids
  :attr:`~capauth.tokens.Capability.ALL` (the ``"*"`` grant),
  :attr:`~capauth.tokens.Capability.TOKEN_ISSUE` and
  :attr:`~capauth.tokens.Capability.IDENTITY_SIGN`: no operator secrets, no
  agent signing, no minting.
* ``allowed_capabilities`` is the positive half of the ceiling. When it does not
  carry the ``"*"`` wildcard it is an ALLOWLIST: a capability that is not listed
  is denied even though nothing explicitly forbids it. A node holds inference
  and read scopes only, so anything new that appears in the rule table is denied
  for nodes by default instead of silently becoming reachable.
* ``minimum_mode`` is an enrollment floor the class imposes on top of whatever
  floor the requested capability's own rule carries. A class may raise that
  floor, never lower it (the PDP evaluates both, and both must be satisfied).

Where the ceiling is enforced
-----------------------------
:func:`capauth.authz.decide` evaluates the class BEFORE it reads any token. That
ordering is the whole point: a token cannot raise a ceiling that was already
applied to the request. A node-class subject holding a valid, signed
``Capability.ALL`` token is still denied ``token:issue``, because the request was
refused before the store was ever consulted.

Because the ceiling is checked against the REQUESTED capability rather than
against the tokens found, a wildcard token buys a classed subject nothing beyond
its class: every capability the class forbids (or does not allow) is denied on
the way in, wildcard or not.

Assignment is stored, not asserted
----------------------------------
A subject's class lives in a small JSON file under the same injectable storage
root the pairing devices and capability tokens use
(``<base_dir>/identity/classes.json``, a flat ``{subject: class name}`` map). It
is deliberately NOT taken from request context: a class the caller can assert is
a class an attacker can assert, and the ceiling would then be theirs to raise.

Unclassified subjects are the default
-------------------------------------
:func:`resolve_identity_class` returns ``None`` for any subject with no
assignment, and the PDP then behaves EXACTLY as it did before this module
existed. This layer is opt-in per subject: the fleet's existing identities keep
their current outcomes until an operator classifies them.

Fail closed on a broken assignment
----------------------------------
An assignments file that cannot be read or parsed, or one naming a class that
does not exist, raises :class:`IdentityClassError`. The PDP turns that into a
deny. A store we cannot read is an uncertainty like any other in the authz
kernel, and the alternative (treating an unreadable file as "no assignments")
would let deleting or corrupting one file remove every ceiling at once.
"""

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from .exceptions import CapAuthError, SubjectNamingError
from .pairing import EnrollmentMode, default_base_dir
from .subject import canonical_subject
from .tokens import Capability

#: Path of the subject -> class-name assignment map, relative to ``base_dir``.
IDENTITY_CLASS_RELPATH = Path("identity") / "classes.json"

#: The wildcard entry that turns ``allowed_capabilities`` from an allowlist into
#: "anything not explicitly forbidden". Same spelling as
#: :attr:`capauth.tokens.Capability.ALL` on purpose: one ``"*"`` in the system.
WILDCARD = Capability.ALL.value


class IdentityClassError(CapAuthError):
    """A subject's identity-class assignment could not be resolved.

    Raised for an unreadable or malformed assignments file and for an assignment
    naming a class that is not in the class table. Callers (the PDP) must treat
    this as a deny: we know an assignment was intended but not what it permits.
    """


class IdentityClassName(str, Enum):
    """The kinds of identity the fleet distinguishes.

    Values are the strings written into the assignments file, so they are part
    of the on-disk format and must stay stable.
    """

    #: A human operator. Holds the secrets, signs, mints, approves.
    OPERATOR = "operator"
    #: A software agent acting on an operator's behalf (lumina, jarvis, ...).
    AGENT = "agent"
    #: A fleet machine: runs inference and reads state, never mints or signs.
    NODE = "node"
    #: A phone / tablet / browser at the edge. Narrowest of all.
    EDGE_DEVICE = "edge-device"
    #: Atlas is an operational observer, never a Portfolio decision maker.
    ATLAS = "atlas"


class IdentityClass(BaseModel):
    """The ceiling a class of identity places on every subject assigned to it.

    Evaluated by :func:`capauth.authz.decide` before any token is read, so a
    token can never raise it.
    """

    name: IdentityClassName = Field(description="Which class this is")
    allowed_capabilities: list[str] = Field(
        default_factory=list,
        description=(
            "Capabilities this class may exercise. A bare '*' means 'anything not "
            "forbidden'; otherwise this is a strict allowlist. A trailing '.*' "
            "matches a whole namespace (e.g. 'skchat.*')."
        ),
    )
    forbidden_capabilities: list[str] = Field(
        default_factory=list,
        description=(
            "Capabilities this class may NEVER exercise, whatever it holds. "
            "Checked before allowed_capabilities, so forbidden always wins."
        ),
    )
    minimum_mode: EnrollmentMode = Field(
        description="Enrollment floor this class imposes, on top of the capability's own floor"
    )
    description: str = Field(default="", description="Why this class exists")

    def forbids(self, capability: str) -> bool:
        """Whether this class forbids ``capability`` outright.

        Args:
            capability: The requested capability string (e.g. ``"token:issue"``).

        Returns:
            bool: True if the capability is on the forbidden list, by exact
            match or by a ``namespace.*`` entry covering it.
        """
        return _matches_any(capability, self.forbidden_capabilities)

    def permits(self, capability: str) -> bool:
        """Whether this class's allowlist admits ``capability``.

        Independent of :meth:`forbids`: a capability can be both listed and
        forbidden (the forbidden list wins, and the PDP checks it first).

        Args:
            capability: The requested capability string.

        Returns:
            bool: True if ``allowed_capabilities`` carries the ``"*"`` wildcard
            or an entry matching the capability.
        """
        if WILDCARD in self.allowed_capabilities:
            return True
        return _matches_any(capability, self.allowed_capabilities)


def _matches_any(capability: str, patterns: list[str]) -> bool:
    """Whether ``capability`` matches an exact entry or a ``namespace.*`` entry."""
    cap = (capability or "").strip()
    for pattern in patterns:
        entry = (pattern or "").strip()
        if not entry:
            continue
        if entry == cap:
            return True
        if entry.endswith(".*") and cap.startswith(entry[:-1]):
            return True
    return False


# --------------------------------------------------------------------------- #
# The default class table
# --------------------------------------------------------------------------- #
# The read/inference capabilities a machine identity legitimately needs. Kept as
# a named tuple rather than inlined because the node and edge-device ceilings
# share most of it, and a fleet-wide "what may a machine read" question should
# have exactly one answer to grep for.
_MACHINE_READ_CAPABILITIES: tuple[str, ...] = (
    Capability.MEMORY_READ.value,
    Capability.SYNC_PULL.value,
    Capability.TRUST_READ.value,
    Capability.AUDIT_READ.value,
    Capability.AGENT_STATUS.value,
    Capability.IDENTITY_VERIFY.value,
    "skchat.inbox",
    "skchat.status",
)

# The capabilities that ARE the operator: minting new authority, signing as an
# identity, and the wildcard that stands in for both. Forbidding these is what
# makes a machine identity structurally incapable of operator action rather than
# merely ungranted today (card fc6500cb).
_OPERATOR_ONLY_CAPABILITIES: tuple[str, ...] = (
    Capability.ALL.value,
    Capability.TOKEN_ISSUE.value,
    Capability.IDENTITY_SIGN.value,
)

#: The process-wide identity-class table, keyed by class name value.
#:
#: Additive by design: a new class is a new row, and an existing class's ceiling
#: is only ever tightened deliberately (loosening one silently re-opens whatever
#: it was added to close).
DEFAULT_CLASSES: dict[str, IdentityClass] = {
    IdentityClassName.OPERATOR.value: IdentityClass(
        name=IdentityClassName.OPERATOR,
        # The operator is the ceiling; there is nothing above them to impose one.
        allowed_capabilities=[WILDCARD],
        forbidden_capabilities=[],
        minimum_mode=EnrollmentMode.VERIFIED,
        description=(
            "A human operator: holds the root secrets, signs identities, mints "
            "tokens, approves devices. Verified enrollment only."
        ),
    ),
    IdentityClassName.AGENT.value: IdentityClass(
        name=IdentityClassName.AGENT,
        # An agent acts broadly on an operator's behalf, so it is not allowlisted
        # capability by capability. What it may NOT do is become the operator:
        # minting and identity signing stay human, and the wildcard grant would
        # hand it both at once.
        allowed_capabilities=[WILDCARD],
        forbidden_capabilities=list(_OPERATOR_ONLY_CAPABILITIES),
        minimum_mode=EnrollmentMode.ATTESTED,
        description=(
            "A software agent acting on an operator's behalf. Wide, but never the "
            "operator: no wildcard grant, no minting, no identity signing."
        ),
    ),
    IdentityClassName.NODE.value: IdentityClass(
        name=IdentityClassName.NODE,
        # Inference plus read scopes. Strict allowlist: a capability added to the
        # rule table later is denied for nodes until someone decides otherwise,
        # which is the safe direction for an unattended machine identity.
        allowed_capabilities=[
            "skgateway.infer",
            *_MACHINE_READ_CAPABILITIES,
        ],
        forbidden_capabilities=list(_OPERATOR_ONLY_CAPABILITIES),
        minimum_mode=EnrollmentMode.ATTESTED,
        description=(
            "A fleet machine (control, builder, worker). Runs inference and reads "
            "state. No operator secrets, no agent signing, no minting."
        ),
    ),
    IdentityClassName.EDGE_DEVICE.value: IdentityClass(
        name=IdentityClassName.EDGE_DEVICE,
        # Narrowest class: a phone or browser is the easiest thing in the fleet
        # to steal. It gets the things a human does FROM a handset (read, message,
        # talk) and nothing that reshapes the fleet. skchat.groups is deliberately
        # out: it mutates OTHER subjects' memberships, which is not a thing a lost
        # phone should be able to do on its own.
        allowed_capabilities=[
            "skchat.send",
            "skchat.media.write",
            "skchat.voice",
            "skchat.calls",
            *_MACHINE_READ_CAPABILITIES,
        ],
        forbidden_capabilities=list(_OPERATOR_ONLY_CAPABILITIES),
        minimum_mode=EnrollmentMode.TOFU,
        description=(
            "A phone, tablet, or browser at the edge: read, message, and call. The "
            "most easily stolen identity in the fleet, so the narrowest ceiling."
        ),
    ),
    IdentityClassName.ATLAS.value: IdentityClass(
        name=IdentityClassName.ATLAS,
        allowed_capabilities=["portfolio.observation.propose"],
        forbidden_capabilities=[
            Capability.ALL.value,
            "portfolio.plan.author",
            "portfolio.rank",
            "portfolio.allocate",
            "portfolio.claim",
            "portfolio.renew",
            "portfolio.release",
            "portfolio.approve",
            "portfolio.review",
            "portfolio.review.assign",
            "portfolio.review.decide",
            "portfolio.complete",
            "portfolio.executor.select",
            "portfolio.handoff",
            "portfolio.policy.mutate",
        ],
        minimum_mode=EnrollmentMode.ATTESTED,
        description=(
            "Atlas reports typed operational observations. It has no Portfolio "
            "planning, ranking, mutation, approval, review, handoff, or policy authority."
        ),
    ),
}


# --------------------------------------------------------------------------- #
# Assignment store (subject -> class name)
# --------------------------------------------------------------------------- #
def _assignments_path(base_dir: Optional[Path] = None) -> Path:
    root = Path(base_dir).expanduser() if base_dir is not None else default_base_dir()
    return root / IDENTITY_CLASS_RELPATH


def _subject_keys(subject: str) -> set[str]:
    """The lookup keys a subject may be stored under (raw lowercased + canonical).

    Mirrors the dual read :func:`capauth.authz._subject_tokens` already does for
    tokens: a caller mid-upgrade may present a legacy-shaped subject whose stored
    records were rewritten to canonical form, and a class assignment that misses
    for that reason would silently drop the ceiling. A subject that does not
    canonicalize is matched on its raw form only, never refused here.
    """
    keys = {(subject or "").strip().lower()}
    try:
        keys.add(canonical_subject((subject or "").strip()))
    except SubjectNamingError:
        pass
    return keys


def load_assignments(base_dir: Optional[Path] = None) -> dict[str, str]:
    """Load the subject -> class-name map.

    Args:
        base_dir: Injectable storage root (defaults to ``~/.skcapstone``).

    Returns:
        dict: Lowercased subject to class name. Empty when no file exists (the
        normal state of a fleet with no classified subjects yet).

    Raises:
        IdentityClassError: The file exists but cannot be read or parsed, or does
            not hold a flat object of strings. Never silently treated as empty:
            see the module docstring.
    """
    path = _assignments_path(base_dir)
    if not path.exists():
        return {}

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IdentityClassError(
            f"identity class assignments at {path} are unreadable: {exc}"
        ) from exc

    if not isinstance(raw, dict):
        raise IdentityClassError(
            f"identity class assignments at {path} must be a JSON object, got {type(raw).__name__}"
        )

    assignments: dict[str, str] = {}
    for subject, class_name in raw.items():
        if not isinstance(subject, str) or not isinstance(class_name, str):
            raise IdentityClassError(
                f"identity class assignments at {path} must map strings to strings"
            )
        assignments[subject.strip().lower()] = class_name.strip()
    return assignments


def assign_identity_class(
    subject: str,
    class_name: "IdentityClassName | str",
    *,
    base_dir: Optional[Path] = None,
    classes: Optional[dict[str, IdentityClass]] = None,
) -> str:
    """Assign ``subject`` to an identity class, persisting it under ``base_dir``.

    Validates the class name up front so a typo fails here, at assignment time,
    rather than at the next authorization decision (where it would deny every
    request from that subject).

    Args:
        subject: The subject identity (fqid) to classify.
        class_name: The class to assign, as an :class:`IdentityClassName` or its
            string value.
        base_dir: Injectable storage root (defaults to ``~/.skcapstone``).
        classes: Override the class table (defaults to :data:`DEFAULT_CLASSES`).

    Returns:
        str: The class name as stored.

    Raises:
        IdentityClassError: ``class_name`` is not in the class table, ``subject``
            is blank, or the existing assignments file is unusable.
    """
    table = classes if classes is not None else DEFAULT_CLASSES
    name = (
        class_name.value if isinstance(class_name, IdentityClassName) else str(class_name).strip()
    )
    if name not in table:
        raise IdentityClassError(
            f"unknown identity class {name!r}; known classes: {sorted(table)}"
        )

    key = (subject or "").strip().lower()
    if not key:
        raise IdentityClassError("cannot assign an identity class to a blank subject")

    assignments = load_assignments(base_dir)
    assignments[key] = name

    path = _assignments_path(base_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(assignments, indent=2, sort_keys=True), encoding="utf-8")
    return name


def resolve_identity_class(
    subject: str,
    *,
    base_dir: Optional[Path] = None,
    classes: Optional[dict[str, IdentityClass]] = None,
) -> Optional[IdentityClass]:
    """The identity class assigned to ``subject``, or ``None`` if unclassified.

    ``None`` is the default and the back-compatible answer: the PDP then applies
    no ceiling and decides exactly as it did before this layer existed.

    Args:
        subject: The already-authenticated subject identity.
        base_dir: Injectable storage root (defaults to ``~/.skcapstone``).
        classes: Override the class table (defaults to :data:`DEFAULT_CLASSES`).

    Returns:
        IdentityClass or None: The subject's class, or ``None`` when no
        assignment exists for it.

    Raises:
        IdentityClassError: The assignments file is unusable, or the subject is
            assigned to a class the table does not define. Both mean "a ceiling
            was intended and we cannot tell what it is", which the PDP denies on.
    """
    table = classes if classes is not None else DEFAULT_CLASSES
    assignments = load_assignments(base_dir)
    if not assignments:
        return None

    for key in _subject_keys(subject):
        name = assignments.get(key)
        if name is None:
            continue
        identity_class = table.get(name)
        if identity_class is None:
            raise IdentityClassError(
                f"subject {subject!r} is assigned to unknown identity class {name!r}"
            )
        return identity_class
    return None


__all__ = [
    "DEFAULT_CLASSES",
    "IDENTITY_CLASS_RELPATH",
    "IdentityClass",
    "IdentityClassError",
    "IdentityClassName",
    "assign_identity_class",
    "load_assignments",
    "resolve_identity_class",
]
