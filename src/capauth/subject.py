"""The one canonical subject normalizer (Identity Naming Standard, fqid grammar).

Coord card N2 (`3b15fcbb`), implementing
``sk-standards/standards/IDENTITY_NAMING_STANDARD.md`` (ratified 2026-08-14,
card `b11144cd`). Read that document first; this module is its normative
code, not a reinterpretation of it.

The live problem this closes: the capauth pairing store accumulated SIX
subject shapes for the same handful of real identities (a deprecated
``capauth:`` wire prefix, a bare ``lumina@skworld.io`` form, a missing-TLD
``lumina@chef.skworld`` form, a retired ``@skcapstone.local`` tier, and a
superseded ``operator:<fingerprint>`` device-seat prefix, on top of the one real
canonical form). :func:`capauth.authz.decide` matches subjects by EXACT
lowercased string, so any shape mismatch between what got enrolled and what a
caller presents silently becomes ``"unknown subject: no enrolled device"``, a
fail-closed deny that reads like a configuration error rather than what it
actually is: a naming defect.

:func:`canonical_subject` is the ONE function that normalizes a subject
string. It is called by :func:`capauth.pairing.enroll_device` (card N3) and
by policy-enforcement points at ingest. It is NEVER called inside
:func:`capauth.authz.decide`: the PDP stays a pure exact matcher over
already-canonical strings, so normalization itself never becomes part of the
security boundary (IDENTITY_NAMING_STANDARD.md sec 2.4).

Order of operations
--------------------
1. Reject non-ASCII outright. No folding, no transliteration: Unicode
   normalization at a security boundary IS the homograph/confusable attack
   this rule exists to close (sec 2.2). Rejecting is safe; folding hides a
   substitution instead of refusing it.
2. Reject a trailing dot or an empty label (sec 2.3). Checked on the raw
   input before anything else touches it, so a malformed caller fails
   loudly instead of being squashed into something that happens to
   validate.
3. Strip exactly ONE leading ``capauth:`` wire-alias prefix (sec 2.1). The
   check is case-insensitive (so a mixed-case ``CAPAUTH:`` prefix is still
   recognized as the same deprecated scheme) but strips only one
   occurrence: a second, leftover ``capauth:`` on a doubly-prefixed input is
   deliberately NOT stripped again, so it falls through to the final
   grammar check and is rejected as the malformed input it is.
4. Lowercase. The fqid grammar is lowercase-only; case is not an identity
   dimension.
5. Run the closed, enumerated alias table (sec 2.5) and reject anything that
   still does not match the fqid grammar afterward.

Step 5 runs the alias table BEFORE the final grammar check, not after: some
legacy shapes (e.g. the bare ``lumina@skworld.io`` form) are otherwise loose
enough to match the grammar's "human at the apex" shape unchanged, under the
wrong spelling for what is actually an enrolled agent identity. Running the
alias table first lets it correct a known-wrong-but-syntactically-legal
spelling before the grammar ever gets to bless it as-is.
"""

from __future__ import annotations

import re

from .agent_identity import SKWORLD_DOMAIN
from .exceptions import SubjectNamingError

#: The one org-domain tail this deployment's fqid grammar ends in. Reused
#: from agent_identity (rather than a second literal) so "skworld.io" lives
#: in exactly one place across the whole subject-naming surface.
ORG_DOMAIN = SKWORLD_DOMAIN

#: This deployment's one enrolled operator segment. IDENTITY_NAMING_STANDARD
#: keeps the operator segment generic (``<agent>@<operator>.<org-domain>``);
#: "chef" is a fact about who runs this deployment today, not a grammar rule.
_CHEF_OPERATOR_DOMAIN = f"chef.{ORG_DOMAIN}"

#: The fqid grammar (IDENTITY_NAMING_STANDARD.md sec 1), applied AFTER
#: mandatory ASCII enforcement and lowercasing. Two legal shapes:
#:   * ``device:<16-64 hex>``           -- the one permitted prefixed class.
#:   * ``<local-part>@(<label>.)*<org-domain>`` -- humans, agents, services,
#:     and nodes alike; the grammar cannot distinguish entity class from
#:     spelling alone (an operator segment is optional in the pattern even
#:     though agents/services/nodes always carry one in practice).
_SUBJECT_REGEX = re.compile(
    r"^(device:[0-9a-f]{16,64}"
    r"|[a-z0-9][a-z0-9-]{0,62}@(?:[a-z0-9][a-z0-9-]{0,62}\.)*" + re.escape(ORG_DOMAIN) + r")$"
)

#: Closed, enumerated alias table (IDENTITY_NAMING_STANDARD.md sec 2.5): a
#: literal, post-prefix-strip, post-lowercase spelling maps to its ONE
#: canonical form. Never add a row algorithmically; every row here is a real
#: legacy shape this deployment's pairing store has actually enrolled a
#: device under (an audit found lumina and opus each enrolled under the bare
#: ``<agent>@skworld.io`` form, distinct from the operator-qualified
#: ``<agent>@chef.skworld.io`` form capauth.agent_identity.resolve_agent_identity
#: resolves as the fqid).
#:
#: The capauth:-prefixed spellings of these same two identities are NOT
#: listed here as separate rows: step 3 above strips any leading
#: ``capauth:`` before this table is ever consulted, so
#: ``capauth:lumina@skworld.io`` and ``lumina@skworld.io`` both arrive here
#: as the same key, ``lumina@skworld.io``.
_LITERAL_ALIASES: dict[str, str] = {
    f"lumina@{ORG_DOMAIN}": f"lumina@{_CHEF_OPERATOR_DOMAIN}",
    f"opus@{ORG_DOMAIN}": f"opus@{_CHEF_OPERATOR_DOMAIN}",
}

#: Suffix -> replacement rows for the two domain-shape aliases. Kept as an
#: explicit, tiny, well-tested pair of literal suffix transforms (never a
#: general regex rewriter): each one exists for a documented, specific
#: legacy reason (see the functions below), not because a pattern happened
#: to look reusable.
_MISSING_TLD_SUFFIX = "@chef.skworld"
_RETIRED_LOCAL_TIER_SUFFIX = "@skcapstone.local"

#: Legacy device-seat prefix retired by IDENTITY_NAMING_STANDARD.md sec 1
#: ("device:<fingerprint>" is the ONE permitted prefixed class, replacing
#: every legacy "operator:<fp>" shape).
_OPERATOR_PREFIX = "operator:"
_DEVICE_PREFIX = "device:"

#: The deprecated capauth: wire-alias prefix (sec 2.1). Compared
#: case-insensitively in _strip_capauth_prefix; the constant itself stays
#: lowercase since every other use of it in this module is post-lowercase.
_CAPAUTH_PREFIX = "capauth:"


def _strip_capauth_prefix(subject: str) -> str:
    """Strip exactly one leading ``capauth:`` wire-alias prefix.

    The comparison is case-insensitive so a mixed-case ``CAPAUTH:`` prefix
    (this step runs before lowercasing) is still recognized, but only ONE
    occurrence is ever removed: ``capauth:capauth:x`` is not a
    double-wrapped alias, it is a malformed caller, and the leftover
    ``capauth:x`` is left for the final grammar check to reject rather than
    silently unwrapped a second time.

    Args:
        subject: The subject string before lowercasing, dot/ASCII checks
            already passed.

    Returns:
        ``subject`` with one leading ``capauth:`` removed, or ``subject``
        unchanged if it did not start with the prefix.
    """
    if subject[: len(_CAPAUTH_PREFIX)].lower() == _CAPAUTH_PREFIX:
        return subject[len(_CAPAUTH_PREFIX) :]
    return subject


def _collapse_missing_tld(subject: str) -> str:
    """Collapse the ``<name>@chef.skworld`` missing-TLD legacy shape.

    Why this exists: ``capauth.agent_identity._build_fqid`` has shipped
    ``<agent>@<operator>.<realm>`` (e.g. ``lumina@chef.skworld``, no
    ``.io``) as its fqid field since before this standard existed. It is the
    exact "domain suffix missing" row IDENTITY_NAMING_STANDARD.md sec 2.5
    names as an illustrative alias, made concrete for this deployment's one
    real operator (``chef``). Only this ONE known missing-TLD domain is
    collapsed; this is not a general TLD-repair heuristic and does not fire
    for any other domain.

    Args:
        subject: Already prefix-stripped and lowercased.

    Returns:
        ``subject`` with the ``@chef.skworld`` suffix replaced by
        ``@chef.skworld.io``, or ``subject`` unchanged if the suffix is not
        present.
    """
    if subject.endswith(_MISSING_TLD_SUFFIX):
        return subject[: -len(_MISSING_TLD_SUFFIX)] + "@" + _CHEF_OPERATOR_DOMAIN
    return subject


def _collapse_retired_local_tier(subject: str) -> str:
    """Collapse the retired ``<name>@skcapstone.local`` sovereign tier.

    Why this exists: an earlier design proposed a distinct ``.local``
    suffix for identities not yet federated, and it shipped briefly enough
    that live enrollment records exist under it. The standard rejects that
    split outright (IDENTITY_NAMING_STANDARD.md sec 3): sovereign-versus-
    federated is a policy attribute on the enrollment record, never a
    spelling, so every ``@skcapstone.local`` record collapses onto this
    deployment's one real operator domain.

    Args:
        subject: Already prefix-stripped and lowercased.

    Returns:
        ``subject`` with the ``@skcapstone.local`` suffix replaced by
        ``@chef.skworld.io``, or ``subject`` unchanged if the suffix is not
        present.
    """
    if subject.endswith(_RETIRED_LOCAL_TIER_SUFFIX):
        return subject[: -len(_RETIRED_LOCAL_TIER_SUFFIX)] + "@" + _CHEF_OPERATOR_DOMAIN
    return subject


def _collapse_operator_prefix(subject: str) -> str:
    """Collapse the legacy ``operator:<fingerprint>`` device-seat prefix.

    Why this exists: IDENTITY_NAMING_STANDARD.md sec 1 names
    ``device:<fingerprint>`` as the ONE permitted prefixed class and
    explicitly retires ``operator:<fp>`` (same section, device seats row).
    The fingerprint itself is preserved byte-for-byte; only the prefix word
    changes.

    Args:
        subject: Already prefix-stripped and lowercased.

    Returns:
        ``subject`` with a leading ``operator:`` replaced by ``device:``, or
        ``subject`` unchanged if it did not start with ``operator:``.
    """
    if subject.startswith(_OPERATOR_PREFIX):
        return _DEVICE_PREFIX + subject[len(_OPERATOR_PREFIX) :]
    return subject


def _has_trailing_dot_or_empty_label(subject: str) -> bool:
    """Whether ``subject`` has a trailing dot or a zero-length label.

    Covers ``operator.example.org.`` (trailing dot), ``operator..example.org``
    (an empty label between two dots), and a leading dot or empty string,
    all evidence of a malformed caller rather than a spelling variant to
    squash past.

    Args:
        subject: The raw subject string, unmodified.

    Returns:
        True if a structural defect is present.
    """
    return subject == "" or subject.startswith(".") or subject.endswith(".") or ".." in subject


def canonical_subject(subject: str) -> str:
    """Normalize ``subject`` to the one canonical fqid form.

    The single normalizer for the deployment (IDENTITY_NAMING_STANDARD.md
    sec 2.4). Call it at ingest (when a record is first written) and at
    enrollment (when a key UID is bound to a subject). NEVER call it inside
    :func:`capauth.authz.decide`: the PDP must stay a pure exact matcher
    over already-canonical strings.

    Applies, in order: ASCII enforcement, a trailing-dot/empty-label check,
    a single leading ``capauth:`` prefix strip, lowercasing, the closed
    alias table, and a final match against the fqid grammar. See the module
    docstring for the full rationale of each step and why the alias table
    runs before the final grammar check rather than after it.

    Args:
        subject: The raw subject string as presented by a caller (e.g. a
            wire identity, a legacy enrollment record, or an already-
            canonical fqid).

    Returns:
        str: The canonical fqid form of ``subject``.

    Raises:
        SubjectNamingError: ``subject`` is non-ASCII, has a trailing dot or
            an empty label, or does not match the fqid grammar even after
            alias translation.

    Examples:
        >>> canonical_subject("capauth:lumina@skworld.io")
        'lumina@chef.skworld.io'
        >>> canonical_subject("operator:0a1b2c3d4e5f6789")
        'device:0a1b2c3d4e5f6789'
    """
    if not isinstance(subject, str):
        raise SubjectNamingError(f"subject must be a string, got {type(subject).__name__}")

    # 1. ASCII only, rejected outright, never folded (sec 2.2).
    if not subject.isascii():
        raise SubjectNamingError(f"subject contains non-ASCII characters: {subject!r}")

    # 2. Trailing dot / empty label, checked on the raw input (sec 2.3).
    if _has_trailing_dot_or_empty_label(subject):
        raise SubjectNamingError(f"subject has a trailing dot or an empty label: {subject!r}")

    # 3. Strip exactly one leading capauth: wire-alias prefix (sec 2.1).
    working = _strip_capauth_prefix(subject)

    # 4. Lowercase. Case is not an identity dimension.
    working = working.lower()

    # 5. Closed alias table, then the final grammar check (sec 2.5).
    working = _LITERAL_ALIASES.get(working, working)
    working = _collapse_missing_tld(working)
    working = _collapse_retired_local_tier(working)
    working = _collapse_operator_prefix(working)

    if not _SUBJECT_REGEX.match(working):
        raise SubjectNamingError(f"subject does not match the canonical fqid grammar: {subject!r}")

    return working


__all__ = [
    "canonical_subject",
    "ORG_DOMAIN",
]
