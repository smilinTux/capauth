"""Tests for capauth.subject.canonical_subject (IDENTITY_NAMING_STANDARD.md,
coord card N2 `3b15fcbb`).

Covers the ordered rule pipeline (ASCII, trailing-dot/empty-label, single
capauth: prefix strip, lowercase, closed alias table, final grammar check)
and every row of the closed alias table. ``capauth.authz.decide`` is
deliberately never imported here: this module tests ONLY the normalizer,
never the PDP, matching the standard's requirement that the two stay
decoupled.
"""

from __future__ import annotations

import pytest

from capauth.exceptions import SubjectNamingError
from capauth.subject import canonical_subject

# --------------------------------------------------------------------------- #
# Alias table: every row from the coord card, plus their capauth:-prefixed
# variants (which collapse onto the same rows via the universal prefix
# strip, step 3, before the literal table is ever consulted).
# --------------------------------------------------------------------------- #
ALIAS_ROWS = [
    ("capauth:lumina@skworld.io", "lumina@chef.skworld.io"),
    ("lumina@skworld.io", "lumina@chef.skworld.io"),
    ("capauth:opus@skworld.io", "opus@chef.skworld.io"),
    ("opus@skworld.io", "opus@chef.skworld.io"),
    ("lumina@chef.skworld", "lumina@chef.skworld.io"),
    ("lumina@skcapstone.local", "lumina@chef.skworld.io"),
    ("operator:0a1b2c3d4e5f6789", "device:0a1b2c3d4e5f6789"),
]


@pytest.mark.parametrize("raw, expected", ALIAS_ROWS)
def test_alias_table_rows_resolve_to_canonical_form(raw: str, expected: str) -> None:
    """Every row of the closed, enumerated alias table maps to its one canonical spelling."""
    assert canonical_subject(raw) == expected


def test_alias_table_pattern_rows_are_not_restricted_to_lumina_opus() -> None:
    """The missing-TLD and retired-local-tier rows are patterned, not literal-only.

    They fire for ANY local part ending in the legacy domain shape, not just
    the two agents the literal rows happen to name; the card describes them
    with a ``*@...`` wildcard for exactly this reason.
    """
    assert canonical_subject("someagent@chef.skworld") == "someagent@chef.skworld.io"
    assert canonical_subject("newdevice@skcapstone.local") == "newdevice@chef.skworld.io"


# --------------------------------------------------------------------------- #
# Happy path: an already-canonical subject round-trips unchanged.
# --------------------------------------------------------------------------- #
def test_already_canonical_agent_subject_is_unchanged() -> None:
    """An already-canonical agent fqid passes through byte-for-byte."""
    assert canonical_subject("lumina@chef.skworld.io") == "lumina@chef.skworld.io"


def test_already_canonical_device_seat_is_unchanged() -> None:
    """An already-canonical device seat passes through byte-for-byte."""
    assert canonical_subject("device:0a1b2c3d4e5f6789") == "device:0a1b2c3d4e5f6789"


def test_apex_human_subject_with_no_operator_segment_is_accepted() -> None:
    """A bare human-at-the-apex fqid (no operator segment) is valid grammar."""
    assert canonical_subject("chef@skworld.io") == "chef@skworld.io"


# --------------------------------------------------------------------------- #
# Mixed case
# --------------------------------------------------------------------------- #
def test_mixed_case_subject_is_lowercased() -> None:
    """A subject presented in mixed case still resolves to the lowercase canonical form."""
    assert canonical_subject("Lumina@Chef.SkWorld.IO") == "lumina@chef.skworld.io"


def test_mixed_case_capauth_prefix_is_still_stripped() -> None:
    """The capauth: prefix strip is case-insensitive even though it runs before lowercasing."""
    assert canonical_subject("CAPAUTH:Lumina@SKWorld.IO") == "lumina@chef.skworld.io"


def test_mixed_case_device_seat_is_lowercased() -> None:
    """A device-seat fingerprint hex string is lowercased like everything else."""
    assert canonical_subject("device:0A1B2C3D4E5F6789") == "device:0a1b2c3d4e5f6789"


# --------------------------------------------------------------------------- #
# Non-ASCII: rejected outright, never folded.
# --------------------------------------------------------------------------- #
def test_non_ascii_subject_is_rejected() -> None:
    """A non-ASCII subject is rejected, not transliterated or folded."""
    with pytest.raises(SubjectNamingError, match="non-ASCII"):
        canonical_subject("café@skworld.io")


def test_homograph_lookalike_is_rejected_not_folded() -> None:
    """A Cyrillic lookalike of 'lumina' is rejected rather than silently folded to ASCII lumina.

    This is the exact attack the standard names: folding a confusable
    character to its ASCII lookalike would let an attacker mint a
    device-record collision under a visually identical spelling.
    """
    cyrillic_a = "а"  # U+0430 CYRILLIC SMALL LETTER A, looks like "a"
    with pytest.raises(SubjectNamingError, match="non-ASCII"):
        canonical_subject(f"lumin{cyrillic_a}@chef.skworld.io")


def test_non_ascii_subject_with_capauth_prefix_is_still_rejected() -> None:
    """ASCII enforcement runs before the prefix strip, so a prefixed non-ASCII subject still fails."""
    with pytest.raises(SubjectNamingError, match="non-ASCII"):
        canonical_subject("capauth:café@skworld.io")


# --------------------------------------------------------------------------- #
# Trailing dot
# --------------------------------------------------------------------------- #
def test_trailing_dot_is_rejected() -> None:
    """A subject ending in a bare trailing dot is rejected, not squashed."""
    with pytest.raises(SubjectNamingError, match="trailing dot"):
        canonical_subject("lumina@chef.skworld.io.")


def test_trailing_dot_on_already_short_domain_is_rejected() -> None:
    """A trailing dot is rejected even on an otherwise-valid short domain."""
    with pytest.raises(SubjectNamingError, match="trailing dot"):
        canonical_subject("chef@skworld.io.")


def test_subject_that_is_only_a_dot_is_rejected() -> None:
    """The degenerate single-dot subject is rejected."""
    with pytest.raises(SubjectNamingError, match="trailing dot"):
        canonical_subject(".")


# --------------------------------------------------------------------------- #
# Empty label
# --------------------------------------------------------------------------- #
def test_empty_label_double_dot_is_rejected() -> None:
    """A double-dot (zero-length label) in the domain is rejected."""
    with pytest.raises(SubjectNamingError, match="empty label"):
        canonical_subject("lumina@chef..skworld.io")


def test_empty_subject_string_is_rejected() -> None:
    """An empty subject string is rejected, not treated as a spelling variant."""
    with pytest.raises(SubjectNamingError, match="empty label"):
        canonical_subject("")


def test_leading_dot_is_rejected() -> None:
    """A subject that starts with a dot has a leading empty label and is rejected."""
    with pytest.raises(SubjectNamingError, match="empty label"):
        canonical_subject(".lumina@chef.skworld.io")


# --------------------------------------------------------------------------- #
# Double capauth: prefix
# --------------------------------------------------------------------------- #
def test_double_capauth_prefix_is_rejected() -> None:
    """A doubly-prefixed subject is rejected: only ONE capauth: layer is ever stripped."""
    with pytest.raises(SubjectNamingError, match="canonical fqid grammar"):
        canonical_subject("capauth:capauth:opus@skworld.io")


def test_double_capauth_prefix_on_a_known_alias_row_is_still_rejected() -> None:
    """Doubling the prefix on an otherwise-aliasable subject still fails, not silently repaired."""
    with pytest.raises(SubjectNamingError, match="canonical fqid grammar"):
        canonical_subject("capauth:capauth:lumina@skworld.io")


def test_single_capauth_prefix_on_the_same_subject_succeeds() -> None:
    """Sanity check: the single-prefix sibling of the double-prefix case above does resolve."""
    assert canonical_subject("capauth:lumina@skworld.io") == "lumina@chef.skworld.io"


# --------------------------------------------------------------------------- #
# General grammar rejection (not merely alias/prefix cases)
# --------------------------------------------------------------------------- #
def test_unknown_domain_is_rejected() -> None:
    """A subject at a domain outside the fqid grammar's one org-domain tail is rejected."""
    with pytest.raises(SubjectNamingError, match="canonical fqid grammar"):
        canonical_subject("lumina@example.com")


def test_short_device_fingerprint_is_rejected() -> None:
    """A device seat with a fingerprint shorter than the grammar's 16-hex floor is rejected."""
    with pytest.raises(SubjectNamingError, match="canonical fqid grammar"):
        canonical_subject("device:0a1b2c3d")


def test_non_string_input_is_rejected() -> None:
    """A non-string subject raises SubjectNamingError rather than an unrelated TypeError."""
    with pytest.raises(SubjectNamingError, match="must be a string"):
        canonical_subject(None)  # type: ignore[arg-type]
