"""Tests for the CapAuth authz kernel (spine M3, ``capauth.authz.decide``).

All hermetic: every test injects a ``tmp_path`` ``base_dir`` that roots BOTH the
pairing device registry and the capability-token store, so nothing touches the
real ``~/.skcapstone``. No real filesystem home, no gpg, no network.

Covered:

* allow with a valid token + a sufficient enrollment mode;
* deny on an expired token;
* deny when no token grants the capability;
* deny on an insufficient enrollment mode (tofu when verified is required);
* ``Capability.ALL`` (the ``"*"`` chain) grants everything;
* the AUDIT obligation is present on EVERY decision (allow and deny);
* an unknown capability fails closed;
* an unknown subject (no enrolled device) fails closed;
* FEB / trust_signal in context never gates allow (advisory only).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from capauth.authz import (
    DEFAULT_RULES,
    OBLIGATION_AUDIT,
    Decision,
    decide,
)
from capauth.pairing import EnrollmentMode, approve, enroll_device, revoke
from capauth.tokens import issue_token

SUBJECT = "alice@chef.skworld"
PUBKEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfake\n-----END PGP PUBLIC KEY BLOCK-----"


# --------------------------------------------------------------------------- #
# helpers (all base_dir-injected)
# --------------------------------------------------------------------------- #
def _enroll(base: Path, *, mode: EnrollmentMode, subject: str = SUBJECT, scopes=None):
    """Enroll + approve a device for ``subject`` under ``mode``. Returns the record."""
    enrollment = enroll_device(
        PUBKEY,
        scopes or ["skchat.send", "skchat.inbox", "skchat.prekey"],
        mode=mode,
        base_dir=base,
        subject=subject,
    )
    return approve(enrollment.enrollment_id, "operator@chef.skworld", base_dir=base)


def _issue(base: Path, capabilities, *, subject: str = SUBJECT, ttl_hours=24):
    """Issue an (unsigned, hermetic) capability token for ``subject``."""
    return issue_token(
        home=base,
        subject=subject,
        capabilities=capabilities,
        ttl_hours=ttl_hours,
        sign=False,
    )


def _audit_entries(decision: Decision):
    return [o for o in decision.obligations if o.kind == OBLIGATION_AUDIT]


# --------------------------------------------------------------------------- #
# allow
# --------------------------------------------------------------------------- #
def test_allow_with_valid_token_and_sufficient_mode(tmp_path):
    _enroll(tmp_path, mode=EnrollmentMode.VERIFIED)
    _issue(tmp_path, ["skchat.send"])

    decision = decide(SUBJECT, "skchat.send", {"peer": "bob@chef.skworld"}, base_dir=tmp_path)

    assert decision.allow is True
    assert "granted" in decision.reason


def test_allow_inbox_with_only_tofu(tmp_path):
    # inbox's minimum mode is tofu, so a tofu device suffices.
    _enroll(tmp_path, mode=EnrollmentMode.TOFU)
    _issue(tmp_path, ["skchat.inbox"])

    decision = decide(SUBJECT, "skchat.inbox", base_dir=tmp_path)

    assert decision.allow is True


def test_prekey_requires_attested(tmp_path):
    # tofu is below prekey's attested floor -> deny; attested passes.
    _enroll(tmp_path, mode=EnrollmentMode.TOFU)
    _issue(tmp_path, ["skchat.prekey"])
    denied = decide(SUBJECT, "skchat.prekey", base_dir=tmp_path)
    assert denied.allow is False
    assert "insufficient enrollment mode" in denied.reason


# --------------------------------------------------------------------------- #
# deny paths (fail closed)
# --------------------------------------------------------------------------- #
def test_deny_on_expired_token(tmp_path):
    _enroll(tmp_path, mode=EnrollmentMode.VERIFIED)
    _issue(tmp_path, ["skchat.send"], ttl_hours=-1)  # already expired

    decision = decide(SUBJECT, "skchat.send", base_dir=tmp_path)

    assert decision.allow is False
    assert "expired" in decision.reason


def test_deny_on_missing_capability(tmp_path):
    _enroll(tmp_path, mode=EnrollmentMode.VERIFIED)
    _issue(tmp_path, ["skchat.inbox"])  # no skchat.send grant

    decision = decide(SUBJECT, "skchat.send", base_dir=tmp_path)

    assert decision.allow is False
    assert "no token grants" in decision.reason


def test_deny_on_insufficient_mode_tofu_when_verified_required(tmp_path):
    # skchat.send requires verified; a tofu device is refused even with a token.
    _enroll(tmp_path, mode=EnrollmentMode.TOFU)
    _issue(tmp_path, ["skchat.send"])

    decision = decide(SUBJECT, "skchat.send", base_dir=tmp_path)

    assert decision.allow is False
    assert "insufficient enrollment mode" in decision.reason
    assert "tofu" in decision.reason


def test_deny_on_unknown_subject(tmp_path):
    # No device enrolled at all -> fail closed even though a token exists.
    _issue(tmp_path, ["skchat.send"])

    decision = decide(SUBJECT, "skchat.send", base_dir=tmp_path)

    assert decision.allow is False
    assert "unknown subject" in decision.reason


def test_deny_on_unknown_capability(tmp_path):
    _enroll(tmp_path, mode=EnrollmentMode.VERIFIED)
    _issue(tmp_path, ["*"])

    decision = decide(SUBJECT, "skchat.telepathy", base_dir=tmp_path)

    assert decision.allow is False
    assert "unknown capability" in decision.reason


def test_deny_when_device_revoked(tmp_path):
    record = _enroll(tmp_path, mode=EnrollmentMode.VERIFIED)
    _issue(tmp_path, ["skchat.send"])
    revoke(record.device_id, "compromised", base_dir=tmp_path)

    decision = decide(SUBJECT, "skchat.send", base_dir=tmp_path)

    assert decision.allow is False
    assert "unknown subject" in decision.reason  # no live device remains


# --------------------------------------------------------------------------- #
# Capability.ALL
# --------------------------------------------------------------------------- #
def test_capability_all_grants_everything(tmp_path):
    _enroll(tmp_path, mode=EnrollmentMode.VERIFIED)
    _issue(tmp_path, ["*"])  # Capability.ALL

    for cap in ("skchat.send", "skchat.inbox", "skchat.prekey"):
        decision = decide(SUBJECT, cap, base_dir=tmp_path)
        assert decision.allow is True, cap
    # reason names the wildcard grant
    assert "Capability.ALL" in decide(SUBJECT, "skchat.send", base_dir=tmp_path).reason


def test_capability_all_still_gated_by_mode(tmp_path):
    # The wildcard grants the capability chain, but the mode floor still applies.
    _enroll(tmp_path, mode=EnrollmentMode.TOFU)
    _issue(tmp_path, ["*"])

    decision = decide(SUBJECT, "skchat.send", base_dir=tmp_path)

    assert decision.allow is False
    assert "insufficient enrollment mode" in decision.reason


# --------------------------------------------------------------------------- #
# audit obligation is ALWAYS present
# --------------------------------------------------------------------------- #
def test_audit_obligation_present_on_allow(tmp_path):
    _enroll(tmp_path, mode=EnrollmentMode.VERIFIED)
    _issue(tmp_path, ["skchat.send"])

    decision = decide(SUBJECT, "skchat.send", {"peer": "bob"}, base_dir=tmp_path)

    audits = _audit_entries(decision)
    assert len(audits) == 1
    data = audits[0].data
    assert data["decision"] == "allow"
    assert data["event"] == "authz.decide"
    assert data["subject"] == SUBJECT
    assert data["capability"] == "skchat.send"
    assert data["resource"] == {"peer": "bob"}
    assert "timestamp" in data


@pytest.mark.parametrize(
    "cap",
    ["skchat.send", "skchat.inbox", "skchat.prekey", "skchat.unknown"],
)
def test_audit_obligation_present_on_every_decision(tmp_path, cap):
    # Even a fail-closed deny (unknown subject / unknown capability) audits.
    decision = decide(SUBJECT, cap, base_dir=tmp_path)
    audits = _audit_entries(decision)
    assert len(audits) == 1
    assert audits[0].data["decision"] == "deny"


# --------------------------------------------------------------------------- #
# FEB / trust signal never gates allow (spec 4.2)
# --------------------------------------------------------------------------- #
def test_trust_signal_never_flips_allow_to_deny(tmp_path):
    _enroll(tmp_path, mode=EnrollmentMode.VERIFIED)
    _issue(tmp_path, ["skchat.send"])

    cold = decide(
        SUBJECT,
        "skchat.send",
        context={"trust_signal": {"oof": 0.0, "feb": 0.0}},
        base_dir=tmp_path,
    )
    warm = decide(
        SUBJECT,
        "skchat.send",
        context={"trust_signal": {"oof": 1.0, "feb": 1.0}},
        base_dir=tmp_path,
    )

    # Identical allow regardless of the (advisory) trust signal.
    assert cold.allow is True and warm.allow is True
    # ... but it IS recorded on the audit obligation as advisory metadata.
    assert _audit_entries(cold)[0].data["advisory"]["trust_signal"]["feb"] == 0.0
    assert _audit_entries(warm)[0].data["advisory"]["trust_signal"]["feb"] == 1.0


def test_trust_signal_never_flips_deny_to_allow(tmp_path):
    # A tofu device requesting skchat.send is denied no matter how "trusted".
    _enroll(tmp_path, mode=EnrollmentMode.TOFU)
    _issue(tmp_path, ["skchat.send"])

    decision = decide(
        SUBJECT,
        "skchat.send",
        context={"trust_signal": {"oof": 1.0, "feb": 1.0}},
        base_dir=tmp_path,
    )

    assert decision.allow is False


# --------------------------------------------------------------------------- #
# rule table
# --------------------------------------------------------------------------- #
def test_default_rules_seed_the_three_skchat_capabilities():
    assert set(DEFAULT_RULES) == {"skchat.send", "skchat.inbox", "skchat.prekey"}
    assert DEFAULT_RULES["skchat.send"].minimum_mode is EnrollmentMode.VERIFIED
    assert DEFAULT_RULES["skchat.prekey"].minimum_mode is EnrollmentMode.ATTESTED
    assert DEFAULT_RULES["skchat.inbox"].minimum_mode is EnrollmentMode.TOFU
