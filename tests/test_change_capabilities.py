"""Tests for the ``change.*`` capability rules (card fe10c9d8).

The change-management end-to-end design (design doc
``2026-08-13-change-management-cab-ai-arch.md`` section 7) seeds five
capabilities into ``DEFAULT_RULES`` that gate the ITIL change state machine:

* ``change.propose``  -> ATTESTED (raise/draft a change; write-class).
* ``change.validate`` -> ATTESTED (attach a CI verdict; compute-spend/write-class).
* ``change.cab_vote``  -> VERIFIED (cast a CAB vote; fixes anonymous voting).
* ``change.schedule``  -> VERIFIED (schedule the deploy window; act-class).
* ``change.deploy``    -> VERIFIED (execute the approved+scheduled change; the
  one merge authority, highest floor).

All hermetic: every test injects a ``tmp_path`` ``base_dir`` that roots BOTH
the pairing device registry and the capability-token store, matching
``tests/test_authz.py`` and ``tests/test_agentrun_capabilities.py`` exactly.
No real filesystem home, no gpg, no network.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from capauth.authz import DEFAULT_RULES, decide
from capauth.identity_class import IdentityClassName, assign_identity_class
from capauth.pairing import EnrollmentMode, approve, enroll_device
from capauth.tokens import issue_token

from .conftest import enrolled_attested_credentials, enrolled_verified_credentials

SUBJECT = "alice@chef.skworld.io"
PUBKEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfake\n-----END PGP PUBLIC KEY BLOCK-----"

ALL_CHANGE_CAPABILITIES = (
    "change.propose",
    "change.validate",
    "change.cab_vote",
    "change.schedule",
    "change.deploy",
)

ATTESTED_CAPABILITIES = ("change.propose", "change.validate")
VERIFIED_CAPABILITIES = ("change.cab_vote", "change.schedule", "change.deploy")

# ``decide`` requires the granting token to carry a verifying signature, so
# tokens here are issued SIGNED against the hermetic gpg stub (see conftest).
pytestmark = pytest.mark.usefixtures("stub_token_signing", "capability_rule_test_ceiling")


# --------------------------------------------------------------------------- #
# helpers (all base_dir-injected; mirrors tests/test_authz.py)
# --------------------------------------------------------------------------- #
def _enroll(base: Path, *, mode: EnrollmentMode, subject: str = SUBJECT, scopes=None):
    """Enroll + approve a device for ``subject`` under ``mode``. Returns the record."""
    # Card N10: verified/attested enrollment now requires real evidence, so a
    # module-level fake PUBKEY no longer enrolls at those tiers. Mint genuine
    # credentials bound to this exact subject. Enrollment is incidental setup
    # in this file; the assertions below are unchanged.
    pubkey = PUBKEY
    extra: dict = {}
    if mode == EnrollmentMode.VERIFIED:
        pubkey, proof = enrolled_verified_credentials(subject)
        extra = {"proof": proof}
    elif mode == EnrollmentMode.ATTESTED:
        operator_pubkey, attestation = enrolled_attested_credentials(pubkey, subject)
        extra = {"operator_pubkey": operator_pubkey, "attestation": attestation}

    enrollment = enroll_device(
        pubkey,
        scopes or list(ALL_CHANGE_CAPABILITIES),
        mode=mode,
        base_dir=base,
        subject=subject,
        **extra,
    )
    record = approve(enrollment.enrollment_id, "operator@chef.skworld", base_dir=base)
    assign_identity_class(subject, IdentityClassName.OPERATOR, base_dir=base)
    return record


def _issue(base: Path, capabilities, *, subject: str = SUBJECT, ttl_hours=24):
    """Issue an (unsigned, hermetic) capability token for ``subject``."""
    return issue_token(
        home=base,
        subject=subject,
        capabilities=capabilities,
        ttl_hours=ttl_hours,
        sign=True,
    )


# --------------------------------------------------------------------------- #
# rule table: all five capabilities are KNOWN, at the tiers the design doc assigns
# --------------------------------------------------------------------------- #
def test_default_rules_include_the_change_capabilities():
    """All five change.* rows are seeded in DEFAULT_RULES at the tiers the
    design doc assigns: propose/validate=attested, cab_vote/schedule/deploy=
    verified. Self-granting, like every other rule."""
    assert set(ALL_CHANGE_CAPABILITIES) <= set(DEFAULT_RULES)

    for cap in ATTESTED_CAPABILITIES:
        assert DEFAULT_RULES[cap].minimum_mode is EnrollmentMode.ATTESTED
        assert DEFAULT_RULES[cap].required_capability == cap

    for cap in VERIFIED_CAPABILITIES:
        assert DEFAULT_RULES[cap].minimum_mode is EnrollmentMode.VERIFIED
        assert DEFAULT_RULES[cap].required_capability == cap


@pytest.mark.parametrize("capability", ALL_CHANGE_CAPABILITIES)
def test_change_capabilities_are_known_not_unknown_capability(tmp_path, capability):
    """An appropriately-enrolled subject resolves a real decision (allow),
    never the fail-closed 'unknown capability' branch, for all five caps."""
    _enroll(tmp_path, mode=EnrollmentMode.VERIFIED)
    _issue(tmp_path, [capability])

    decision = decide(SUBJECT, capability, base_dir=tmp_path)

    assert "unknown capability" not in decision.reason
    assert decision.allow is True


# --------------------------------------------------------------------------- #
# change.propose / change.validate: allowed at their (lower) attested tier
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("capability", ATTESTED_CAPABILITIES)
def test_attested_change_capability_allowed_at_attested(tmp_path, capability):
    _enroll(tmp_path, mode=EnrollmentMode.ATTESTED, scopes=[capability])
    _issue(tmp_path, [capability])

    decision = decide(SUBJECT, capability, {"change": "chg-1"}, base_dir=tmp_path)

    assert decision.allow is True
    assert "granted" in decision.reason


@pytest.mark.parametrize("capability", ATTESTED_CAPABILITIES)
def test_attested_change_capability_denied_below_attested(tmp_path, capability):
    # tofu is below propose/validate's attested floor.
    _enroll(tmp_path, mode=EnrollmentMode.TOFU, scopes=[capability])
    _issue(tmp_path, [capability])

    decision = decide(SUBJECT, capability, base_dir=tmp_path)

    assert decision.allow is False
    assert "insufficient enrollment mode" in decision.reason


# --------------------------------------------------------------------------- #
# change.cab_vote / change.schedule / change.deploy: require verified
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("capability", VERIFIED_CAPABILITIES)
def test_verified_change_capability_requires_verified(tmp_path, capability):
    """cab_vote/schedule/deploy are verified: an attested device is refused
    (this is the CAB anonymous-voting fix); verified passes."""
    _enroll(tmp_path, mode=EnrollmentMode.ATTESTED, scopes=[capability])
    _issue(tmp_path, [capability])
    denied = decide(SUBJECT, capability, base_dir=tmp_path)
    assert denied.allow is False
    assert "insufficient enrollment mode" in denied.reason

    verified_subject = "bob@chef.skworld.io"
    _enroll(
        tmp_path,
        mode=EnrollmentMode.VERIFIED,
        subject=verified_subject,
        scopes=[capability],
    )
    _issue(tmp_path, [capability], subject=verified_subject)
    allowed = decide(verified_subject, capability, base_dir=tmp_path)
    assert allowed.allow is True


@pytest.mark.parametrize("capability", VERIFIED_CAPABILITIES)
def test_verified_change_capability_denied_below_verified_even_with_token(tmp_path, capability):
    # A tofu device requesting a verified change.* capability is denied no
    # matter the token (e.g. this is the fix for a free-text CAB vote:
    # tofu/attested identities can never cast a vote that counts).
    _enroll(tmp_path, mode=EnrollmentMode.TOFU, scopes=[capability])
    _issue(tmp_path, [capability])

    decision = decide(SUBJECT, capability, base_dir=tmp_path)

    assert decision.allow is False
    assert "insufficient enrollment mode" in decision.reason
    assert "tofu" in decision.reason


# --------------------------------------------------------------------------- #
# existing rules are untouched (additive change, sanity check)
# --------------------------------------------------------------------------- #
def test_agentrun_and_skchat_rules_still_present_alongside_change_rules():
    assert {"agentrun.queue", "agentrun.execute"} <= set(DEFAULT_RULES)
    assert {"skchat.send", "skchat.inbox", "skchat.prekey"} <= set(DEFAULT_RULES)
    assert DEFAULT_RULES["agentrun.execute"].minimum_mode is EnrollmentMode.VERIFIED
