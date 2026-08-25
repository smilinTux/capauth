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
from capauth.identity_class import IdentityClassName, assign_identity_class
from capauth.pairing import EnrollmentMode, approve, enroll_device, revoke
from capauth.tokens import issue_token

from .conftest import enrolled_attested_credentials, enrolled_verified_credentials

SUBJECT = "alice@chef.skworld.io"
PUBKEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfake\n-----END PGP PUBLIC KEY BLOCK-----"

# ``decide`` requires the granting token to carry a verifying signature, so every
# test here issues SIGNED tokens against the hermetic gpg stub (see conftest).
# The stub still refuses unsigned/tampered tokens; the real OpenPGP path is
# covered in test_authz_signature_gate.py.
pytestmark = pytest.mark.usefixtures("stub_token_signing", "capability_rule_test_ceiling")


# --------------------------------------------------------------------------- #
# helpers (all base_dir-injected)
# --------------------------------------------------------------------------- #
def _enroll(base: Path, *, mode: EnrollmentMode, subject: str = SUBJECT, scopes=None):
    """Enroll + approve a device for ``subject`` under ``mode``. Returns the record.

    ``PUBKEY`` is a fake armored-looking placeholder, never real key material,
    so it cannot carry a real proof of possession. ``enroll_device`` now
    validates proof for verified/attested (card N10, 09a6d6f3), so this helper
    mints a real keypair and signs the real challenge for those two modes; tofu
    still needs neither and keeps using the placeholder, matching this suite's
    subject matter (capability chains / expiry / revocation, not OpenPGP).
    """
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
        scopes or ["skchat.send", "skchat.inbox", "skchat.prekey"],
        mode=mode,
        base_dir=base,
        subject=subject,
        **extra,
    )
    record = approve(enrollment.enrollment_id, "operator@chef.skworld", base_dir=base)
    assign_identity_class(subject, IdentityClassName.OPERATOR, base_dir=base)
    return record


def _issue(base: Path, capabilities, *, subject: str = SUBJECT, ttl_hours=24):
    """Issue a signed (hermetic, stubbed-gpg) capability token for ``subject``."""
    return issue_token(
        home=base,
        subject=subject,
        capabilities=capabilities,
        ttl_hours=ttl_hours,
        sign=True,
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
    # No class or device exists. The structural ceiling denies first.
    _issue(tmp_path, ["skchat.send"])

    decision = decide(SUBJECT, "skchat.send", base_dir=tmp_path)

    assert decision.allow is False
    assert "has no identity class assignment" in decision.reason


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
    # The three shipped rows are unchanged (mode floors preserved exactly).
    assert {"skchat.send", "skchat.inbox", "skchat.prekey"} <= set(DEFAULT_RULES)
    assert DEFAULT_RULES["skchat.send"].minimum_mode is EnrollmentMode.VERIFIED
    assert DEFAULT_RULES["skchat.prekey"].minimum_mode is EnrollmentMode.ATTESTED
    assert DEFAULT_RULES["skchat.inbox"].minimum_mode is EnrollmentMode.TOFU


def test_default_rules_include_the_eight_skchat_capabilities():
    """SKWorld Authorization Model L2.2: 8 skchat capabilities (3 shipped + 5 new),
    each at the tier->mode the taxonomy assigns (read=tofu, write=attested,
    act=verified). These eight are a SUBSET now that other subapps (skgateway)
    also seed rows into DEFAULT_RULES."""
    assert {
        "skchat.send",
        "skchat.inbox",
        "skchat.prekey",
        "skchat.status",
        "skchat.media.write",
        "skchat.voice",
        "skchat.groups",
        "skchat.calls",
    } <= set(DEFAULT_RULES)
    # read tier -> tofu
    assert DEFAULT_RULES["skchat.status"].minimum_mode is EnrollmentMode.TOFU
    # write tier -> attested
    assert DEFAULT_RULES["skchat.media.write"].minimum_mode is EnrollmentMode.ATTESTED
    assert DEFAULT_RULES["skchat.voice"].minimum_mode is EnrollmentMode.ATTESTED
    # act tier -> verified
    assert DEFAULT_RULES["skchat.groups"].minimum_mode is EnrollmentMode.VERIFIED
    assert DEFAULT_RULES["skchat.calls"].minimum_mode is EnrollmentMode.VERIFIED
    # every rule's required_capability equals its own name (self-granting rows)
    for name, rule in DEFAULT_RULES.items():
        assert rule.required_capability == name


def test_default_rules_include_the_skgateway_capabilities():
    """SKWorld Authorization Model L1.8: skgateway is the one non-Python PEP; it
    seeds two rows into the shared PDP rule table. infer=attested (spend compute
    as yourself), admin=verified (mutate the fleet's model catalog / routing)."""
    assert {"skgateway.infer", "skgateway.admin"} <= set(DEFAULT_RULES)
    # write/compute-spend tier -> attested
    assert DEFAULT_RULES["skgateway.infer"].minimum_mode is EnrollmentMode.ATTESTED
    # act/admin tier -> verified
    assert DEFAULT_RULES["skgateway.admin"].minimum_mode is EnrollmentMode.VERIFIED
    # self-granting rows, like every other rule
    assert DEFAULT_RULES["skgateway.infer"].required_capability == "skgateway.infer"
    assert DEFAULT_RULES["skgateway.admin"].required_capability == "skgateway.admin"


def test_skgateway_infer_decision_end_to_end(tmp_path):
    """The skgateway.infer rule decides through the same PDP path: an attested
    device + a granting token allows; a tofu device is denied (below floor)."""
    _enroll(tmp_path, mode=EnrollmentMode.ATTESTED, scopes=["skgateway.infer"])
    _issue(tmp_path, ["skgateway.infer"])
    allowed = decide(SUBJECT, "skgateway.infer", base_dir=tmp_path)
    assert allowed.allow is True

    # A fresh tofu-only subject cannot infer (attested floor).
    tofu_subject = "carol@chef.skworld.io"
    _enroll(tmp_path, mode=EnrollmentMode.TOFU, subject=tofu_subject, scopes=["skgateway.infer"])
    _issue(tmp_path, ["skgateway.infer"], subject=tofu_subject)
    denied = decide(tofu_subject, "skgateway.infer", base_dir=tmp_path)
    assert denied.allow is False
    assert "insufficient enrollment mode" in denied.reason


def test_skgateway_admin_requires_verified(tmp_path):
    """skgateway.admin is verified: an attested device is refused; verified passes."""
    _enroll(tmp_path, mode=EnrollmentMode.ATTESTED, scopes=["skgateway.admin"])
    _issue(tmp_path, ["skgateway.admin"])
    denied = decide(SUBJECT, "skgateway.admin", base_dir=tmp_path)
    assert denied.allow is False
    assert "insufficient enrollment mode" in denied.reason

    verified_subject = "dave@chef.skworld.io"
    _enroll(
        tmp_path,
        mode=EnrollmentMode.VERIFIED,
        subject=verified_subject,
        scopes=["skgateway.admin"],
    )
    _issue(tmp_path, ["skgateway.admin"], subject=verified_subject)
    allowed = decide(verified_subject, "skgateway.admin", base_dir=tmp_path)
    assert allowed.allow is True


def test_default_rules_include_the_skcode_rce_capabilities():
    """CR-6.2 C3: the two skcode RCE capabilities are seeded rows in the shared
    PDP table, not per-callsite injections. Both take the VERIFIED floor (spawn
    and keystroke-inject each act AS the subject with the widest blast radius).
    ``skcode.stream`` stays scope-only, so it is deliberately NOT a rule row."""
    assert {"skcode.dispatch", "skcode.inject"} <= set(DEFAULT_RULES)
    assert DEFAULT_RULES["skcode.dispatch"].minimum_mode is EnrollmentMode.VERIFIED
    assert DEFAULT_RULES["skcode.inject"].minimum_mode is EnrollmentMode.VERIFIED
    # self-granting rows, like every other rule
    assert DEFAULT_RULES["skcode.dispatch"].required_capability == "skcode.dispatch"
    assert DEFAULT_RULES["skcode.inject"].required_capability == "skcode.inject"
    # skcode.stream is a scope-only read capability: NO PDP rule row by design.
    assert "skcode.stream" not in DEFAULT_RULES


def test_skcode_inject_requires_verified(tmp_path):
    """skcode.inject is verified: an attested device is refused; verified passes.
    This is the enrollment-mode floor CR-6.2 moves into code (was scope-only)."""
    _enroll(tmp_path, mode=EnrollmentMode.ATTESTED, scopes=["skcode.inject"])
    _issue(tmp_path, ["skcode.inject"])
    denied = decide(SUBJECT, "skcode.inject", base_dir=tmp_path)
    assert denied.allow is False
    assert "insufficient enrollment mode" in denied.reason

    verified_subject = "erin@chef.skworld.io"
    _enroll(
        tmp_path, mode=EnrollmentMode.VERIFIED, subject=verified_subject, scopes=["skcode.inject"]
    )
    _issue(tmp_path, ["skcode.inject"], subject=verified_subject)
    allowed = decide(verified_subject, "skcode.inject", base_dir=tmp_path)
    assert allowed.allow is True


def test_skcode_dispatch_requires_verified(tmp_path):
    """skcode.dispatch (spawn/RCE) decides through the same PDP path at the
    verified floor: a tofu device is denied, a verified device with a grant
    allows."""
    tofu_subject = "frank@chef.skworld.io"
    _enroll(tmp_path, mode=EnrollmentMode.TOFU, subject=tofu_subject, scopes=["skcode.dispatch"])
    _issue(tmp_path, ["skcode.dispatch"], subject=tofu_subject)
    denied = decide(tofu_subject, "skcode.dispatch", base_dir=tmp_path)
    assert denied.allow is False

    _enroll(tmp_path, mode=EnrollmentMode.VERIFIED, scopes=["skcode.dispatch"])
    _issue(tmp_path, ["skcode.dispatch"])
    allowed = decide(SUBJECT, "skcode.dispatch", base_dir=tmp_path)
    assert allowed.allow is True
