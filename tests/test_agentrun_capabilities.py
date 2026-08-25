"""Tests for the ``agentrun.*`` capability rules (card 640698fa).

skdashboard's fleet suggestion engine (``skdashboard.queue_authz``) calls
``capauth.authz.decide`` to authorize queuing an AI run against a work item's
suggestion. Two capabilities are seeded into ``DEFAULT_RULES``:

* ``agentrun.queue``   -> ATTESTED (propose/dry-run; compute-spend, no side
  effect beyond a proposal).
* ``agentrun.execute`` -> VERIFIED (EXECUTE run; produces a draft with real
  side-effect potential).

All hermetic: every test injects a ``tmp_path`` ``base_dir`` that roots BOTH
the pairing device registry and the capability-token store, matching
``tests/test_authz.py``'s pattern exactly. No real filesystem home, no gpg, no
network.
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

# ``decide`` requires the granting token to carry a verifying signature, so
# tokens here are issued SIGNED against the hermetic gpg stub (see conftest).
pytestmark = pytest.mark.usefixtures("stub_token_signing", "capability_rule_test_ceiling")


# --------------------------------------------------------------------------- #
# helpers (all base_dir-injected; mirrors tests/test_authz.py)
# --------------------------------------------------------------------------- #
def _enroll(base: Path, *, mode: EnrollmentMode, subject: str = SUBJECT, scopes=None):
    """Enroll + approve a device for ``subject`` under ``mode``. Returns the record.

    ``PUBKEY`` is a fake armored-looking placeholder with no real key behind
    it, so it cannot carry a real proof of possession. ``enroll_device`` now
    validates proof for verified/attested (card N10, 09a6d6f3), so this helper
    mints a real keypair and signs the real challenge for those two modes,
    mirroring ``tests/test_authz.py``'s ``_enroll``; tofu still needs neither
    and keeps using the placeholder.
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
        scopes or ["agentrun.queue", "agentrun.execute"],
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


# --------------------------------------------------------------------------- #
# rule table: both capabilities are KNOWN, at the chosen tiers
# --------------------------------------------------------------------------- #
def test_default_rules_include_the_agentrun_capabilities():
    """Both agentrun.* rows are seeded in DEFAULT_RULES at the tiers the design
    doc assigns: queue=attested (compute-spend, propose-only), execute=verified
    (act-class, real side-effect potential)."""
    assert {"agentrun.queue", "agentrun.execute"} <= set(DEFAULT_RULES)
    assert DEFAULT_RULES["agentrun.queue"].minimum_mode is EnrollmentMode.ATTESTED
    assert DEFAULT_RULES["agentrun.execute"].minimum_mode is EnrollmentMode.VERIFIED
    # self-granting rows, like every other rule
    assert DEFAULT_RULES["agentrun.queue"].required_capability == "agentrun.queue"
    assert DEFAULT_RULES["agentrun.execute"].required_capability == "agentrun.execute"


def test_agentrun_capabilities_are_known_not_unknown_capability(tmp_path):
    """An appropriately-enrolled subject resolves a real decision (allow), never
    the fail-closed 'unknown capability' branch."""
    _enroll(tmp_path, mode=EnrollmentMode.VERIFIED)
    _issue(tmp_path, ["agentrun.queue", "agentrun.execute"])

    queue_decision = decide(SUBJECT, "agentrun.queue", base_dir=tmp_path)
    execute_decision = decide(SUBJECT, "agentrun.execute", base_dir=tmp_path)

    assert "unknown capability" not in queue_decision.reason
    assert "unknown capability" not in execute_decision.reason
    assert queue_decision.allow is True
    assert execute_decision.allow is True


# --------------------------------------------------------------------------- #
# agentrun.queue: allowed at its (lower) attested tier
# --------------------------------------------------------------------------- #
def test_agentrun_queue_allowed_at_attested(tmp_path):
    _enroll(tmp_path, mode=EnrollmentMode.ATTESTED, scopes=["agentrun.queue"])
    _issue(tmp_path, ["agentrun.queue"])

    decision = decide(SUBJECT, "agentrun.queue", {"work_item": "wi-1"}, base_dir=tmp_path)

    assert decision.allow is True
    assert "granted" in decision.reason


def test_agentrun_queue_denied_below_attested(tmp_path):
    # tofu is below queue's attested floor.
    _enroll(tmp_path, mode=EnrollmentMode.TOFU, scopes=["agentrun.queue"])
    _issue(tmp_path, ["agentrun.queue"])

    decision = decide(SUBJECT, "agentrun.queue", base_dir=tmp_path)

    assert decision.allow is False
    assert "insufficient enrollment mode" in decision.reason


# --------------------------------------------------------------------------- #
# agentrun.execute: requires verified (highest tier)
# --------------------------------------------------------------------------- #
def test_agentrun_execute_requires_verified(tmp_path):
    """agentrun.execute is verified: an attested device is refused; verified
    passes. Mirrors the skcode.inject / skgateway.admin verified-floor tests."""
    _enroll(tmp_path, mode=EnrollmentMode.ATTESTED, scopes=["agentrun.execute"])
    _issue(tmp_path, ["agentrun.execute"])
    denied = decide(SUBJECT, "agentrun.execute", base_dir=tmp_path)
    assert denied.allow is False
    assert "insufficient enrollment mode" in denied.reason

    verified_subject = "bob@chef.skworld.io"
    _enroll(
        tmp_path,
        mode=EnrollmentMode.VERIFIED,
        subject=verified_subject,
        scopes=["agentrun.execute"],
    )
    _issue(tmp_path, ["agentrun.execute"], subject=verified_subject)
    allowed = decide(verified_subject, "agentrun.execute", base_dir=tmp_path)
    assert allowed.allow is True


def test_agentrun_execute_denied_below_verified_even_with_token(tmp_path):
    # A tofu device requesting agentrun.execute is denied no matter the token.
    _enroll(tmp_path, mode=EnrollmentMode.TOFU, scopes=["agentrun.execute"])
    _issue(tmp_path, ["agentrun.execute"])

    decision = decide(SUBJECT, "agentrun.execute", base_dir=tmp_path)

    assert decision.allow is False
    assert "insufficient enrollment mode" in decision.reason
    assert "tofu" in decision.reason
