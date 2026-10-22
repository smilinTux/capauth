"""Tests for the identity-class ceiling (card fc6500cb, node-roles epic).

Hermetic like ``tests/test_authz.py``: every test injects a ``tmp_path``
``base_dir`` rooting the pairing device registry, the capability-token store,
AND the identity-class assignment map, so nothing touches the real
``~/.skcapstone``. No real home, no gpg, no network.

The claim under test is structural, not incidental: a ``node``-class subject
must be UNABLE to exercise operator capabilities, not merely ungranted. So the
core cases deliberately hand the node the strongest token in the system (a
signed ``Capability.ALL`` grant) and still require a deny.

Covered:

* a node holding a valid, signed ``Capability.ALL`` token is STILL denied
  ``token:issue`` (and ``identity:sign``, and the wildcard itself);
* the deny reason strings are pinned exactly, since operators grep them;
* the class allowlist denies a capability nothing explicitly forbids;
* a node is still allowed the inference and read capabilities it exists for;
* the AUDIT obligation survives on BOTH the allow and the deny path;
* an UNCLASSIFIED subject decides exactly as it did before this layer existed;
* the class enrollment floor stacks on top of the capability's own floor;
* an unusable assignment (corrupt file, unknown class name) fails closed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from capauth.authz import OBLIGATION_AUDIT, Decision, decide
from capauth.identity_class import (
    DEFAULT_CLASSES,
    IDENTITY_CLASS_RELPATH,
    IdentityClass,
    IdentityClassError,
    IdentityClassName,
    assign_identity_class,
    resolve_identity_class,
)
from capauth.pairing import EnrollmentMode, approve, enroll_device
from capauth.subject import canonical_subject
from capauth.tokens import Capability, issue_token

from .conftest import enrolled_attested_credentials, enrolled_verified_credentials

NODE_SUBJECT = "worker@chef.skworld.io"
OTHER_SUBJECT = "alice@chef.skworld.io"

# ``decide`` requires a verifying signature on the granting token, so every test
# here issues SIGNED tokens against the hermetic gpg stub (see conftest).
pytestmark = pytest.mark.usefixtures("stub_token_signing")


# --------------------------------------------------------------------------- #
# helpers (all base_dir-injected)
# --------------------------------------------------------------------------- #
def _enroll(base: Path, *, mode: EnrollmentMode, subject: str = NODE_SUBJECT):
    """Enroll + approve a device for ``subject`` under ``mode``.

    Card N10 (``09a6d6f3``) made ``enroll_device`` VALIDATE the evidence for the
    two non-``tofu`` modes instead of storing a caller-asserted claim, so the
    fake armored-pubkey placeholder this file used no longer enrolls at
    ``verified`` or ``attested``. Real keys and real signatures over the exact
    challenges
    ``enroll_device`` re-derives are built here instead. Enrollment is incidental
    setup for this file: what it actually tests is the identity-class CEILING,
    which sits above enrollment entirely. Both challenges bind to the CANONICAL
    subject, so that is what is resolved and passed.
    """
    canonical = canonical_subject(subject)
    pubkey, proof = enrolled_verified_credentials(canonical)

    evidence: dict = {}
    if mode is EnrollmentMode.VERIFIED:
        evidence["proof"] = proof
    elif mode is EnrollmentMode.ATTESTED:
        operator_pubkey, attestation = enrolled_attested_credentials(pubkey, canonical)
        evidence["operator_pubkey"] = operator_pubkey
        evidence["attestation"] = attestation

    enrollment = enroll_device(
        pubkey,
        ["skgateway.infer", "skchat.inbox"],
        mode=mode,
        base_dir=base,
        subject=subject,
        **evidence,
    )
    return approve(enrollment.enrollment_id, "operator@chef.skworld", base_dir=base)


def _issue(base: Path, capabilities, *, subject: str = NODE_SUBJECT, ttl_hours=24):
    """Issue a signed (hermetic, stubbed-gpg) capability token for ``subject``."""
    return issue_token(
        home=base,
        subject=subject,
        capabilities=capabilities,
        ttl_hours=ttl_hours,
        sign=True,
    )


def _wildcard_node(base: Path, *, mode: EnrollmentMode = EnrollmentMode.VERIFIED):
    """The worst case: a node-class subject holding a signed ``Capability.ALL`` token."""
    _enroll(base, mode=mode)
    _issue(base, [Capability.ALL.value])
    assign_identity_class(NODE_SUBJECT, IdentityClassName.NODE, base_dir=base)


def _audit_entries(decision: Decision):
    return [o for o in decision.obligations if o.kind == OBLIGATION_AUDIT]


# --------------------------------------------------------------------------- #
# the class table itself
# --------------------------------------------------------------------------- #
def test_node_class_forbids_the_three_operator_capabilities():
    node = DEFAULT_CLASSES[IdentityClassName.NODE.value]

    assert node.forbids(Capability.ALL.value)
    assert node.forbids(Capability.TOKEN_ISSUE.value)
    assert node.forbids(Capability.IDENTITY_SIGN.value)


def test_atlas_class_permits_only_operational_observation_proposals():
    atlas = DEFAULT_CLASSES[IdentityClassName.ATLAS.value]

    assert atlas.permits("portfolio.observation.propose")
    assert atlas.forbids("portfolio.plan.author")
    assert atlas.forbids("portfolio.rank")
    assert atlas.forbids("portfolio.allocate")
    assert atlas.forbids("portfolio.claim")
    assert atlas.forbids("portfolio.renew")
    assert atlas.forbids("portfolio.release")
    assert atlas.forbids("portfolio.approve")
    assert atlas.forbids("portfolio.review.assign")
    assert atlas.forbids("portfolio.review.decide")
    assert atlas.forbids("portfolio.complete")
    assert atlas.forbids("portfolio.executor.select")
    assert atlas.forbids("portfolio.handoff")
    assert atlas.forbids("portfolio.policy.mutate")
    assert not atlas.permits("portfolio.read")


def test_node_allowlist_is_inference_and_reads_only():
    node = DEFAULT_CLASSES[IdentityClassName.NODE.value]

    assert node.permits("skgateway.infer")
    assert node.permits(Capability.MEMORY_READ.value)
    # Not an allowlisted capability, and nothing forbids it either: the
    # allowlist is what makes "nobody has decided about this yet" a deny.
    assert not node.permits(Capability.MEMORY_WRITE.value)
    assert not node.permits("skcode.dispatch")


def test_forbidden_beats_allowed_on_the_same_capability():
    # A class that lists a capability in BOTH places must still deny it.
    contradictory = IdentityClass(
        name=IdentityClassName.NODE,
        allowed_capabilities=[Capability.TOKEN_ISSUE.value],
        forbidden_capabilities=[Capability.TOKEN_ISSUE.value],
        minimum_mode=EnrollmentMode.TOFU,
    )

    assert contradictory.forbids(Capability.TOKEN_ISSUE.value)


def test_namespace_wildcard_entry_matches_the_whole_namespace():
    narrow = IdentityClass(
        name=IdentityClassName.NODE,
        allowed_capabilities=["skchat.*"],
        forbidden_capabilities=[],
        minimum_mode=EnrollmentMode.TOFU,
    )

    assert narrow.permits("skchat.inbox")
    assert not narrow.permits("skgateway.admin")


def test_assign_rejects_an_unknown_class_name(tmp_path):
    # A typo must fail at assignment time, not silently deny every request the
    # subject makes later.
    with pytest.raises(IdentityClassError):
        assign_identity_class(NODE_SUBJECT, "nodee", base_dir=tmp_path)


# --------------------------------------------------------------------------- #
# the ceiling: a wildcard token does not lift it
# --------------------------------------------------------------------------- #
def test_node_with_wildcard_token_is_still_denied_token_issue(tmp_path):
    _wildcard_node(tmp_path)

    decision = decide(NODE_SUBJECT, Capability.TOKEN_ISSUE.value, base_dir=tmp_path)

    assert decision.allow is False
    # Pinned exactly: operators grep this string.
    assert decision.reason == "identity class 'node' forbids capability 'token:issue'"


def test_node_with_wildcard_token_is_still_denied_identity_sign(tmp_path):
    _wildcard_node(tmp_path)

    decision = decide(NODE_SUBJECT, Capability.IDENTITY_SIGN.value, base_dir=tmp_path)

    assert decision.allow is False
    assert decision.reason == "identity class 'node' forbids capability 'identity:sign'"


def test_node_cannot_request_the_wildcard_capability_itself(tmp_path):
    _wildcard_node(tmp_path)

    decision = decide(NODE_SUBJECT, Capability.ALL.value, base_dir=tmp_path)

    assert decision.allow is False
    assert decision.reason == "identity class 'node' forbids capability '*'"


def test_node_with_wildcard_token_denied_a_capability_outside_its_allowlist(tmp_path):
    # change.deploy is a real rule row a Capability.ALL token would otherwise
    # satisfy outright. Nothing forbids it for a node; the allowlist is what
    # denies it.
    _wildcard_node(tmp_path)

    decision = decide(NODE_SUBJECT, "change.deploy", base_dir=tmp_path)

    assert decision.allow is False
    assert decision.reason == "identity class 'node' does not permit capability 'change.deploy'"


def test_node_is_still_allowed_the_inference_capability_it_exists_for(tmp_path):
    # The ceiling must not brick the node: an allowlisted capability with a real
    # grant behind it still passes every downstream check.
    _enroll(tmp_path, mode=EnrollmentMode.ATTESTED)
    _issue(tmp_path, ["skgateway.infer"])
    assign_identity_class(NODE_SUBJECT, IdentityClassName.NODE, base_dir=tmp_path)

    decision = decide(NODE_SUBJECT, "skgateway.infer", base_dir=tmp_path)

    assert decision.allow is True
    assert "granted" in decision.reason


def test_class_floor_stacks_on_top_of_the_capability_floor(tmp_path):
    # skchat.inbox's own floor is tofu, but the node class requires attested, so
    # a tofu-enrolled node is refused a capability the rule alone would allow.
    _enroll(tmp_path, mode=EnrollmentMode.TOFU)
    _issue(tmp_path, ["skchat.inbox"])
    assign_identity_class(NODE_SUBJECT, IdentityClassName.NODE, base_dir=tmp_path)

    decision = decide(NODE_SUBJECT, "skchat.inbox", base_dir=tmp_path)

    assert decision.allow is False
    assert decision.reason == (
        "identity class 'node' requires at least 'attested' enrollment, device is 'tofu'"
    )


# --------------------------------------------------------------------------- #
# obligations: a deny that forgets to audit is worse than a wrong deny
# --------------------------------------------------------------------------- #
def test_audit_obligation_present_on_the_class_deny_path(tmp_path):
    _wildcard_node(tmp_path)

    decision = decide(NODE_SUBJECT, Capability.TOKEN_ISSUE.value, base_dir=tmp_path)

    assert decision.obligations
    audits = _audit_entries(decision)
    assert len(audits) == 1
    assert audits[0].data["decision"] == "deny"
    assert audits[0].data["capability"] == Capability.TOKEN_ISSUE.value
    assert audits[0].data["reason"] == decision.reason


def test_audit_obligation_present_on_the_class_allow_path(tmp_path):
    _enroll(tmp_path, mode=EnrollmentMode.ATTESTED)
    _issue(tmp_path, ["skgateway.infer"])
    assign_identity_class(NODE_SUBJECT, IdentityClassName.NODE, base_dir=tmp_path)

    decision = decide(NODE_SUBJECT, "skgateway.infer", base_dir=tmp_path)

    assert decision.allow is True
    assert decision.obligations
    audits = _audit_entries(decision)
    assert len(audits) == 1
    assert audits[0].data["decision"] == "allow"
    assert audits[0].data["reason"] == decision.reason


# --------------------------------------------------------------------------- #
# back-compat: an unclassified subject is untouched
# --------------------------------------------------------------------------- #
def _unclassified_outcomes(base: Path) -> list[tuple[bool, str]]:
    """Run a representative decision matrix for an UNCLASSIFIED subject."""
    _enroll(base, mode=EnrollmentMode.VERIFIED, subject=OTHER_SUBJECT)
    _issue(base, ["skchat.send", "skchat.inbox"], subject=OTHER_SUBJECT)
    return [
        (d.allow, d.reason)
        for d in (
            decide(OTHER_SUBJECT, "skchat.send", base_dir=base),
            decide(OTHER_SUBJECT, "skchat.inbox", base_dir=base),
            decide(OTHER_SUBJECT, "skchat.prekey", base_dir=base),
            decide(OTHER_SUBJECT, "change.deploy", base_dir=base),
            decide(OTHER_SUBJECT, Capability.TOKEN_ISSUE.value, base_dir=base),
            decide("nobody@chef.skworld.io", "skchat.send", base_dir=base),
        )
    ]


def test_unclassified_subject_outcomes_are_unchanged(tmp_path):
    # Baseline: no assignments file exists at all, the state of the whole fleet
    # today. Then the same matrix in a store where the class layer is in USE
    # (another subject is classified) must produce byte-identical outcomes.
    baseline_dir = tmp_path / "baseline"
    classified_dir = tmp_path / "classified"
    baseline_dir.mkdir()
    classified_dir.mkdir()

    baseline = _unclassified_outcomes(baseline_dir)

    _enroll(classified_dir, mode=EnrollmentMode.VERIFIED)
    assign_identity_class(NODE_SUBJECT, IdentityClassName.NODE, base_dir=classified_dir)
    with_classes = _unclassified_outcomes(classified_dir)

    assert not (baseline_dir / IDENTITY_CLASS_RELPATH).exists()
    assert (classified_dir / IDENTITY_CLASS_RELPATH).exists()
    assert with_classes == baseline
    # And the matrix is worth something: it contains real allows and real denies.
    assert [allow for allow, _ in baseline].count(True) == 2


def test_resolve_returns_none_for_an_unclassified_subject(tmp_path):
    assign_identity_class(NODE_SUBJECT, IdentityClassName.NODE, base_dir=tmp_path)

    assert resolve_identity_class(OTHER_SUBJECT, base_dir=tmp_path) is None
    assert resolve_identity_class(NODE_SUBJECT, base_dir=tmp_path) is not None


# --------------------------------------------------------------------------- #
# fail closed on an unusable assignment
# --------------------------------------------------------------------------- #
def test_corrupt_assignments_file_denies(tmp_path):
    _enroll(tmp_path, mode=EnrollmentMode.VERIFIED)
    _issue(tmp_path, ["skchat.send"])
    path = tmp_path / IDENTITY_CLASS_RELPATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json", encoding="utf-8")

    decision = decide(NODE_SUBJECT, "skchat.send", base_dir=tmp_path)

    assert decision.allow is False
    assert decision.reason.startswith("identity class assignment is unusable:")
    assert _audit_entries(decision)


def test_assignment_to_an_unknown_class_denies(tmp_path):
    # Written straight to disk: assign_identity_class refuses this, but a hand
    # edit or a downgrade that drops a class row can still produce it.
    _enroll(tmp_path, mode=EnrollmentMode.VERIFIED)
    _issue(tmp_path, ["skchat.send"])
    path = tmp_path / IDENTITY_CLASS_RELPATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({NODE_SUBJECT: "overlord"}), encoding="utf-8")

    decision = decide(NODE_SUBJECT, "skchat.send", base_dir=tmp_path)

    assert decision.allow is False
    assert "unknown identity class 'overlord'" in decision.reason
