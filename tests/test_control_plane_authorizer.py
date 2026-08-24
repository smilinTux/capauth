from __future__ import annotations

import copy
import json
import logging
import pickle
from datetime import datetime, timedelta, timezone
from threading import Barrier, Lock, Thread

import pytest

from capauth.control_plane import (
    ClientKind,
    ControlPlaneBinding,
    DecisionCode,
    DecisionState,
    OwnerPolicyDecision,
    RequestBoundary,
)
from capauth.control_plane_authorizer import (
    MAX_CONTROL_PLANE_BEARER_BYTES,
    ControlPlaneDecisionAuthorizer,
    ControlPlaneInvocationV1,
    SanitizedControlPlaneDecisionV1,
    export_control_plane_bearer,
    parse_control_plane_bearer,
)
from capauth.delegated import (
    AuthorizationCurrentnessReceipt,
    AuthorizationReceiptError,
    AuthorizationRequest,
    CapabilityAuthorizer,
    CapabilityIssuer,
    CapabilityScope,
    DelegatingCapabilityIssuer,
    InMemoryAuditSink,
    InMemoryPrincipalPolicyBackend,
    InMemoryReplayBackend,
    InMemoryRevocationBackend,
    IssuerGrant,
    PresentedCapability,
    Principal,
    StaticTrustedIssuerBackend,
    parse_presented_token,
)

UTC = timezone.utc
NOW = datetime(2026, 8, 24, 12, tzinfo=UTC)
ISSUER = "A" * 40
OWNER_REVISION = "b" * 64
ORIGIN = "https://dashboard.example.test"


class Clock:
    def __init__(self) -> None:
        self.value = NOW

    def __call__(self) -> datetime:
        return self.value


class RegistrySigner:
    def __init__(self) -> None:
        self._lock = Lock()
        self._signed: dict[str, bytes] = {}
        self._counter = 0
        self.verify_calls = 0

    @property
    def issuer_fingerprint(self) -> str:
        return ISSUER

    def sign(self, payload_bytes: bytes) -> str:
        with self._lock:
            self._counter += 1
            signature = f"test-signature-{self._counter}"
            self._signed[signature] = payload_bytes
        return signature

    def verify(self, token) -> bool:
        with self._lock:
            self.verify_calls += 1
            return (
                self._signed.get(token.signature or "") == token.payload.model_dump_json().encode()
            )


class CountingReplay(InMemoryReplayBackend):
    def __init__(self, *, clock) -> None:
        super().__init__(clock=clock)
        self.reserve_calls = 0

    def reserve(self, **values) -> bool:
        self.reserve_calls += 1
        return super().reserve(**values)


class OwnerPolicy:
    def __init__(self, values=None) -> None:
        self.values = list(values or [])
        self.calls = []
        self._lock = Lock()

    def decide(self, binding, capauth_decision):
        with self._lock:
            self.calls.append((binding, capauth_decision))
            if self.values:
                value = self.values.pop(0)
                if isinstance(value, Exception):
                    raise value
                return value
        return _owner(binding)


class Rig:
    def __init__(self, principal: Principal | None = None) -> None:
        self.clock = Clock()
        self.signer = RegistrySigner()
        self.principal = principal or Principal(
            principal_id="human-1", subject="human@example.test", kind="human"
        )
        self.binding = ControlPlaneBinding(
            principal=self.principal,
            agent_id=(self.principal.principal_id if self.principal.kind == "agent" else None),
            node_id="chiap04",
            purpose="read authorized project snapshot",
            capability="skdashboard.read",
            target="/api/v1/overview",
            resource_type="skcoord.card_store.project_snapshot",
            resource_id="authorized-card-set:sha256:" + "1" * 64,
            owner_policy_revision=OWNER_REVISION,
            expires_at=NOW + timedelta(minutes=1),
        )
        self.principals = InMemoryPrincipalPolicyBackend((self.principal,))
        self.revocations = InMemoryRevocationBackend()
        self.replay = CountingReplay(clock=self.clock)
        self.audit = InMemoryAuditSink()
        self.trusted = StaticTrustedIssuerBackend(
            (
                IssuerGrant(
                    fingerprint=ISSUER,
                    capabilities=frozenset({"skdashboard.read"}),
                    audiences=frozenset({"skdashboard"}),
                    principal_kinds=frozenset({"human", "agent"}),
                ),
            )
        )
        self.capability_authorizer = CapabilityAuthorizer(
            trusted_issuers=self.trusted,
            principals=self.principals,
            revocations=self.revocations,
            replay=self.replay,
            audit=self.audit,
            signature_verifier=self.signer,
            clock=self.clock,
        )
        self.issuer = CapabilityIssuer(self.signer, clock=self.clock)

    def bearer(self, *, ttl_seconds: int = 60) -> str:
        presented = self.issuer.issue_root(
            principal=self.principal,
            scope=self.binding.capability_scope(),
            ttl_seconds=ttl_seconds,
        )
        return export_control_plane_bearer(presented)

    def invocation(self, **changes) -> ControlPlaneInvocationV1:
        values = {
            "node_id": self.binding.node_id,
            "purpose": self.binding.purpose,
            "capability": self.binding.capability,
            "target": self.binding.target,
            "resource_type": self.binding.resource_type,
            "resource_id": self.binding.resource_id,
            "correlation_id": "request-1",
            "boundary": RequestBoundary(client_kind=ClientKind.BROWSER, origin=ORIGIN),
        }
        values.update(changes)
        return ControlPlaneInvocationV1(**values)

    def authorizer(self, owner=None, **changes) -> ControlPlaneDecisionAuthorizer:
        values = {
            "capability_authorizer": self.capability_authorizer,
            "owner_policy": owner or OwnerPolicy(),
            "allowed_origins": frozenset({ORIGIN}),
            "clock": self.clock,
        }
        values.update(changes)
        return ControlPlaneDecisionAuthorizer(**values)


def _owner(binding, state=DecisionState.ALLOW, **changes):
    values = {
        "state": state,
        "revision": (
            binding.owner_policy_revision
            if state in {DecisionState.ALLOW, DecisionState.DENY}
            else None
        ),
        "resource_type": binding.resource_type,
        "resource_id": binding.resource_id,
        "reason_code": f"owner_{state.value}",
    }
    values.update(changes)
    return OwnerPolicyDecision(**values)


def _allow(rig: Rig, *, bearer=None, owner=None):
    return rig.authorizer(owner).authorize(bearer or rig.bearer(), rig.invocation())


def _request(rig: Rig) -> AuthorizationRequest:
    return AuthorizationRequest(
        principal=rig.binding.principal,
        scope=rig.binding.capability_scope(),
        correlation_id="request-1",
    )


def _keys(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from _keys(item)


def test_canonical_direct_bearer_returns_sanitized_attributable_allow() -> None:
    rig = Rig()
    result = _allow(rig)

    assert result.allow is True
    assert result.state is DecisionState.ALLOW
    assert result.code is DecisionCode.ALLOW
    context = result.context
    assert context is not None
    assert context.binding == rig.binding
    assert context.joined_decision.capauth_decision_id == context.capauth_decision.decision_id
    assert context.authenticated_identity_ref.startswith("sha256:")
    assert context.issued_at == NOW
    assert context.expires_at == NOW + timedelta(minutes=1)
    assert context.capauth_decision.trusted_issuer_policy_revision
    assert context.capauth_decision.revocation_revision

    with pytest.raises(ValueError, match="identity reference"):
        SanitizedControlPlaneDecisionV1(
            binding=context.binding,
            boundary=context.boundary,
            capauth_decision=context.capauth_decision,
            joined_decision=context.joined_decision,
            authenticated_identity_ref="sha256:" + "0" * 64,
            issued_at=context.issued_at,
            expires_at=context.expires_at,
        )
    assert rig.signer.verify_calls == 1
    assert rig.replay.reserve_calls == 1


def test_canonical_delegated_chain_returns_the_agent_context() -> None:
    clock = Clock()
    signer = RegistrySigner()
    human = Principal(principal_id="human-parent", subject="parent@test", kind="human")
    agent = Principal(principal_id="agent-child", subject="agent@test", kind="agent")
    parent = ControlPlaneBinding(
        principal=human,
        node_id="chiap04",
        purpose="read authorized project snapshot",
        capability="skdashboard.read",
        target="/api/v1/overview",
        resource_type="skcoord.card_store.project_snapshot",
        resource_id="authorized-card-set:sha256:" + "1" * 64,
        owner_policy_revision=OWNER_REVISION,
        expires_at=NOW + timedelta(seconds=30),
    )
    child = parent.model_copy(update={"principal": agent, "agent_id": agent.principal_id})
    principals = InMemoryPrincipalPolicyBackend((human, agent))
    revocations = InMemoryRevocationBackend()
    authorizer = CapabilityAuthorizer(
        trusted_issuers=StaticTrustedIssuerBackend(
            (
                IssuerGrant(
                    fingerprint=ISSUER,
                    capabilities=frozenset({"skdashboard.read"}),
                    audiences=frozenset({"skdashboard"}),
                    principal_kinds=frozenset({"human", "agent"}),
                ),
            )
        ),
        principals=principals,
        revocations=revocations,
        replay=InMemoryReplayBackend(clock=clock),
        audit=InMemoryAuditSink(),
        signature_verifier=signer,
        clock=clock,
    )
    issuer = CapabilityIssuer(signer, clock=clock)
    root = issuer.issue_root(
        principal=human,
        scope=parent.capability_scope(),
        ttl_seconds=30,
        max_delegation_depth=1,
    )
    delegated = DelegatingCapabilityIssuer(authorizer=authorizer, issuer=issuer).delegate(
        parent=root,
        authenticated_parent=human,
        child_principal=agent,
        child_scope=child.capability_scope(),
        correlation_id="delegate-agent",
        ttl_seconds=30,
    )
    invocation = ControlPlaneInvocationV1(
        node_id=child.node_id,
        purpose=child.purpose,
        capability=child.capability,
        target=child.target,
        resource_type=child.resource_type,
        resource_id=child.resource_id,
        correlation_id="request-agent",
        boundary=RequestBoundary(client_kind=ClientKind.AGENT),
    )
    result = ControlPlaneDecisionAuthorizer(
        capability_authorizer=authorizer,
        owner_policy=OwnerPolicy(),
        allowed_origins=frozenset({ORIGIN}),
        clock=clock,
    ).authorize(export_control_plane_bearer(delegated), invocation)
    assert result.allow is True
    assert result.context.binding.principal == agent
    assert result.context.binding.agent_id == agent.principal_id
    assert result.context.capauth_decision.delegation_depth == 1


def test_agent_constraint_must_name_the_signed_agent_principal() -> None:
    principal = Principal(principal_id="agent-real", subject="agent@test", kind="agent")
    rig = Rig(principal)
    rig.binding = rig.binding.model_copy(update={"agent_id": "agent-other"})
    owner = OwnerPolicy()
    result = rig.authorizer(owner).authorize(rig.bearer(), rig.invocation())
    assert result.code is DecisionCode.CAPAUTH_DENIED
    assert owner.calls == []


def test_exact_five_minute_lifetime_is_allowed() -> None:
    rig = Rig()
    rig.binding = rig.binding.model_copy(update={"expires_at": NOW + timedelta(minutes=5)})
    result = _allow(rig, bearer=rig.bearer(ttl_seconds=300))
    assert result.allow is True
    assert result.context.expires_at - result.context.issued_at == timedelta(minutes=5)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.rstrip("="),
        lambda value: value + "\n",
        lambda value: "{" + value[1:],
        lambda value: "%%%%",
        lambda value: value.replace("-", "+", 1) if "-" in value else "+" + value[1:],
    ],
)
def test_noncanonical_transport_is_one_generic_deny(mutate) -> None:
    rig = Rig()
    result = rig.authorizer().authorize(mutate(rig.bearer()), rig.invocation())
    assert result.model_dump(mode="json") == {
        "schema_version": "capauth-control-plane-authorization-result/v1",
        "allow": False,
        "state": "deny",
        "code": "capauth_denied",
        "context": None,
    }


def test_transport_parser_rejects_raw_json_and_oversize_without_echo() -> None:
    rig = Rig()
    bearer = rig.bearer()
    decoded = parse_control_plane_bearer(bearer)
    raw = decoded.credentials_for_verification()[-1]
    with pytest.raises(ValueError, match="malformed") as raw_error:
        parse_control_plane_bearer(raw)
    with pytest.raises(ValueError, match="malformed") as size_error:
        parse_control_plane_bearer("A" * (MAX_CONTROL_PLANE_BEARER_BYTES + 1))
    assert raw not in str(raw_error.value)
    assert bearer not in str(size_error.value)


@pytest.mark.parametrize(
    "constraints",
    [
        frozenset({"node:chiap04", "purpose:read authorized project snapshot"}),
        frozenset(
            {
                "node:chiap04",
                "purpose:read authorized project snapshot",
                f"owner-policy-revision:{OWNER_REVISION}",
                "expires-at:2026-08-24T12:01:00Z",
                "unknown:value",
            }
        ),
        frozenset(
            {
                "node:chiap04",
                "node:other",
                "purpose:read authorized project snapshot",
                f"owner-policy-revision:{OWNER_REVISION}",
                "expires-at:2026-08-24T12:01:00Z",
            }
        ),
    ],
)
def test_malformed_signed_constraint_sets_deny_before_owner_policy(constraints) -> None:
    rig = Rig()
    owner = OwnerPolicy()
    scope = CapabilityScope(
        **{
            **rig.binding.capability_scope().model_dump(),
            "constraints": constraints,
        }
    )
    bearer = export_control_plane_bearer(
        rig.issuer.issue_root(principal=rig.principal, scope=scope, ttl_seconds=60)
    )
    result = rig.authorizer(owner).authorize(bearer, rig.invocation())
    assert result.code is DecisionCode.CAPAUTH_DENIED
    assert owner.calls == []


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"node_id": "other"}, DecisionCode.CAPAUTH_DENIED),
        ({"purpose": "other"}, DecisionCode.CAPAUTH_DENIED),
        ({"capability": "skdashboard.events.read"}, DecisionCode.CAPAUTH_DENIED),
        ({"target": "/api/v1/other"}, DecisionCode.CAPAUTH_DENIED),
        ({"resource_type": "other"}, DecisionCode.CAPAUTH_DENIED),
        ({"resource_id": "other"}, DecisionCode.CAPAUTH_DENIED),
    ],
)
def test_invocation_mismatch_denies_before_one_use_consumption(change, code) -> None:
    rig = Rig()
    bearer = rig.bearer()
    denied = rig.authorizer().authorize(bearer, rig.invocation(**change))
    allowed = rig.authorizer().authorize(bearer, rig.invocation())
    assert denied.code is code
    assert allowed.allow is True


@pytest.mark.parametrize(
    ("boundary", "origins", "code"),
    [
        (RequestBoundary(client_kind=ClientKind.BROWSER), {ORIGIN}, DecisionCode.CORS_DENIED),
        (
            RequestBoundary(client_kind=ClientKind.BROWSER, origin="https://public.test"),
            {ORIGIN},
            DecisionCode.CORS_DENIED,
        ),
        (
            RequestBoundary(client_kind=ClientKind.SERVICE),
            {ORIGIN},
            DecisionCode.INVALID_CLIENT,
        ),
    ],
)
def test_boundary_denial_does_not_consume_bearer(boundary, origins, code) -> None:
    rig = Rig()
    bearer = rig.bearer()
    denied = rig.authorizer(allowed_origins=frozenset(origins)).authorize(
        bearer, rig.invocation(boundary=boundary)
    )
    allowed = rig.authorizer().authorize(bearer, rig.invocation())
    assert denied.code is code
    assert allowed.allow is True


def test_wildcard_origin_configuration_is_rejected() -> None:
    rig = Rig()
    with pytest.raises(ValueError, match="wildcard"):
        rig.authorizer(allowed_origins=frozenset({"*"}))


@pytest.mark.parametrize(
    ("state", "expected_state", "expected_code"),
    [
        (DecisionState.DENY, DecisionState.DENY, DecisionCode.OWNER_DENIED),
        (DecisionState.UNKNOWN, DecisionState.UNKNOWN, DecisionCode.OWNER_POLICY_UNKNOWN),
        (
            DecisionState.UNAVAILABLE,
            DecisionState.UNAVAILABLE,
            DecisionCode.OWNER_POLICY_UNAVAILABLE,
        ),
    ],
)
def test_owner_non_allow_is_typed_and_carries_no_policy_detail(
    state, expected_state, expected_code
) -> None:
    rig = Rig()
    owner = OwnerPolicy([_owner(rig.binding, state), _owner(rig.binding, state)])
    result = _allow(rig, owner=owner)
    assert result.allow is False
    assert result.state is expected_state
    assert result.code is expected_code
    assert result.context is None
    assert rig.binding.resource_id not in result.model_dump_json()


def test_owner_allow_reason_is_never_part_of_the_sanitized_context() -> None:
    rig = Rig()
    secret = "SECRET-TENANT-42-RAW-POLICY-DETAIL"
    decision = _owner(rig.binding, reason_code=secret)
    result = _allow(rig, owner=OwnerPolicy([decision, decision]))
    serialized = result.model_dump_json()
    assert result.allow is True
    assert secret not in serialized
    assert "owner_decision" not in serialized
    assert "reason_code" not in serialized


def test_owner_exception_none_mismatch_and_race_fail_closed() -> None:
    for owner, expected in (
        (OwnerPolicy([RuntimeError("SECRET")]), DecisionCode.OWNER_POLICY_UNAVAILABLE),
        (OwnerPolicy([None]), DecisionCode.OWNER_POLICY_UNAVAILABLE),
        (
            OwnerPolicy(
                [
                    _owner(Rig().binding),
                    _owner(Rig().binding, resource_id="different"),
                ]
            ),
            DecisionCode.BINDING_MISMATCH,
        ),
    ):
        rig = Rig()
        result = _allow(rig, owner=owner)
        assert result.allow is False
        assert result.code is expected
        assert "SECRET" not in result.model_dump_json()


def test_wrong_owner_provider_result_type_is_unavailable() -> None:
    rig = Rig()

    class WrongTypeOwner:
        def decide(self, _binding, _capauth_decision):
            return {"state": "allow"}

    result = _allow(rig, owner=WrongTypeOwner())
    assert result.state is DecisionState.UNAVAILABLE
    assert result.code is DecisionCode.OWNER_POLICY_UNAVAILABLE
    assert result.context is None


def test_expiry_boundary_and_expiry_during_owner_work_fail_closed() -> None:
    rig = Rig()
    bearer = rig.bearer()
    rig.clock.value = rig.binding.expires_at
    assert rig.authorizer().authorize(bearer, rig.invocation()).code is DecisionCode.EXPIRED

    rig = Rig()

    class ExpiringOwner(OwnerPolicy):
        def decide(self, binding, capauth_decision):
            value = super().decide(binding, capauth_decision)
            rig.clock.value = binding.expires_at
            return value

    result = _allow(rig, owner=ExpiringOwner())
    assert result.code is DecisionCode.CAPAUTH_DENIED
    assert result.context is None


def test_revocation_after_prior_allow_has_no_stale_context() -> None:
    rig = Rig()
    assert _allow(rig).allow is True
    bearer = rig.bearer()
    raw = parse_control_plane_bearer(bearer).credentials_for_verification()[-1]
    rig.revocations.revoke(parse_presented_token(raw).credential_digest)
    result = rig.authorizer().authorize(bearer, rig.invocation())
    assert result.allow is False
    assert result.code is DecisionCode.CAPAUTH_DENIED
    assert result.context is None


def test_revocation_during_owner_evaluation_denies_without_second_consumption() -> None:
    rig = Rig()

    class RevokingOwner(OwnerPolicy):
        def decide(self, binding, capauth_decision):
            value = super().decide(binding, capauth_decision)
            if len(self.calls) == 1:
                rig.revocations.revoke(capauth_decision.credential_digest)
            return value

    result = _allow(rig, owner=RevokingOwner())
    assert result.allow is False
    assert result.code is DecisionCode.CAPAUTH_DENIED
    assert result.context is None
    decisions = rig.audit.decisions()
    assert len(decisions) == 2
    assert decisions[0].allow is True
    assert decisions[1].allow is False
    assert decisions[1].attempt_sequence == 2
    assert decisions[1].decision_id == decisions[0].decision_id
    assert rig.signer.verify_calls == 1
    assert rig.replay.reserve_calls == 1


def test_principal_revision_change_during_owner_evaluation_denies() -> None:
    rig = Rig()

    class RevisingOwner(OwnerPolicy):
        def decide(self, binding, capauth_decision):
            value = super().decide(binding, capauth_decision)
            if len(self.calls) == 1:
                rig.principals.set(rig.principal)
            return value

    result = _allow(rig, owner=RevisingOwner())
    assert result.allow is False
    assert result.code is DecisionCode.CAPAUTH_DENIED
    assert result.context is None
    assert rig.audit.decisions()[-1].reason.value == "current_state_changed"
    assert rig.signer.verify_calls == 1
    assert rig.replay.reserve_calls == 1


def test_owner_final_read_detects_change_during_capauth_revalidation() -> None:
    rig = Rig()

    class MutableOwner(OwnerPolicy):
        state = DecisionState.ALLOW

        def decide(self, binding, capauth_decision):
            with self._lock:
                self.calls.append((binding, capauth_decision))
            return _owner(binding, self.state)

    owner = MutableOwner()

    class OwnerFlippingRevocations(InMemoryRevocationBackend):
        def __init__(self) -> None:
            super().__init__()
            self.calls = 0

        def snapshot(self, credential_digests):
            self.calls += 1
            if self.calls == 4:
                owner.state = DecisionState.DENY
            return super().snapshot(credential_digests)

    rig.revocations = OwnerFlippingRevocations()
    rig.capability_authorizer = CapabilityAuthorizer(
        trusted_issuers=rig.trusted,
        principals=rig.principals,
        revocations=rig.revocations,
        replay=rig.replay,
        audit=rig.audit,
        signature_verifier=rig.signer,
        clock=rig.clock,
    )
    result = _allow(rig, owner=owner)
    assert result.allow is False
    assert result.code is DecisionCode.BINDING_MISMATCH
    assert len(owner.calls) == 2
    assert rig.signer.verify_calls == 1
    assert rig.replay.reserve_calls == 1


def test_forged_prior_and_signature_cannot_use_a_genuine_or_fake_receipt() -> None:
    rig = Rig()
    bearer = rig.bearer()
    presented = parse_control_plane_bearer(bearer)
    request = _request(rig)
    prior, receipt = rig.capability_authorizer.authorize_with_receipt(presented, request)
    raw = presented.credentials_for_verification()[-1]
    forged_wire = json.loads(raw)
    forged_wire["signature"] = "attacker-forged-signature"
    forged_presented = PresentedCapability.single(
        json.dumps(forged_wire, sort_keys=True, separators=(",", ":"))
    )
    forged_leaf = parse_presented_token(forged_presented.credentials_for_verification()[-1])
    forged_prior = prior.model_copy(update={"credential_digest": forged_leaf.credential_digest})
    fake_receipt = AuthorizationCurrentnessReceipt(b"n" * 32, b"m" * 32)
    before = rig.audit.decisions()
    for candidate in (receipt, fake_receipt):
        with pytest.raises(AuthorizationReceiptError, match="receipt is invalid"):
            rig.capability_authorizer.revalidate_current(
                forged_presented, request, forged_prior, candidate
            )
    assert rig.audit.decisions() == before
    assert rig.signer.verify_calls == 1
    assert rig.replay.reserve_calls == 1


def test_receipt_is_one_use_cross_instance_bound_and_nonserializable() -> None:
    rig = Rig()
    presented = parse_control_plane_bearer(rig.bearer())
    request = _request(rig)
    prior, receipt = rig.capability_authorizer.authorize_with_receipt(presented, request)
    assert repr(receipt) == "<redacted authorization currentness receipt>"
    for operation in (
        lambda: copy.copy(receipt),
        lambda: copy.deepcopy(receipt),
        lambda: pickle.dumps(receipt),
    ):
        with pytest.raises(TypeError):
            operation()
    foreign = Rig().capability_authorizer
    with pytest.raises(AuthorizationReceiptError):
        foreign.revalidate_current(presented, request, prior, receipt)
    assert (
        rig.capability_authorizer.revalidate_current(presented, request, prior, receipt) is prior
    )
    with pytest.raises(AuthorizationReceiptError):
        rig.capability_authorizer.revalidate_current(presented, request, prior, receipt)


def test_receipt_accepts_before_expiry_and_is_invalid_and_pruned_at_expiry() -> None:
    before = Rig()
    before.binding = before.binding.model_copy(update={"expires_at": NOW + timedelta(seconds=1)})
    presented = parse_control_plane_bearer(before.bearer(ttl_seconds=1))
    request = _request(before)
    prior, receipt = before.capability_authorizer.authorize_with_receipt(presented, request)
    before.clock.value = before.binding.expires_at - timedelta(microseconds=1)
    assert (
        before.capability_authorizer.revalidate_current(presented, request, prior, receipt)
        is prior
    )

    expired = Rig()
    expired.binding = expired.binding.model_copy(update={"expires_at": NOW + timedelta(seconds=1)})
    presented = parse_control_plane_bearer(expired.bearer(ttl_seconds=1))
    request = _request(expired)
    prior, receipt = expired.capability_authorizer.authorize_with_receipt(presented, request)
    expired.clock.value = expired.binding.expires_at
    with pytest.raises(AuthorizationReceiptError, match="receipt is invalid"):
        expired.capability_authorizer.revalidate_current(presented, request, prior, receipt)
    assert expired.capability_authorizer._receipt_expiries == {}


def test_receipt_race_allows_exactly_one_currentness_revalidation() -> None:
    rig = Rig()
    presented = parse_control_plane_bearer(rig.bearer())
    request = _request(rig)
    prior, receipt = rig.capability_authorizer.authorize_with_receipt(presented, request)
    nonce, mac = receipt._proof()
    cloned_receipt = AuthorizationCurrentnessReceipt(nonce, mac)
    barrier = Barrier(2)
    outcomes = []

    def worker(candidate) -> None:
        barrier.wait()
        try:
            outcomes.append(
                rig.capability_authorizer.revalidate_current(presented, request, prior, candidate)
            )
        except AuthorizationReceiptError as exc:
            outcomes.append(exc)

    threads = [Thread(target=worker, args=(candidate,)) for candidate in (receipt, cloned_receipt)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sum(value is prior for value in outcomes) == 1
    assert sum(isinstance(value, AuthorizationReceiptError) for value in outcomes) == 1
    assert rig.signer.verify_calls == 1
    assert rig.replay.reserve_calls == 1


def test_bad_signature_never_reaches_owner_policy() -> None:
    rig = Rig()
    owner = OwnerPolicy()
    bearer = rig.bearer()
    presented = parse_control_plane_bearer(bearer)
    raw = presented.credentials_for_verification()[-1]
    corrupted = json.loads(raw)
    corrupted["signature"] = "not-a-valid-signature"
    presented = PresentedCapability.single(
        json.dumps(corrupted, sort_keys=True, separators=(",", ":"))
    )
    result = rig.authorizer(owner).authorize(
        export_control_plane_bearer(presented), rig.invocation()
    )
    assert result.code is DecisionCode.CAPAUTH_DENIED
    assert owner.calls == []


def test_backend_and_audit_unavailability_are_typed_unavailable() -> None:
    rig = Rig()

    class UnavailableAudit:
        def record(self, _decision):
            raise RuntimeError("unavailable")

    rig.capability_authorizer = CapabilityAuthorizer(
        trusted_issuers=rig.trusted,
        principals=rig.principals,
        revocations=rig.revocations,
        replay=rig.replay,
        audit=UnavailableAudit(),
        signature_verifier=rig.signer,
        clock=rig.clock,
    )
    result = _allow(rig)
    assert result.state is DecisionState.UNAVAILABLE
    assert result.code is DecisionCode.CAPAUTH_UNAVAILABLE
    assert result.context is None


def test_identity_reference_changes_with_principal_credential_and_revision() -> None:
    first = Rig()
    first_result = _allow(first)
    second_result = _allow(first)
    other = Rig(Principal(principal_id="human-2", subject="other@example.test", kind="human"))
    other_result = _allow(other)
    refs = {
        first_result.context.authenticated_identity_ref,
        second_result.context.authenticated_identity_ref,
        other_result.context.authenticated_identity_ref,
    }
    assert len(refs) == 3


def test_identity_reference_changes_when_current_principal_revision_changes() -> None:
    rig = Rig()
    bearer = rig.bearer()
    first = rig.authorizer().authorize(bearer, rig.invocation())
    rig.principals.set(rig.principal)
    rig.replay = CountingReplay(clock=rig.clock)
    rig.capability_authorizer = CapabilityAuthorizer(
        trusted_issuers=rig.trusted,
        principals=rig.principals,
        revocations=rig.revocations,
        replay=rig.replay,
        audit=rig.audit,
        signature_verifier=rig.signer,
        clock=rig.clock,
    )
    second = rig.authorizer().authorize(bearer, rig.invocation())
    assert first.allow is True
    assert second.allow is True
    assert first.context.capauth_decision.credential_digest == (
        second.context.capauth_decision.credential_digest
    )
    assert first.context.authenticated_identity_ref != second.context.authenticated_identity_ref


def test_two_concurrent_principals_receive_only_their_own_context() -> None:
    rigs = [
        Rig(Principal(principal_id=f"human-{index}", subject=f"h{index}@test", kind="human"))
        for index in (1, 2)
    ]
    barrier = Barrier(2)
    results = []

    def worker(rig):
        bearer = rig.bearer()
        barrier.wait()
        results.append(rig.authorizer().authorize(bearer, rig.invocation()))

    threads = [Thread(target=worker, args=(rig,)) for rig in rigs]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert {result.context.binding.principal.principal_id for result in results} == {
        "human-1",
        "human-2",
    }


def test_serialization_repr_errors_and_logs_never_contain_raw_material(caplog) -> None:
    rig = Rig()
    bearer = rig.bearer()
    raw = parse_control_plane_bearer(bearer).credentials_for_verification()[-1]
    signature = parse_presented_token(raw).token.signature
    with caplog.at_level(logging.DEBUG):
        result = rig.authorizer().authorize(bearer, rig.invocation())
    serialized = result.model_dump_json()
    combined = " ".join((serialized, repr(result), caplog.text))
    assert bearer not in combined
    assert raw not in combined
    assert signature not in combined
    forbidden = {
        "bearer",
        "raw_token",
        "signature",
        "capability_chain",
        "presented_capability",
        "secret",
        "raw_policy",
    }
    assert not forbidden & set(_keys(json.loads(serialized)))
