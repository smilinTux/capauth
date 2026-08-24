"""Delegated-capability tests using exact SKDashboard policy bindings."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from threading import Lock

import pytest

from capauth.control_plane import (
    ControlPlaneBinding,
    DecisionState,
    OwnerPolicyDecision,
    join_policy_decisions,
)
from capauth.delegated import (
    AuthorizationDeniedError,
    AuthorizationRequest,
    CapabilityAuthorizer,
    CapabilityIssuer,
    DecisionReason,
    DelegatingCapabilityIssuer,
    DelegationDeniedError,
    InMemoryAuditSink,
    InMemoryPrincipalPolicyBackend,
    InMemoryReplayBackend,
    InMemoryRevocationBackend,
    IssuerGrant,
    Principal,
    StaticTrustedIssuerBackend,
    parse_presented_token,
)

UTC = timezone.utc
ISSUER = "A" * 40
REVISION = "b" * 64


class Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.value


class RegistrySigner:
    """Test-only signature registry with deterministic verification."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._signed: dict[str, bytes] = {}
        self._counter = 0

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
        return self._signed.get(token.signature or "") == token.payload.model_dump_json().encode()


class UnavailableIssuerPolicy:
    def snapshot(self):
        raise RuntimeError("unavailable")


class Rig:
    def __init__(self, *, max_delegation_depth: int = 1) -> None:
        self.clock = Clock()
        self.signer = RegistrySigner()
        self.human = Principal(principal_id="human-1", subject="human@example.test", kind="human")
        self.agent = Principal(principal_id="agent-1", subject="agent@example.test", kind="agent")
        self.binding = ControlPlaneBinding(
            principal=self.human,
            node_id="node-1",
            purpose="route coordination command",
            capability="skdashboard.commands.coordination",
            target="coordination.claim",
            resource_type="work-card",
            resource_id="card-1",
            owner_policy_revision=REVISION,
            expires_at=self.clock() + timedelta(minutes=1),
        )
        self.principals = InMemoryPrincipalPolicyBackend((self.human, self.agent))
        self.revocations = InMemoryRevocationBackend()
        self.replay = InMemoryReplayBackend(clock=self.clock)
        self.audit = InMemoryAuditSink()
        self.trusted = StaticTrustedIssuerBackend(
            (
                IssuerGrant(
                    fingerprint=ISSUER,
                    capabilities=frozenset({self.binding.capability}),
                    audiences=frozenset({self.binding.audience}),
                    principal_kinds=frozenset({"human", "agent"}),
                ),
            )
        )
        self.issuer = CapabilityIssuer(self.signer, clock=self.clock)
        self.authorizer = self.new_authorizer()
        self.presented = self.issuer.issue_root(
            principal=self.human,
            scope=self.binding.capability_scope(),
            ttl_seconds=60,
            max_delegation_depth=max_delegation_depth,
        )

    def new_authorizer(self, **overrides) -> CapabilityAuthorizer:
        values = {
            "trusted_issuers": self.trusted,
            "principals": self.principals,
            "revocations": self.revocations,
            "replay": self.replay,
            "audit": self.audit,
            "signature_verifier": self.signer,
            "clock": self.clock,
        }
        values.update(overrides)
        return CapabilityAuthorizer(**values)

    def request(self, value: ControlPlaneBinding | None = None) -> AuthorizationRequest:
        selected = value or self.binding
        return AuthorizationRequest(
            principal=selected.principal,
            scope=selected.capability_scope(),
            correlation_id="request-1",
        )

    def owner_allow(self, value: ControlPlaneBinding | None = None) -> OwnerPolicyDecision:
        selected = value or self.binding
        return OwnerPolicyDecision(
            state=DecisionState.ALLOW,
            revision=selected.owner_policy_revision,
            resource_type=selected.resource_type,
            resource_id=selected.resource_id,
            reason_code="owner_allow",
        )


def denial_reason(authorizer, presented, request) -> DecisionReason:
    with pytest.raises(AuthorizationDeniedError) as caught:
        authorizer.authorize(presented, request)
    return caught.value.decision.reason


def test_exact_delegated_capability_and_owner_policy_join_allow() -> None:
    rig = Rig()

    capauth = rig.authorizer.authorize(rig.presented, rig.request())
    decision = join_policy_decisions(rig.binding, capauth, rig.owner_allow())

    assert decision.allow is True
    assert decision.state is DecisionState.ALLOW
    assert decision.capauth_decision_id == capauth.decision_id


def test_one_use_replay_fails_closed() -> None:
    rig = Rig()
    rig.authorizer.authorize(rig.presented, rig.request())

    assert denial_reason(rig.authorizer, rig.presented, rig.request()) is DecisionReason.REPLAYED


def test_revocation_fails_closed_before_use() -> None:
    rig = Rig()
    raw = rig.presented.credentials_for_verification()[-1]
    rig.revocations.revoke(parse_presented_token(raw).credential_digest)

    assert denial_reason(rig.authorizer, rig.presented, rig.request()) is DecisionReason.REVOKED


def test_principal_rotation_invalidates_old_binding() -> None:
    rig = Rig()
    rotated = rig.human.model_copy(update={"subject": "rotated@example.test"})
    rig.principals.set(rotated)

    assert (
        denial_reason(rig.authorizer, rig.presented, rig.request())
        is DecisionReason.PRINCIPAL_REBOUND
    )


def test_policy_backend_unavailable_fails_closed() -> None:
    rig = Rig()
    authorizer = rig.new_authorizer(trusted_issuers=UnavailableIssuerPolicy())

    assert (
        denial_reason(authorizer, rig.presented, rig.request())
        is DecisionReason.BACKEND_UNAVAILABLE
    )


def test_delegation_can_only_narrow_exact_control_plane_scope() -> None:
    rig = Rig()
    delegator = DelegatingCapabilityIssuer(authorizer=rig.authorizer, issuer=rig.issuer)
    broader = rig.binding.capability_scope().model_copy(update={"resource_id": None})

    with pytest.raises(DelegationDeniedError, match="broaden"):
        delegator.delegate(
            parent=rig.presented,
            authenticated_parent=rig.human,
            child_principal=rig.agent,
            child_scope=broader,
            correlation_id="delegate-broad",
        )


def test_valid_delegation_binds_agent_and_retains_parent_limits() -> None:
    rig = Rig()
    agent_binding = rig.binding.model_copy(update={"principal": rig.agent, "agent_id": "agent-1"})
    delegated = DelegatingCapabilityIssuer(authorizer=rig.authorizer, issuer=rig.issuer).delegate(
        parent=rig.presented,
        authenticated_parent=rig.human,
        child_principal=rig.agent,
        child_scope=agent_binding.capability_scope(),
        correlation_id="delegate-agent",
        ttl_seconds=30,
    )

    decision = rig.authorizer.authorize(delegated, rig.request(agent_binding))

    assert decision.allow is True
    assert decision.delegation_depth == 1
    assert "agent:agent-1" in decision.scope.constraints


def test_decisions_and_errors_never_leak_presented_capability() -> None:
    rig = Rig()
    raw = rig.presented.credentials_for_verification()[-1]
    decision = rig.authorizer.authorize(rig.presented, rig.request())

    assert raw not in repr(rig.presented)
    assert raw not in decision.model_dump_json()
    with pytest.raises(AuthorizationDeniedError) as caught:
        rig.authorizer.authorize(rig.presented, rig.request())
    assert raw not in str(caught.value)
    assert raw not in caught.value.decision.model_dump_json()
