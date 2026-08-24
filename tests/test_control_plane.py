"""Contract tests for the SKDashboard CapAuth policy boundary."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from capauth.authz import DEFAULT_RULES
from capauth.control_plane import (
    CAPABILITY_MATRIX,
    ISSUANCE_PROFILES,
    SERVICE_IDENTITIES,
    ClientKind,
    ControlPlaneBinding,
    DecisionCode,
    DecisionState,
    IssuanceMode,
    OperationClass,
    OwnerPolicyDecision,
    RequestBoundary,
    join_policy_decisions,
    validate_request_boundary,
)
from capauth.delegated import (
    AuthorizationDecision,
    DecisionReason,
    Principal,
)
from capauth.pairing import EnrollmentMode
from capauth.tokens import AUDIENCE_SCOPES

UTC = timezone.utc
NOW = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)
REVISION = "a" * 64


def binding(
    *,
    capability: str = "skdashboard.actions.authorize",
    principal: Principal | None = None,
    expires_at: datetime | None = None,
) -> ControlPlaneBinding:
    return ControlPlaneBinding(
        principal=principal
        or Principal(principal_id="human-1", subject="human@example.test", kind="human"),
        node_id="node-1",
        purpose="approve exact preview",
        capability=capability,
        target="coordination.claim",
        resource_type="work-card",
        resource_id="card-1",
        owner_policy_revision=REVISION,
        expires_at=expires_at or NOW + timedelta(minutes=2),
    )


def capauth_decision(value: ControlPlaneBinding, *, reason=DecisionReason.ALLOW):
    allowed = reason is DecisionReason.ALLOW
    return AuthorizationDecision(
        decision_id="decision-1",
        correlation_id="request-1",
        allow=allowed,
        reason=reason,
        credential_digest="b" * 64,
        principal_id=value.principal.principal_id,
        scope=value.capability_scope(),
        delegation_depth=0,
        trusted_issuer_policy_revision="c" * 64,
        revocation_revision="d" * 64,
    )


def owner_decision(
    value: ControlPlaneBinding, state: DecisionState = DecisionState.ALLOW
) -> OwnerPolicyDecision:
    return OwnerPolicyDecision(
        state=state,
        revision=(
            value.owner_policy_revision
            if state in {DecisionState.ALLOW, DecisionState.DENY}
            else None
        ),
        resource_type=value.resource_type,
        resource_id=value.resource_id,
        reason_code=f"owner_{state.value}",
    )


def test_capability_matrix_is_closed_and_separates_operation_families() -> None:
    by_family = {entry.family: entry for entry in CAPABILITY_MATRIX}

    assert len(by_family) == len(CAPABILITY_MATRIX)
    assert by_family["anonymous_discovery"].capability is None
    assert by_family["read_projections"].operation is OperationClass.READ
    assert by_family["event_streams"].capability == "skdashboard.events.read"
    assert by_family["insight_proposals"].operation is OperationClass.PROPOSE
    assert by_family["action_authorization"].operation is OperationClass.MUTATE
    assert {
        "coordination_commands",
        "cmdb_commands",
        "service_operations",
        "report_delivery",
    } <= {entry.family for entry in CAPABILITY_MATRIX if entry.operation is OperationClass.MUTATE}
    protected = [entry.capability for entry in CAPABILITY_MATRIX if entry.capability]
    assert len(protected) == len(set(protected))


def test_audience_default_is_read_only_and_pdp_floors_match_sensitivity() -> None:
    assert AUDIENCE_SCOPES["skdashboard"] == ["skdashboard.read"]
    assert DEFAULT_RULES["skdashboard.read"].minimum_mode is EnrollmentMode.TOFU
    assert DEFAULT_RULES["skdashboard.insights.query"].minimum_mode is EnrollmentMode.ATTESTED
    assert (
        DEFAULT_RULES["skdashboard.commands.coordination"].minimum_mode is EnrollmentMode.VERIFIED
    )
    protected = {entry.capability for entry in CAPABILITY_MATRIX if entry.capability}
    assert protected <= set(DEFAULT_RULES)


def test_service_identity_separation_has_no_generic_executor() -> None:
    identities = {item.identity: item for item in SERVICE_IDENTITIES}

    assert identities["skdashboard-api"].responsibility == "enforce"
    assert identities["capauth-issuer"].responsibility == "issue"
    assert identities["capauth-pdp"].responsibility == "decide_capability"
    assert identities["owner-policy-gateway"].responsibility == "decide_resource"
    assert identities["capauth-issuer"].may_issue_capabilities is True
    assert identities["capauth-pdp"].may_issue_capabilities is False
    assert not any(item.may_execute_owner_operation for item in SERVICE_IDENTITIES)


def test_local_bootstrap_and_production_issuance_are_separate() -> None:
    profiles = {item.mode: item for item in ISSUANCE_PROFILES}

    assert profiles[IssuanceMode.DEVELOPMENT].browser_capability_handoff is True
    assert profiles[IssuanceMode.PRODUCTION].browser_capability_handoff is False
    assert all(item.persistent_bearer_storage is False for item in ISSUANCE_PROFILES)
    assert all(item.trusted_issuer_policy_required is True for item in ISSUANCE_PROFILES)


def test_binding_carries_every_confused_deputy_and_expiry_fact() -> None:
    value = binding()
    scope = value.capability_scope()

    assert value.principal.subject == "human@example.test"
    assert scope.audience == "skdashboard"
    assert scope.resource_id == "card-1"
    assert scope.constraints == frozenset(
        {
            "node:node-1",
            "purpose:approve exact preview",
            f"owner-policy-revision:{REVISION}",
            "expires-at:2026-08-24T12:02:00Z",
        }
    )


def test_agent_binding_requires_explicit_agent_id() -> None:
    agent = Principal(principal_id="agent-1", subject="agent@example.test", kind="agent")

    with pytest.raises(ValueError, match="agent_id"):
        binding(capability="skdashboard.read", principal=agent)

    value = ControlPlaneBinding(
        principal=agent,
        agent_id="agent-1",
        node_id="node-1",
        purpose="read authorized projection",
        capability="skdashboard.read",
        target="estate.pulse",
        resource_type="estate",
        owner_policy_revision=REVISION,
        expires_at=NOW + timedelta(minutes=1),
    )
    assert "agent:agent-1" in value.capability_scope().constraints


@pytest.mark.parametrize(
    ("boundary", "origins", "expected"),
    [
        (
            RequestBoundary(
                client_kind=ClientKind.BROWSER,
                origin="https://dashboard.example.test",
                csrf_verified=True,
                idempotency_key="idempotency-key-1",
            ),
            frozenset({"*"}),
            DecisionCode.CORS_DENIED,
        ),
        (
            RequestBoundary(
                client_kind=ClientKind.BROWSER,
                origin="https://evil.example.test",
                csrf_verified=True,
                idempotency_key="idempotency-key-1",
            ),
            frozenset({"https://dashboard.example.test"}),
            DecisionCode.CORS_DENIED,
        ),
        (
            RequestBoundary(
                client_kind=ClientKind.BROWSER,
                origin="https://dashboard.example.test",
                idempotency_key="idempotency-key-1",
            ),
            frozenset({"https://dashboard.example.test"}),
            DecisionCode.CSRF_DENIED,
        ),
        (
            RequestBoundary(
                client_kind=ClientKind.BROWSER,
                origin="https://dashboard.example.test",
                csrf_verified=True,
            ),
            frozenset({"https://dashboard.example.test"}),
            DecisionCode.REPLAY_PROOF_MISSING,
        ),
    ],
)
def test_browser_and_replay_preconditions_fail_closed(boundary, origins, expected) -> None:
    assert (
        validate_request_boundary(binding(), boundary, allowed_origins=origins, as_of=NOW)
        is expected
    )


def test_browser_preconditions_allow_exact_origin_csrf_and_replay_proof() -> None:
    boundary = RequestBoundary(
        client_kind=ClientKind.BROWSER,
        origin="https://dashboard.example.test",
        csrf_verified=True,
        idempotency_key="idempotency-key-1",
    )

    assert (
        validate_request_boundary(
            binding(),
            boundary,
            allowed_origins=frozenset({"https://dashboard.example.test"}),
            as_of=NOW,
        )
        is None
    )


@pytest.mark.parametrize(
    ("expires_at", "expected"),
    [
        (NOW, DecisionCode.EXPIRED),
        (NOW + timedelta(minutes=6), DecisionCode.INVALID_TTL),
    ],
)
def test_expiry_and_ttl_fail_closed(expires_at, expected) -> None:
    boundary = RequestBoundary(client_kind=ClientKind.NATIVE, idempotency_key="idempotency-key-1")

    assert (
        validate_request_boundary(
            binding(expires_at=expires_at), boundary, allowed_origins=frozenset(), as_of=NOW
        )
        is expected
    )


def test_client_kind_cannot_impersonate_a_human_principal() -> None:
    boundary = RequestBoundary(client_kind=ClientKind.AGENT, idempotency_key="idempotency-key-1")

    assert (
        validate_request_boundary(binding(), boundary, allowed_origins=frozenset(), as_of=NOW)
        is DecisionCode.INVALID_CLIENT
    )


def test_join_allows_only_two_exact_resolved_allows() -> None:
    value = binding()

    decision = join_policy_decisions(value, capauth_decision(value), owner_decision(value))

    assert decision.allow is True
    assert decision.state is DecisionState.ALLOW
    assert decision.code is DecisionCode.ALLOW
    assert decision.subject == value.principal.subject
    assert decision.node_id == value.node_id
    assert decision.purpose == value.purpose
    assert decision.scope == value.capability_scope()


@pytest.mark.parametrize(
    ("capauth", "owner", "state", "code"),
    [
        (None, "allow", DecisionState.UNAVAILABLE, DecisionCode.CAPAUTH_UNAVAILABLE),
        (
            DecisionReason.BACKEND_UNAVAILABLE,
            "allow",
            DecisionState.UNAVAILABLE,
            DecisionCode.CAPAUTH_UNAVAILABLE,
        ),
        (
            DecisionReason.REVOKED,
            "allow",
            DecisionState.DENY,
            DecisionCode.CAPAUTH_DENIED,
        ),
        (
            DecisionReason.ALLOW,
            None,
            DecisionState.UNAVAILABLE,
            DecisionCode.OWNER_POLICY_UNAVAILABLE,
        ),
        (
            DecisionReason.ALLOW,
            "unknown",
            DecisionState.UNKNOWN,
            DecisionCode.OWNER_POLICY_UNKNOWN,
        ),
        (
            DecisionReason.ALLOW,
            "deny",
            DecisionState.DENY,
            DecisionCode.OWNER_DENIED,
        ),
    ],
)
def test_unknown_unavailable_and_unauthorized_stay_distinct(capauth, owner, state, code) -> None:
    value = binding()
    capauth_value = capauth_decision(value, reason=capauth) if capauth is not None else None
    owner_value = owner_decision(value, DecisionState(owner)) if owner is not None else None

    decision = join_policy_decisions(value, capauth_value, owner_value)

    assert decision.allow is False
    assert decision.state is state
    assert decision.code is code


def test_policy_binding_mismatch_denies_and_output_has_no_capability_material() -> None:
    value = binding()
    wrong = owner_decision(value).model_copy(update={"revision": "f" * 64})
    decision = join_policy_decisions(value, capauth_decision(value), wrong)
    dumped = decision.model_dump_json()

    assert decision.code is DecisionCode.BINDING_MISMATCH
    assert "Bearer" not in dumped
    assert "skcapstone_token" not in dumped
    assert "signature" not in dumped
