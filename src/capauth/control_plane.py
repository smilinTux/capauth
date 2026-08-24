"""Fail-closed CapAuth contract for the SKDashboard control plane.

CapAuth owns identity, capability verification, and its authorization decision.
SKDashboard is the policy enforcement point (PEP). Each resource-owning service
owns the second policy decision. This module defines the stable contract joining
those decisions without accepting or returning bearer material.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_serializer, model_validator
from typing_extensions import Self

from .delegated import AuthorizationDecision, CapabilityScope, DecisionReason, Principal

UTC = timezone.utc
SKDASHBOARD_AUDIENCE = "skdashboard"
MAX_CONTROL_PLANE_TTL = timedelta(minutes=5)


class StrEnum(str, Enum):
    """Python 3.10 compatible string enum."""

    def __str__(self) -> str:
        return str.__str__(self.value)


class StrictValue(BaseModel):
    """Immutable, closed value object for a security boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class PrincipalKind(StrEnum):
    HUMAN = "human"
    AGENT = "agent"
    SERVICE = "service"


class ClientKind(StrEnum):
    BROWSER = "browser"
    NATIVE = "native"
    AGENT = "agent"
    SERVICE = "service"


class OperationClass(StrEnum):
    DISCOVERY = "discovery"
    READ = "read"
    PROPOSE = "propose"
    MUTATE = "mutate"


class DecisionState(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    UNKNOWN = "unknown"
    UNAVAILABLE = "unavailable"


class DecisionCode(StrEnum):
    ALLOW = "allow"
    ANONYMOUS_ONLY = "anonymous_only"
    BINDING_MISMATCH = "binding_mismatch"
    CAPAUTH_DENIED = "capauth_denied"
    CAPAUTH_UNAVAILABLE = "capauth_unavailable"
    CORS_DENIED = "cors_denied"
    CSRF_DENIED = "csrf_denied"
    EXPIRED = "expired"
    INVALID_CLIENT = "invalid_client"
    INVALID_TTL = "invalid_ttl"
    OWNER_DENIED = "owner_denied"
    OWNER_POLICY_UNKNOWN = "owner_policy_unknown"
    OWNER_POLICY_UNAVAILABLE = "owner_policy_unavailable"
    REPLAY_PROOF_MISSING = "replay_proof_missing"


class IssuanceMode(StrEnum):
    DEVELOPMENT = "development"
    PRODUCTION = "production"


class IssuanceProfile(StrictValue):
    """Fixed separation between local bootstrap and production issuance."""

    mode: IssuanceMode
    browser_capability_handoff: bool
    persistent_bearer_storage: Literal[False] = False
    trusted_issuer_policy_required: Literal[True] = True
    max_ttl_seconds: int = Field(ge=1, le=300)


ISSUANCE_PROFILES = (
    IssuanceProfile(
        mode=IssuanceMode.DEVELOPMENT,
        browser_capability_handoff=True,
        max_ttl_seconds=300,
    ),
    IssuanceProfile(
        mode=IssuanceMode.PRODUCTION,
        browser_capability_handoff=False,
        max_ttl_seconds=300,
    ),
)


class ServiceIdentity(StrictValue):
    """Logical identity and fixed responsibility of one policy participant."""

    identity: str
    responsibility: Literal["enforce", "issue", "decide_capability", "decide_resource"]
    may_issue_capabilities: bool = False
    may_execute_owner_operation: bool = False


SERVICE_IDENTITIES = (
    ServiceIdentity(identity="skdashboard-api", responsibility="enforce"),
    ServiceIdentity(
        identity="capauth-issuer",
        responsibility="issue",
        may_issue_capabilities=True,
    ),
    ServiceIdentity(
        identity="capauth-pdp",
        responsibility="decide_capability",
    ),
    ServiceIdentity(identity="owner-policy-gateway", responsibility="decide_resource"),
)


class CapabilityEntry(StrictValue):
    """One closed control-plane operation family and its least privilege."""

    family: str
    capability: str | None
    operation: OperationClass
    principal_kinds: frozenset[PrincipalKind]


CAPABILITY_MATRIX = (
    CapabilityEntry(
        family="anonymous_discovery",
        capability=None,
        operation=OperationClass.DISCOVERY,
        principal_kinds=frozenset(),
    ),
    CapabilityEntry(
        family="read_projections",
        capability="skdashboard.read",
        operation=OperationClass.READ,
        principal_kinds=frozenset({PrincipalKind.HUMAN, PrincipalKind.AGENT}),
    ),
    CapabilityEntry(
        family="event_streams",
        capability="skdashboard.events.read",
        operation=OperationClass.READ,
        principal_kinds=frozenset({PrincipalKind.HUMAN, PrincipalKind.AGENT}),
    ),
    CapabilityEntry(
        family="report_snapshots",
        capability="skdashboard.reports.read",
        operation=OperationClass.READ,
        principal_kinds=frozenset({PrincipalKind.HUMAN, PrincipalKind.AGENT}),
    ),
    CapabilityEntry(
        family="insight_proposals",
        capability="skdashboard.insights.query",
        operation=OperationClass.PROPOSE,
        principal_kinds=frozenset({PrincipalKind.HUMAN, PrincipalKind.AGENT}),
    ),
    CapabilityEntry(
        family="action_previews",
        capability="skdashboard.actions.preview",
        operation=OperationClass.PROPOSE,
        principal_kinds=frozenset({PrincipalKind.HUMAN, PrincipalKind.AGENT}),
    ),
    CapabilityEntry(
        family="action_authorization",
        capability="skdashboard.actions.authorize",
        operation=OperationClass.MUTATE,
        principal_kinds=frozenset({PrincipalKind.HUMAN}),
    ),
    CapabilityEntry(
        family="coordination_commands",
        capability="skdashboard.commands.coordination",
        operation=OperationClass.MUTATE,
        principal_kinds=frozenset({PrincipalKind.HUMAN, PrincipalKind.AGENT}),
    ),
    CapabilityEntry(
        family="cmdb_commands",
        capability="skdashboard.commands.cmdb",
        operation=OperationClass.MUTATE,
        principal_kinds=frozenset({PrincipalKind.HUMAN, PrincipalKind.AGENT}),
    ),
    CapabilityEntry(
        family="service_operations",
        capability="skdashboard.commands.service_operations",
        operation=OperationClass.MUTATE,
        principal_kinds=frozenset({PrincipalKind.HUMAN, PrincipalKind.AGENT}),
    ),
    CapabilityEntry(
        family="report_delivery",
        capability="skdashboard.reports.deliver",
        operation=OperationClass.MUTATE,
        principal_kinds=frozenset({PrincipalKind.HUMAN}),
    ),
)

_CAPABILITIES = {entry.capability: entry for entry in CAPABILITY_MATRIX if entry.capability}


class ControlPlaneBinding(StrictValue):
    """Exact invocation facts bound into the signed delegated capability."""

    principal: Principal
    agent_id: str | None = Field(default=None, min_length=1, max_length=256)
    node_id: str = Field(min_length=1, max_length=256)
    purpose: str = Field(min_length=1, max_length=256)
    audience: Literal["skdashboard"] = SKDASHBOARD_AUDIENCE
    capability: str
    target: str = Field(min_length=1, max_length=512)
    resource_type: str = Field(min_length=1, max_length=128)
    resource_id: str | None = Field(default=None, min_length=1, max_length=1024)
    owner_policy_revision: str = Field(pattern=r"^[0-9a-f]{64}$")
    expires_at: datetime

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        if self.principal.kind == PrincipalKind.AGENT.value and self.agent_id is None:
            raise ValueError("agent principal requires agent_id")
        if self.principal.kind != PrincipalKind.AGENT.value and self.agent_id is not None:
            raise ValueError("only an agent principal may bind agent_id")
        values = (self.node_id, self.purpose, self.target, self.resource_type)
        if any(value != value.strip() for value in values):
            raise ValueError("binding fields cannot have surrounding whitespace")
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() != timedelta(0):
            raise ValueError("expires_at must use UTC offset zero")
        if self.capability not in _CAPABILITIES:
            raise ValueError("unknown control-plane capability")
        return self

    @field_serializer("expires_at")
    def serialize_expiry(self, value: datetime) -> str:
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")

    @property
    def operation(self) -> OperationClass:
        return _CAPABILITIES[self.capability].operation

    def capability_scope(self) -> CapabilityScope:
        """Return the exact scope that CapAuth signs and verifies."""

        constraints = {
            f"node:{self.node_id}",
            f"purpose:{self.purpose}",
            f"owner-policy-revision:{self.owner_policy_revision}",
            f"expires-at:{self.model_dump(mode='json')['expires_at']}",
        }
        if self.agent_id is not None:
            constraints.add(f"agent:{self.agent_id}")
        return CapabilityScope(
            audience=self.audience,
            target=self.target,
            capability=self.capability,
            operation=self.operation.value,
            resource_type=self.resource_type,
            resource_id=self.resource_id,
            constraints=frozenset(constraints),
        )


class RequestBoundary(StrictValue):
    """Non-secret browser and replay inputs checked before capability use."""

    client_kind: ClientKind
    origin: str | None = Field(default=None, min_length=1, max_length=2048)
    csrf_verified: bool = False
    idempotency_key: str | None = Field(default=None, min_length=16, max_length=256)


class OwnerPolicyDecision(StrictValue):
    """Sanitized result supplied by the resource-owning policy gateway."""

    state: DecisionState
    revision: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    resource_type: str
    resource_id: str | None = None
    reason_code: str = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def validate_revision(self) -> Self:
        if self.state in {DecisionState.ALLOW, DecisionState.DENY} and self.revision is None:
            raise ValueError("resolved owner decision requires a policy revision")
        return self


class ControlPlaneDecision(StrictValue):
    """Non-secret joined decision retaining Unknown and unavailable truth."""

    allow: bool
    state: DecisionState
    code: DecisionCode
    principal_id: str
    subject: str
    agent_id: str | None
    node_id: str
    purpose: str
    capability: str
    audience: Literal["skdashboard"]
    target: str
    resource_type: str
    resource_id: str | None
    scope: CapabilityScope
    expires_at: datetime
    owner_policy_revision: str
    capauth_decision_id: str | None = None
    capauth_reason: DecisionReason | None = None

    @model_validator(mode="after")
    def validate_disposition(self) -> Self:
        if self.allow != (self.state is DecisionState.ALLOW):
            raise ValueError("allow flag and decision state disagree")
        return self


def validate_request_boundary(
    binding: ControlPlaneBinding,
    boundary: RequestBoundary,
    *,
    allowed_origins: frozenset[str],
    as_of: datetime,
) -> DecisionCode | None:
    """Fail closed before bearer verification can consume a one-use token."""

    if "*" in allowed_origins:
        return DecisionCode.CORS_DENIED
    if as_of.tzinfo is None or as_of.utcoffset() != timedelta(0):
        return DecisionCode.INVALID_TTL
    remaining = binding.expires_at - as_of
    if remaining <= timedelta(0):
        return DecisionCode.EXPIRED
    if remaining > MAX_CONTROL_PLANE_TTL:
        return DecisionCode.INVALID_TTL
    client_principal_kinds = {
        ClientKind.BROWSER: PrincipalKind.HUMAN,
        ClientKind.NATIVE: PrincipalKind.HUMAN,
        ClientKind.AGENT: PrincipalKind.AGENT,
        ClientKind.SERVICE: PrincipalKind.SERVICE,
    }
    try:
        principal_kind = PrincipalKind(binding.principal.kind)
    except ValueError:
        return DecisionCode.INVALID_CLIENT
    if principal_kind is not client_principal_kinds[boundary.client_kind]:
        return DecisionCode.INVALID_CLIENT
    if principal_kind not in _CAPABILITIES[binding.capability].principal_kinds:
        return DecisionCode.INVALID_CLIENT
    if boundary.client_kind is ClientKind.BROWSER:
        if boundary.origin is None or boundary.origin not in allowed_origins:
            return DecisionCode.CORS_DENIED
        if binding.operation is OperationClass.MUTATE and not boundary.csrf_verified:
            return DecisionCode.CSRF_DENIED
    if binding.operation is OperationClass.MUTATE and boundary.idempotency_key is None:
        return DecisionCode.REPLAY_PROOF_MISSING
    return None


def join_policy_decisions(
    binding: ControlPlaneBinding,
    capauth: AuthorizationDecision | None,
    owner: OwnerPolicyDecision | None,
) -> ControlPlaneDecision:
    """Join CapAuth and owner policy decisions, denying every uncertainty."""

    values = dict(
        allow=False,
        principal_id=binding.principal.principal_id,
        subject=binding.principal.subject,
        agent_id=binding.agent_id,
        node_id=binding.node_id,
        purpose=binding.purpose,
        capability=binding.capability,
        audience=binding.audience,
        target=binding.target,
        resource_type=binding.resource_type,
        resource_id=binding.resource_id,
        scope=binding.capability_scope(),
        expires_at=binding.expires_at,
        owner_policy_revision=binding.owner_policy_revision,
    )
    if capauth is None:
        return ControlPlaneDecision(
            **values, state=DecisionState.UNAVAILABLE, code=DecisionCode.CAPAUTH_UNAVAILABLE
        )
    values.update(
        capauth_decision_id=capauth.decision_id,
        capauth_reason=capauth.reason,
    )
    expected_scope = binding.capability_scope()
    if capauth.principal_id != binding.principal.principal_id or capauth.scope != expected_scope:
        return ControlPlaneDecision(
            **values, state=DecisionState.DENY, code=DecisionCode.BINDING_MISMATCH
        )
    if not capauth.allow:
        unavailable = capauth.reason in {
            DecisionReason.BACKEND_UNAVAILABLE,
            DecisionReason.AUDIT_UNAVAILABLE,
        }
        return ControlPlaneDecision(
            **values,
            state=DecisionState.UNAVAILABLE if unavailable else DecisionState.DENY,
            code=(
                DecisionCode.CAPAUTH_UNAVAILABLE if unavailable else DecisionCode.CAPAUTH_DENIED
            ),
        )
    if owner is None or owner.state is DecisionState.UNAVAILABLE:
        return ControlPlaneDecision(
            **values,
            state=DecisionState.UNAVAILABLE,
            code=DecisionCode.OWNER_POLICY_UNAVAILABLE,
        )
    if owner.state is DecisionState.UNKNOWN:
        return ControlPlaneDecision(
            **values, state=DecisionState.UNKNOWN, code=DecisionCode.OWNER_POLICY_UNKNOWN
        )
    owner_matches = (
        owner.revision == binding.owner_policy_revision
        and owner.resource_type == binding.resource_type
        and owner.resource_id == binding.resource_id
    )
    if not owner_matches:
        return ControlPlaneDecision(
            **values, state=DecisionState.DENY, code=DecisionCode.BINDING_MISMATCH
        )
    if owner.state is DecisionState.DENY:
        return ControlPlaneDecision(
            **values, state=DecisionState.DENY, code=DecisionCode.OWNER_DENIED
        )
    values["allow"] = True
    return ControlPlaneDecision(**values, state=DecisionState.ALLOW, code=DecisionCode.ALLOW)


__all__ = [
    "CAPABILITY_MATRIX",
    "ISSUANCE_PROFILES",
    "MAX_CONTROL_PLANE_TTL",
    "SERVICE_IDENTITIES",
    "SKDASHBOARD_AUDIENCE",
    "CapabilityEntry",
    "ClientKind",
    "ControlPlaneBinding",
    "ControlPlaneDecision",
    "DecisionCode",
    "DecisionState",
    "IssuanceMode",
    "IssuanceProfile",
    "OperationClass",
    "OwnerPolicyDecision",
    "PrincipalKind",
    "RequestBoundary",
    "ServiceIdentity",
    "join_policy_decisions",
    "validate_request_boundary",
]
