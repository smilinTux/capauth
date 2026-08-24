"""Typed, stateless authorization composition for SKDashboard control-plane reads."""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Literal, Protocol

from pydantic import Field, field_serializer, model_validator
from typing_extensions import Self

from .control_plane import (
    SKDASHBOARD_AUDIENCE,
    ControlPlaneBinding,
    ControlPlaneDecision,
    DecisionCode,
    DecisionState,
    OwnerPolicyDecision,
    RequestBoundary,
    StrictValue,
    join_policy_decisions,
    validate_request_boundary,
)
from .delegated import (
    AuthorizationDecision,
    AuthorizationDeniedError,
    AuthorizationReceiptError,
    AuthorizationReceiptUnavailableError,
    AuthorizationRequest,
    CapabilityAuthorizer,
    DecisionReason,
    PresentedCapability,
    PrincipalPolicyReference,
    export_authorization_bearer,
    parse_authorization_bearer,
    parse_presented_token,
)

UTC = timezone.utc
MAX_CONTROL_PLANE_BEARER_BYTES = 64 * 1024
MAX_CONTROL_PLANE_TTL = timedelta(minutes=5)


class ControlPlaneInvocationV1(StrictValue):
    """Trusted request facts, excluding identity and policy assertions."""

    schema_version: Literal["capauth-control-plane-invocation/v1"] = (
        "capauth-control-plane-invocation/v1"
    )
    node_id: str = Field(min_length=1, max_length=256)
    purpose: str = Field(min_length=1, max_length=256)
    audience: Literal["skdashboard"] = SKDASHBOARD_AUDIENCE
    capability: str = Field(min_length=1, max_length=256)
    target: str = Field(min_length=1, max_length=512)
    resource_type: str = Field(min_length=1, max_length=128)
    resource_id: str | None = Field(default=None, min_length=1, max_length=1024)
    correlation_id: str = Field(min_length=1, max_length=256)
    boundary: RequestBoundary

    @model_validator(mode="after")
    def validate_names(self) -> Self:
        values = (self.node_id, self.purpose, self.capability, self.target, self.resource_type)
        if any(value != value.strip() for value in values):
            raise ValueError("invocation fields cannot have surrounding whitespace")
        if self.resource_id is not None and self.resource_id != self.resource_id.strip():
            raise ValueError("resource id cannot have surrounding whitespace")
        return self


class OwnerPolicyProvider(Protocol):
    """Resource-owner decision seam; implementations supply their own durable policy."""

    def decide(
        self,
        binding: ControlPlaneBinding,
        capauth_decision: AuthorizationDecision,
    ) -> OwnerPolicyDecision | None: ...


class SanitizedControlPlaneDecisionV1(StrictValue):
    """Attributable allow context containing no presented credential material."""

    schema_version: Literal["capauth-control-plane-decision/v1"] = (
        "capauth-control-plane-decision/v1"
    )
    binding: ControlPlaneBinding
    boundary: RequestBoundary
    capauth_decision: AuthorizationDecision
    joined_decision: ControlPlaneDecision
    authenticated_identity_ref: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    issued_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        binding = self.binding
        capauth = self.capauth_decision
        joined = self.joined_decision
        expected = {
            "allow": True,
            "state": DecisionState.ALLOW,
            "code": DecisionCode.ALLOW,
            "principal_id": binding.principal.principal_id,
            "subject": binding.principal.subject,
            "agent_id": binding.agent_id,
            "node_id": binding.node_id,
            "purpose": binding.purpose,
            "capability": binding.capability,
            "audience": binding.audience,
            "target": binding.target,
            "resource_type": binding.resource_type,
            "resource_id": binding.resource_id,
            "scope": binding.capability_scope(),
            "expires_at": binding.expires_at,
            "owner_policy_revision": binding.owner_policy_revision,
            "capauth_decision_id": capauth.decision_id,
            "capauth_reason": capauth.reason,
        }
        if any(getattr(joined, name) != value for name, value in expected.items()):
            raise ValueError("joined decision does not match its exact inputs")
        if not joined.allow or joined.state is not DecisionState.ALLOW:
            raise ValueError("sanitized context requires a joined allow")
        if joined.code is not DecisionCode.ALLOW:
            raise ValueError("sanitized context requires the allow code")
        if capauth.reason is not DecisionReason.ALLOW or not capauth.allow:
            raise ValueError("sanitized context requires a delegated allow")
        if capauth.credential_digest is None:
            raise ValueError("sanitized context requires a credential digest")
        if capauth.trusted_issuer_policy_revision is None:
            raise ValueError("sanitized context requires an issuer policy revision")
        if capauth.revocation_revision is None:
            raise ValueError("sanitized context requires a revocation revision")
        if _principal_reference(capauth, binding.principal.principal_id) is None:
            raise ValueError("sanitized context requires a current principal policy reference")
        if self.authenticated_identity_ref != _identity_ref(binding, capauth):
            raise ValueError("authenticated identity reference does not match the decision")
        if self.issued_at.tzinfo is None or self.issued_at.utcoffset() != timedelta(0):
            raise ValueError("issued_at must use UTC offset zero")
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() != timedelta(0):
            raise ValueError("expires_at must use UTC offset zero")
        if self.expires_at != binding.expires_at:
            raise ValueError("expiry does not match the signed binding")
        if not self.issued_at < self.expires_at:
            raise ValueError("decision lifetime is empty")
        if self.expires_at - self.issued_at > MAX_CONTROL_PLANE_TTL:
            raise ValueError("decision lifetime exceeds five minutes")
        return self

    @field_serializer("issued_at", "expires_at")
    def serialize_time(self, value: datetime) -> str:
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


class ControlPlaneAuthorizationResultV1(StrictValue):
    """Closed outcome; non-allow results carry no protected decision detail."""

    schema_version: Literal["capauth-control-plane-authorization-result/v1"] = (
        "capauth-control-plane-authorization-result/v1"
    )
    allow: bool
    state: DecisionState
    code: DecisionCode
    context: SanitizedControlPlaneDecisionV1 | None = None

    @model_validator(mode="after")
    def validate_disposition(self) -> Self:
        if self.allow != (self.state is DecisionState.ALLOW):
            raise ValueError("allow flag and state disagree")
        if self.allow != (self.code is DecisionCode.ALLOW):
            raise ValueError("allow flag and code disagree")
        if self.allow != (self.context is not None):
            raise ValueError("context must exist if and only if authorization allows")
        return self


def export_control_plane_bearer(presented: PresentedCapability) -> str:
    """Encode delegated transport in the canonical padded browser handoff form."""

    raw = export_authorization_bearer(presented).encode("utf-8")
    encoded = base64.urlsafe_b64encode(raw).decode("ascii")
    if len(encoded.encode("ascii")) > MAX_CONTROL_PLANE_BEARER_BYTES:
        raise ValueError("control-plane bearer exceeds the size limit")
    return encoded


def parse_control_plane_bearer(bearer: str) -> PresentedCapability:
    """Decode one exact padded URL-safe base64 delegated bearer."""

    if not isinstance(bearer, str) or not bearer or not bearer.isascii():
        raise ValueError("control-plane bearer is malformed")
    encoded = bearer.encode("ascii")
    if len(encoded) > MAX_CONTROL_PLANE_BEARER_BYTES:
        raise ValueError("control-plane bearer is malformed")
    try:
        decoded = base64.b64decode(encoded, altchars=b"-_", validate=True)
        if base64.urlsafe_b64encode(decoded) != encoded:
            raise ValueError
        raw = decoded.decode("utf-8")
        return parse_authorization_bearer(raw)
    except Exception:
        raise ValueError("control-plane bearer is malformed") from None


class ControlPlaneDecisionAuthorizer:
    """Compose delegated CapAuth and resource-owner policy without storing requests."""

    __slots__ = ("_allowed_origins", "_authorizer", "_clock", "_owner_policy")

    def __init__(
        self,
        *,
        capability_authorizer: CapabilityAuthorizer,
        owner_policy: OwnerPolicyProvider,
        allowed_origins: frozenset[str],
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if "*" in allowed_origins:
            raise ValueError("wildcard control-plane origins are forbidden")
        if any(not value or value != value.strip() for value in allowed_origins):
            raise ValueError("control-plane origins must be nonempty and canonical")
        self._authorizer = capability_authorizer
        self._owner_policy = owner_policy
        self._allowed_origins = frozenset(allowed_origins)
        self._clock = clock or (lambda: datetime.now(UTC))

    def authorize(
        self,
        bearer: str,
        invocation: ControlPlaneInvocationV1,
    ) -> ControlPlaneAuthorizationResultV1:
        """Return one sanitized typed result and never retain the bearer."""

        denied = _result(DecisionState.DENY, DecisionCode.CAPAUTH_DENIED)
        if not isinstance(invocation, ControlPlaneInvocationV1):
            return denied
        try:
            presented = parse_control_plane_bearer(bearer)
            leaf_raw = presented.credentials_for_verification()[-1]
            leaf = parse_presented_token(leaf_raw)
            binding = _binding_from_leaf(leaf, invocation)
            issued_at = _utc(leaf.token.payload.issued_at)
            expires_at = _utc(leaf.token.payload.expires_at)
            now = _utc(self._clock())
        except Exception:
            return denied

        boundary_code = validate_request_boundary(
            binding,
            invocation.boundary,
            allowed_origins=self._allowed_origins,
            as_of=now,
        )
        if boundary_code is not None:
            return _result(DecisionState.DENY, boundary_code)
        if not issued_at <= now < expires_at:
            return _result(DecisionState.DENY, DecisionCode.EXPIRED)

        request = AuthorizationRequest(
            principal=binding.principal,
            scope=binding.capability_scope(),
            correlation_id=invocation.correlation_id,
        )
        try:
            capauth, receipt = self._authorizer.authorize_with_receipt(presented, request)
        except AuthorizationDeniedError as exc:
            return _capauth_denial(exc.decision.reason)
        except AuthorizationReceiptUnavailableError:
            return _result(DecisionState.UNAVAILABLE, DecisionCode.CAPAUTH_UNAVAILABLE)
        except Exception:
            return _result(DecisionState.UNAVAILABLE, DecisionCode.CAPAUTH_UNAVAILABLE)

        try:
            now = _utc(self._clock())
        except Exception:
            return _result(DecisionState.UNAVAILABLE, DecisionCode.CAPAUTH_UNAVAILABLE)
        if not issued_at <= now < expires_at:
            return _result(DecisionState.DENY, DecisionCode.EXPIRED)

        first = self._owner_decision(binding, capauth)
        if first is None:
            return _result(DecisionState.UNAVAILABLE, DecisionCode.OWNER_POLICY_UNAVAILABLE)
        first_joined = join_policy_decisions(binding, capauth, first)
        if not first_joined.allow:
            return _result(first_joined.state, first_joined.code)
        try:
            capauth = self._authorizer.revalidate_current(presented, request, capauth, receipt)
        except AuthorizationReceiptError:
            return _result(DecisionState.DENY, DecisionCode.CAPAUTH_DENIED)
        except AuthorizationDeniedError as exc:
            if exc.decision.reason is DecisionReason.EXPIRED:
                return _result(DecisionState.DENY, DecisionCode.EXPIRED)
            return _capauth_denial(exc.decision.reason)
        except Exception:
            return _result(DecisionState.UNAVAILABLE, DecisionCode.CAPAUTH_UNAVAILABLE)
        second = self._owner_decision(binding, capauth)
        if second is None:
            return _result(DecisionState.UNAVAILABLE, DecisionCode.OWNER_POLICY_UNAVAILABLE)
        if first != second:
            return _result(DecisionState.DENY, DecisionCode.BINDING_MISMATCH)
        joined = join_policy_decisions(binding, capauth, second)
        if not joined.allow:
            return _result(joined.state, joined.code)

        try:
            now = _utc(self._clock())
            if not issued_at <= now < expires_at:
                return _result(DecisionState.DENY, DecisionCode.EXPIRED)
            context = SanitizedControlPlaneDecisionV1(
                binding=binding,
                boundary=invocation.boundary,
                capauth_decision=capauth,
                joined_decision=joined,
                authenticated_identity_ref=_identity_ref(binding, capauth),
                issued_at=issued_at,
                expires_at=expires_at,
            )
        except Exception:
            return _result(DecisionState.DENY, DecisionCode.BINDING_MISMATCH)
        return ControlPlaneAuthorizationResultV1(
            allow=True,
            state=DecisionState.ALLOW,
            code=DecisionCode.ALLOW,
            context=context,
        )

    def _owner_decision(
        self,
        binding: ControlPlaneBinding,
        capauth: AuthorizationDecision,
    ) -> OwnerPolicyDecision | None:
        try:
            value = self._owner_policy.decide(binding, capauth)
        except Exception:
            return None
        return value if isinstance(value, OwnerPolicyDecision) else None


def _binding_from_leaf(leaf, invocation: ControlPlaneInvocationV1) -> ControlPlaneBinding:
    scope = leaf.claims.scope
    payload = leaf.token.payload
    values = _constraints(scope.constraints)
    principal = leaf.claims.principal
    expected_agent = values.get("agent")
    if principal.kind == "agent":
        if expected_agent != principal.principal_id:
            raise ValueError("agent constraint does not match the signed principal")
    elif expected_agent is not None:
        raise ValueError("agent constraint is not permitted")
    if (
        invocation.node_id != values["node"]
        or invocation.purpose != values["purpose"]
        or invocation.audience != scope.audience
        or invocation.capability != scope.capability
        or invocation.target != scope.target
        or invocation.resource_type != scope.resource_type
        or invocation.resource_id != scope.resource_id
    ):
        raise ValueError("invocation does not match the signed scope")
    issued_at = _utc(payload.issued_at)
    expires_at = _utc(payload.expires_at)
    if not issued_at < expires_at or expires_at - issued_at > MAX_CONTROL_PLANE_TTL:
        raise ValueError("signed lifetime is invalid")
    binding = ControlPlaneBinding(
        principal=principal,
        agent_id=expected_agent,
        node_id=values["node"],
        purpose=values["purpose"],
        audience=scope.audience,
        capability=scope.capability,
        target=scope.target,
        resource_type=scope.resource_type,
        resource_id=scope.resource_id,
        owner_policy_revision=values["owner-policy-revision"],
        expires_at=expires_at,
    )
    if binding.capability_scope() != scope:
        raise ValueError("signed scope cannot be reconstructed exactly")
    if values["expires-at"] != binding.model_dump(mode="json")["expires_at"]:
        raise ValueError("expiry constraint does not match the signed payload")
    return binding


def _constraints(constraints: frozenset[str]) -> dict[str, str]:
    allowed = {"agent", "expires-at", "node", "owner-policy-revision", "purpose"}
    values: dict[str, str] = {}
    for constraint in constraints:
        prefix, separator, value = constraint.partition(":")
        if not separator or prefix not in allowed or not value or prefix in values:
            raise ValueError("signed constraints are outside the closed contract")
        values[prefix] = value
    required = {"expires-at", "node", "owner-policy-revision", "purpose"}
    if not required <= values.keys():
        raise ValueError("signed constraints are incomplete")
    if set(values) not in (required, required | {"agent"}):
        raise ValueError("signed constraints are outside the closed contract")
    return values


def _principal_reference(
    decision: AuthorizationDecision,
    principal_id: str,
) -> PrincipalPolicyReference | None:
    matches = [
        value
        for value in decision.principal_policy_revisions
        if value.principal_id == principal_id
    ]
    return matches[0] if len(matches) == 1 else None


def _identity_ref(binding: ControlPlaneBinding, decision: AuthorizationDecision) -> str:
    reference = _principal_reference(decision, binding.principal.principal_id)
    if reference is None or decision.credential_digest is None:
        raise ValueError("attributable identity inputs are incomplete")
    facts = {
        "domain": "capauth-control-plane-authenticated-identity/v1",
        "principal": binding.principal.model_dump(mode="json"),
        "credential_digest": decision.credential_digest,
        "principal_policy_revision": reference.revision,
    }
    encoded = json.dumps(facts, sort_keys=True, separators=(",", ":")).encode()
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _utc(value: datetime | None) -> datetime:
    if value is None or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("time must use UTC offset zero")
    return value.astimezone(UTC)


def _capauth_denial(reason: DecisionReason) -> ControlPlaneAuthorizationResultV1:
    unavailable = reason in {DecisionReason.BACKEND_UNAVAILABLE, DecisionReason.AUDIT_UNAVAILABLE}
    return _result(
        DecisionState.UNAVAILABLE if unavailable else DecisionState.DENY,
        DecisionCode.CAPAUTH_UNAVAILABLE if unavailable else DecisionCode.CAPAUTH_DENIED,
    )


def _result(
    state: DecisionState,
    code: DecisionCode,
) -> ControlPlaneAuthorizationResultV1:
    return ControlPlaneAuthorizationResultV1(allow=False, state=state, code=code)


__all__ = [
    "MAX_CONTROL_PLANE_BEARER_BYTES",
    "ControlPlaneAuthorizationResultV1",
    "ControlPlaneDecisionAuthorizer",
    "ControlPlaneInvocationV1",
    "OwnerPolicyProvider",
    "SanitizedControlPlaneDecisionV1",
    "export_control_plane_bearer",
    "parse_control_plane_bearer",
]
