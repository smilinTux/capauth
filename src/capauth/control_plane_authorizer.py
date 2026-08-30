"""Typed, stateless authorization composition for SKDashboard control-plane reads."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import Lock
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
    AuthorizationCurrentnessReceipt,
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
MAX_SIGNED_EXPIRY_CEILING_WINDOW = timedelta(seconds=1)
MAX_CONTROL_PLANE_CURRENTNESS_VERIFIERS = 1024


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


_CURRENTNESS_FACTORY = object()


class ControlPlaneCurrentnessVerifier:
    """Opaque request-local verifier for two downstream currentness checks."""

    __slots__ = (
        "_context",
        "_context_fingerprint",
        "_handle",
        "_lock",
        "_phase",
    )

    def __init__(
        self,
        factory_token: object,
        *,
        issuer: "ControlPlaneDecisionAuthorizer",
        issue_nonce: bytes,
        issue_mac: bytes,
        authorizer: CapabilityAuthorizer,
        presented: PresentedCapability,
        request: AuthorizationRequest,
        prior: AuthorizationDecision,
        context: SanitizedControlPlaneDecisionV1,
        receipts: tuple[AuthorizationCurrentnessReceipt, ...],
    ) -> None:
        if (
            factory_token is not _CURRENTNESS_FACTORY
            or type(issuer) is not ControlPlaneDecisionAuthorizer
            or len(issue_nonce) != 32
            or len(issue_mac) != 32
            or type(authorizer) is not CapabilityAuthorizer
            or not isinstance(presented, PresentedCapability)
            or not isinstance(request, AuthorizationRequest)
            or not isinstance(prior, AuthorizationDecision)
            or not isinstance(context, SanitizedControlPlaneDecisionV1)
            or len(receipts) != 2
            or any(not isinstance(value, AuthorizationCurrentnessReceipt) for value in receipts)
        ):
            raise TypeError("control-plane currentness verifiers are authorizer-issued")
        object.__setattr__(self, "_context", context)
        object.__setattr__(self, "_context_fingerprint", _context_fingerprint(context))
        object.__setattr__(self, "_lock", Lock())
        object.__setattr__(self, "_phase", 0)
        object.__setattr__(
            self,
            "_handle",
            _register_currentness_state(
                verifier=self,
                issuer=issuer,
                issue_nonce=issue_nonce,
                issue_mac=issue_mac,
                authorizer=authorizer,
                presented=presented,
                request=request,
                prior=prior,
                context=context,
                receipts=receipts,
            ),
        )

    def __setattr__(self, name, value) -> None:
        del name, value
        raise AttributeError("control-plane currentness verifier is immutable")

    def check_before_owner_read(self, context: SanitizedControlPlaneDecisionV1) -> DecisionState:
        """Consume the pre-read proof for the exact issued context."""

        return self._check(context, expected_phase=0)

    def check_after_owner_read(self, context: SanitizedControlPlaneDecisionV1) -> DecisionState:
        """Consume the post-read proof before protected output is released."""

        return self._check(context, expected_phase=1)

    def _check(
        self,
        context: SanitizedControlPlaneDecisionV1,
        *,
        expected_phase: int,
    ) -> DecisionState:
        with self._lock:
            if self._phase != expected_phase or context is not self._context:
                self._close_locked()
                return DecisionState.DENY
            try:
                fingerprint = _context_fingerprint(context)
            except Exception:
                self._close_locked()
                return DecisionState.DENY
            if fingerprint != self._context_fingerprint:
                self._close_locked()
                return DecisionState.DENY
            state = _check_currentness_state(
                self._handle,
                verifier=self,
                context=context,
                expected_phase=expected_phase,
            )
            if state is not DecisionState.ALLOW or expected_phase == 1:
                self._close_locked()
            else:
                object.__setattr__(self, "_phase", 1)
            return state

    def close(self) -> None:
        """Invalidate unused proofs and release request credential material."""

        with self._lock:
            self._close_locked()

    def _close_locked(self) -> None:
        if self._phase == 2:
            return
        _discard_currentness_state(self._handle, verifier=self)
        object.__setattr__(self, "_context", None)
        object.__setattr__(self, "_context_fingerprint", b"")
        object.__setattr__(self, "_handle", b"")
        object.__setattr__(self, "_phase", 2)

    def __repr__(self) -> str:
        return "<opaque control-plane currentness verifier>"

    __str__ = __repr__

    def __copy__(self):
        raise TypeError("control-plane currentness verifier cannot be copied")

    def __deepcopy__(self, memo):
        del memo
        raise TypeError("control-plane currentness verifier cannot be copied")

    def __reduce__(self):
        raise TypeError("control-plane currentness verifier cannot be serialized")

    def __del__(self) -> None:
        try:
            _discard_currentness_state(
                object.__getattribute__(self, "_handle"),
                verifier=self,
            )
        except Exception:
            pass


@dataclass(slots=True)
class _CurrentnessState:
    verifier_id: int
    issuer: "ControlPlaneDecisionAuthorizer"
    issue_nonce: bytes
    issue_mac: bytes
    authorizer: CapabilityAuthorizer
    presented: PresentedCapability
    request: AuthorizationRequest
    prior: AuthorizationDecision
    context: SanitizedControlPlaneDecisionV1
    receipts: tuple[AuthorizationCurrentnessReceipt, ...]
    phase: int = 0


_CURRENTNESS_STATE_LOCK = Lock()
_CURRENTNESS_STATES: dict[bytes, _CurrentnessState] = {}


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

    __slots__ = (
        "_allowed_origins",
        "_authorizer",
        "_clock",
        "_owner_policy",
        "_verifier_key",
        "_verifier_lock",
        "_verifier_states",
    )

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
        self._verifier_key = secrets.token_bytes(32)
        self._verifier_lock = Lock()
        self._verifier_states = {}

    def _register_currentness_verifier(
        self,
        context: SanitizedControlPlaneDecisionV1,
    ) -> tuple[bytes, bytes]:
        now = _utc(self._clock())
        fingerprint = _context_fingerprint(context)
        with self._verifier_lock:
            self._verifier_states = {
                nonce: state for nonce, state in self._verifier_states.items() if state[0] > now
            }
            if len(self._verifier_states) >= MAX_CONTROL_PLANE_CURRENTNESS_VERIFIERS:
                raise RuntimeError("control-plane currentness verifier capacity exhausted")
            for _attempt in range(16):
                nonce = secrets.token_bytes(32)
                if nonce in self._verifier_states:
                    continue
                mac = self._currentness_verifier_mac(nonce, fingerprint)
                self._verifier_states[nonce] = (
                    context.expires_at,
                    0,
                    id(context),
                    fingerprint,
                    mac,
                    None,
                )
                return nonce, mac
        raise RuntimeError("control-plane currentness verifier nonce unavailable")

    def _bind_currentness_verifier(
        self,
        nonce: bytes,
        mac: bytes,
        context: SanitizedControlPlaneDecisionV1,
        verifier: ControlPlaneCurrentnessVerifier,
    ) -> bool:
        fingerprint = _context_fingerprint(context)
        with self._verifier_lock:
            state = self._verifier_states.get(nonce)
            valid = (
                state is not None
                and state[1] == 0
                and state[2] == id(context)
                and state[3] == fingerprint
                and hmac.compare_digest(state[4], mac)
                and state[5] is None
            )
            if not valid:
                self._verifier_states.pop(nonce, None)
                return False
            self._verifier_states[nonce] = (*state[:5], id(verifier))
            return True

    def _claim_currentness_verifier(
        self,
        nonce: bytes,
        mac: bytes,
        context: SanitizedControlPlaneDecisionV1,
        *,
        verifier: ControlPlaneCurrentnessVerifier,
        expected_phase: int,
    ) -> bool:
        now = _utc(self._clock())
        fingerprint = _context_fingerprint(context)
        with self._verifier_lock:
            state = self._verifier_states.get(nonce)
            self._verifier_states = {
                value: item for value, item in self._verifier_states.items() if item[0] > now
            }
            if state is None or state[0] <= now:
                return False
            valid_mac = hmac.compare_digest(
                mac,
                self._currentness_verifier_mac(nonce, fingerprint),
            )
            valid = (
                valid_mac
                and state[1] == expected_phase
                and state[2] == id(context)
                and state[3] == fingerprint
                and hmac.compare_digest(state[4], mac)
                and state[5] == id(verifier)
            )
            if not valid:
                return False
            if expected_phase == 0:
                self._verifier_states[nonce] = (state[0], 1, *state[2:])
            else:
                self._verifier_states.pop(nonce, None)
            return True

    def _discard_currentness_verifier(
        self,
        nonce: bytes,
        *,
        verifier: ControlPlaneCurrentnessVerifier | None = None,
        verifier_id: int | None = None,
    ) -> bool:
        if verifier is not None and verifier_id is not None:
            return False
        expected_id = id(verifier) if verifier is not None else verifier_id
        with self._verifier_lock:
            state = self._verifier_states.get(nonce)
            if expected_id is not None and state is not None and state[5] != expected_id:
                return False
            return self._verifier_states.pop(nonce, None) is not None

    def _currentness_verifier_mac(self, nonce: bytes, fingerprint: bytes) -> bytes:
        return hmac.new(
            self._verifier_key,
            b"capauth-control-plane-currentness-verifier/v1\0" + nonce + fingerprint,
            hashlib.sha256,
        ).digest()

    def authorize(
        self,
        bearer: str,
        invocation: ControlPlaneInvocationV1,
    ) -> ControlPlaneAuthorizationResultV1:
        """Return one sanitized typed result and never retain the bearer."""

        result, verifier = self._authorize(
            bearer,
            invocation,
            issue_verifier=False,
            presented_input=False,
        )
        if verifier is not None:
            verifier.close()
        return result

    def authorize_with_currentness(
        self,
        bearer: str,
        invocation: ControlPlaneInvocationV1,
    ) -> tuple[ControlPlaneAuthorizationResultV1, ControlPlaneCurrentnessVerifier | None]:
        """Return a sanitized result and two-use opaque downstream verifier."""

        return self._authorize(
            bearer,
            invocation,
            issue_verifier=True,
            presented_input=False,
        )

    def _authorize_presented_with_currentness(
        self,
        presented: PresentedCapability,
        invocation: ControlPlaneInvocationV1,
    ) -> tuple[ControlPlaneAuthorizationResultV1, ControlPlaneCurrentnessVerifier | None]:
        """Authorize one in-process capability and issue downstream currentness proofs."""

        return self._authorize(
            presented,
            invocation,
            issue_verifier=True,
            presented_input=True,
        )

    def _authorize(
        self,
        credential: str | PresentedCapability,
        invocation: ControlPlaneInvocationV1,
        *,
        issue_verifier: bool,
        presented_input: bool,
    ) -> tuple[ControlPlaneAuthorizationResultV1, ControlPlaneCurrentnessVerifier | None]:
        active_receipts = ()
        downstream_receipts = ()
        registered_nonce = b""

        def closed(
            result: ControlPlaneAuthorizationResultV1,
        ) -> tuple[ControlPlaneAuthorizationResultV1, None]:
            self._authorizer.discard_currentness_receipts(active_receipts + downstream_receipts)
            self._discard_currentness_verifier(registered_nonce)
            return result, None

        denied = _result(DecisionState.DENY, DecisionCode.CAPAUTH_DENIED)
        if not isinstance(invocation, ControlPlaneInvocationV1):
            return closed(denied)
        try:
            if presented_input:
                if not isinstance(credential, PresentedCapability):
                    raise ValueError
                presented = credential
            else:
                if not isinstance(credential, str):
                    raise ValueError
                presented = parse_control_plane_bearer(credential)
            leaf_raw = presented.credentials_for_verification()[-1]
            leaf = parse_presented_token(leaf_raw)
            binding = _binding_from_leaf(leaf, invocation)
            issued_at = _utc(leaf.token.payload.issued_at)
            expires_at = _utc(leaf.token.payload.expires_at)
            now = _utc(self._clock())
        except Exception:
            return closed(denied)

        boundary_code = validate_request_boundary(
            binding,
            invocation.boundary,
            allowed_origins=self._allowed_origins,
            as_of=now,
        )
        if boundary_code is not None:
            return closed(_result(DecisionState.DENY, boundary_code))
        if not issued_at <= now < expires_at:
            return closed(_result(DecisionState.DENY, DecisionCode.EXPIRED))

        request = AuthorizationRequest(
            principal=binding.principal,
            scope=leaf.claims.scope,
            correlation_id=invocation.correlation_id,
        )
        try:
            capauth, receipt = self._authorizer.authorize_with_receipt(presented, request)
            active_receipts = (receipt,)
        except AuthorizationDeniedError as exc:
            return closed(_capauth_denial(exc.decision.reason))
        except AuthorizationReceiptUnavailableError:
            return closed(_result(DecisionState.UNAVAILABLE, DecisionCode.CAPAUTH_UNAVAILABLE))
        except Exception:
            return closed(_result(DecisionState.UNAVAILABLE, DecisionCode.CAPAUTH_UNAVAILABLE))

        try:
            now = _utc(self._clock())
        except Exception:
            return closed(_result(DecisionState.UNAVAILABLE, DecisionCode.CAPAUTH_UNAVAILABLE))
        if not issued_at <= now < expires_at:
            return closed(_result(DecisionState.DENY, DecisionCode.EXPIRED))

        effective_capauth = capauth.model_copy(update={"scope": binding.capability_scope()})
        first = self._owner_decision(binding, effective_capauth)
        if first is None:
            return closed(
                _result(DecisionState.UNAVAILABLE, DecisionCode.OWNER_POLICY_UNAVAILABLE)
            )
        first_joined = join_policy_decisions(binding, effective_capauth, first)
        if not first_joined.allow:
            return closed(_result(first_joined.state, first_joined.code))
        try:
            if issue_verifier:
                capauth, downstream_receipts = self._authorizer.revalidate_current_with_receipts(
                    presented,
                    request,
                    capauth,
                    receipt,
                    count=2,
                )
            else:
                capauth = self._authorizer.revalidate_current(presented, request, capauth, receipt)
            active_receipts = ()
        except AuthorizationReceiptError:
            return closed(_result(DecisionState.DENY, DecisionCode.CAPAUTH_DENIED))
        except AuthorizationDeniedError as exc:
            if exc.decision.reason is DecisionReason.EXPIRED:
                return closed(_result(DecisionState.DENY, DecisionCode.EXPIRED))
            return closed(_capauth_denial(exc.decision.reason))
        except Exception:
            return closed(_result(DecisionState.UNAVAILABLE, DecisionCode.CAPAUTH_UNAVAILABLE))
        effective_capauth = capauth.model_copy(update={"scope": binding.capability_scope()})
        second = self._owner_decision(binding, effective_capauth)
        if second is None:
            return closed(
                _result(DecisionState.UNAVAILABLE, DecisionCode.OWNER_POLICY_UNAVAILABLE)
            )
        if first != second:
            return closed(_result(DecisionState.DENY, DecisionCode.BINDING_MISMATCH))
        joined = join_policy_decisions(binding, effective_capauth, second)
        if not joined.allow:
            return closed(_result(joined.state, joined.code))

        try:
            now = _utc(self._clock())
            if not issued_at <= now < expires_at:
                return closed(_result(DecisionState.DENY, DecisionCode.EXPIRED))
            context = SanitizedControlPlaneDecisionV1(
                binding=binding,
                boundary=invocation.boundary,
                capauth_decision=effective_capauth,
                joined_decision=joined,
                authenticated_identity_ref=_identity_ref(binding, capauth),
                issued_at=issued_at,
                expires_at=expires_at,
            )
        except Exception:
            return closed(_result(DecisionState.DENY, DecisionCode.BINDING_MISMATCH))
        result = ControlPlaneAuthorizationResultV1(
            allow=True,
            state=DecisionState.ALLOW,
            code=DecisionCode.ALLOW,
            context=context,
        )
        if not issue_verifier:
            return result, None
        verifier = None
        try:
            registered_nonce, issue_mac = self._register_currentness_verifier(context)
            verifier = ControlPlaneCurrentnessVerifier(
                _CURRENTNESS_FACTORY,
                issuer=self,
                issue_nonce=registered_nonce,
                issue_mac=issue_mac,
                authorizer=self._authorizer,
                presented=presented,
                request=request,
                prior=capauth,
                context=context,
                receipts=downstream_receipts,
            )
            if not self._bind_currentness_verifier(
                registered_nonce,
                issue_mac,
                context,
                verifier,
            ):
                raise RuntimeError("control-plane currentness verifier binding failed")
            registered_nonce = b""
        except Exception:
            if verifier is not None:
                verifier.close()
            return closed(_result(DecisionState.UNAVAILABLE, DecisionCode.CAPAUTH_UNAVAILABLE))
        return result, verifier

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


def _register_currentness_state(
    *,
    verifier: ControlPlaneCurrentnessVerifier,
    issuer: ControlPlaneDecisionAuthorizer,
    issue_nonce: bytes,
    issue_mac: bytes,
    authorizer: CapabilityAuthorizer,
    presented: PresentedCapability,
    request: AuthorizationRequest,
    prior: AuthorizationDecision,
    context: SanitizedControlPlaneDecisionV1,
    receipts: tuple[AuthorizationCurrentnessReceipt, ...],
) -> bytes:
    now = _utc(issuer._clock())
    expired: list[_CurrentnessState] = []
    handle = b""
    failure: RuntimeError | None = None
    with _CURRENTNESS_STATE_LOCK:
        for handle, state in tuple(_CURRENTNESS_STATES.items()):
            if state.context.expires_at <= now:
                expired.append(_CURRENTNESS_STATES.pop(handle))
        if len(_CURRENTNESS_STATES) >= MAX_CONTROL_PLANE_CURRENTNESS_VERIFIERS:
            failure = RuntimeError("control-plane currentness state capacity exhausted")
        else:
            for _attempt in range(16):
                handle = secrets.token_bytes(32)
                if handle in _CURRENTNESS_STATES:
                    continue
                _CURRENTNESS_STATES[handle] = _CurrentnessState(
                    verifier_id=id(verifier),
                    issuer=issuer,
                    issue_nonce=bytes(issue_nonce),
                    issue_mac=bytes(issue_mac),
                    authorizer=authorizer,
                    presented=presented,
                    request=request,
                    prior=prior,
                    context=context,
                    receipts=tuple(receipts),
                )
                break
            else:
                failure = RuntimeError("control-plane currentness state handle unavailable")
    for state in expired:
        _release_currentness_state(state)
    if failure is not None:
        raise failure
    return handle


def _check_currentness_state(
    handle: bytes,
    *,
    verifier: ControlPlaneCurrentnessVerifier,
    context: SanitizedControlPlaneDecisionV1,
    expected_phase: int,
) -> DecisionState:
    with _CURRENTNESS_STATE_LOCK:
        state = _CURRENTNESS_STATES.get(handle)
        if state is None or state.verifier_id != id(verifier):
            return DecisionState.DENY
        del _CURRENTNESS_STATES[handle]
    if state.phase != expected_phase or state.context is not context or len(state.receipts) != 2:
        _release_currentness_state(state)
        return DecisionState.DENY
    try:
        issued = state.issuer._claim_currentness_verifier(
            state.issue_nonce,
            state.issue_mac,
            context,
            verifier=verifier,
            expected_phase=expected_phase,
        )
    except Exception:
        _release_currentness_state(state)
        return DecisionState.UNAVAILABLE
    if not issued:
        _release_currentness_state(state)
        return DecisionState.DENY
    receipt = state.receipts[expected_phase]
    try:
        current = state.authorizer.revalidate_current(
            state.presented,
            state.request,
            state.prior,
            receipt,
        )
        result = DecisionState.ALLOW if current is state.prior else DecisionState.DENY
    except AuthorizationDeniedError as exc:
        state.authorizer.discard_currentness_receipts((receipt,))
        result = _capauth_denial(exc.decision.reason).state
    except AuthorizationReceiptError:
        state.authorizer.discard_currentness_receipts((receipt,))
        result = DecisionState.DENY
    except AuthorizationReceiptUnavailableError:
        state.authorizer.discard_currentness_receipts((receipt,))
        result = DecisionState.UNAVAILABLE
    except Exception:
        state.authorizer.discard_currentness_receipts((receipt,))
        result = DecisionState.UNAVAILABLE
    if result is DecisionState.ALLOW and expected_phase == 0:
        state.phase = 1
        with _CURRENTNESS_STATE_LOCK:
            collision = handle in _CURRENTNESS_STATES
            if not collision:
                _CURRENTNESS_STATES[handle] = state
        if collision:
            _release_currentness_state(state)
            return DecisionState.UNAVAILABLE
    else:
        _release_currentness_state(state)
    return result


def _discard_currentness_state(
    handle: bytes,
    *,
    verifier: ControlPlaneCurrentnessVerifier,
) -> None:
    with _CURRENTNESS_STATE_LOCK:
        state = _CURRENTNESS_STATES.get(handle)
        if state is None or state.verifier_id != id(verifier):
            return
        del _CURRENTNESS_STATES[handle]
    _release_currentness_state(state)


def _release_currentness_state(state: _CurrentnessState) -> None:
    state.issuer._discard_currentness_verifier(
        state.issue_nonce,
        verifier_id=state.verifier_id,
    )
    state.authorizer.discard_currentness_receipts(state.receipts)
    del state.presented
    del state.request
    del state.prior
    state.receipts = ()


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
    constraint_expires_at = _utc(
        datetime.fromisoformat(values["expires-at"].replace("Z", "+00:00"))
    )
    signed_scope_binding = ControlPlaneBinding(
        principal=principal,
        acting_principal_id=values.get("acting-principal"),
        session_jti=values.get("session"),
        device_fingerprint_ref=values.get("device"),
        session_policy_revisions_ref=values.get("session-policy"),
        agent_id=expected_agent,
        node_id=values["node"],
        purpose=values["purpose"],
        audience=scope.audience,
        capability=scope.capability,
        target=scope.target,
        resource_type=scope.resource_type,
        resource_id=scope.resource_id,
        owner_policy_revision=values["owner-policy-revision"],
        expires_at=constraint_expires_at,
    )
    if signed_scope_binding.capability_scope() != scope:
        raise ValueError("signed scope cannot be reconstructed exactly")
    if (
        expires_at > constraint_expires_at
        or constraint_expires_at - expires_at > MAX_SIGNED_EXPIRY_CEILING_WINDOW
    ):
        raise ValueError("signed payload exceeds the expiry constraint")
    return signed_scope_binding.model_copy(update={"expires_at": expires_at})


def _constraints(constraints: frozenset[str]) -> dict[str, str]:
    allowed = {
        "acting-principal",
        "agent",
        "expires-at",
        "node",
        "owner-policy-revision",
        "purpose",
        "session",
        "device",
        "session-policy",
    }
    values: dict[str, str] = {}
    for constraint in constraints:
        prefix, separator, value = constraint.partition(":")
        if not separator or prefix not in allowed or not value or prefix in values:
            raise ValueError("signed constraints are outside the closed contract")
        values[prefix] = value
    required = {"expires-at", "node", "owner-policy-revision", "purpose"}
    if not required <= values.keys():
        raise ValueError("signed constraints are incomplete")
    optional = {"acting-principal", "agent", "session", "device", "session-policy"}
    if not set(values) <= required | optional:
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


def _context_fingerprint(context: SanitizedControlPlaneDecisionV1) -> bytes:
    encoded = json.dumps(
        context.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).digest()


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
    "ControlPlaneCurrentnessVerifier",
    "ControlPlaneDecisionAuthorizer",
    "ControlPlaneInvocationV1",
    "OwnerPolicyProvider",
    "SanitizedControlPlaneDecisionV1",
    "export_control_plane_bearer",
    "parse_control_plane_bearer",
]
