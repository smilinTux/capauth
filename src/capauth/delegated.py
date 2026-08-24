"""Strict, request-local verification for delegated capability chains.

This module supplies authorization primitives, not an authorization service.
Applications own their policy and persistence backends and pass current snapshots
into :class:`CapabilityAuthorizer`. CapAuth verifies the signed chain and returns
only a sanitized decision that is safe to retain or audit.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from enum import Enum
from threading import Lock
from typing import Literal, Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_serializer, model_validator
from typing_extensions import Never, Self

from .tokens import SignedToken, TokenPayload, TokenType, signature_verifies

UTC = timezone.utc


class StrEnum(str, Enum):
    """Python 3.10 compatible subset of enum.StrEnum used by this module."""

    def __str__(self) -> str:
        return str.__str__(self.value)


MAX_DELEGATION_DEPTH = 2
MAX_TTL_SECONDS = 3600
MAX_CREDENTIAL_BYTES = 256 * 1024
MAX_AUTHORIZATION_BYTES = (MAX_DELEGATION_DEPTH + 1) * MAX_CREDENTIAL_BYTES + 4096
MAX_SIGNATURE_LENGTH = 128 * 1024
MAX_CURRENTNESS_RECEIPTS = 1024
MAX_CURRENTNESS_RECEIPTS_PER_AUTHORIZATION = 2
METADATA_KEY = "capauth_delegated_capability"
VERIFIER_POLICY_VERSION = "capauth-delegated-authz/v1"


class StrictValue(BaseModel):
    """Immutable, closed value object used at the authorization boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class CredentialFormatError(ValueError):
    """A presented credential does not match the strict wire contract."""


class CredentialSigningError(RuntimeError):
    """A configured signer did not produce a usable detached signature."""


class BackendUnavailableError(RuntimeError):
    """A required current-state backend has no trustworthy answer."""


class PrincipalUnboundError(RuntimeError):
    """A principal has no current authorization-policy binding."""


class DecisionReason(StrEnum):
    """Stable, non-secret authorization outcomes."""

    ALLOW = "allow"
    MISSING_CREDENTIAL = "missing_credential"
    MALFORMED_CREDENTIAL = "malformed_credential"
    UNSIGNED_CREDENTIAL = "unsigned_credential"
    INVALID_SIGNATURE = "invalid_signature"
    UNTRUSTED_ISSUER = "untrusted_issuer"
    POLICY_MISMATCH = "policy_mismatch"
    BACKEND_UNAVAILABLE = "backend_unavailable"
    PRINCIPAL_UNBOUND = "principal_unbound"
    PRINCIPAL_INACTIVE = "principal_inactive"
    PRINCIPAL_REBOUND = "principal_rebound"
    EXPIRED = "expired"
    ANCESTOR_EXPIRED = "ancestor_expired"
    NOT_YET_VALID = "not_yet_valid"
    TTL_EXCEEDED = "ttl_exceeded"
    REVOKED = "revoked"
    ANCESTOR_REVOKED = "ancestor_revoked"
    REPLAYED = "replayed"
    WRONG_PRINCIPAL = "wrong_principal"
    WRONG_SCOPE = "wrong_scope"
    OVER_DELEGATED = "over_delegated"
    DELEGATION_CHAIN_INVALID = "delegation_chain_invalid"
    AUDIT_UNAVAILABLE = "audit_unavailable"
    CURRENT_STATE_CHANGED = "current_state_changed"


class Principal(StrictValue):
    """Identity established by authentication, not request content."""

    principal_id: str = Field(min_length=1, max_length=256)
    subject: str = Field(min_length=1, max_length=1024)
    kind: str = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def validate_names(self) -> Self:
        if any(value != value.strip() for value in (self.principal_id, self.subject, self.kind)):
            raise ValueError("principal fields cannot have surrounding whitespace")
        return self


class CapabilityScope(StrictValue):
    """Exact protected invocation and its generic narrowing constraints."""

    audience: str = Field(min_length=1, max_length=256)
    target: str = Field(min_length=1, max_length=512)
    capability: str = Field(min_length=1, max_length=256)
    operation: str = Field(min_length=1, max_length=128)
    resource_type: str = Field(min_length=1, max_length=128)
    resource_id: str | None = Field(default=None, min_length=1, max_length=1024)
    constraints: frozenset[str] = Field(default_factory=frozenset, max_length=128)

    @model_validator(mode="after")
    def validate_constraints(self) -> Self:
        scalar_values = (
            self.audience,
            self.target,
            self.capability,
            self.operation,
            self.resource_type,
        )
        if any(value != value.strip() for value in scalar_values):
            raise ValueError("scope fields cannot have surrounding whitespace")
        if self.resource_id is not None and self.resource_id != self.resource_id.strip():
            raise ValueError("resource id cannot have surrounding whitespace")
        if any(not item or item != item.strip() or len(item) > 1024 for item in self.constraints):
            raise ValueError("scope constraints must be nonempty and bounded")
        return self

    @field_serializer("constraints")
    def serialize_constraints(self, value: frozenset[str]) -> tuple[str, ...]:
        """Keep signed scope bytes independent of Python hash iteration order."""

        return tuple(sorted(value))


class DelegationClaims(StrictValue):
    depth: int = Field(ge=0, le=MAX_DELEGATION_DEPTH)
    max_depth: int = Field(ge=0, le=MAX_DELEGATION_DEPTH)
    parent_credential_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_lineage(self) -> Self:
        if self.depth == 0 and self.parent_credential_digest is not None:
            raise ValueError("root capability cannot name a parent")
        if self.depth > 0 and self.parent_credential_digest is None:
            raise ValueError("delegated capability requires a parent digest")
        if self.depth > self.max_depth:
            raise ValueError("delegation depth exceeds its signed maximum")
        return self


class CapabilityClaims(StrictValue):
    schema_version: Literal["capauth-delegated-capability/v1"] = "capauth-delegated-capability/v1"
    verifier_policy_version: Literal["capauth-delegated-authz/v1"] = VERIFIER_POLICY_VERSION
    credential_nonce: str = Field(min_length=32, max_length=64)
    principal: Principal
    scope: CapabilityScope
    delegation: DelegationClaims
    use_limit: Literal[1] = 1


class AuthorizationRequest(StrictValue):
    """Exact invocation derived by trusted application boundary code."""

    principal: Principal
    scope: CapabilityScope
    correlation_id: str = Field(min_length=1, max_length=256)


class PrincipalPolicyReference(StrictValue):
    principal_id: str
    revision: str = Field(pattern=r"^[0-9a-f]{64}$")


class AuthorizationDecision(StrictValue):
    """Sanitized exact-scope result containing no bearer or signature bytes."""

    decision_id: str
    attempt_sequence: int = Field(default=1, ge=1, le=2)
    correlation_id: str
    allow: bool
    reason: DecisionReason
    credential_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    ancestor_credential_digests: tuple[str, ...] = ()
    principal_id: str
    scope: CapabilityScope
    delegation_depth: int | None = Field(default=None, ge=0, le=MAX_DELEGATION_DEPTH)
    verifier_policy_version: Literal["capauth-delegated-authz/v1"] = VERIFIER_POLICY_VERSION
    trusted_issuer_policy_revision: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    principal_policy_revisions: tuple[PrincipalPolicyReference, ...] = ()
    revocation_revision: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_disposition(self) -> Self:
        if self.allow != (self.reason is DecisionReason.ALLOW):
            raise ValueError("allow flag and reason disagree")
        return self


class AuthorizationDeniedError(PermissionError):
    """Fail-closed denial carrying only a sanitized decision."""

    def __init__(self, decision: AuthorizationDecision) -> None:
        self.decision = decision
        super().__init__(
            f"authorization denied ({decision.reason.value}); decision_id={decision.decision_id}"
        )


class AuthorizationReceiptError(PermissionError):
    """An opaque currentness receipt was invalid, foreign, altered, or reused."""

    def __init__(self) -> None:
        super().__init__("authorization currentness receipt is invalid")


class AuthorizationReceiptUnavailableError(RuntimeError):
    """A currentness receipt could not be issued safely."""

    def __init__(self) -> None:
        super().__init__("authorization currentness receipt is unavailable")


class AuthorizationCurrentnessReceipt:
    """One-use, request-local proof that an allow came from this authorizer."""

    __slots__ = ("__mac", "__nonce")

    def __init__(self, nonce: bytes, mac: bytes) -> None:
        self.__nonce = bytes(nonce)
        self.__mac = bytes(mac)

    def _proof(self) -> tuple[bytes, bytes]:
        return self.__nonce, self.__mac

    def __repr__(self) -> str:
        return "<redacted authorization currentness receipt>"

    __str__ = __repr__

    def __copy__(self):
        raise TypeError("authorization currentness receipt cannot be copied")

    def __deepcopy__(self, memo):
        del memo
        raise TypeError("authorization currentness receipt cannot be copied")

    def __reduce__(self):
        raise TypeError("authorization currentness receipt cannot be serialized")


class DelegationDeniedError(PermissionError):
    """A proposed child would broaden or misuse delegated authority."""


def _reject_duplicate_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise CredentialFormatError("JSON object contains a duplicate member")
        value[key] = item
    return value


def _strict_json_value(raw: str | bytes) -> object:
    try:
        return json.loads(raw, object_pairs_hook=_reject_duplicate_members)
    except Exception:
        raise CredentialFormatError("JSON input is malformed") from None


class PresentedCapability:
    """Volatile raw leaf plus its complete ordered ancestry, always redacted."""

    __slots__ = ("__ancestors", "__leaf")

    def __init__(self, leaf: str, ancestors: tuple[str, ...] = ()) -> None:
        if not isinstance(leaf, str) or not leaf:
            raise CredentialFormatError("presented leaf credential is empty")
        if any(not isinstance(item, str) or not item for item in ancestors):
            raise CredentialFormatError("presented ancestor credential is empty")
        if len(ancestors) > MAX_DELEGATION_DEPTH:
            raise CredentialFormatError("presented credential chain is too deep")
        if len(set((*ancestors, leaf))) != len(ancestors) + 1:
            raise CredentialFormatError("presented credential chain repeats a credential")
        self.__leaf = leaf
        self.__ancestors = tuple(ancestors)

    @classmethod
    def single(cls, raw_credential: str) -> Self:
        return cls(raw_credential)

    @classmethod
    def delegated(cls, *, leaf: str, ancestors: tuple[str, ...]) -> Self:
        return cls(leaf, ancestors)

    def credentials_for_verification(self) -> tuple[str, ...]:
        """Return root through leaf for immediate boundary verification."""

        return (*self.__ancestors, self.__leaf)

    def with_child(self, child: str) -> PresentedCapability:
        return PresentedCapability(child, (*self.__ancestors, self.__leaf))

    def __repr__(self) -> str:
        return "PresentedCapability(<redacted>)"

    def __str__(self) -> str:
        return "<redacted capability>"

    def __reduce__(self) -> Never:
        raise TypeError("presented capabilities cannot be serialized")


class _WirePayload(StrictValue):
    token_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    token_type: Literal["capability"]
    issuer: str = Field(pattern=r"^(?:[0-9A-F]{40}|[0-9A-F]{64})$")
    subject: str
    capabilities: tuple[str, ...]
    issued_at: datetime
    expires_at: datetime
    not_before: datetime
    metadata: dict[str, object]
    audience: str


class _WireEnvelope(StrictValue):
    skcapstone_token: Literal["1.0"]
    payload: _WirePayload
    signature: str = Field(min_length=1, max_length=MAX_SIGNATURE_LENGTH)


class _AuthorizationChain(StrictValue):
    leaf: str = Field(min_length=1, max_length=MAX_CREDENTIAL_BYTES)
    ancestors: tuple[str, ...] = Field(default=(), max_length=MAX_DELEGATION_DEPTH)

    @model_validator(mode="after")
    def validate_unique(self) -> Self:
        if len(set((*self.ancestors, self.leaf))) != len(self.ancestors) + 1:
            raise ValueError("presented chain repeats a credential")
        return self


class _AuthorizationEnvelope(StrictValue):
    capauth_presented_capability: Literal["1.0"]
    chain: _AuthorizationChain


class ParsedCapability(StrictValue):
    """Parsed signed claims with only an opaque digest in its representation."""

    token: SignedToken = Field(repr=False)
    claims: CapabilityClaims = Field(repr=False)
    credential_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    def __repr__(self) -> str:
        return f"ParsedCapability(credential_digest={self.credential_digest!r}, claims=<signed>)"


def _require_utc(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise CredentialFormatError(f"{field_name} must use UTC offset zero")
    return value.astimezone(UTC)


def _payload_identity(payload: TokenPayload) -> str:
    data = payload.model_dump(mode="json")
    data["token_id"] = ""
    encoded = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode()).hexdigest()


def credential_digest(token: SignedToken, policy_version: str) -> str:
    """Bind signed payload, signature, issuer, and verifier policy to one ID."""

    material = b"\x00".join(
        (
            b"capauth-delegated-credential/v1",
            token.payload.issuer.strip().upper().encode("ascii"),
            policy_version.encode("ascii"),
            token.payload.model_dump_json().encode(),
            (token.signature or "").replace("\r\n", "\n").strip().encode(),
        )
    )
    return hashlib.sha256(material).hexdigest()


def _export_presented_token(token: SignedToken) -> str:
    if not token.signature or not token.signature.strip():
        raise CredentialSigningError("refusing to export an unsigned credential")
    envelope = {
        "skcapstone_token": "1.0",
        "payload": token.payload.model_dump(mode="json"),
        "signature": token.signature.replace("\r\n", "\n").strip(),
    }
    return json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def parse_presented_token(raw_credential: str) -> ParsedCapability:
    """Parse the exact delegated token envelope without permissive legacy paths."""

    if not isinstance(raw_credential, str):
        raise CredentialFormatError("credential must be text")
    if len(raw_credential.encode()) > MAX_CREDENTIAL_BYTES:
        raise CredentialFormatError("credential exceeds the size limit")
    try:
        raw = _strict_json_value(raw_credential)
        envelope = _WireEnvelope.model_validate_json(
            json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        )
        payload = envelope.payload
        if set(payload.metadata) != {METADATA_KEY}:
            raise ValueError("metadata is outside the closed contract")
        claims = CapabilityClaims.model_validate_json(
            json.dumps(payload.metadata[METADATA_KEY], separators=(",", ":"))
        )
        if payload.subject != claims.principal.subject:
            raise ValueError("subject mismatch")
        if payload.audience != claims.scope.audience:
            raise ValueError("audience mismatch")
        if payload.capabilities != (claims.scope.capability,):
            raise ValueError("capability mismatch")
        token_payload = TokenPayload(
            token_id=payload.token_id,
            token_type=TokenType.CAPABILITY,
            issuer=payload.issuer,
            subject=payload.subject,
            capabilities=list(payload.capabilities),
            issued_at=_require_utc(payload.issued_at, "issued_at"),
            expires_at=_require_utc(payload.expires_at, "expires_at"),
            not_before=_require_utc(payload.not_before, "not_before"),
            metadata={METADATA_KEY: claims.model_dump(mode="json")},
            audience=payload.audience,
        )
        if token_payload.token_id != _payload_identity(token_payload):
            raise ValueError("payload identity mismatch")
        token = SignedToken(
            payload=token_payload,
            signature=envelope.signature.strip(),
            verified=False,
        )
    except Exception:
        raise CredentialFormatError("credential envelope is malformed") from None
    return ParsedCapability(
        token=token,
        claims=claims,
        credential_digest=credential_digest(token, claims.verifier_policy_version),
    )


def export_authorization_bearer(presented: PresentedCapability) -> str:
    """Encode the full ordered chain in a versioned transport envelope."""

    chain = presented.credentials_for_verification()
    encoded = _AuthorizationEnvelope(
        capauth_presented_capability="1.0",
        chain=_AuthorizationChain(leaf=chain[-1], ancestors=chain[:-1]),
    ).model_dump_json()
    if len(encoded.encode()) > MAX_AUTHORIZATION_BYTES:
        raise CredentialFormatError("authorization value exceeds the size limit")
    return encoded


def parse_authorization_bearer(raw_bearer: str) -> PresentedCapability:
    """Accept an exact direct token or a versioned complete-chain envelope."""

    if not isinstance(raw_bearer, str) or not raw_bearer:
        raise CredentialFormatError("authorization value is empty")
    if len(raw_bearer.encode()) > MAX_AUTHORIZATION_BYTES:
        raise CredentialFormatError("authorization value exceeds the size limit")
    try:
        value = _strict_json_value(raw_bearer)
        if not isinstance(value, dict):
            raise ValueError("not an object")
        if set(value) == {"skcapstone_token", "payload", "signature"}:
            parse_presented_token(raw_bearer)
            return PresentedCapability.single(raw_bearer)
        envelope = _AuthorizationEnvelope.model_validate_json(
            json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        )
        return PresentedCapability.delegated(
            leaf=envelope.chain.leaf,
            ancestors=envelope.chain.ancestors,
        )
    except Exception:
        raise CredentialFormatError("authorization value is malformed") from None


class CredentialSigner(Protocol):
    @property
    def issuer_fingerprint(self) -> str: ...

    def sign(self, payload_bytes: bytes) -> str: ...


class SignatureVerifier(Protocol):
    def verify(self, token: SignedToken) -> bool: ...


class CapAuthSignatureVerifier:
    """Default adapter over CapAuth's existing issuer-pinned verifier."""

    def verify(self, token: SignedToken) -> bool:
        return signature_verifies(token)


class CapabilityIssuer:
    """Issue short-lived, one-use, non-persistent delegated credentials."""

    def __init__(
        self, signer: CredentialSigner, *, clock: Callable[[], datetime] | None = None
    ) -> None:
        fingerprint = signer.issuer_fingerprint.strip().upper()
        if len(fingerprint) not in {40, 64} or any(
            c not in "0123456789ABCDEF" for c in fingerprint
        ):
            raise ValueError("issuer fingerprint must be full uppercase hexadecimal")
        self._signer = signer
        self._clock = clock or (lambda: datetime.now(UTC))

    def issue_root(
        self,
        *,
        principal: Principal,
        scope: CapabilityScope,
        ttl_seconds: int = 300,
        max_delegation_depth: int = 0,
    ) -> PresentedCapability:
        raw = self._issue(
            principal=principal,
            scope=scope,
            delegation=DelegationClaims(depth=0, max_depth=max_delegation_depth),
            ttl_seconds=ttl_seconds,
            parent_expires_at=None,
        )
        return PresentedCapability.single(raw)

    def _issue_child(
        self,
        *,
        parent: ParsedCapability,
        principal: Principal,
        scope: CapabilityScope,
        ttl_seconds: int,
    ) -> str:
        return self._issue(
            principal=principal,
            scope=scope,
            delegation=DelegationClaims(
                depth=parent.claims.delegation.depth + 1,
                max_depth=parent.claims.delegation.max_depth,
                parent_credential_digest=parent.credential_digest,
            ),
            ttl_seconds=ttl_seconds,
            parent_expires_at=parent.token.payload.expires_at,
        )

    def _issue(
        self,
        *,
        principal: Principal,
        scope: CapabilityScope,
        delegation: DelegationClaims,
        ttl_seconds: int,
        parent_expires_at: datetime | None,
    ) -> str:
        if not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
            raise ValueError("capability TTL must be between 1 second and 1 hour")
        now = _require_utc(self._clock(), "issuer clock")
        expires_at = now + timedelta(seconds=ttl_seconds)
        if parent_expires_at is not None:
            expires_at = min(expires_at, parent_expires_at)
        if expires_at <= now:
            raise ValueError("delegated capability would already be expired")
        claims = CapabilityClaims(
            credential_nonce=uuid4().hex,
            principal=principal,
            scope=scope,
            delegation=delegation,
        )
        payload = TokenPayload(
            token_id="",
            token_type=TokenType.CAPABILITY,
            issuer=self._signer.issuer_fingerprint.strip().upper(),
            subject=principal.subject,
            capabilities=[scope.capability],
            issued_at=now,
            expires_at=expires_at,
            not_before=now,
            metadata={METADATA_KEY: claims.model_dump(mode="json")},
            audience=scope.audience,
        )
        payload.token_id = _payload_identity(payload)
        try:
            signature = self._signer.sign(payload.model_dump_json().encode())
        except Exception:
            raise CredentialSigningError("trusted signer failed") from None
        if not signature or not signature.strip():
            raise CredentialSigningError("trusted signer returned no signature")
        return _export_presented_token(
            SignedToken(payload=payload, signature=signature.strip(), verified=True)
        )


def _revision(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


class IssuerGrant(StrictValue):
    fingerprint: str = Field(pattern=r"^(?:[0-9A-F]{40}|[0-9A-F]{64})$")
    capabilities: frozenset[str]
    audiences: frozenset[str]
    principal_kinds: frozenset[str]

    @model_validator(mode="after")
    def validate_authority(self) -> Self:
        if not self.capabilities or not self.audiences or not self.principal_kinds:
            raise ValueError("issuer authority sets cannot be empty")
        values = self.capabilities | self.audiences | self.principal_kinds
        if any(not item or item != item.strip() or len(item) > 256 for item in values):
            raise ValueError("issuer authority names must be nonempty and bounded")
        return self


class TrustedIssuerSnapshot(StrictValue):
    policy_version: str = Field(min_length=1, max_length=128)
    revision: str = Field(pattern=r"^[0-9a-f]{64}$")
    issuers: tuple[IssuerGrant, ...]

    @model_validator(mode="after")
    def validate_unique_issuers(self) -> Self:
        fingerprints = tuple(item.fingerprint for item in self.issuers)
        if len(fingerprints) != len(set(fingerprints)):
            raise ValueError("trusted issuer fingerprints must be unique")
        return self


class PrincipalPolicySnapshot(StrictValue):
    revision: str = Field(pattern=r"^[0-9a-f]{64}$")
    principal: Principal
    active: bool


class RevocationSnapshot(StrictValue):
    revision: str = Field(pattern=r"^[0-9a-f]{64}$")
    revoked_credential_digests: frozenset[str]

    @model_validator(mode="after")
    def validate_digests(self) -> Self:
        if any(
            len(item) != 64 or any(char not in "0123456789abcdef" for char in item)
            for item in self.revoked_credential_digests
        ):
            raise ValueError("revoked credential digests must be lowercase SHA-256")
        return self


class TrustedIssuerBackend(Protocol):
    def snapshot(self) -> TrustedIssuerSnapshot: ...


class PrincipalPolicyBackend(Protocol):
    def snapshot(self, principal: Principal) -> PrincipalPolicySnapshot: ...


class RevocationBackend(Protocol):
    def snapshot(self, credential_digests: tuple[str, ...]) -> RevocationSnapshot: ...


class ReplayBackend(Protocol):
    def reserve(
        self, *, credential_digest: str, decision_id: str, expires_at: datetime
    ) -> bool: ...


class AuditSink(Protocol):
    def record(self, decision: AuthorizationDecision) -> None: ...


class StaticTrustedIssuerBackend:
    """Immutable issuer policy for tests and isolated local composition."""

    def __init__(
        self,
        issuers: tuple[IssuerGrant, ...],
        *,
        policy_version: str = VERIFIER_POLICY_VERSION,
    ) -> None:
        if len({item.fingerprint for item in issuers}) != len(issuers):
            raise ValueError("trusted issuer fingerprints must be unique")
        self._snapshot = TrustedIssuerSnapshot(
            policy_version=policy_version,
            revision=_revision(
                {
                    "policy_version": policy_version,
                    "issuers": [item.model_dump(mode="json") for item in issuers],
                }
            ),
            issuers=issuers,
        )

    def snapshot(self) -> TrustedIssuerSnapshot:
        return self._snapshot


class InMemoryPrincipalPolicyBackend:
    """Atomic process-local current-principal backend for tests and development."""

    def __init__(self, principals: tuple[Principal, ...] = ()) -> None:
        self._lock = Lock()
        self._principals = {item.principal_id: (item, True) for item in principals}
        self._counter = 0

    def set(self, principal: Principal, *, active: bool = True) -> None:
        with self._lock:
            self._principals[principal.principal_id] = (principal, active)
            self._counter += 1

    def remove(self, principal_id: str) -> None:
        with self._lock:
            self._principals.pop(principal_id, None)
            self._counter += 1

    def snapshot(self, principal: Principal) -> PrincipalPolicySnapshot:
        with self._lock:
            current = self._principals.get(principal.principal_id)
            if current is None:
                raise PrincipalUnboundError("principal is not bound")
            value, active = current
            revision = _revision(
                {
                    "counter": self._counter,
                    "principal": value.model_dump(mode="json"),
                    "active": active,
                }
            )
        return PrincipalPolicySnapshot(revision=revision, principal=value, active=active)


class InMemoryRevocationBackend:
    """Atomic process-local revocation backend for tests and development."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._revoked: set[str] = set()
        self._counter = 0

    def revoke(self, credential_digest: str) -> None:
        with self._lock:
            self._revoked.add(credential_digest)
            self._counter += 1

    def snapshot(self, credential_digests: tuple[str, ...]) -> RevocationSnapshot:
        with self._lock:
            revoked = frozenset(set(credential_digests).intersection(self._revoked))
            revision = _revision({"counter": self._counter, "revoked": sorted(self._revoked)})
        return RevocationSnapshot(revision=revision, revoked_credential_digests=revoked)


class InMemoryReplayBackend:
    """Atomic process-local replay backend, never a production default."""

    def __init__(self, *, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = Lock()
        self._reservations: dict[str, datetime] = {}

    def reserve(self, *, credential_digest: str, decision_id: str, expires_at: datetime) -> bool:
        del decision_id
        with self._lock:
            now = self._clock()
            self._reservations = {
                digest: expiry for digest, expiry in self._reservations.items() if expiry >= now
            }
            if credential_digest in self._reservations:
                return False
            self._reservations[credential_digest] = expires_at
            return True


class InMemoryAuditSink:
    """Atomic process-local sink retaining only sanitized decisions."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._decisions: list[AuthorizationDecision] = []

    def record(self, decision: AuthorizationDecision) -> None:
        with self._lock:
            self._decisions.append(decision)

    def decisions(self) -> tuple[AuthorizationDecision, ...]:
        with self._lock:
            return tuple(self._decisions)


class CapabilityAuthorizer:
    """Verify a complete current chain and reserve its leaf exactly once."""

    def __init__(
        self,
        *,
        trusted_issuers: TrustedIssuerBackend,
        principals: PrincipalPolicyBackend,
        revocations: RevocationBackend,
        replay: ReplayBackend,
        audit: AuditSink,
        signature_verifier: SignatureVerifier | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._trusted_issuers = trusted_issuers
        self._principals = principals
        self._revocations = revocations
        self._replay = replay
        self._audit = audit
        self._signature_verifier = signature_verifier or CapAuthSignatureVerifier()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._receipt_key = secrets.token_bytes(32)
        self._receipt_lock = Lock()
        self._receipt_expiries: dict[bytes, datetime] = {}

    def authorize(
        self, presented: PresentedCapability | None, request: AuthorizationRequest
    ) -> AuthorizationDecision:
        decision_id = str(uuid4())
        if presented is None:
            self._deny(request, decision_id, DecisionReason.MISSING_CREDENTIAL)
        try:
            raw_chain = presented.credentials_for_verification()
            chain = tuple(parse_presented_token(raw) for raw in raw_chain)
        except Exception:
            self._deny(request, decision_id, DecisionReason.MALFORMED_CREDENTIAL)
        leaf = chain[-1]

        try:
            issuer_policy = self._trusted_issuers.snapshot()
            if not isinstance(issuer_policy, TrustedIssuerSnapshot):
                raise TypeError("invalid issuer snapshot")
        except Exception:
            self._deny(request, decision_id, DecisionReason.BACKEND_UNAVAILABLE, chain)
        if issuer_policy.policy_version != VERIFIER_POLICY_VERSION:
            self._deny(
                request,
                decision_id,
                DecisionReason.POLICY_MISMATCH,
                chain,
                issuer_revision=issuer_policy.revision,
            )

        principal_reason, principal_refs = self._validate_principals(chain, request)
        if principal_reason:
            self._deny(
                request,
                decision_id,
                principal_reason,
                chain,
                issuer_revision=issuer_policy.revision,
                principal_references=principal_refs,
            )

        try:
            chain_reason = self._validate_chain(chain, issuer_policy)
        except Exception:
            self._deny(
                request,
                decision_id,
                DecisionReason.BACKEND_UNAVAILABLE,
                chain,
                issuer_revision=issuer_policy.revision,
                principal_references=principal_refs,
            )
        if chain_reason:
            self._deny(
                request,
                decision_id,
                chain_reason,
                chain,
                issuer_revision=issuer_policy.revision,
                principal_references=principal_refs,
            )

        digests = tuple(item.credential_digest for item in chain)
        try:
            revocation = self._revocations.snapshot(digests)
            if not isinstance(revocation, RevocationSnapshot):
                raise TypeError("invalid revocation snapshot")
        except Exception:
            self._deny(
                request,
                decision_id,
                DecisionReason.BACKEND_UNAVAILABLE,
                chain,
                issuer_revision=issuer_policy.revision,
                principal_references=principal_refs,
            )
        if leaf.credential_digest in revocation.revoked_credential_digests:
            self._deny_with_state(
                request,
                decision_id,
                DecisionReason.REVOKED,
                chain,
                issuer_policy,
                principal_refs,
                revocation,
            )
        if any(
            item.credential_digest in revocation.revoked_credential_digests for item in chain[:-1]
        ):
            self._deny_with_state(
                request,
                decision_id,
                DecisionReason.ANCESTOR_REVOKED,
                chain,
                issuer_policy,
                principal_refs,
                revocation,
            )

        for item in chain:
            if not item.token.signature:
                self._deny_with_state(
                    request,
                    decision_id,
                    DecisionReason.UNSIGNED_CREDENTIAL,
                    chain,
                    issuer_policy,
                    principal_refs,
                    revocation,
                )
            try:
                verified = self._signature_verifier.verify(item.token)
            except Exception:
                verified = False
            if not verified:
                self._deny_with_state(
                    request,
                    decision_id,
                    DecisionReason.INVALID_SIGNATURE,
                    chain,
                    issuer_policy,
                    principal_refs,
                    revocation,
                )

        try:
            time_reason = self._validate_chain_time(chain)
        except Exception:
            self._deny_with_state(
                request,
                decision_id,
                DecisionReason.BACKEND_UNAVAILABLE,
                chain,
                issuer_policy,
                principal_refs,
                revocation,
            )
        if time_reason:
            self._deny_with_state(
                request, decision_id, time_reason, chain, issuer_policy, principal_refs, revocation
            )
        if leaf.claims.principal != request.principal:
            self._deny_with_state(
                request,
                decision_id,
                DecisionReason.WRONG_PRINCIPAL,
                chain,
                issuer_policy,
                principal_refs,
                revocation,
            )
        if leaf.claims.scope != request.scope:
            self._deny_with_state(
                request,
                decision_id,
                DecisionReason.WRONG_SCOPE,
                chain,
                issuer_policy,
                principal_refs,
                revocation,
            )

        expires_at = leaf.token.payload.expires_at
        assert expires_at is not None
        try:
            reserved = self._replay.reserve(
                credential_digest=leaf.credential_digest,
                decision_id=decision_id,
                expires_at=expires_at,
            )
            if not isinstance(reserved, bool):
                raise TypeError("invalid replay result")
        except Exception:
            self._deny_with_state(
                request,
                decision_id,
                DecisionReason.BACKEND_UNAVAILABLE,
                chain,
                issuer_policy,
                principal_refs,
                revocation,
            )
        if not reserved:
            self._deny_with_state(
                request,
                decision_id,
                DecisionReason.REPLAYED,
                chain,
                issuer_policy,
                principal_refs,
                revocation,
            )

        try:
            final_time_reason = self._validate_chain_time(chain)
        except Exception:
            self._deny_with_state(
                request,
                decision_id,
                DecisionReason.BACKEND_UNAVAILABLE,
                chain,
                issuer_policy,
                principal_refs,
                revocation,
            )
        if final_time_reason:
            self._deny_with_state(
                request,
                decision_id,
                final_time_reason,
                chain,
                issuer_policy,
                principal_refs,
                revocation,
            )

        # Cryptographic verification and replay reservation may take long enough
        # for live issuer, principal, or revocation policy to change. Refresh all
        # three after that work, immediately before emitting an allow decision.
        issuer_policy, principal_refs, revocation = self._refresh_current_state(
            request=request,
            decision_id=decision_id,
            chain=chain,
            previous_issuer=issuer_policy,
            previous_principals=principal_refs,
            previous_revocation=revocation,
        )
        decision = self._decision(
            request,
            decision_id,
            True,
            DecisionReason.ALLOW,
            chain,
            issuer_revision=issuer_policy.revision,
            principal_references=principal_refs,
            revocation_revision=revocation.revision,
        )
        try:
            self._audit.record(decision)
        except Exception:
            denied = self._decision(
                request,
                decision_id,
                False,
                DecisionReason.AUDIT_UNAVAILABLE,
                chain,
                issuer_revision=issuer_policy.revision,
                principal_references=principal_refs,
                revocation_revision=revocation.revision,
            )
            raise AuthorizationDeniedError(denied) from None
        final_issuer, final_principals, final_revocation = self._refresh_current_state(
            request=request,
            decision_id=decision_id,
            chain=chain,
            previous_issuer=issuer_policy,
            previous_principals=principal_refs,
            previous_revocation=revocation,
            audit_sequence=2,
        )
        try:
            final_time_reason = self._validate_chain_time(chain)
        except Exception:
            self._deny_with_state(
                request,
                decision_id,
                DecisionReason.BACKEND_UNAVAILABLE,
                chain,
                final_issuer,
                final_principals,
                final_revocation,
                audit_sequence=2,
            )
        if final_time_reason:
            self._deny_with_state(
                request,
                decision_id,
                final_time_reason,
                chain,
                final_issuer,
                final_principals,
                final_revocation,
                audit_sequence=2,
            )
        if (
            final_issuer.revision != issuer_policy.revision
            or final_principals != principal_refs
            or final_revocation.revision != revocation.revision
        ):
            self._deny_with_state(
                request,
                decision_id,
                DecisionReason.CURRENT_STATE_CHANGED,
                chain,
                final_issuer,
                final_principals,
                final_revocation,
                audit_sequence=2,
            )
        return decision

    def authorize_with_receipt(
        self,
        presented: PresentedCapability | None,
        request: AuthorizationRequest,
    ) -> tuple[AuthorizationDecision, AuthorizationCurrentnessReceipt]:
        """Authorize once and mint an opaque proof for one later currentness check."""

        decision = self.authorize(presented, request)
        receipts = self._mint_currentness_receipts(presented, request, decision, count=1)
        return decision, receipts[0]

    def revalidate_current_with_receipts(
        self,
        presented: PresentedCapability,
        request: AuthorizationRequest,
        prior: AuthorizationDecision,
        receipt: AuthorizationCurrentnessReceipt,
        *,
        count: int,
    ) -> tuple[AuthorizationDecision, tuple[AuthorizationCurrentnessReceipt, ...]]:
        """Revalidate one real allow and mint bounded proofs for downstream checks."""

        decision = self.revalidate_current(presented, request, prior, receipt)
        receipts = self._mint_currentness_receipts(
            presented,
            request,
            decision,
            count=count,
        )
        return decision, receipts

    def discard_currentness_receipts(
        self,
        receipts: tuple[AuthorizationCurrentnessReceipt, ...],
    ) -> None:
        """Invalidate request-local receipts that will not be used."""

        nonces = []
        for receipt in receipts:
            if not isinstance(receipt, AuthorizationCurrentnessReceipt):
                continue
            try:
                nonce, _mac = receipt._proof()
            except Exception:
                continue
            nonces.append(nonce)
        with self._receipt_lock:
            for nonce in nonces:
                self._receipt_expiries.pop(nonce, None)

    def revalidate_current(
        self,
        presented: PresentedCapability,
        request: AuthorizationRequest,
        prior: AuthorizationDecision,
        receipt: AuthorizationCurrentnessReceipt,
    ) -> AuthorizationDecision:
        """Recheck current policy after downstream work without consuming replay again."""

        if not isinstance(receipt, AuthorizationCurrentnessReceipt):
            raise AuthorizationReceiptError
        try:
            nonce, actual_mac = receipt._proof()
            expected_mac = self._receipt_mac(nonce, request, prior)
        except Exception:
            raise AuthorizationReceiptError from None
        try:
            now = _require_utc(self._clock(), "authorizer clock")
        except Exception:
            raise AuthorizationReceiptUnavailableError from None
        with self._receipt_lock:
            registered_expiry = self._receipt_expiries.get(nonce)
            self._receipt_expiries = {
                value: deadline
                for value, deadline in self._receipt_expiries.items()
                if deadline > now
            }
            valid = (
                registered_expiry is not None
                and registered_expiry > now
                and hmac.compare_digest(actual_mac, expected_mac)
            )
            if valid:
                del self._receipt_expiries[nonce]
        if not valid:
            raise AuthorizationReceiptError

        decision_id = prior.decision_id
        try:
            raw_chain = presented.credentials_for_verification()
            chain = tuple(parse_presented_token(raw) for raw in raw_chain)
        except Exception:
            self._deny(
                request,
                decision_id,
                DecisionReason.MALFORMED_CREDENTIAL,
                audit_sequence=2,
            )
        leaf = chain[-1]
        prior_is_bound = (
            isinstance(prior, AuthorizationDecision)
            and prior.allow
            and prior.reason is DecisionReason.ALLOW
            and prior.attempt_sequence == 1
            and prior.correlation_id == request.correlation_id
            and prior.principal_id == request.principal.principal_id
            and prior.scope == request.scope
            and prior.credential_digest == leaf.credential_digest
            and prior.ancestor_credential_digests
            == tuple(item.credential_digest for item in chain[:-1])
            and prior.delegation_depth == leaf.claims.delegation.depth
            and leaf.claims.principal == request.principal
            and leaf.claims.scope == request.scope
            and prior.trusted_issuer_policy_revision is not None
            and bool(prior.principal_policy_revisions)
            and prior.revocation_revision is not None
        )
        if not prior_is_bound:
            self._deny(
                request,
                decision_id,
                DecisionReason.CURRENT_STATE_CHANGED,
                chain,
                audit_sequence=2,
            )

        try:
            time_reason = self._validate_chain_time(chain)
        except Exception:
            time_reason = DecisionReason.BACKEND_UNAVAILABLE
        if time_reason:
            self._deny(
                request,
                decision_id,
                time_reason,
                chain,
                issuer_revision=prior.trusted_issuer_policy_revision,
                principal_references=prior.principal_policy_revisions,
                revocation_revision=prior.revocation_revision,
                audit_sequence=2,
            )

        try:
            issuer = self._trusted_issuers.snapshot()
            if not isinstance(issuer, TrustedIssuerSnapshot):
                raise TypeError("invalid issuer snapshot")
        except Exception:
            self._deny(
                request,
                decision_id,
                DecisionReason.BACKEND_UNAVAILABLE,
                chain,
                principal_references=prior.principal_policy_revisions,
                revocation_revision=prior.revocation_revision,
                audit_sequence=2,
            )
        if issuer.policy_version != VERIFIER_POLICY_VERSION:
            self._deny(
                request,
                decision_id,
                DecisionReason.POLICY_MISMATCH,
                chain,
                issuer_revision=issuer.revision,
                principal_references=prior.principal_policy_revisions,
                revocation_revision=prior.revocation_revision,
                audit_sequence=2,
            )
        try:
            chain_reason = self._validate_chain(chain, issuer)
        except Exception:
            chain_reason = DecisionReason.BACKEND_UNAVAILABLE
        if chain_reason:
            self._deny(
                request,
                decision_id,
                chain_reason,
                chain,
                issuer_revision=issuer.revision,
                principal_references=prior.principal_policy_revisions,
                revocation_revision=prior.revocation_revision,
                audit_sequence=2,
            )

        principal_reason, principal_refs = self._validate_principals(chain, request)
        if principal_reason:
            self._deny(
                request,
                decision_id,
                principal_reason,
                chain,
                issuer_revision=issuer.revision,
                principal_references=principal_refs,
                revocation_revision=prior.revocation_revision,
                audit_sequence=2,
            )
        digests = tuple(item.credential_digest for item in chain)
        try:
            revocation = self._revocations.snapshot(digests)
            if not isinstance(revocation, RevocationSnapshot):
                raise TypeError("invalid revocation snapshot")
        except Exception:
            self._deny(
                request,
                decision_id,
                DecisionReason.BACKEND_UNAVAILABLE,
                chain,
                issuer_revision=issuer.revision,
                principal_references=principal_refs,
                revocation_revision=prior.revocation_revision,
                audit_sequence=2,
            )
        if leaf.credential_digest in revocation.revoked_credential_digests:
            self._deny_with_state(
                request,
                decision_id,
                DecisionReason.REVOKED,
                chain,
                issuer,
                principal_refs,
                revocation,
                audit_sequence=2,
            )
        if any(
            item.credential_digest in revocation.revoked_credential_digests for item in chain[:-1]
        ):
            self._deny_with_state(
                request,
                decision_id,
                DecisionReason.ANCESTOR_REVOKED,
                chain,
                issuer,
                principal_refs,
                revocation,
                audit_sequence=2,
            )
        try:
            final_time_reason = self._validate_chain_time(chain)
        except Exception:
            final_time_reason = DecisionReason.BACKEND_UNAVAILABLE
        if final_time_reason:
            self._deny_with_state(
                request,
                decision_id,
                final_time_reason,
                chain,
                issuer,
                principal_refs,
                revocation,
                audit_sequence=2,
            )
        if (
            issuer.revision != prior.trusted_issuer_policy_revision
            or principal_refs != prior.principal_policy_revisions
            or revocation.revision != prior.revocation_revision
        ):
            self._deny_with_state(
                request,
                decision_id,
                DecisionReason.CURRENT_STATE_CHANGED,
                chain,
                issuer,
                principal_refs,
                revocation,
                audit_sequence=2,
            )
        return prior

    def _receipt_mac(
        self,
        nonce: bytes,
        request: AuthorizationRequest,
        decision: AuthorizationDecision,
    ) -> bytes:
        try:
            facts = {
                "domain": "capauth-authorization-currentness-receipt/v1",
                "nonce": nonce.hex(),
                "request": request.model_dump(mode="json"),
                "decision": decision.model_dump(mode="json"),
            }
            encoded = json.dumps(
                facts, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("ascii")
        except Exception:
            raise AuthorizationReceiptError from None
        return hmac.new(self._receipt_key, encoded, hashlib.sha256).digest()

    def _mint_currentness_receipts(
        self,
        presented: PresentedCapability | None,
        request: AuthorizationRequest,
        decision: AuthorizationDecision,
        *,
        count: int,
    ) -> tuple[AuthorizationCurrentnessReceipt, ...]:
        if type(count) is not int or not 1 <= count <= MAX_CURRENTNESS_RECEIPTS_PER_AUTHORIZATION:
            raise AuthorizationReceiptUnavailableError
        if presented is None:
            raise AuthorizationReceiptUnavailableError
        try:
            leaf = parse_presented_token(presented.credentials_for_verification()[-1])
            expiry = _require_utc(leaf.token.payload.expires_at, "expires_at")
            now = _require_utc(self._clock(), "authorizer clock")
        except Exception:
            raise AuthorizationReceiptUnavailableError from None
        issued: dict[bytes, tuple[datetime, bytes]] = {}
        with self._receipt_lock:
            self._receipt_expiries = {
                value: deadline
                for value, deadline in self._receipt_expiries.items()
                if deadline > now
            }
            if len(self._receipt_expiries) + count > MAX_CURRENTNESS_RECEIPTS:
                raise AuthorizationReceiptUnavailableError
            for _attempt in range(16):
                if len(issued) == count:
                    break
                try:
                    nonce = secrets.token_bytes(32)
                    if nonce in self._receipt_expiries or nonce in issued:
                        continue
                    issued[nonce] = (expiry, self._receipt_mac(nonce, request, decision))
                except Exception:
                    raise AuthorizationReceiptUnavailableError from None
            if len(issued) != count:
                raise AuthorizationReceiptUnavailableError
            self._receipt_expiries.update({nonce: value[0] for nonce, value in issued.items()})
        return tuple(
            AuthorizationCurrentnessReceipt(nonce, value[1]) for nonce, value in issued.items()
        )

    def _refresh_current_state(
        self,
        *,
        request: AuthorizationRequest,
        decision_id: str,
        chain: tuple[ParsedCapability, ...],
        previous_issuer: TrustedIssuerSnapshot,
        previous_principals: tuple[PrincipalPolicyReference, ...],
        previous_revocation: RevocationSnapshot,
        audit_sequence: int = 1,
    ) -> tuple[
        TrustedIssuerSnapshot,
        tuple[PrincipalPolicyReference, ...],
        RevocationSnapshot,
    ]:
        try:
            issuer = self._trusted_issuers.snapshot()
            if not isinstance(issuer, TrustedIssuerSnapshot):
                raise TypeError("invalid issuer snapshot")
        except Exception:
            self._deny_with_state(
                request,
                decision_id,
                DecisionReason.BACKEND_UNAVAILABLE,
                chain,
                previous_issuer,
                previous_principals,
                previous_revocation,
                audit_sequence=audit_sequence,
            )
        if issuer.policy_version != VERIFIER_POLICY_VERSION:
            self._deny(
                request,
                decision_id,
                DecisionReason.POLICY_MISMATCH,
                chain,
                issuer_revision=issuer.revision,
                principal_references=previous_principals,
                revocation_revision=previous_revocation.revision,
                audit_sequence=audit_sequence,
            )
        try:
            chain_reason = self._validate_chain(chain, issuer)
        except Exception:
            chain_reason = DecisionReason.BACKEND_UNAVAILABLE
        if chain_reason:
            self._deny(
                request,
                decision_id,
                chain_reason,
                chain,
                issuer_revision=issuer.revision,
                principal_references=previous_principals,
                revocation_revision=previous_revocation.revision,
                audit_sequence=audit_sequence,
            )

        principal_reason, principal_references = self._validate_principals(chain, request)
        if principal_reason:
            self._deny(
                request,
                decision_id,
                principal_reason,
                chain,
                issuer_revision=issuer.revision,
                principal_references=principal_references,
                revocation_revision=previous_revocation.revision,
                audit_sequence=audit_sequence,
            )

        digests = tuple(item.credential_digest for item in chain)
        try:
            revocation = self._revocations.snapshot(digests)
            if not isinstance(revocation, RevocationSnapshot):
                raise TypeError("invalid revocation snapshot")
        except Exception:
            self._deny(
                request,
                decision_id,
                DecisionReason.BACKEND_UNAVAILABLE,
                chain,
                issuer_revision=issuer.revision,
                principal_references=principal_references,
                revocation_revision=previous_revocation.revision,
                audit_sequence=audit_sequence,
            )
        leaf = chain[-1]
        if leaf.credential_digest in revocation.revoked_credential_digests:
            self._deny_with_state(
                request,
                decision_id,
                DecisionReason.REVOKED,
                chain,
                issuer,
                principal_references,
                revocation,
                audit_sequence=audit_sequence,
            )
        if any(
            item.credential_digest in revocation.revoked_credential_digests for item in chain[:-1]
        ):
            self._deny_with_state(
                request,
                decision_id,
                DecisionReason.ANCESTOR_REVOKED,
                chain,
                issuer,
                principal_references,
                revocation,
                audit_sequence=audit_sequence,
            )
        return issuer, principal_references, revocation

    def _validate_principals(
        self, chain: tuple[ParsedCapability, ...], request: AuthorizationRequest
    ) -> tuple[DecisionReason | None, tuple[PrincipalPolicyReference, ...]]:
        asserted: dict[str, list[Principal]] = {}
        for principal in (*(item.claims.principal for item in chain), request.principal):
            asserted.setdefault(principal.principal_id, [])
            if principal not in asserted[principal.principal_id]:
                asserted[principal.principal_id].append(principal)
        references: list[PrincipalPolicyReference] = []
        for principal_id, values in asserted.items():
            try:
                snapshot = self._principals.snapshot(values[0])
                if not isinstance(snapshot, PrincipalPolicySnapshot):
                    raise TypeError("invalid principal snapshot")
            except PrincipalUnboundError:
                return DecisionReason.PRINCIPAL_UNBOUND, tuple(references)
            except Exception:
                return DecisionReason.BACKEND_UNAVAILABLE, tuple(references)
            references.append(
                PrincipalPolicyReference(principal_id=principal_id, revision=snapshot.revision)
            )
            if any(snapshot.principal != value for value in values):
                return DecisionReason.PRINCIPAL_REBOUND, tuple(references)
            if not snapshot.active:
                return DecisionReason.PRINCIPAL_INACTIVE, tuple(references)
        return None, tuple(references)

    def _validate_chain(
        self,
        chain: tuple[ParsedCapability, ...],
        issuer_policy: TrustedIssuerSnapshot,
    ) -> DecisionReason | None:
        if not 1 <= len(chain) <= MAX_DELEGATION_DEPTH + 1:
            return DecisionReason.DELEGATION_CHAIN_INVALID
        time_reason = self._validate_chain_time(chain)
        if time_reason:
            return time_reason
        for index, item in enumerate(chain):
            grant = next(
                (
                    candidate
                    for candidate in issuer_policy.issuers
                    if candidate.fingerprint == item.token.payload.issuer.upper()
                ),
                None,
            )
            if grant is None:
                return DecisionReason.UNTRUSTED_ISSUER
            if (
                item.claims.scope.capability not in grant.capabilities
                or item.claims.scope.audience not in grant.audiences
                or item.claims.principal.kind not in grant.principal_kinds
            ):
                return DecisionReason.UNTRUSTED_ISSUER
            if item.claims.verifier_policy_version != VERIFIER_POLICY_VERSION:
                return DecisionReason.POLICY_MISMATCH
            delegation = item.claims.delegation
            if delegation.depth != index:
                return DecisionReason.DELEGATION_CHAIN_INVALID
            if index == 0:
                if delegation.parent_credential_digest is not None:
                    return DecisionReason.DELEGATION_CHAIN_INVALID
            else:
                parent = chain[index - 1]
                if delegation.parent_credential_digest != parent.credential_digest:
                    return DecisionReason.DELEGATION_CHAIN_INVALID
                if not _is_monotonic(parent, item):
                    return DecisionReason.OVER_DELEGATED
        return None

    def _validate_chain_time(self, chain: tuple[ParsedCapability, ...]) -> DecisionReason | None:
        now = _require_utc(self._clock(), "authorizer clock")
        for index, item in enumerate(chain):
            payload = item.token.payload
            if payload.expires_at is None or payload.not_before is None:
                return DecisionReason.MALFORMED_CREDENTIAL
            issued = _require_utc(payload.issued_at, "issued_at")
            expires = _require_utc(payload.expires_at, "expires_at")
            not_before = _require_utc(payload.not_before, "not_before")
            if expires <= now:
                if index == len(chain) - 1:
                    return DecisionReason.EXPIRED
                return DecisionReason.ANCESTOR_EXPIRED
            if not_before > now or issued > now:
                return DecisionReason.NOT_YET_VALID
            if expires - issued > timedelta(seconds=MAX_TTL_SECONDS):
                return DecisionReason.TTL_EXCEEDED
            if index and expires > chain[index - 1].token.payload.expires_at:
                return DecisionReason.OVER_DELEGATED
        return None

    def _decision(
        self,
        request: AuthorizationRequest,
        decision_id: str,
        allow: bool,
        reason: DecisionReason,
        chain: tuple[ParsedCapability, ...] = (),
        *,
        issuer_revision: str | None = None,
        principal_references: tuple[PrincipalPolicyReference, ...] = (),
        revocation_revision: str | None = None,
        audit_sequence: int = 1,
    ) -> AuthorizationDecision:
        leaf = chain[-1] if chain else None
        return AuthorizationDecision(
            decision_id=decision_id,
            attempt_sequence=audit_sequence,
            correlation_id=request.correlation_id,
            allow=allow,
            reason=reason,
            credential_digest=leaf.credential_digest if leaf else None,
            ancestor_credential_digests=tuple(item.credential_digest for item in chain[:-1]),
            principal_id=request.principal.principal_id,
            scope=request.scope,
            delegation_depth=leaf.claims.delegation.depth if leaf else None,
            trusted_issuer_policy_revision=issuer_revision,
            principal_policy_revisions=principal_references,
            revocation_revision=revocation_revision,
        )

    def _deny_with_state(
        self,
        request: AuthorizationRequest,
        decision_id: str,
        reason: DecisionReason,
        chain: tuple[ParsedCapability, ...],
        issuer_policy: TrustedIssuerSnapshot,
        principal_references: tuple[PrincipalPolicyReference, ...],
        revocation: RevocationSnapshot,
        audit_sequence: int = 1,
    ) -> Never:
        self._deny(
            request,
            decision_id,
            reason,
            chain,
            issuer_revision=issuer_policy.revision,
            principal_references=principal_references,
            revocation_revision=revocation.revision,
            audit_sequence=audit_sequence,
        )

    def _deny(
        self,
        request: AuthorizationRequest,
        decision_id: str,
        reason: DecisionReason,
        chain: tuple[ParsedCapability, ...] = (),
        *,
        issuer_revision: str | None = None,
        principal_references: tuple[PrincipalPolicyReference, ...] = (),
        revocation_revision: str | None = None,
        audit_sequence: int = 1,
    ) -> Never:
        decision = self._decision(
            request,
            decision_id,
            False,
            reason,
            chain,
            issuer_revision=issuer_revision,
            principal_references=principal_references,
            revocation_revision=revocation_revision,
            audit_sequence=audit_sequence,
        )
        try:
            self._audit.record(decision)
        except Exception:
            decision = self._decision(
                request,
                decision_id,
                False,
                DecisionReason.AUDIT_UNAVAILABLE,
                chain,
                issuer_revision=issuer_revision,
                principal_references=principal_references,
                revocation_revision=revocation_revision,
                audit_sequence=audit_sequence,
            )
        raise AuthorizationDeniedError(decision) from None


def _scope_is_monotonic(parent: CapabilityScope, child: CapabilityScope) -> bool:
    exact_fields = ("audience", "target", "capability", "operation", "resource_type")
    if any(getattr(parent, name) != getattr(child, name) for name in exact_fields):
        return False
    if parent.resource_id is not None and child.resource_id != parent.resource_id:
        return False
    return parent.constraints.issubset(child.constraints)


def _is_monotonic(parent: ParsedCapability, child: ParsedCapability) -> bool:
    return (
        child.claims.delegation.depth == parent.claims.delegation.depth + 1
        and child.claims.delegation.max_depth <= parent.claims.delegation.max_depth
        and parent.claims.delegation.depth < parent.claims.delegation.max_depth
        and _scope_is_monotonic(parent.claims.scope, child.claims.scope)
    )


class DelegatingCapabilityIssuer:
    """Consume a parent invocation and mint one strictly attenuated child."""

    def __init__(self, *, authorizer: CapabilityAuthorizer, issuer: CapabilityIssuer) -> None:
        self._authorizer = authorizer
        self._issuer = issuer

    def delegate(
        self,
        *,
        parent: PresentedCapability,
        authenticated_parent: Principal,
        child_principal: Principal,
        child_scope: CapabilityScope,
        correlation_id: str,
        ttl_seconds: int = 300,
    ) -> PresentedCapability:
        try:
            raw_chain = parent.credentials_for_verification()
            parsed_parent = parse_presented_token(raw_chain[-1])
        except Exception:
            raise DelegationDeniedError("parent credential is malformed") from None
        if (
            parsed_parent.claims.delegation.depth >= parsed_parent.claims.delegation.max_depth
            or not _scope_is_monotonic(parsed_parent.claims.scope, child_scope)
        ):
            raise DelegationDeniedError("delegation would broaden authority") from None
        try:
            self._authorizer.authorize(
                parent,
                AuthorizationRequest(
                    principal=authenticated_parent,
                    scope=parsed_parent.claims.scope,
                    correlation_id=correlation_id,
                ),
            )
        except AuthorizationDeniedError as exc:
            raise DelegationDeniedError(str(exc)) from None
        try:
            verified_parent = parse_presented_token(raw_chain[-1])
            raw_child = self._issuer._issue_child(
                parent=verified_parent,
                principal=child_principal,
                scope=child_scope,
                ttl_seconds=ttl_seconds,
            )
            return parent.with_child(raw_child)
        except Exception:
            raise DelegationDeniedError("delegated credential issuance failed") from None


__all__ = [
    "AuditSink",
    "AuthorizationCurrentnessReceipt",
    "AuthorizationDecision",
    "AuthorizationDeniedError",
    "AuthorizationReceiptError",
    "AuthorizationReceiptUnavailableError",
    "AuthorizationRequest",
    "BackendUnavailableError",
    "CapabilityAuthorizer",
    "CapabilityIssuer",
    "CapabilityScope",
    "CapAuthSignatureVerifier",
    "CredentialFormatError",
    "CredentialSigner",
    "CredentialSigningError",
    "DecisionReason",
    "DelegatingCapabilityIssuer",
    "DelegationDeniedError",
    "InMemoryAuditSink",
    "InMemoryPrincipalPolicyBackend",
    "InMemoryReplayBackend",
    "InMemoryRevocationBackend",
    "IssuerGrant",
    "MAX_DELEGATION_DEPTH",
    "MAX_TTL_SECONDS",
    "PresentedCapability",
    "Principal",
    "PrincipalPolicyBackend",
    "ReplayBackend",
    "RevocationBackend",
    "SignatureVerifier",
    "StaticTrustedIssuerBackend",
    "TrustedIssuerBackend",
    "VERIFIER_POLICY_VERSION",
    "credential_digest",
    "export_authorization_bearer",
    "parse_authorization_bearer",
    "parse_presented_token",
]
