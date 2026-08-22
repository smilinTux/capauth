"""Security contract tests for strict delegated capabilities."""

from __future__ import annotations

import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Lock
from uuid import uuid4

import pytest

from capauth.delegated import (
    VERIFIER_POLICY_VERSION,
    AuthorizationDeniedError,
    AuthorizationRequest,
    CapabilityAuthorizer,
    CapabilityIssuer,
    CapabilityScope,
    DecisionReason,
    DelegatingCapabilityIssuer,
    DelegationDeniedError,
    InMemoryAuditSink,
    InMemoryPrincipalPolicyBackend,
    InMemoryReplayBackend,
    InMemoryRevocationBackend,
    IssuerGrant,
    PresentedCapability,
    Principal,
    SignatureVerifier,
    StaticTrustedIssuerBackend,
    credential_digest,
    export_authorization_bearer,
    parse_authorization_bearer,
    parse_presented_token,
)

UTC = timezone.utc

ISSUER = "A" * 40


class MutableClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


class RegistrySigner:
    """Test-only signature registry, with no production crypto behavior."""

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


class AdvancingVerifier(SignatureVerifier):
    def __init__(self, delegate: RegistrySigner, clock: MutableClock, seconds: int) -> None:
        self.delegate = delegate
        self.clock = clock
        self.seconds = seconds

    def verify(self, token) -> bool:
        result = self.delegate.verify(token)
        self.clock.advance(self.seconds)
        return result


class AdvancingReplay(InMemoryReplayBackend):
    def __init__(self, clock: MutableClock, seconds: int) -> None:
        super().__init__(clock=clock)
        self.clock = clock
        self.seconds = seconds

    def reserve(self, **kwargs) -> bool:
        result = super().reserve(**kwargs)
        self.clock.advance(self.seconds)
        return result


class RevokingVerifier(SignatureVerifier):
    def __init__(self, delegate: RegistrySigner, revocations: InMemoryRevocationBackend) -> None:
        self.delegate = delegate
        self.revocations = revocations

    def verify(self, token) -> bool:
        result = self.delegate.verify(token)
        self.revocations.revoke(credential_digest(token, VERIFIER_POLICY_VERSION))
        return result


class AdvancingAudit(InMemoryAuditSink):
    def __init__(self, clock: MutableClock, seconds: int) -> None:
        super().__init__()
        self.clock = clock
        self.seconds = seconds

    def record(self, decision) -> None:
        super().record(decision)
        if decision.allow:
            self.clock.advance(self.seconds)


class RevokingAudit(InMemoryAuditSink):
    def __init__(self, revocations: InMemoryRevocationBackend) -> None:
        super().__init__()
        self.revocations = revocations

    def record(self, decision) -> None:
        super().record(decision)
        if decision.allow and decision.credential_digest:
            self.revocations.revoke(decision.credential_digest)


class RevisingPrincipalAudit(InMemoryAuditSink):
    def __init__(self, principals: InMemoryPrincipalPolicyBackend, principal: Principal) -> None:
        super().__init__()
        self.principals = principals
        self.principal = principal

    def record(self, decision) -> None:
        super().record(decision)
        if decision.allow:
            self.principals.set(self.principal, active=True)


class Rig:
    def __init__(self, *, ttl_seconds: int = 60) -> None:
        self.clock = MutableClock()
        self.signer = RegistrySigner()
        self.root = Principal(
            principal_id="operator-1", subject="operator@example.test", kind="human"
        )
        self.child = Principal(principal_id="agent-1", subject="agent@example.test", kind="agent")
        self.grandchild = Principal(
            principal_id="service-1", subject="service@example.test", kind="service"
        )
        self.scope = CapabilityScope(
            audience="records-api",
            target="record.read",
            capability="records.read",
            operation="read",
            resource_type="record",
            resource_id=None,
            constraints=frozenset({"tenant:blue"}),
        )
        self.principals = InMemoryPrincipalPolicyBackend((self.root, self.child, self.grandchild))
        self.revocations = InMemoryRevocationBackend()
        self.replay = InMemoryReplayBackend(clock=self.clock)
        self.audit = InMemoryAuditSink()
        self.trusted = StaticTrustedIssuerBackend(
            (
                IssuerGrant(
                    fingerprint=ISSUER,
                    capabilities=frozenset({"records.read"}),
                    audiences=frozenset({"records-api"}),
                    principal_kinds=frozenset({"human", "agent", "service"}),
                ),
            )
        )
        self.issuer = CapabilityIssuer(self.signer, clock=self.clock)
        self.authorizer = self.new_authorizer()
        self.presented = self.issuer.issue_root(
            principal=self.root,
            scope=self.scope,
            ttl_seconds=ttl_seconds,
            max_delegation_depth=2,
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

    def request(self, principal: Principal | None = None, scope: CapabilityScope | None = None):
        return AuthorizationRequest(
            principal=principal or self.root,
            scope=scope or self.scope,
            correlation_id=str(uuid4()),
        )


def denial_reason(authorizer, presented, request) -> DecisionReason:
    with pytest.raises(AuthorizationDeniedError) as caught:
        authorizer.authorize(presented, request)
    return caught.value.decision.reason


def test_valid_root_returns_exact_sanitized_decision() -> None:
    rig = Rig()

    decision = rig.authorizer.authorize(rig.presented, rig.request())

    assert decision.allow is True
    assert decision.scope == rig.scope
    assert decision.principal_id == rig.root.principal_id
    assert decision.reason is DecisionReason.ALLOW
    dumped = decision.model_dump_json()
    assert "test-signature" not in dumped
    assert "skcapstone_token" not in dumped


def test_scope_constraints_have_canonical_signed_order() -> None:
    rig = Rig()
    scope = rig.scope.model_copy(update={"constraints": frozenset({"tenant:blue", "case:7"})})

    assert scope.model_dump(mode="json")["constraints"] == ["case:7", "tenant:blue"]


def test_versioned_transport_round_trip_and_recursive_duplicate_rejection() -> None:
    rig = Rig()
    encoded = export_authorization_bearer(rig.presented)

    assert parse_authorization_bearer(encoded).credentials_for_verification() == (
        rig.presented.credentials_for_verification()
    )
    duplicate_outer = '{"capauth_presented_capability":"1.0",' + encoded[1:]
    duplicate_nested = encoded.replace('"leaf":', '"leaf":"duplicate","leaf":', 1)
    wrong_version = encoded.replace('"1.0"', '"2.0"', 1)

    for malformed in (duplicate_outer, duplicate_nested, wrong_version):
        with pytest.raises(ValueError, match="malformed"):
            parse_authorization_bearer(malformed)

    raw = rig.presented.credentials_for_verification()[0]
    duplicate_token_member = '{"signature":"duplicate",' + raw[1:]
    duplicate_claim_member = raw.replace('"kind":"human"', '"kind":"agent","kind":"human"', 1)
    for malformed in (duplicate_token_member, duplicate_claim_member):
        with pytest.raises(ValueError, match="malformed"):
            parse_presented_token(malformed)


def test_complete_chain_and_parent_digest_are_required() -> None:
    rig = Rig()
    delegated = DelegatingCapabilityIssuer(authorizer=rig.authorizer, issuer=rig.issuer).delegate(
        parent=rig.presented,
        authenticated_parent=rig.root,
        child_principal=rig.child,
        child_scope=rig.scope,
        correlation_id=str(uuid4()),
    )
    root_raw, child_raw = delegated.credentials_for_verification()

    assert rig.authorizer.authorize(delegated, rig.request(rig.child)).allow is True
    assert (
        denial_reason(
            rig.new_authorizer(replay=InMemoryReplayBackend(clock=rig.clock)),
            PresentedCapability.single(child_raw),
            rig.request(rig.child),
        )
        is DecisionReason.DELEGATION_CHAIN_INVALID
    )
    assert (
        denial_reason(
            rig.new_authorizer(replay=InMemoryReplayBackend(clock=rig.clock)),
            PresentedCapability.delegated(leaf=root_raw, ancestors=(child_raw,)),
            rig.request(rig.root),
        )
        is DecisionReason.DELEGATION_CHAIN_INVALID
    )


def test_every_ancestor_and_leaf_principal_must_be_current() -> None:
    rig = Rig()
    delegated = DelegatingCapabilityIssuer(authorizer=rig.authorizer, issuer=rig.issuer).delegate(
        parent=rig.presented,
        authenticated_parent=rig.root,
        child_principal=rig.child,
        child_scope=rig.scope,
        correlation_id=str(uuid4()),
    )
    rig.principals.set(rig.root, active=False)

    assert (
        denial_reason(
            rig.new_authorizer(replay=InMemoryReplayBackend(clock=rig.clock)),
            delegated,
            rig.request(rig.child),
        )
        is DecisionReason.PRINCIPAL_INACTIVE
    )


def test_expired_ancestor_denies_the_complete_chain() -> None:
    rig = Rig()
    delegated = DelegatingCapabilityIssuer(authorizer=rig.authorizer, issuer=rig.issuer).delegate(
        parent=rig.presented,
        authenticated_parent=rig.root,
        child_principal=rig.child,
        child_scope=rig.scope,
        correlation_id=str(uuid4()),
    )
    rig.clock.advance(61)

    assert (
        denial_reason(
            rig.new_authorizer(replay=InMemoryReplayBackend(clock=rig.clock)),
            delegated,
            rig.request(rig.child),
        )
        is DecisionReason.ANCESTOR_EXPIRED
    )


def test_revoked_ancestor_and_untrusted_issuer_deny() -> None:
    rig = Rig()
    delegated = DelegatingCapabilityIssuer(authorizer=rig.authorizer, issuer=rig.issuer).delegate(
        parent=rig.presented,
        authenticated_parent=rig.root,
        child_principal=rig.child,
        child_scope=rig.scope,
        correlation_id=str(uuid4()),
    )
    root = parse_presented_token(delegated.credentials_for_verification()[0])
    rig.revocations.revoke(root.credential_digest)
    fresh_replay = InMemoryReplayBackend(clock=rig.clock)

    assert (
        denial_reason(rig.new_authorizer(replay=fresh_replay), delegated, rig.request(rig.child))
        is DecisionReason.ANCESTOR_REVOKED
    )
    empty_trust = StaticTrustedIssuerBackend(())
    assert (
        denial_reason(
            rig.new_authorizer(
                trusted_issuers=empty_trust,
                revocations=InMemoryRevocationBackend(),
                replay=InMemoryReplayBackend(clock=rig.clock),
            ),
            delegated,
            rig.request(rig.child),
        )
        is DecisionReason.UNTRUSTED_ISSUER
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("audience", "wrong-api"),
        ("target", "record.delete"),
        ("capability", "records.write"),
        ("operation", "write"),
        ("resource_type", "folder"),
        ("resource_id", "record-9"),
        ("constraints", frozenset({"tenant:red"})),
    ),
)
def test_every_scope_field_is_bound_exactly(field: str, value: object) -> None:
    rig = Rig()
    wrong = rig.scope.model_copy(update={field: value})

    assert denial_reason(rig.authorizer, rig.presented, rig.request(scope=wrong)) is (
        DecisionReason.WRONG_SCOPE
    )


def test_delegation_is_monotonic_and_bounded() -> None:
    rig = Rig()
    delegator = DelegatingCapabilityIssuer(authorizer=rig.authorizer, issuer=rig.issuer)
    narrowed = rig.scope.model_copy(
        update={"resource_id": "record-1", "constraints": frozenset({"tenant:blue", "case:7"})}
    )
    child = delegator.delegate(
        parent=rig.presented,
        authenticated_parent=rig.root,
        child_principal=rig.child,
        child_scope=narrowed,
        correlation_id=str(uuid4()),
    )

    with pytest.raises(DelegationDeniedError, match="broaden"):
        DelegatingCapabilityIssuer(
            authorizer=rig.new_authorizer(replay=InMemoryReplayBackend(clock=rig.clock)),
            issuer=rig.issuer,
        ).delegate(
            parent=child,
            authenticated_parent=rig.child,
            child_principal=rig.grandchild,
            child_scope=rig.scope,
            correlation_id=str(uuid4()),
        )

    second = DelegatingCapabilityIssuer(
        authorizer=rig.new_authorizer(replay=InMemoryReplayBackend(clock=rig.clock)),
        issuer=rig.issuer,
    ).delegate(
        parent=child,
        authenticated_parent=rig.child,
        child_principal=rig.grandchild,
        child_scope=narrowed,
        correlation_id=str(uuid4()),
    )
    with pytest.raises(DelegationDeniedError):
        DelegatingCapabilityIssuer(
            authorizer=rig.new_authorizer(replay=InMemoryReplayBackend(clock=rig.clock)),
            issuer=rig.issuer,
        ).delegate(
            parent=second,
            authenticated_parent=rig.grandchild,
            child_principal=rig.root,
            child_scope=narrowed,
            correlation_id=str(uuid4()),
        )


def test_expiry_is_rechecked_after_signature_and_replay_work() -> None:
    signature_rig = Rig(ttl_seconds=1)
    slow_verifier = AdvancingVerifier(signature_rig.signer, signature_rig.clock, 2)
    assert (
        denial_reason(
            signature_rig.new_authorizer(signature_verifier=slow_verifier),
            signature_rig.presented,
            signature_rig.request(),
        )
        is DecisionReason.EXPIRED
    )
    replay_rig = Rig(ttl_seconds=1)
    slow_replay = AdvancingReplay(replay_rig.clock, 2)
    assert (
        denial_reason(
            replay_rig.new_authorizer(replay=slow_replay),
            replay_rig.presented,
            replay_rig.request(),
        )
        is DecisionReason.EXPIRED
    )


def test_revocation_is_refreshed_after_signature_work() -> None:
    rig = Rig()
    verifier = RevokingVerifier(rig.signer, rig.revocations)

    assert (
        denial_reason(
            rig.new_authorizer(signature_verifier=verifier),
            rig.presented,
            rig.request(),
        )
        is DecisionReason.REVOKED
    )


def test_expiry_and_revocation_during_audit_never_return_allow() -> None:
    expiry_rig = Rig(ttl_seconds=1)
    expiry_audit = AdvancingAudit(expiry_rig.clock, 2)
    assert (
        denial_reason(
            expiry_rig.new_authorizer(audit=expiry_audit),
            expiry_rig.presented,
            expiry_rig.request(),
        )
        is DecisionReason.EXPIRED
    )
    assert [item.attempt_sequence for item in expiry_audit.decisions()] == [1, 2]
    assert expiry_audit.decisions()[-1].reason is DecisionReason.EXPIRED

    revocation_rig = Rig()
    revoking_audit = RevokingAudit(revocation_rig.revocations)
    assert (
        denial_reason(
            revocation_rig.new_authorizer(audit=revoking_audit),
            revocation_rig.presented,
            revocation_rig.request(),
        )
        is DecisionReason.REVOKED
    )
    assert [item.attempt_sequence for item in revoking_audit.decisions()] == [1, 2]
    assert revoking_audit.decisions()[-1].reason is DecisionReason.REVOKED

    revision_rig = Rig()
    revising_audit = RevisingPrincipalAudit(revision_rig.principals, revision_rig.root)
    assert (
        denial_reason(
            revision_rig.new_authorizer(audit=revising_audit),
            revision_rig.presented,
            revision_rig.request(),
        )
        is DecisionReason.CURRENT_STATE_CHANGED
    )
    assert [item.attempt_sequence for item in revising_audit.decisions()] == [1, 2]


def test_atomic_replay_reservation_allows_one_concurrent_invocation() -> None:
    rig = Rig()

    def invoke(index: int) -> DecisionReason:
        try:
            rig.authorizer.authorize(rig.presented, rig.request())
            return DecisionReason.ALLOW
        except AuthorizationDeniedError as exc:
            return exc.decision.reason

    with ThreadPoolExecutor(max_workers=8) as pool:
        reasons = list(pool.map(invoke, range(8)))

    assert reasons.count(DecisionReason.ALLOW) == 1
    assert reasons.count(DecisionReason.REPLAYED) == 7


def test_presented_credentials_and_failures_are_redacted() -> None:
    secret = '{"secret":"do-not-print"}'
    presented = PresentedCapability.single(secret)
    rig = Rig()

    assert repr(presented) == "PresentedCapability(<redacted>)"
    assert str(presented) == "<redacted capability>"
    with pytest.raises(TypeError):
        presented.__reduce__()
    try:
        rig.authorizer.authorize(presented, rig.request())
    except AuthorizationDeniedError as exc:
        rendered = "".join(traceback.format_exception(exc))
    else:  # pragma: no cover
        pytest.fail("malformed credential unexpectedly authorized")
    assert secret not in rendered
    assert "do-not-print" not in rendered


def test_presented_chain_rejects_duplicate_credentials() -> None:
    rig = Rig()
    raw = rig.presented.credentials_for_verification()[0]
    with pytest.raises(ValueError, match="repeats"):
        PresentedCapability.delegated(leaf=raw, ancestors=(raw,))


def test_credential_digest_binds_signature_and_policy() -> None:
    rig = Rig()
    raw = rig.presented.credentials_for_verification()[0]
    parsed = parse_presented_token(raw)
    changed_signature = parsed.token.model_copy(update={"signature": "different"})

    assert credential_digest(parsed.token, VERIFIER_POLICY_VERSION) != credential_digest(
        changed_signature, VERIFIER_POLICY_VERSION
    )
    assert credential_digest(parsed.token, VERIFIER_POLICY_VERSION) != credential_digest(
        parsed.token, "capauth-delegated-authz/v2"
    )
