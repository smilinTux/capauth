import copy
import os
import pickle
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier, Lock

import pytest

from capauth.control_plane import ClientKind, DecisionState, OwnerPolicyDecision, RequestBoundary
from capauth.control_plane_authorizer import (
    ControlPlaneDecisionAuthorizer,
    ControlPlaneInvocationV1,
)
from capauth.control_plane_session import (
    ControlPlaneSessionDeniedError,
    CurrentPolicyRevisions,
    DashboardIssuerAuthorizationConfigV1,
    InMemoryOperatorSessionBackendForTests,
    InProcessIssuerFactory,
    InProcessIssuerRequest,
    OperatorSessionManager,
    SQLiteOperatorSessionBackend,
)
from capauth.delegated import (
    CapabilityAuthorizer,
    CapabilityIssuer,
    InMemoryAuditSink,
    InMemoryPrincipalPolicyBackend,
    InMemoryReplayBackend,
    InMemoryRevocationBackend,
    IssuerGrant,
    Principal,
    StaticTrustedIssuerBackend,
)

UTC = timezone.utc
NOW = datetime(2026, 8, 24, tzinfo=UTC)
REV = CurrentPolicyRevisions(
    issuer="1" * 64,
    principal="2" * 64,
    acting_principal="3" * 64,
    revocation="4" * 64,
    owner="5" * 64,
)
P = Principal(principal_id="p1", subject="chef@example.test", kind="human")
A = Principal(principal_id="a1", subject="chef@example.test", kind="human")
ISSUER = "A" * 40
ORIGIN = "https://dashboard.test"
DEVICE = "device-001"


class Clock:
    now = NOW

    def __call__(self):
        return self.now


class RegistrySigner:
    def __init__(self):
        self._lock = Lock()
        self._signed = {}

    @property
    def issuer_fingerprint(self):
        return ISSUER

    def sign(self, payload_bytes):
        with self._lock:
            signature = f"signature-{len(self._signed) + 1}"
            self._signed[signature] = payload_bytes
            return signature

    def verify(self, token):
        with self._lock:
            return (
                self._signed.get(token.signature or "") == token.payload.model_dump_json().encode()
            )


class InjectedIssuer:
    def __init__(self, issuer):
        self._issuer = issuer

    def issue(self, request):
        return self._issuer.issue_root(
            principal=request.principal,
            scope=request.scope,
            ttl_seconds=request.ttl_seconds,
        )


class OwnerPolicy:
    def decide(self, binding, _capauth_decision):
        return OwnerPolicyDecision(
            state=DecisionState.ALLOW,
            revision=binding.owner_policy_revision,
            resource_type=binding.resource_type,
            resource_id=binding.resource_id,
            reason_code="owner_allow",
        )


def config(**changes):
    values = {
        "allowed_origin": ORIGIN,
        "node_id": "chiap08",
        "purpose": "reporting",
        "capability": "skdashboard.read",
        "operation": "read",
        "target": "/api/v1/overview",
        "resource_type": "skcoord.card_store.project_snapshot",
        "resource_id": "authorized-card-set:sha256:" + "1" * 64,
        "owner_policy_revision": REV.owner,
        "ttl_seconds": 60,
    }
    values.update(changes)
    return DashboardIssuerAuthorizationConfigV1(**values)


def invocation(configuration=None, **changes):
    selected = configuration or config()
    values = {
        "node_id": selected.node_id,
        "purpose": selected.purpose,
        "capability": selected.capability,
        "target": selected.target,
        "resource_type": selected.resource_type,
        "resource_id": selected.resource_id,
        "correlation_id": "request-1",
        "boundary": RequestBoundary(client_kind=ClientKind.BROWSER, origin=ORIGIN),
    }
    values.update(changes)
    return ControlPlaneInvocationV1(**values)


def new_session(manager, *, device=DEVICE):
    material = manager.create(
        principal=P,
        acting_principal=A,
        device_fingerprint=device,
        capability_ceiling=frozenset({"skdashboard.read"}),
        purpose="reporting",
        allowed_origin=ORIGIN,
        revisions=REV,
        ttl_seconds=300,
        idle_seconds=120,
    )
    return material.take()


def make_rig(backend=None):
    clock = Clock()
    current = {"rev": REV}
    selected_backend = backend or InMemoryOperatorSessionBackendForTests()
    manager = OperatorSessionManager(
        backend=selected_backend,
        current_revisions=lambda _: current["rev"],
        enabled=True,
        clock=clock,
    )
    cookie, csrf = new_session(manager)
    signer = RegistrySigner()
    factory = InProcessIssuerFactory(
        sessions=manager,
        config=config(),
        issuer=InjectedIssuer(CapabilityIssuer(signer, clock=clock)),
        enabled=True,
        clock=clock,
    )
    authorizer = ControlPlaneDecisionAuthorizer(
        capability_authorizer=CapabilityAuthorizer(
            trusted_issuers=StaticTrustedIssuerBackend(
                (
                    IssuerGrant(
                        fingerprint=ISSUER,
                        capabilities=frozenset({"skdashboard.read"}),
                        audiences=frozenset({"skdashboard"}),
                        principal_kinds=frozenset({"human"}),
                    ),
                )
            ),
            principals=InMemoryPrincipalPolicyBackend((P,)),
            revocations=InMemoryRevocationBackend(),
            replay=InMemoryReplayBackend(clock=clock),
            audit=InMemoryAuditSink(),
            signature_verifier=signer,
            clock=clock,
        ),
        owner_policy=OwnerPolicy(),
        allowed_origins=frozenset({ORIGIN}),
        clock=clock,
    )
    return manager, factory, authorizer, clock, current, cookie, csrf


def request(cookie, csrf, *, nonce="nonce-issuer-00000001", device=DEVICE):
    return InProcessIssuerRequest(
        session_cookie=cookie,
        csrf_token=csrf,
        request_nonce=nonce,
        device_fingerprint=device,
    )


def test_atomic_factory_authorizes_and_returns_only_sanitized_context_and_verifier():
    manager, factory, authorizer, _clock, _current, cookie, csrf = make_rig()
    result, verifier = factory.authorize(request(cookie, csrf), authorizer, invocation())

    assert result.allow is True
    assert result.context is not None
    assert result.context.binding.acting_principal_id == A.principal_id
    assert result.context.binding.session_jti
    assert result.context.binding.device_fingerprint_ref.startswith("sha256:")
    assert result.context.binding.session_policy_revisions_ref == REV.reference()
    assert verifier is not None
    serialized = result.model_dump_json()
    assert cookie not in serialized
    assert csrf not in serialized
    assert DEVICE not in serialized
    assert not hasattr(verifier, "credentials_for_verification")
    assert not hasattr(verifier._inner, "_presented")
    assert not hasattr(verifier._inner, "_authorizer")
    assert not hasattr(verifier._inner, "_issuer")
    with pytest.raises(TypeError):
        copy.copy(verifier)
    with pytest.raises(TypeError):
        pickle.dumps(verifier)
    assert verifier.check_before_owner_read(result.context) is DecisionState.ALLOW
    assert verifier.check_after_owner_read(result.context) is DecisionState.ALLOW
    manager.revoke(cookie)


def test_request_is_one_use_redacted_and_has_no_identity_or_topology_fields():
    value = request("cookie-secret", "csrf-secret")
    assert repr(value) == "InProcessIssuerRequest(<redacted>)"
    for name in ("principal", "acting_principal", "target", "node_id", "resource_id"):
        assert not hasattr(value, name)
    with pytest.raises(TypeError):
        copy.copy(value)
    with pytest.raises(TypeError):
        copy.deepcopy(value)
    with pytest.raises(TypeError):
        pickle.dumps(value)


@pytest.mark.parametrize(
    "changes",
    [
        {"target": "/api/v1/schedule/projection"},
        {"node_id": "chiap04"},
        {"resource_id": "other"},
        {"resource_type": "other.type"},
    ],
)
def test_arbitrary_topology_is_denied_before_issuer_is_called(changes):
    manager, _factory, authorizer, clock, _current, cookie, csrf = make_rig()
    calls = []

    class Issuer:
        def issue(self, value):
            calls.append(value)
            raise AssertionError

    factory = InProcessIssuerFactory(
        sessions=manager,
        config=config(),
        issuer=Issuer(),
        enabled=True,
        clock=clock,
    )
    result, verifier = factory.authorize(request(cookie, csrf), authorizer, invocation(**changes))
    assert result.allow is False and verifier is None and calls == []


@pytest.mark.parametrize(
    ("request_changes", "boundary_changes"),
    [
        ({"device": "wrong-device"}, {}),
        ({"csrf": "wrong-csrf-value"}, {}),
        ({}, {"origin": "https://evil.test"}),
    ],
)
def test_device_csrf_and_origin_fail_closed(request_changes, boundary_changes):
    _manager, factory, authorizer, _clock, _current, cookie, csrf = make_rig()
    req = request(
        cookie,
        request_changes.get("csrf", csrf),
        device=request_changes.get("device", DEVICE),
    )
    bound = RequestBoundary(client_kind=ClientKind.BROWSER, origin=ORIGIN).model_copy(
        update=boundary_changes
    )
    result, verifier = factory.authorize(req, authorizer, invocation(boundary=bound))
    assert result.allow is False and verifier is None


def test_post_issue_session_revoke_denies_before_owner_read():
    manager, factory, authorizer, _clock, _current, cookie, csrf = make_rig()
    result, verifier = factory.authorize(request(cookie, csrf), authorizer, invocation())
    assert result.allow and verifier is not None
    manager.revoke(cookie)
    assert verifier.check_before_owner_read(result.context) is DecisionState.DENY


def test_session_revoke_after_pre_read_denies_before_output_release():
    manager, factory, authorizer, _clock, _current, cookie, csrf = make_rig()
    result, verifier = factory.authorize(request(cookie, csrf), authorizer, invocation())
    assert result.allow and verifier is not None
    assert verifier.check_before_owner_read(result.context) is DecisionState.ALLOW
    manager.revoke(cookie)
    assert verifier.check_after_owner_read(result.context) is DecisionState.DENY


@pytest.mark.parametrize("field", ["acting_principal", "owner", "principal", "revocation"])
def test_post_issue_policy_revision_drift_denies_before_owner_read(field):
    _manager, factory, authorizer, _clock, current, cookie, csrf = make_rig()
    result, verifier = factory.authorize(request(cookie, csrf), authorizer, invocation())
    assert result.allow and verifier is not None
    current["rev"] = REV.model_copy(update={field: "9" * 64})
    assert verifier.check_before_owner_read(result.context) is DecisionState.DENY


def test_policy_revision_drift_after_pre_read_denies_before_output_release():
    _manager, factory, authorizer, _clock, current, cookie, csrf = make_rig()
    result, verifier = factory.authorize(request(cookie, csrf), authorizer, invocation())
    assert result.allow and verifier is not None
    assert verifier.check_before_owner_read(result.context) is DecisionState.ALLOW
    current["rev"] = REV.model_copy(update={"owner": "9" * 64})
    assert verifier.check_after_owner_read(result.context) is DecisionState.DENY


def test_replay_request_is_denied():
    _manager, factory, authorizer, _clock, _current, cookie, csrf = make_rig()
    first, verifier = factory.authorize(request(cookie, csrf), authorizer, invocation())
    assert first.allow and verifier is not None
    verifier.close()
    second, second_verifier = factory.authorize(request(cookie, csrf), authorizer, invocation())
    assert second.allow is False and second_verifier is None


def test_expired_session_is_denied():
    _manager, factory, authorizer, clock, _current, cookie, csrf = make_rig()
    clock.now = NOW + timedelta(minutes=6)
    result, verifier = factory.authorize(request(cookie, csrf), authorizer, invocation())
    assert result.allow is False and verifier is None


def test_disabled_factory_never_calls_issuer():
    manager, _factory, authorizer, clock, _current, cookie, csrf = make_rig()
    calls = []

    class Issuer:
        def issue(self, value):
            calls.append(value)

    disabled = InProcessIssuerFactory(
        sessions=manager, config=config(), issuer=Issuer(), clock=clock
    )
    result, verifier = disabled.authorize(request(cookie, csrf), authorizer, invocation())
    assert result.allow is False and verifier is None and calls == []


def test_sqlite_backend_is_shared_mode_0600_and_stores_no_raw_session_material(tmp_path):
    os.chmod(tmp_path, 0o700)
    path = tmp_path / "operator-sessions.sqlite3"
    first = SQLiteOperatorSessionBackend(path)
    manager, _factory, _authorizer, _clock, _current, cookie, csrf = make_rig(first)

    second = SQLiteOperatorSessionBackend(path)
    second_manager = OperatorSessionManager(
        backend=second,
        current_revisions=lambda _: REV,
        enabled=True,
        clock=lambda: NOW,
    )
    context = second_manager.authenticate(
        cookie=cookie,
        csrf=csrf,
        origin=ORIGIN,
        device_fingerprint=DEVICE,
        request_nonce="nonce-shared-00000001",
    )
    assert context.binding.principal == P
    assert os.stat(path).st_mode & 0o777 == 0o600
    raw = path.read_bytes()
    assert cookie.encode() not in raw
    assert csrf.encode() not in raw
    assert DEVICE.encode() not in raw
    assert b"skdashboard.read" not in raw


def test_sqlite_backend_reserves_one_concurrent_nonce(tmp_path):
    os.chmod(tmp_path, 0o700)
    path = tmp_path / "operator-sessions.sqlite3"
    backend = SQLiteOperatorSessionBackend(path)
    manager, _factory, _authorizer, _clock, _current, cookie, csrf = make_rig(backend)
    ready = Barrier(8)

    def authenticate_once(_):
        ready.wait()
        try:
            manager.authenticate(
                cookie=cookie,
                csrf=csrf,
                origin=ORIGIN,
                device_fingerprint=DEVICE,
                request_nonce="nonce-concurrent-00001",
            )
            return True
        except ControlPlaneSessionDeniedError:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(authenticate_once, range(8)))
    assert sum(outcomes) == 1
    with pytest.raises(ControlPlaneSessionDeniedError):
        manager.authenticate(
            cookie=cookie,
            csrf=csrf,
            origin=ORIGIN,
            device_fingerprint=DEVICE,
            request_nonce="nonce-concurrent-00001",
        )


def test_sqlite_backend_lock_wait_is_bounded_and_fails_closed(tmp_path):
    os.chmod(tmp_path, 0o700)
    path = tmp_path / "operator-sessions.sqlite3"
    backend = SQLiteOperatorSessionBackend(path)
    manager, _factory, _authorizer, _clock, _current, cookie, csrf = make_rig(backend)
    lock_holder = sqlite3.connect(path, timeout=0, isolation_level=None)
    lock_holder.execute("BEGIN EXCLUSIVE")
    started = time.monotonic()
    try:
        with pytest.raises(ControlPlaneSessionDeniedError):
            manager.authenticate(
                cookie=cookie,
                csrf=csrf,
                origin=ORIGIN,
                device_fingerprint=DEVICE,
                request_nonce="nonce-locked-00000001",
            )
    finally:
        lock_holder.rollback()
        lock_holder.close()
    elapsed = time.monotonic() - started
    assert 4.5 <= elapsed < 10.0


def test_unsafe_sqlite_parent_and_file_are_rejected(tmp_path):
    os.chmod(tmp_path, 0o755)
    with pytest.raises(ValueError):
        SQLiteOperatorSessionBackend(tmp_path / "unsafe.sqlite3")

    os.chmod(tmp_path, 0o700)
    path = tmp_path / "unsafe.sqlite3"
    path.touch(mode=0o644)
    with pytest.raises(ValueError):
        SQLiteOperatorSessionBackend(path)


def test_configuration_rejects_capability_operation_mismatch():
    with pytest.raises(ValueError):
        config(operation="mutate")
