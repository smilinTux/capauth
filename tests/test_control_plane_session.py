from datetime import datetime, timedelta, timezone

import pytest

from capauth.control_plane_session import (
    ControlPlaneSessionDeniedError,
    CurrentPolicyRevisions,
    InMemoryOperatorSessionBackendForTests,
    IssuerChannelDeniedError,
    LocalIssuerChannel,
    OpaqueOneUseCapability,
    OperatorSessionManager,
    _parse,
    _validate_socket,
)
from capauth.delegated import Principal

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


class Clock:
    now = NOW

    def __call__(self):
        return self.now


@pytest.fixture
def rig():
    clock = Clock()
    current = {"rev": REV}
    backend = InMemoryOperatorSessionBackendForTests()
    manager = OperatorSessionManager(
        backend=backend, current_revisions=lambda _: current["rev"], enabled=True, clock=clock
    )
    material = manager.create(
        principal=P,
        acting_principal=A,
        device_fingerprint="device-001",
        capability_ceiling=frozenset({"skdashboard.read"}),
        purpose="reporting",
        allowed_origin="https://dashboard.test",
        revisions=REV,
        ttl_seconds=300,
        idle_seconds=120,
    )
    cookie, csrf = material.take()
    return manager, clock, current, cookie, csrf


def test_subject_bound_session_authenticates_once(rig):
    manager, *_rest = rig
    _, clock, _, cookie, csrf = rig
    context = manager.authenticate(
        cookie=cookie,
        csrf=csrf,
        origin="https://dashboard.test",
        device_fingerprint="device-001",
        request_nonce="nonce-000000000001",
    )
    assert context.binding.principal == P and context.binding.acting_principal == A
    with pytest.raises(ControlPlaneSessionDeniedError):
        manager.authenticate(
            cookie=cookie,
            csrf=csrf,
            origin="https://dashboard.test",
            device_fingerprint="device-001",
            request_nonce="nonce-000000000001",
        )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"device_fingerprint": "other-001"},
        {"origin": "https://evil.test"},
        {"csrf": "x" * 40},
    ],
)
def test_wrong_binding_fails_closed(rig, kwargs):
    manager, _clock, _current, cookie, csrf = rig
    values = {
        "cookie": cookie,
        "csrf": csrf,
        "origin": "https://dashboard.test",
        "device_fingerprint": "device-001",
        "request_nonce": "nonce-000000000002",
    }
    values.update(kwargs)
    with pytest.raises(ControlPlaneSessionDeniedError):
        manager.authenticate(**values)


@pytest.mark.parametrize("nonce", [None, 42, b"nonce-000000000000"])
def test_non_text_nonce_fails_closed(rig, nonce):
    manager, _clock, _current, cookie, csrf = rig
    with pytest.raises(ControlPlaneSessionDeniedError):
        manager.authenticate(
            cookie=cookie,
            csrf=csrf,
            origin="https://dashboard.test",
            device_fingerprint="device-001",
            request_nonce=nonce,
        )


def test_revision_revocation_and_expiry_fail_closed(rig):
    manager, clock, current, cookie, csrf = rig
    current["rev"] = REV.model_copy(update={"principal": "9" * 64})
    with pytest.raises(ControlPlaneSessionDeniedError):
        manager.authenticate(
            cookie=cookie,
            csrf=csrf,
            origin="https://dashboard.test",
            device_fingerprint="device-001",
            request_nonce="nonce-000000000003",
        )
    current["rev"] = REV
    manager.revoke(cookie)
    with pytest.raises(ControlPlaneSessionDeniedError):
        manager.authenticate(
            cookie=cookie,
            csrf=csrf,
            origin="https://dashboard.test",
            device_fingerprint="device-001",
            request_nonce="nonce-000000000004",
        )
    material = manager.create(
        principal=P,
        acting_principal=A,
        device_fingerprint="device-002",
        capability_ceiling=frozenset({"skdashboard.read"}),
        purpose="reporting",
        allowed_origin="https://dashboard.test",
        revisions=REV,
        ttl_seconds=30,
        idle_seconds=10,
    )
    c, s = material.take()
    clock.now = NOW + timedelta(minutes=1)
    with pytest.raises(ControlPlaneSessionDeniedError):
        manager.authenticate(
            cookie=c,
            csrf=s,
            origin="https://dashboard.test",
            device_fingerprint="device-002",
            request_nonce="nonce-000000000005",
        )


def test_disabled_manager_and_one_use_capability_are_fail_closed(rig):
    manager, _clock, _current, cookie, csrf = rig
    disabled = OperatorSessionManager(
        backend=InMemoryOperatorSessionBackendForTests(), current_revisions=lambda _: REV
    )
    with pytest.raises(ControlPlaneSessionDeniedError):
        disabled.create(
            principal=P,
            acting_principal=A,
            device_fingerprint="device-001",
            capability_ceiling=frozenset({"skdashboard.read"}),
            purpose="reporting",
            allowed_origin="https://dashboard.test",
            revisions=REV,
            ttl_seconds=30,
            idle_seconds=10,
        )
    cap = OpaqueOneUseCapability(b"secret")
    seen = []
    cap.consume(lambda value: seen.append(bytes(value)))
    assert seen == [b"secret"] and set(cap._buffer) == {0}
    with pytest.raises(IssuerChannelDeniedError):
        cap.consume(lambda _: None)


def test_duplicate_and_oversized_wire_requests_fail_closed():
    with pytest.raises(ValueError):
        _parse(b'{"schema_version":"capauth-dashboard-issuer/v1","schema_version":"x"}')
    with pytest.raises(ValueError):
        _parse(b"{" + b"x" * (16 * 1024) + b"}")


def test_disabled_sidecar_never_calls_injected_issuer(rig):
    manager, _clock, _current, _cookie, _csrf = rig
    calls = []

    class Issuer:
        def issue(self, request):
            calls.append(request)
            raise AssertionError("issuer must not be called")

    channel = LocalIssuerChannel(sessions=manager, issuer=Issuer())
    with pytest.raises(IssuerChannelDeniedError):
        channel.issue(b"not-json", connection=object())
    assert calls == []


def test_one_use_capability_is_thread_safe():
    from concurrent.futures import ThreadPoolExecutor

    cap = OpaqueOneUseCapability(b"capability")
    results = []

    def consume():
        try:
            cap.consume(lambda value: results.append(bytes(value)))
            return True
        except IssuerChannelDeniedError:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _: consume(), range(8)))
    assert sum(outcomes) == 1
    assert results == [b"capability"]


def test_socket_mode_and_owner_are_required(tmp_path):
    import os
    import socket

    path = tmp_path / "issuer.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    try:
        os.chmod(path, 0o660)
        with pytest.raises(ValueError):
            _validate_socket(path, os.getuid())
        os.chmod(path, 0o600)
        with pytest.raises(ValueError):
            _validate_socket(path, os.getuid() + 1)
        _validate_socket(path, os.getuid())
    finally:
        listener.close()
