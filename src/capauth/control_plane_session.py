"""Disabled-by-default, subject-bound control-plane session primitives."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import socket
import stat
import struct
import threading
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, Protocol
from urllib.parse import urlsplit

from pydantic import Field, model_validator
from typing_extensions import Never, Self

from .control_plane import CAPABILITY_MATRIX, SKDASHBOARD_AUDIENCE, StrictValue
from .delegated import (
    MAX_AUTHORIZATION_BYTES,
    CapabilityScope,
    PresentedCapability,
    Principal,
    export_authorization_bearer,
    parse_presented_token,
)

UTC = timezone.utc
MAX_SESSION_TTL = timedelta(hours=8)
MAX_SESSION_IDLE = timedelta(minutes=30)
MAX_ISSUER_REQUEST_BYTES = 16 * 1024
MAX_ISSUED_CAPABILITY_BYTES = MAX_AUTHORIZATION_BYTES
_OPS = {x.capability: x.operation.value for x in CAPABILITY_MATRIX if x.capability}


class ControlPlaneSessionDeniedError(PermissionError):
    pass


class IssuerChannelDeniedError(PermissionError):
    pass


class CurrentPolicyRevisions(StrictValue):
    issuer: str = Field(pattern=r"^[0-9a-f]{64}$")
    principal: str = Field(pattern=r"^[0-9a-f]{64}$")
    acting_principal: str = Field(pattern=r"^[0-9a-f]{64}$")
    revocation: str = Field(pattern=r"^[0-9a-f]{64}$")
    owner: str = Field(pattern=r"^[0-9a-f]{64}$")


class OperatorSessionCookiePolicy(StrictValue):
    name: Literal["__Host-skdashboard_session"] = "__Host-skdashboard_session"
    secure: Literal[True] = True
    http_only: Literal[True] = True
    same_site: Literal["Strict"] = "Strict"
    path: Literal["/"] = "/"
    domain: None = None


OPERATOR_SESSION_COOKIE_POLICY = OperatorSessionCookiePolicy()


class OperatorSessionBinding(StrictValue):
    principal: Principal
    acting_principal: Principal
    device_fingerprint: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,255}$")
    audience: Literal["skdashboard"] = SKDASHBOARD_AUDIENCE
    capability_ceiling: frozenset[str] = Field(min_length=1, max_length=32)
    purpose: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
    allowed_origin: str = Field(min_length=1, max_length=2048)
    session_jti: str = Field(pattern=r"^[0-9a-f]{32}$")
    revisions: CurrentPolicyRevisions
    issued_at: datetime
    idle_expires_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def valid(self) -> Self:
        if any(
            x != x.strip() for x in (self.device_fingerprint, self.purpose, self.allowed_origin)
        ):
            raise ValueError("whitespace")
        if not _origin(self.allowed_origin):
            raise ValueError("origin")
        if any(
            not x.startswith("skdashboard.") or x != x.strip() or len(x) > 256
            for x in self.capability_ceiling
        ):
            raise ValueError("ceiling")
        if any(
            x.tzinfo is None or x.utcoffset() != timedelta(0)
            for x in (self.issued_at, self.idle_expires_at, self.expires_at)
        ):
            raise ValueError("time")
        if not self.issued_at < self.idle_expires_at <= self.expires_at:
            raise ValueError("lifetime")
        if (
            self.expires_at - self.issued_at > MAX_SESSION_TTL
            or self.idle_expires_at - self.issued_at > MAX_SESSION_IDLE
        ):
            raise ValueError("bounds")
        return self

    def __repr__(self):
        return "OperatorSessionBinding(<redacted>)"

    __str__ = __repr__

    def __reduce__(self) -> Never:
        raise TypeError("operator session bindings cannot be serialized")


@dataclass(frozen=True, slots=True, repr=False)
class _StoredSession:
    binding: OperatorSessionBinding
    csrf_digest: bytes
    revoked: bool = False


class OperatorSessionBackend(Protocol):
    def create(self, digest: str, record: _StoredSession) -> None: ...
    def get(self, digest: str) -> _StoredSession | None: ...
    def revoke(self, digest: str) -> None: ...
    def reserve_request(self, digest: str, nonce: str) -> _StoredSession | None: ...


class InMemoryOperatorSessionBackendForTests:
    def __init__(self, *, max_sessions=1024, max_nonces_per_session=256):
        if max_sessions < 1 or max_nonces_per_session < 1:
            raise ValueError("bounds")
        self._max_sessions, self._max_nonces = max_sessions, max_nonces_per_session
        self._records, self._nonces, self._lock = {}, {}, threading.Lock()

    def create(self, digest, record):
        with self._lock:
            if digest in self._records or len(self._records) >= self._max_sessions:
                raise RuntimeError("unavailable")
            self._records[digest], self._nonces[digest] = record, set()

    def get(self, digest):
        with self._lock:
            return self._records.get(digest)

    def revoke(self, digest):
        with self._lock:
            if (r := self._records.get(digest)) is not None:
                self._records[digest] = replace(r, revoked=True)

    def reserve_request(self, digest, nonce):
        with self._lock:
            r, seen = self._records.get(digest), self._nonces.get(digest)
            if (
                r is None
                or r.revoked
                or seen is None
                or nonce in seen
                or len(seen) >= self._max_nonces
            ):
                return None
            seen.add(nonce)
            return r


class OpaqueSessionMaterial:
    __slots__ = ("_cookie", "_csrf", "_lock", "_taken")

    def __init__(self, cookie, csrf):
        self._cookie, self._csrf, self._taken, self._lock = cookie, csrf, False, threading.Lock()

    def take(self):
        with self._lock:
            if self._taken:
                raise ControlPlaneSessionDeniedError("control-plane session denied")
            self._taken = True
            c, s = self._cookie, self._csrf
            self._cookie = self._csrf = ""
            return c, s

    def __repr__(self):
        return "OpaqueSessionMaterial(<redacted>)"

    __str__ = __repr__

    def __reduce__(self) -> Never:
        raise TypeError("operator session material cannot be serialized")

    def __copy__(self):
        raise TypeError("operator session material cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError("operator session material cannot be copied")


@dataclass(frozen=True, slots=True, repr=False)
class AuthenticatedOperatorSession:
    binding: OperatorSessionBinding
    _session_digest: str

    def __repr__(self):
        return "AuthenticatedOperatorSession(<redacted>)"

    __str__ = __repr__

    def __reduce__(self) -> Never:
        raise TypeError("authenticated operator sessions cannot be serialized")


class OperatorSessionManager:
    def __init__(self, *, backend, current_revisions, enabled=False, clock=None):
        self._backend, self._current_revisions, self._enabled, self._clock = (
            backend,
            current_revisions,
            enabled,
            clock or (lambda: datetime.now(UTC)),
        )

    def create(
        self,
        *,
        principal,
        acting_principal,
        device_fingerprint,
        capability_ceiling,
        purpose,
        allowed_origin,
        revisions,
        ttl_seconds,
        idle_seconds,
    ):
        self._enabled_or_deny()
        if not 1 <= ttl_seconds <= int(
            MAX_SESSION_TTL.total_seconds()
        ) or not 1 <= idle_seconds <= min(ttl_seconds, int(MAX_SESSION_IDLE.total_seconds())):
            raise ControlPlaneSessionDeniedError("control-plane session denied")
        now = _utc(self._clock())
        cookie, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        try:
            b = OperatorSessionBinding(
                principal=principal,
                acting_principal=acting_principal,
                device_fingerprint=device_fingerprint,
                capability_ceiling=capability_ceiling,
                purpose=purpose,
                allowed_origin=allowed_origin,
                session_jti=secrets.token_hex(16),
                revisions=revisions,
                issued_at=now,
                idle_expires_at=now + timedelta(seconds=idle_seconds),
                expires_at=now + timedelta(seconds=ttl_seconds),
            )
            if self._current_revisions(b) != revisions:
                raise ValueError
            self._backend.create(
                _digest("cookie", cookie), _StoredSession(b, _digest_bytes("csrf", csrf))
            )
        except Exception:
            raise ControlPlaneSessionDeniedError("control-plane session denied") from None
        return OpaqueSessionMaterial(cookie, csrf)

    def authenticate(self, *, cookie, csrf, origin, device_fingerprint, request_nonce):
        self._enabled_or_deny()
        if (
            not all(isinstance(x, str) and x for x in (cookie, csrf, origin))
            or not isinstance(request_nonce, str)
            or not 16 <= len(request_nonce) <= 256
            or request_nonce != request_nonce.strip()
        ):
            raise ControlPlaneSessionDeniedError("control-plane session denied")
        try:
            d = _digest("cookie", cookie)
            r = self._backend.reserve_request(d, request_nonce)
            if r is None or r.revoked:
                raise ValueError
            b, now = r.binding, _utc(self._clock())
            if (
                now >= b.idle_expires_at
                or now >= b.expires_at
                or origin != b.allowed_origin
                or device_fingerprint != b.device_fingerprint
                or not hmac.compare_digest(_digest_bytes("csrf", csrf), r.csrf_digest)
                or self._current_revisions(b) != b.revisions
            ):
                raise ValueError
            return AuthenticatedOperatorSession(b, d)
        except Exception:
            raise ControlPlaneSessionDeniedError("control-plane session denied") from None

    def revalidate(self, context):
        self._enabled_or_deny()
        if type(context) is not AuthenticatedOperatorSession:
            raise ControlPlaneSessionDeniedError("control-plane session denied")
        try:
            r = self._backend.get(context._session_digest)
            b = context.binding
            if (
                r is None
                or r.revoked
                or r.binding is not b
                or _utc(self._clock()) >= b.idle_expires_at
                or _utc(self._clock()) >= b.expires_at
                or self._current_revisions(b) != b.revisions
            ):
                raise ValueError
        except Exception:
            raise ControlPlaneSessionDeniedError("control-plane session denied") from None

    def revoke(self, cookie):
        self._enabled_or_deny()
        try:
            self._backend.revoke(_digest("cookie", cookie))
        except Exception:
            raise ControlPlaneSessionDeniedError("control-plane session denied") from None

    def _enabled_or_deny(self):
        if not self._enabled:
            raise ControlPlaneSessionDeniedError("control-plane session denied")


class IssuerWireRequestV1(StrictValue):
    schema_version: Literal["capauth-dashboard-issuer/v1"] = "capauth-dashboard-issuer/v1"
    session_cookie: str = Field(min_length=32, max_length=128, repr=False)
    csrf_token: str = Field(min_length=32, max_length=128, repr=False)
    request_nonce: str = Field(min_length=16, max_length=256)
    origin: str = Field(min_length=1, max_length=2048)
    device_fingerprint: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,255}$")
    principal: Principal
    acting_principal: Principal
    node_id: str = Field(min_length=1, max_length=256)
    purpose: str = Field(min_length=1, max_length=256)
    capability: str = Field(min_length=1, max_length=256)
    target: str = Field(min_length=1, max_length=512)
    operation: str = Field(min_length=1, max_length=128)
    resource_type: str = Field(min_length=1, max_length=128)
    resource_id: str | None = Field(default=None, min_length=1, max_length=1024)
    owner_policy_revision: str = Field(pattern=r"^[0-9a-f]{64}$")
    ttl_seconds: int = Field(ge=1, le=300)

    @model_validator(mode="after")
    def valid(self) -> Self:
        if any(
            x != x.strip()
            for x in (
                self.request_nonce,
                self.origin,
                self.device_fingerprint,
                self.node_id,
                self.purpose,
                self.capability,
                self.target,
                self.operation,
                self.resource_type,
            )
        ) or not _origin(self.origin):
            raise ValueError("invalid request")
        return self

    def __repr__(self):
        return "IssuerWireRequestV1(<redacted>)"

    __str__ = __repr__


class DelegatedCapabilityIssuance(StrictValue):
    principal: Principal
    acting_principal: Principal
    session_jti: str = Field(pattern=r"^[0-9a-f]{32}$")
    scope: CapabilityScope
    revisions: CurrentPolicyRevisions
    ttl_seconds: int = Field(ge=1, le=300)

    def __repr__(self):
        return "DelegatedCapabilityIssuance(<redacted>)"

    __str__ = __repr__


class InjectedCapabilityIssuer(Protocol):
    def issue(self, request: DelegatedCapabilityIssuance) -> PresentedCapability: ...


class OpaqueOneUseCapability:
    __slots__ = ("_buffer", "_lock", "_used")

    def __init__(self, raw):
        if not raw or len(raw) > MAX_ISSUED_CAPABILITY_BYTES:
            raise ValueError
        self._buffer, self._lock, self._used = bytearray(raw), threading.Lock(), False

    def consume(self, consumer):
        with self._lock:
            if self._used:
                raise IssuerChannelDeniedError("issuer channel denied")
            self._used = True
            try:
                consumer(memoryview(self._buffer))
            finally:
                self._buffer[:] = b"\0" * len(self._buffer)

    def __repr__(self):
        return "OpaqueOneUseCapability(<redacted>)"

    __str__ = __repr__

    def __reduce__(self) -> Never:
        raise TypeError("issued capabilities cannot be serialized")

    def __copy__(self):
        raise TypeError("issued capabilities cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError("issued capabilities cannot be copied")


class LocalIssuerChannel:
    def __init__(
        self,
        *,
        sessions,
        issuer=None,
        allowed_peer_uids=frozenset(),
        socket_path=None,
        socket_uid=None,
        enabled=False,
        clock=None,
    ):
        (
            self._sessions,
            self._issuer,
            self._allowed_peer_uids,
            self._socket_path,
            self._socket_uid,
            self._enabled,
            self._clock,
        ) = (
            sessions,
            issuer,
            allowed_peer_uids,
            socket_path,
            socket_uid,
            enabled,
            clock or (lambda: datetime.now(UTC)),
        )

    def issue(self, raw_request: bytes, *, connection):
        try:
            if (
                not self._enabled
                or self._issuer is None
                or not self._allowed_peer_uids
                or self._socket_path is None
                or self._socket_uid is None
            ):
                raise ValueError
            _validate_socket(self._socket_path, self._socket_uid)
            _validate_connection(connection, self._socket_path)
            if _peer_uid(connection) not in self._allowed_peer_uids:
                raise ValueError
            r = _parse(raw_request)
            c = self._sessions.authenticate(
                cookie=r.session_cookie,
                csrf=r.csrf_token,
                origin=r.origin,
                device_fingerprint=r.device_fingerprint,
                request_nonce=r.request_nonce,
            )
            b = c.binding
            if (
                (r.principal, r.acting_principal, r.purpose)
                != (b.principal, b.acting_principal, b.purpose)
                or r.capability not in b.capability_ceiling
                or _OPS.get(r.capability) != r.operation
                or r.owner_policy_revision != b.revisions.owner
            ):
                raise ValueError
            scope = CapabilityScope(
                audience=SKDASHBOARD_AUDIENCE,
                target=r.target,
                capability=r.capability,
                operation=r.operation,
                resource_type=r.resource_type,
                resource_id=r.resource_id,
                constraints=frozenset(
                    {
                        f"node:{r.node_id}",
                        f"purpose:{r.purpose}",
                        f"session:{b.session_jti}",
                        f"owner-policy-revision:{b.revisions.owner}",
                    }
                ),
            )
            exact = DelegatedCapabilityIssuance(
                principal=b.principal,
                acting_principal=b.acting_principal,
                session_jti=b.session_jti,
                scope=scope,
                revisions=b.revisions,
                ttl_seconds=r.ttl_seconds,
            )
            p = self._issuer.issue(exact)
            self._sessions.revalidate(c)
            self._validate(p, exact)
            return OpaqueOneUseCapability(export_authorization_bearer(p).encode())
        except Exception:
            raise IssuerChannelDeniedError("issuer channel denied") from None

    def _validate(self, p, r):
        chain = tuple(parse_presented_token(raw) for raw in p.credentials_for_verification())
        if not chain:
            raise ValueError
        leaf = chain[-1]
        now = _utc(self._clock())
        claims = leaf.claims
        if claims.principal != r.principal or claims.scope != r.scope or claims.use_limit != 1:
            raise ValueError
        for item in chain:
            payload = item.token.payload
            if item.claims.principal != r.principal:
                raise ValueError
            if payload.not_before > now or payload.issued_at > now or payload.expires_at <= now:
                raise ValueError
        if (
            leaf.token.payload.issued_at > now
            or leaf.token.payload.expires_at <= now
            or leaf.token.payload.expires_at - leaf.token.payload.issued_at
            > timedelta(seconds=r.ttl_seconds)
        ):
            raise ValueError


def _parse(raw):
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_ISSUER_REQUEST_BYTES:
        raise ValueError
    return IssuerWireRequestV1.model_validate(
        json.loads(raw.decode(), object_pairs_hook=_pairs), strict=True
    )


def _pairs(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError
        d[k] = v
    return d


def _digest(domain, value):
    return hashlib.sha256(f"capauth:{domain}:v1\0{value}".encode()).hexdigest()


def _digest_bytes(domain, value):
    return bytes.fromhex(_digest(domain, value))


def _origin(value):
    try:
        p = urlsplit(value)
        return (
            p.scheme == "https"
            and bool(p.hostname)
            and p.username is None
            and p.password is None
            and not p.path
            and not p.query
            and not p.fragment
            and value == f"https://{p.netloc}"
        )
    except Exception:
        return False


def _utc(value):
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError
    return value.astimezone(UTC)


def _validate_socket(path, uid):
    s = os.stat(path, follow_symlinks=False)
    if not stat.S_ISSOCK(s.st_mode) or s.st_uid != uid or s.st_mode & 0o77:
        raise ValueError


def _validate_connection(c, path):
    if c.family != socket.AF_UNIX or Path(c.getsockname()) != Path(path):
        raise ValueError


def _peer_uid(c):
    if not hasattr(socket, "SO_PEERCRED"):
        raise ValueError
    _, uid, _ = struct.unpack(
        "3i", c.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    )
    return uid


__all__ = [
    "AuthenticatedOperatorSession",
    "ControlPlaneSessionDeniedError",
    "CurrentPolicyRevisions",
    "DelegatedCapabilityIssuance",
    "InjectedCapabilityIssuer",
    "IssuerChannelDeniedError",
    "IssuerWireRequestV1",
    "LocalIssuerChannel",
    "OpaqueOneUseCapability",
    "OpaqueSessionMaterial",
    "OPERATOR_SESSION_COOKIE_POLICY",
    "OperatorSessionBackend",
    "OperatorSessionBinding",
    "OperatorSessionCookiePolicy",
    "OperatorSessionManager",
    "InMemoryOperatorSessionBackendForTests",
]
