"""Durable operator sessions and atomic Dashboard authorization."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import stat
import threading
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, Protocol
from urllib.parse import urlsplit

from pydantic import Field, model_validator
from typing_extensions import Never, Self

from .control_plane import (
    CAPABILITY_MATRIX,
    SKDASHBOARD_AUDIENCE,
    ControlPlaneBinding,
    DecisionCode,
    DecisionState,
    StrictValue,
)
from .control_plane_authorizer import (
    MAX_SIGNED_EXPIRY_CEILING_WINDOW,
    ControlPlaneAuthorizationResultV1,
    ControlPlaneCurrentnessVerifier,
    ControlPlaneDecisionAuthorizer,
    ControlPlaneInvocationV1,
    SanitizedControlPlaneDecisionV1,
)
from .delegated import CapabilityScope, PresentedCapability, Principal, parse_presented_token

UTC = timezone.utc
MAX_SESSION_TTL = timedelta(hours=8)
MAX_SESSION_IDLE = timedelta(minutes=30)
_OPS = {entry.capability: entry.operation.value for entry in CAPABILITY_MATRIX if entry.capability}
_REQUEST_FACTORY = object()
_VERIFIER_FACTORY = object()


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

    def reference(self) -> str:
        return _json_ref(self.model_dump(mode="json"))


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
    device_fingerprint_ref: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    audience: Literal["skdashboard"] = SKDASHBOARD_AUDIENCE
    capability_ceiling_ref: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    purpose: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
    allowed_origin: str = Field(min_length=1, max_length=2048)
    session_jti: str = Field(pattern=r"^[0-9a-f]{32}$")
    revisions: CurrentPolicyRevisions
    issued_at: datetime
    idle_expires_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def valid(self) -> Self:
        if any(value != value.strip() for value in (self.purpose, self.allowed_origin)):
            raise ValueError("whitespace")
        if not _origin(self.allowed_origin):
            raise ValueError("origin")
        times = (self.issued_at, self.idle_expires_at, self.expires_at)
        if any(value.tzinfo is None or value.utcoffset() != timedelta(0) for value in times):
            raise ValueError("time")
        if not self.issued_at < self.idle_expires_at <= self.expires_at:
            raise ValueError("lifetime")
        if (
            self.expires_at - self.issued_at > MAX_SESSION_TTL
            or self.idle_expires_at - self.issued_at > MAX_SESSION_IDLE
        ):
            raise ValueError("bounds")
        return self

    def __repr__(self) -> str:
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

    def reserve_request(self, digest: str, nonce_digest: str) -> _StoredSession | None: ...


class InMemoryOperatorSessionBackendForTests:
    def __init__(self, *, max_sessions: int = 1024, max_nonces_per_session: int = 256):
        if max_sessions < 1 or max_nonces_per_session < 1:
            raise ValueError("bounds")
        self._max_sessions = max_sessions
        self._max_nonces = max_nonces_per_session
        self._records: dict[str, _StoredSession] = {}
        self._nonces: dict[str, set[str]] = {}
        self._lock = threading.Lock()

    def create(self, digest: str, record: _StoredSession) -> None:
        with self._lock:
            if digest in self._records or len(self._records) >= self._max_sessions:
                raise RuntimeError("unavailable")
            self._records[digest] = record
            self._nonces[digest] = set()

    def get(self, digest: str) -> _StoredSession | None:
        with self._lock:
            return self._records.get(digest)

    def revoke(self, digest: str) -> None:
        with self._lock:
            record = self._records.get(digest)
            if record is not None:
                self._records[digest] = replace(record, revoked=True)

    def reserve_request(self, digest: str, nonce_digest: str) -> _StoredSession | None:
        with self._lock:
            record = self._records.get(digest)
            seen = self._nonces.get(digest)
            if (
                record is None
                or record.revoked
                or seen is None
                or nonce_digest in seen
                or len(seen) >= self._max_nonces
            ):
                return None
            seen.add(nonce_digest)
            return record


class SQLiteOperatorSessionBackend:
    """Cross-process storage containing digests and nonsecret identity metadata."""

    def __init__(self, path: str | Path, *, max_sessions: int = 4096, max_nonces: int = 1024):
        if max_sessions < 1 or max_nonces < 1:
            raise ValueError("bounds")
        self._path = Path(path)
        self._max_sessions = max_sessions
        self._max_nonces = max_nonces
        self._prepare()

    def _prepare(self) -> None:
        parent_stat = os.stat(self._path.parent, follow_symlinks=False)
        if (
            not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_uid != os.getuid()
            or parent_stat.st_mode & 0o077
        ):
            raise ValueError("unsafe session database parent")
        if not self._path.exists():
            descriptor = os.open(
                self._path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            os.close(descriptor)
        self._validate_file()
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS sessions (
                    cookie_digest TEXT PRIMARY KEY,
                    binding_json TEXT NOT NULL,
                    csrf_digest BLOB NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1))
                );
                CREATE TABLE IF NOT EXISTS request_nonces (
                    cookie_digest TEXT NOT NULL,
                    nonce_digest TEXT NOT NULL,
                    PRIMARY KEY (cookie_digest, nonce_digest),
                    FOREIGN KEY (cookie_digest) REFERENCES sessions(cookie_digest)
                );
                """)
        self._validate_file()

    def _validate_file(self) -> None:
        value = os.stat(self._path, follow_symlinks=False)
        if (
            not stat.S_ISREG(value.st_mode)
            or value.st_uid != os.getuid()
            or stat.S_IMODE(value.st_mode) != 0o600
            or value.st_nlink != 1
        ):
            raise ValueError("unsafe session database")

    def _connect(self) -> sqlite3.Connection:
        self._validate_file()
        connection = sqlite3.connect(self._path, timeout=5.0, isolation_level=None)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def create(self, digest: str, record: _StoredSession) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            count = connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
            if count >= self._max_sessions:
                raise RuntimeError("unavailable")
            connection.execute(
                "INSERT INTO sessions(cookie_digest, binding_json, csrf_digest, revoked) "
                "VALUES (?, ?, ?, ?)",
                (
                    digest,
                    record.binding.model_dump_json(),
                    record.csrf_digest,
                    int(record.revoked),
                ),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def get(self, digest: str) -> _StoredSession | None:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT binding_json, csrf_digest, revoked FROM sessions WHERE cookie_digest = ?",
                (digest,),
            ).fetchone()
            return _stored_from_row(row)
        finally:
            connection.close()

    def revoke(self, digest: str) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE sessions SET revoked = 1 WHERE cookie_digest = ?", (digest,)
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def reserve_request(self, digest: str, nonce_digest: str) -> _StoredSession | None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT binding_json, csrf_digest, revoked FROM sessions WHERE cookie_digest = ?",
                (digest,),
            ).fetchone()
            record = _stored_from_row(row)
            if record is None or record.revoked:
                connection.rollback()
                return None
            count = connection.execute(
                "SELECT COUNT(*) FROM request_nonces WHERE cookie_digest = ?", (digest,)
            ).fetchone()[0]
            if count >= self._max_nonces:
                connection.rollback()
                return None
            try:
                connection.execute(
                    "INSERT INTO request_nonces(cookie_digest, nonce_digest) VALUES (?, ?)",
                    (digest, nonce_digest),
                )
            except sqlite3.IntegrityError:
                connection.rollback()
                return None
            connection.commit()
            return record
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


class OpaqueSessionMaterial:
    __slots__ = ("_cookie", "_csrf", "_lock", "_taken")

    def __init__(self, cookie: str, csrf: str):
        self._cookie = cookie
        self._csrf = csrf
        self._taken = False
        self._lock = threading.Lock()

    def take(self) -> tuple[str, str]:
        with self._lock:
            if self._taken:
                raise ControlPlaneSessionDeniedError("control-plane session denied")
            self._taken = True
            cookie, csrf = self._cookie, self._csrf
            self._cookie = self._csrf = ""
            return cookie, csrf

    def __repr__(self) -> str:
        return "OpaqueSessionMaterial(<redacted>)"

    __str__ = __repr__

    def __reduce__(self) -> Never:
        raise TypeError("operator session material cannot be serialized")

    def __copy__(self):
        raise TypeError("operator session material cannot be copied")

    def __deepcopy__(self, memo):
        del memo
        raise TypeError("operator session material cannot be copied")


@dataclass(frozen=True, slots=True, repr=False)
class AuthenticatedOperatorSession:
    binding: OperatorSessionBinding
    _session_digest: str

    def __repr__(self) -> str:
        return "AuthenticatedOperatorSession(<redacted>)"

    __str__ = __repr__

    def __reduce__(self) -> Never:
        raise TypeError("authenticated operator sessions cannot be serialized")


class OperatorSessionManager:
    def __init__(self, *, backend, current_revisions, enabled: bool = False, clock=None):
        self._backend = backend
        self._current_revisions = current_revisions
        self._enabled = enabled
        self._clock = clock or (lambda: datetime.now(UTC))

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
    ) -> OpaqueSessionMaterial:
        self._enabled_or_deny()
        if not 1 <= ttl_seconds <= int(
            MAX_SESSION_TTL.total_seconds()
        ) or not 1 <= idle_seconds <= min(ttl_seconds, int(MAX_SESSION_IDLE.total_seconds())):
            raise ControlPlaneSessionDeniedError("control-plane session denied")
        now = _utc(self._clock())
        cookie, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        try:
            ceiling = _capability_ceiling(capability_ceiling)
            binding = OperatorSessionBinding(
                principal=principal,
                acting_principal=acting_principal,
                device_fingerprint_ref=_secret_ref("device", device_fingerprint),
                capability_ceiling_ref=_json_ref(sorted(ceiling)),
                purpose=purpose,
                allowed_origin=allowed_origin,
                session_jti=secrets.token_hex(16),
                revisions=revisions,
                issued_at=now,
                idle_expires_at=now + timedelta(seconds=idle_seconds),
                expires_at=now + timedelta(seconds=ttl_seconds),
            )
            if self._current_revisions(binding) != revisions:
                raise ValueError
            self._backend.create(
                _digest("cookie", cookie),
                _StoredSession(binding, _digest_bytes("csrf", csrf)),
            )
        except Exception:
            raise ControlPlaneSessionDeniedError("control-plane session denied") from None
        return OpaqueSessionMaterial(cookie, csrf)

    def authenticate(self, *, cookie, csrf, origin, device_fingerprint, request_nonce):
        self._enabled_or_deny()
        if (
            not all(isinstance(value, str) and value for value in (cookie, csrf, origin))
            or not isinstance(device_fingerprint, str)
            or not device_fingerprint
            or not isinstance(request_nonce, str)
            or not 16 <= len(request_nonce) <= 256
            or request_nonce != request_nonce.strip()
        ):
            raise ControlPlaneSessionDeniedError("control-plane session denied")
        try:
            digest = _digest("cookie", cookie)
            before = self._backend.get(digest)
            if not self._valid(
                before,
                csrf=csrf,
                origin=origin,
                device_fingerprint=device_fingerprint,
            ):
                raise ValueError
            record = self._backend.reserve_request(digest, _digest("nonce", request_nonce))
            if record != before or not self._valid(
                record,
                csrf=csrf,
                origin=origin,
                device_fingerprint=device_fingerprint,
            ):
                raise ValueError
            return AuthenticatedOperatorSession(record.binding, digest)
        except Exception:
            raise ControlPlaneSessionDeniedError("control-plane session denied") from None

    def revalidate(self, context) -> None:
        self._enabled_or_deny()
        if type(context) is not AuthenticatedOperatorSession:
            raise ControlPlaneSessionDeniedError("control-plane session denied")
        try:
            record = self._backend.get(context._session_digest)
            binding = context.binding
            now = _utc(self._clock())
            if (
                record is None
                or record.revoked
                or record.binding != binding
                or now >= binding.idle_expires_at
                or now >= binding.expires_at
                or self._current_revisions(binding) != binding.revisions
            ):
                raise ValueError
        except Exception:
            raise ControlPlaneSessionDeniedError("control-plane session denied") from None

    def revoke(self, cookie) -> None:
        self._enabled_or_deny()
        try:
            self._backend.revoke(_digest("cookie", cookie))
        except Exception:
            raise ControlPlaneSessionDeniedError("control-plane session denied") from None

    def _valid(self, record, *, csrf, origin, device_fingerprint) -> bool:
        if not isinstance(record, _StoredSession) or record.revoked:
            return False
        binding = record.binding
        now = _utc(self._clock())
        return (
            now < binding.idle_expires_at
            and now < binding.expires_at
            and origin == binding.allowed_origin
            and _secret_ref("device", device_fingerprint) == binding.device_fingerprint_ref
            and hmac.compare_digest(_digest_bytes("csrf", csrf), record.csrf_digest)
            and self._current_revisions(binding) == binding.revisions
        )

    def _enabled_or_deny(self) -> None:
        if not self._enabled:
            raise ControlPlaneSessionDeniedError("control-plane session denied")


class DashboardIssuerAuthorizationConfigV1(StrictValue):
    schema_version: Literal["capauth-dashboard-issuer-config/v1"] = (
        "capauth-dashboard-issuer-config/v1"
    )
    allowed_origin: str = Field(min_length=1, max_length=2048)
    node_id: str = Field(min_length=1, max_length=256)
    purpose: str = Field(min_length=1, max_length=256)
    capability: str = Field(min_length=1, max_length=256)
    operation: str = Field(min_length=1, max_length=128)
    target: str = Field(min_length=1, max_length=512)
    resource_type: str = Field(min_length=1, max_length=128)
    resource_id: str | None = Field(default=None, min_length=1, max_length=1024)
    owner_policy_revision: str = Field(pattern=r"^[0-9a-f]{64}$")
    ttl_seconds: int = Field(ge=1, le=300)

    @model_validator(mode="after")
    def valid(self) -> Self:
        strings = (
            self.allowed_origin,
            self.node_id,
            self.purpose,
            self.capability,
            self.operation,
            self.target,
            self.resource_type,
        )
        if any(value != value.strip() for value in strings) or not _origin(self.allowed_origin):
            raise ValueError("invalid issuer configuration")
        if self.resource_id is not None and self.resource_id != self.resource_id.strip():
            raise ValueError("invalid resource")
        if _OPS.get(self.capability) != self.operation:
            raise ValueError("operation does not match capability")
        return self


class InProcessIssuerRequest:
    """Opaque one-use browser proof containing no identity or authorization topology."""

    __slots__ = (
        "_cookie",
        "_csrf",
        "_device_fingerprint",
        "_lock",
        "_nonce",
        "_taken",
    )

    def __init__(self, *, session_cookie, csrf_token, request_nonce, device_fingerprint):
        values = (session_cookie, csrf_token, request_nonce, device_fingerprint)
        if (
            not all(isinstance(value, str) and value for value in values)
            or not 16 <= len(request_nonce) <= 256
            or request_nonce != request_nonce.strip()
        ):
            raise ValueError("invalid issuer request")
        self._cookie = session_cookie
        self._csrf = csrf_token
        self._nonce = request_nonce
        self._device_fingerprint = device_fingerprint
        self._taken = False
        self._lock = threading.Lock()

    def _take(self, factory_token: object) -> tuple[str, str, str, str]:
        if factory_token is not _REQUEST_FACTORY:
            raise IssuerChannelDeniedError("issuer channel denied")
        with self._lock:
            if self._taken:
                raise IssuerChannelDeniedError("issuer channel denied")
            self._taken = True
            values = self._cookie, self._csrf, self._nonce, self._device_fingerprint
            self._cookie = self._csrf = self._nonce = self._device_fingerprint = ""
            return values

    def __repr__(self) -> str:
        return "InProcessIssuerRequest(<redacted>)"

    __str__ = __repr__

    def __reduce__(self) -> Never:
        raise TypeError("issuer requests cannot be serialized")

    def __copy__(self):
        raise TypeError("issuer requests cannot be copied")

    def __deepcopy__(self, memo):
        del memo
        raise TypeError("issuer requests cannot be copied")


class DelegatedCapabilityIssuance(StrictValue):
    principal: Principal
    acting_principal: Principal
    session_jti: str = Field(pattern=r"^[0-9a-f]{32}$")
    scope: CapabilityScope
    revisions: CurrentPolicyRevisions
    ttl_seconds: int = Field(ge=1, le=300)

    def __repr__(self) -> str:
        return "DelegatedCapabilityIssuance(<redacted>)"

    __str__ = __repr__


class InjectedCapabilityIssuer(Protocol):
    def issue(self, request: DelegatedCapabilityIssuance) -> PresentedCapability: ...


class OperatorSessionCurrentnessVerifier:
    __slots__ = ("_context", "_inner", "_lock", "_phase", "_session", "_sessions")

    def __init__(
        self,
        factory_token: object,
        *,
        sessions: OperatorSessionManager,
        session: AuthenticatedOperatorSession,
        context: SanitizedControlPlaneDecisionV1,
        inner: ControlPlaneCurrentnessVerifier,
    ):
        if (
            factory_token is not _VERIFIER_FACTORY
            or type(sessions) is not OperatorSessionManager
            or type(session) is not AuthenticatedOperatorSession
            or not isinstance(context, SanitizedControlPlaneDecisionV1)
            or not isinstance(inner, ControlPlaneCurrentnessVerifier)
        ):
            raise TypeError("operator currentness verifiers are factory issued")
        self._sessions = sessions
        self._session = session
        self._context = context
        self._inner = inner
        self._phase = 0
        self._lock = threading.Lock()

    def check_before_owner_read(self, context) -> DecisionState:
        return self._check(context, 0)

    def check_after_owner_read(self, context) -> DecisionState:
        return self._check(context, 1)

    def _check(self, context, phase) -> DecisionState:
        with self._lock:
            if self._phase != phase or context is not self._context:
                self._close_locked()
                return DecisionState.DENY
            try:
                self._sessions.revalidate(self._session)
                if phase == 0:
                    state = self._inner.check_before_owner_read(context)
                else:
                    state = self._inner.check_after_owner_read(context)
                self._sessions.revalidate(self._session)
            except Exception:
                state = DecisionState.DENY
            if state is DecisionState.ALLOW and phase == 0:
                self._phase = 1
            else:
                self._close_locked()
            return state

    def close(self) -> None:
        with self._lock:
            self._close_locked()

    def _close_locked(self) -> None:
        if self._phase == 2:
            return
        self._inner.close()
        self._inner = None
        self._session = None
        self._sessions = None
        self._context = None
        self._phase = 2

    def __repr__(self) -> str:
        return "<opaque operator session currentness verifier>"

    __str__ = __repr__

    def __reduce__(self) -> Never:
        raise TypeError("operator currentness verifiers cannot be serialized")

    def __copy__(self):
        raise TypeError("operator currentness verifiers cannot be copied")

    def __deepcopy__(self, memo):
        del memo
        raise TypeError("operator currentness verifiers cannot be copied")


class InProcessIssuerFactory:
    """Authenticate, issue, authorize, and consume without exposing bearer material."""

    def __init__(self, *, sessions, config, issuer=None, enabled=False, clock=None):
        self._sessions = sessions
        self._config = config
        self._issuer = issuer
        self._enabled = enabled
        self._clock = clock or (lambda: datetime.now(UTC))

    def authorize(
        self,
        request: InProcessIssuerRequest,
        authorizer: ControlPlaneDecisionAuthorizer,
        invocation: ControlPlaneInvocationV1,
    ) -> tuple[ControlPlaneAuthorizationResultV1, OperatorSessionCurrentnessVerifier | None]:
        inner = None
        try:
            if (
                not self._enabled
                or self._issuer is None
                or not isinstance(request, InProcessIssuerRequest)
                or not isinstance(authorizer, ControlPlaneDecisionAuthorizer)
                or not isinstance(invocation, ControlPlaneInvocationV1)
                or not isinstance(self._config, DashboardIssuerAuthorizationConfigV1)
                or not self._invocation_matches(invocation)
            ):
                raise ValueError
            cookie, csrf, nonce, device = request._take(_REQUEST_FACTORY)
            session = self._sessions.authenticate(
                cookie=cookie,
                csrf=csrf,
                origin=self._config.allowed_origin,
                device_fingerprint=device,
                request_nonce=nonce,
            )
            session_binding = session.binding
            if (
                session_binding.allowed_origin != self._config.allowed_origin
                or session_binding.purpose != self._config.purpose
                or session_binding.capability_ceiling_ref != _json_ref([self._config.capability])
                or session_binding.revisions.owner != self._config.owner_policy_revision
            ):
                raise ValueError
            now = _utc(self._clock())
            expires_at = (
                now
                + timedelta(seconds=self._config.ttl_seconds)
                + MAX_SIGNED_EXPIRY_CEILING_WINDOW
            )
            if expires_at > session_binding.expires_at:
                raise ValueError
            binding = ControlPlaneBinding(
                principal=session_binding.principal,
                acting_principal_id=session_binding.acting_principal.principal_id,
                session_jti=session_binding.session_jti,
                device_fingerprint_ref=session_binding.device_fingerprint_ref,
                session_policy_revisions_ref=session_binding.revisions.reference(),
                node_id=self._config.node_id,
                purpose=self._config.purpose,
                capability=self._config.capability,
                target=self._config.target,
                resource_type=self._config.resource_type,
                resource_id=self._config.resource_id,
                owner_policy_revision=self._config.owner_policy_revision,
                expires_at=expires_at,
            )
            issuance = DelegatedCapabilityIssuance(
                principal=session_binding.principal,
                acting_principal=session_binding.acting_principal,
                session_jti=session_binding.session_jti,
                scope=binding.capability_scope(),
                revisions=session_binding.revisions,
                ttl_seconds=self._config.ttl_seconds,
            )
            presented = self._issuer.issue(issuance)
            self._sessions.revalidate(session)
            self._validate_capability(
                presented,
                issuance,
                binding,
                issued_not_before=now,
                session_expires_at=session_binding.expires_at,
            )
            result, inner = authorizer._authorize_presented_with_currentness(
                presented,
                invocation,
            )
            self._sessions.revalidate(session)
            if not result.allow or result.context is None or inner is None:
                if inner is not None:
                    inner.close()
                return result, None
            verifier = OperatorSessionCurrentnessVerifier(
                _VERIFIER_FACTORY,
                sessions=self._sessions,
                session=session,
                context=result.context,
                inner=inner,
            )
            inner = None
            return result, verifier
        except Exception:
            if inner is not None:
                inner.close()
            return _denied(), None

    def _invocation_matches(self, invocation: ControlPlaneInvocationV1) -> bool:
        config = self._config
        return (
            invocation.node_id == config.node_id
            and invocation.purpose == config.purpose
            and invocation.audience == SKDASHBOARD_AUDIENCE
            and invocation.capability == config.capability
            and invocation.target == config.target
            and invocation.resource_type == config.resource_type
            and invocation.resource_id == config.resource_id
            and invocation.boundary.origin == config.allowed_origin
        )

    def _validate_capability(
        self,
        presented,
        request,
        binding,
        *,
        issued_not_before,
        session_expires_at,
    ) -> None:
        if not isinstance(presented, PresentedCapability):
            raise ValueError
        chain = tuple(
            parse_presented_token(raw) for raw in presented.credentials_for_verification()
        )
        if not chain:
            raise ValueError
        now = _utc(self._clock())
        leaf = chain[-1]
        if (
            leaf.claims.principal != request.principal
            or leaf.claims.scope != request.scope
            or leaf.claims.scope != binding.capability_scope()
            or leaf.claims.use_limit != 1
        ):
            raise ValueError
        for item in chain:
            payload = item.token.payload
            if (
                item.claims.principal != request.principal
                or payload.not_before > now
                or payload.issued_at > now
                or payload.expires_at <= now
            ):
                raise ValueError
        payload = leaf.token.payload
        if (
            payload.issued_at < issued_not_before
            or payload.expires_at <= payload.issued_at
            or payload.expires_at > binding.expires_at
            or payload.expires_at > session_expires_at
            or payload.expires_at - payload.issued_at > timedelta(seconds=request.ttl_seconds)
        ):
            raise ValueError


def _stored_from_row(row) -> _StoredSession | None:
    if row is None:
        return None
    binding_json, csrf_digest, revoked = row
    return _StoredSession(
        OperatorSessionBinding.model_validate_json(binding_json, strict=True),
        bytes(csrf_digest),
        bool(revoked),
    )


def _capability_ceiling(value) -> frozenset[str]:
    ceiling = frozenset(value)
    if (
        not ceiling
        or len(ceiling) > 32
        or any(
            not isinstance(item, str)
            or item not in _OPS
            or item != item.strip()
            or len(item) > 256
            for item in ceiling
        )
    ):
        raise ValueError("ceiling")
    return ceiling


def _denied() -> ControlPlaneAuthorizationResultV1:
    return ControlPlaneAuthorizationResultV1(
        allow=False,
        state=DecisionState.DENY,
        code=DecisionCode.CAPAUTH_DENIED,
    )


def _digest(domain: str, value: str) -> str:
    return hashlib.sha256(f"capauth:{domain}:v1\0{value}".encode()).hexdigest()


def _digest_bytes(domain: str, value: str) -> bytes:
    return bytes.fromhex(_digest(domain, value))


def _secret_ref(domain: str, value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("secret reference input")
    return f"sha256:{_digest(domain, value)}"


def _json_ref(value) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _origin(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        return (
            parsed.scheme == "https"
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
            and not parsed.path
            and not parsed.query
            and not parsed.fragment
            and value == f"https://{parsed.netloc}"
        )
    except Exception:
        return False


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError
    return value.astimezone(UTC)


__all__ = [
    "AuthenticatedOperatorSession",
    "ControlPlaneSessionDeniedError",
    "CurrentPolicyRevisions",
    "DashboardIssuerAuthorizationConfigV1",
    "DelegatedCapabilityIssuance",
    "InjectedCapabilityIssuer",
    "InMemoryOperatorSessionBackendForTests",
    "InProcessIssuerFactory",
    "InProcessIssuerRequest",
    "IssuerChannelDeniedError",
    "OpaqueSessionMaterial",
    "OPERATOR_SESSION_COOKIE_POLICY",
    "OperatorSessionBackend",
    "OperatorSessionBinding",
    "OperatorSessionCookiePolicy",
    "OperatorSessionCurrentnessVerifier",
    "OperatorSessionManager",
    "SQLiteOperatorSessionBackend",
]
