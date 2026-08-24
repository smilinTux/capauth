"""Durable, fail-closed state for the CapAuth OIDC authorization-code flow."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional

from ... import resolve_capauth_home

MAX_REQUEST_TTL = 300
MAX_CODE_TTL = 120
MAX_REFRESH_FAMILY_TTL = 8 * 60 * 60


class OIDCStateUnavailableError(RuntimeError):
    """The durable OIDC state boundary could not be read or mutated."""


class InvalidGrantError(ValueError):
    """An authorization code is absent, expired, replayed, or mis-bound."""


class RateLimitExceededError(ValueError):
    """A bounded OIDC request rate was exceeded."""


@dataclass(frozen=True)
class LoginRequest:
    """A pending authorization request awaiting identity proof."""

    request_id: str
    client_id: str
    redirect_uri: str
    scope: str
    state: str
    code_challenge: str
    code_challenge_method: str
    nonce: str
    issued_at: float
    expires_at: float


@dataclass(frozen=True)
class AuthCode:
    """A one-use authorization code bound to one validated request."""

    code: str
    client_id: str
    redirect_uri: str
    scope: str
    nonce: str
    code_challenge: str
    code_challenge_method: str
    fingerprint: str
    claims: dict[str, Any]
    issued_at: float
    expires_at: float


@dataclass(frozen=True)
class RefreshGrant:
    """One fixed, client-bound member of a rotating refresh family."""

    token: str
    family_id: str
    generation: int
    subject: str
    client_id: str
    audience: str
    scope: str
    policy_version: str
    expires_at: float


def verify_pkce(code_verifier: str, code_challenge: str, method: str) -> bool:
    """Verify a mandatory RFC 7636 S256 challenge."""
    if method != "S256" or not (43 <= len(code_verifier) <= 128):
        return False
    if not (43 <= len(code_challenge) <= 128):
        return False
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
    if any(char not in allowed for char in code_verifier):
        return False
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return hmac.compare_digest(computed, code_challenge)


def _default_path() -> Path:
    override = os.environ.get("CAPAUTH_OIDC_STATE_DB")
    if override:
        return Path(override).expanduser()
    data_dir = os.environ.get("CAPAUTH_DATA_DIR")
    if data_dir:
        return Path(data_dir).expanduser() / "oidc_state.db"
    return resolve_capauth_home() / "service" / "oidc_state.db"


class AuthCodeStore:
    """SQLite-backed OIDC requests, codes, rate limits, and token currentness."""

    def __init__(
        self,
        path: Path | str | None = None,
        request_ttl: int = MAX_REQUEST_TTL,
        code_ttl: int = MAX_CODE_TTL,
    ) -> None:
        if not 1 <= request_ttl <= MAX_REQUEST_TTL:
            raise ValueError("request_ttl must be between 1 and 300 seconds")
        if not 1 <= code_ttl <= MAX_CODE_TTL:
            raise ValueError("code_ttl must be between 1 and 120 seconds")
        self.path = Path(path) if path is not None else _default_path()
        self.request_ttl = request_ttl
        self.code_ttl = code_ttl
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _initialize(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self._connect() as conn:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS login_requests (
                        request_id TEXT PRIMARY KEY,
                        payload TEXT NOT NULL,
                        expires_at REAL NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS auth_codes (
                        code_hash TEXT PRIMARY KEY,
                        payload TEXT NOT NULL,
                        expires_at REAL NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS access_tokens (
                        jti_hash TEXT PRIMARY KEY,
                        subject TEXT NOT NULL,
                        client_id TEXT NOT NULL,
                        expires_at REAL NOT NULL,
                        revoked_at REAL
                    );
                    CREATE TABLE IF NOT EXISTS rate_events (
                        bucket TEXT NOT NULL,
                        key_hash TEXT NOT NULL,
                        occurred_at REAL NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS rate_window
                        ON rate_events(bucket, key_hash, occurred_at);
                    CREATE TABLE IF NOT EXISTS refresh_tokens (
                        token_hash TEXT PRIMARY KEY,
                        family_hash TEXT NOT NULL,
                        generation INTEGER NOT NULL,
                        subject TEXT NOT NULL,
                        client_id TEXT NOT NULL,
                        audience TEXT NOT NULL,
                        scope TEXT NOT NULL,
                        policy_version TEXT NOT NULL,
                        expires_at REAL NOT NULL,
                        used_at REAL,
                        revoked_at REAL
                    );
                    CREATE INDEX IF NOT EXISTS refresh_family
                        ON refresh_tokens(family_hash, generation);
                    """
                )
            os.chmod(self.path, 0o600)
        except (OSError, sqlite3.Error) as exc:
            raise OIDCStateUnavailableError("OIDC state initialization failed") from exc

    @staticmethod
    def _digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _request_from_row(row: sqlite3.Row) -> LoginRequest:
        return LoginRequest(**json.loads(row["payload"]))

    @staticmethod
    def _code_from_row(row: sqlite3.Row) -> AuthCode:
        return AuthCode(**json.loads(row["payload"]))

    def create_login_request(
        self,
        client_id: str,
        redirect_uri: str,
        scope: str,
        state: str,
        code_challenge: str,
        code_challenge_method: str,
        nonce: str,
    ) -> LoginRequest:
        now = time.time()
        record = LoginRequest(
            request_id=secrets.token_urlsafe(32),
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            nonce=nonce,
            issued_at=now,
            expires_at=now + self.request_ttl,
        )
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO login_requests VALUES (?, ?, ?)",
                    (record.request_id, json.dumps(asdict(record)), record.expires_at),
                )
            return record
        except sqlite3.Error as exc:
            raise OIDCStateUnavailableError("OIDC request write failed") from exc

    def get_login_request(self, request_id: str) -> Optional[LoginRequest]:
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT payload, expires_at FROM login_requests WHERE request_id = ?",
                    (request_id,),
                ).fetchone()
                if row is None:
                    return None
                if row["expires_at"] < time.time():
                    conn.execute("DELETE FROM login_requests WHERE request_id = ?", (request_id,))
                    return None
                return self._request_from_row(row)
        except sqlite3.Error as exc:
            raise OIDCStateUnavailableError("OIDC request read failed") from exc

    def complete_login_request(
        self, request_id: str, fingerprint: str, claims: dict[str, Any]
    ) -> tuple[LoginRequest, AuthCode]:
        """Atomically consume a login request and persist its one-use code."""
        now = time.time()
        try:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    "SELECT payload, expires_at FROM login_requests WHERE request_id = ?",
                    (request_id,),
                ).fetchone()
                if row is None or row["expires_at"] < now:
                    conn.execute("DELETE FROM login_requests WHERE request_id = ?", (request_id,))
                    conn.commit()
                    raise InvalidGrantError("expired_or_unknown_request")
                request = self._request_from_row(row)
                code = AuthCode(
                    code=secrets.token_urlsafe(32),
                    client_id=request.client_id,
                    redirect_uri=request.redirect_uri,
                    scope=request.scope,
                    nonce=request.nonce,
                    code_challenge=request.code_challenge,
                    code_challenge_method=request.code_challenge_method,
                    fingerprint=fingerprint,
                    claims=claims,
                    issued_at=now,
                    expires_at=now + self.code_ttl,
                )
                conn.execute("DELETE FROM login_requests WHERE request_id = ?", (request_id,))
                stored_code = asdict(code)
                stored_code["code"] = ""
                conn.execute(
                    "INSERT INTO auth_codes VALUES (?, ?, ?)",
                    (self._digest(code.code), json.dumps(stored_code), code.expires_at),
                )
                conn.commit()
                return request, code
            except Exception:
                if conn.in_transaction:
                    conn.rollback()
                raise
            finally:
                conn.close()
        except InvalidGrantError:
            raise
        except (TypeError, ValueError, sqlite3.Error) as exc:
            raise OIDCStateUnavailableError("OIDC completion transaction failed") from exc

    def consume_code(
        self, code: str, client_id: str, redirect_uri: str, code_verifier: str
    ) -> AuthCode:
        """Atomically consume a live code after exact client, redirect, and PKCE checks."""
        now = time.time()
        code_hash = self._digest(code)
        try:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    "SELECT payload, expires_at FROM auth_codes WHERE code_hash = ?", (code_hash,)
                ).fetchone()
                if row is None:
                    conn.commit()
                    raise InvalidGrantError("unknown_or_replayed_code")
                conn.execute("DELETE FROM auth_codes WHERE code_hash = ?", (code_hash,))
                record = self._code_from_row(row)
                valid = (
                    row["expires_at"] >= now
                    and hmac.compare_digest(record.client_id, client_id)
                    and hmac.compare_digest(record.redirect_uri, redirect_uri)
                    and verify_pkce(
                        code_verifier, record.code_challenge, record.code_challenge_method
                    )
                )
                conn.commit()
                if not valid:
                    raise InvalidGrantError("invalid_code_binding")
                return record
            except Exception:
                if conn.in_transaction:
                    conn.rollback()
                raise
            finally:
                conn.close()
        except InvalidGrantError:
            raise
        except sqlite3.Error as exc:
            raise OIDCStateUnavailableError("OIDC code transaction failed") from exc

    def register_access_token(
        self, jti: str, subject: str, client_id: str, expires_at: float
    ) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO access_tokens VALUES (?, ?, ?, ?, NULL)",
                    (self._digest(jti), subject, client_id, expires_at),
                )
        except sqlite3.Error as exc:
            raise OIDCStateUnavailableError("OIDC token registration failed") from exc

    def access_token_current(self, jti: str, subject: str, client_id: str) -> bool:
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT subject, client_id, expires_at, revoked_at FROM access_tokens "
                    "WHERE jti_hash = ?",
                    (self._digest(jti),),
                ).fetchone()
            return bool(
                row
                and row["revoked_at"] is None
                and row["expires_at"] >= time.time()
                and hmac.compare_digest(row["subject"], subject)
                and hmac.compare_digest(row["client_id"], client_id)
            )
        except sqlite3.Error as exc:
            raise OIDCStateUnavailableError("OIDC token currentness read failed") from exc

    def revoke_access_token(self, jti: str) -> bool:
        try:
            with self._connect() as conn:
                cursor = conn.execute(
                    "UPDATE access_tokens SET revoked_at = ? "
                    "WHERE jti_hash = ? AND revoked_at IS NULL",
                    (time.time(), self._digest(jti)),
                )
            return cursor.rowcount == 1
        except sqlite3.Error as exc:
            raise OIDCStateUnavailableError("OIDC token revocation failed") from exc

    def create_refresh_family(
        self,
        *,
        subject: str,
        client_id: str,
        audience: str,
        scope: str,
        policy_version: str,
        ttl_seconds: int = MAX_REFRESH_FAMILY_TTL,
    ) -> RefreshGrant:
        """Create one opaque refresh family without storing its bearer bytes."""
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= MAX_REFRESH_FAMILY_TTL:
            raise ValueError("refresh family ttl must be between 1 and 28800 seconds")
        now = time.time()
        grant = RefreshGrant(
            token=secrets.token_urlsafe(48),
            family_id=self._digest(secrets.token_urlsafe(32)),
            generation=0,
            subject=subject,
            client_id=client_id,
            audience=audience,
            scope=scope,
            policy_version=policy_version,
            expires_at=now + ttl_seconds,
        )
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO refresh_tokens VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
                    (
                        self._digest(grant.token),
                        grant.family_id,
                        grant.generation,
                        subject,
                        client_id,
                        audience,
                        scope,
                        policy_version,
                        grant.expires_at,
                    ),
                )
            return grant
        except sqlite3.Error as exc:
            raise OIDCStateUnavailableError("OIDC refresh-family write failed") from exc

    def inspect_refresh_token(self, token: str) -> RefreshGrant:
        """Read a live refresh member for preflight without consuming it."""
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM refresh_tokens WHERE token_hash = ?", (self._digest(token),)
                ).fetchone()
                if row is None:
                    raise InvalidGrantError("unknown_refresh_token")
                if row["used_at"] is not None:
                    conn.execute(
                        "UPDATE refresh_tokens SET revoked_at = ? WHERE family_hash = ?",
                        (time.time(), row["family_hash"]),
                    )
                    conn.commit()
                    raise InvalidGrantError("replayed_refresh_token")
                if row["revoked_at"] is not None or row["expires_at"] < time.time():
                    raise InvalidGrantError("inactive_refresh_token")
                return RefreshGrant(
                    token=token,
                    family_id=row["family_hash"],
                    generation=row["generation"],
                    subject=row["subject"],
                    client_id=row["client_id"],
                    audience=row["audience"],
                    scope=row["scope"],
                    policy_version=row["policy_version"],
                    expires_at=row["expires_at"],
                )
        except InvalidGrantError:
            raise
        except sqlite3.Error as exc:
            raise OIDCStateUnavailableError("OIDC refresh-family read failed") from exc

    def rotate_refresh_token(self, grant: RefreshGrant) -> RefreshGrant:
        """Atomically consume the exact member and insert its one successor."""
        now = time.time()
        next_token = secrets.token_urlsafe(48)
        try:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    "SELECT * FROM refresh_tokens WHERE token_hash = ?",
                    (self._digest(grant.token),),
                ).fetchone()
                if (
                    row is None
                    or row["used_at"] is not None
                    or row["revoked_at"] is not None
                    or row["expires_at"] < now
                    or row["generation"] != grant.generation
                    or not hmac.compare_digest(row["client_id"], grant.client_id)
                ):
                    if row is not None:
                        conn.execute(
                            "UPDATE refresh_tokens SET revoked_at = ? WHERE family_hash = ?",
                            (now, row["family_hash"]),
                        )
                    conn.commit()
                    raise InvalidGrantError("refresh_rotation_conflict")
                conn.execute(
                    "UPDATE refresh_tokens SET used_at = ? WHERE token_hash = ?",
                    (now, self._digest(grant.token)),
                )
                conn.execute(
                    "INSERT INTO refresh_tokens VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
                    (
                        self._digest(next_token),
                        row["family_hash"],
                        grant.generation + 1,
                        grant.subject,
                        grant.client_id,
                        grant.audience,
                        grant.scope,
                        grant.policy_version,
                        grant.expires_at,
                    ),
                )
                conn.commit()
                return RefreshGrant(
                    token=next_token,
                    family_id=row["family_hash"],
                    generation=grant.generation + 1,
                    subject=grant.subject,
                    client_id=grant.client_id,
                    audience=grant.audience,
                    scope=grant.scope,
                    policy_version=grant.policy_version,
                    expires_at=grant.expires_at,
                )
            except Exception:
                if conn.in_transaction:
                    conn.rollback()
                raise
            finally:
                conn.close()
        except InvalidGrantError:
            raise
        except sqlite3.Error as exc:
            raise OIDCStateUnavailableError("OIDC refresh-family rotation failed") from exc

    def revoke_refresh_family(self, token: str) -> bool:
        """Revoke every generation reachable from one opaque family member."""
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT family_hash FROM refresh_tokens WHERE token_hash = ?",
                    (self._digest(token),),
                ).fetchone()
                if row is None:
                    return False
                cursor = conn.execute(
                    "UPDATE refresh_tokens SET revoked_at = ? "
                    "WHERE family_hash = ? AND revoked_at IS NULL",
                    (time.time(), row["family_hash"]),
                )
            return cursor.rowcount > 0
        except sqlite3.Error as exc:
            raise OIDCStateUnavailableError("OIDC refresh-family revocation failed") from exc

    def enforce_rate_limit(
        self, bucket: str, key: str, *, limit: int, window_seconds: int = 60
    ) -> None:
        now = time.time()
        key_hash = self._digest(key)
        try:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("DELETE FROM rate_events WHERE occurred_at < ?", (now - 3600,))
                count = conn.execute(
                    "SELECT COUNT(*) FROM rate_events "
                    "WHERE bucket = ? AND key_hash = ? AND occurred_at >= ?",
                    (bucket, key_hash, now - window_seconds),
                ).fetchone()[0]
                if count >= limit:
                    conn.commit()
                    raise RateLimitExceededError(bucket)
                conn.execute("INSERT INTO rate_events VALUES (?, ?, ?)", (bucket, key_hash, now))
                conn.commit()
            except Exception:
                if conn.in_transaction:
                    conn.rollback()
                raise
            finally:
                conn.close()
        except RateLimitExceededError:
            raise
        except sqlite3.Error as exc:
            raise OIDCStateUnavailableError("OIDC rate-limit state unavailable") from exc

    def _count(self, table: str) -> int:
        try:
            with self._connect() as conn:
                conn.execute(f"DELETE FROM {table} WHERE expires_at < ?", (time.time(),))
                return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        except sqlite3.Error as exc:
            raise OIDCStateUnavailableError("OIDC state count failed") from exc

    @property
    def pending_requests(self) -> int:
        return self._count("login_requests")

    @property
    def pending_codes(self) -> int:
        return self._count("auth_codes")
