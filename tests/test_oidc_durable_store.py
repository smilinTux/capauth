"""Durability and sensitivity tests for OIDC authorization state."""

from __future__ import annotations

import base64
import hashlib

import pytest

from capauth.service.oidc.store import (
    AuthCodeStore,
    InvalidGrantError,
    RateLimitExceededError,
)

CLIENT = "authentik"
REDIRECT = "https://authentik.test/callback"
VERIFIER = "verifier-string-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
CHALLENGE = (
    base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).rstrip(b"=").decode()
)
FINGERPRINT = "A" * 40


def _request(store: AuthCodeStore):
    return store.create_login_request(
        CLIENT,
        REDIRECT,
        "openid profile",
        "state-0123456789abcdef",
        CHALLENGE,
        "S256",
        "nonce-0123456789abcdef",
    )


def test_request_and_one_use_code_survive_restart(tmp_path):
    path = tmp_path / "state.db"
    first = AuthCodeStore(path)
    request = _request(first)

    restarted = AuthCodeStore(path)
    assert restarted.get_login_request(request.request_id) == request
    login, code = restarted.complete_login_request(request.request_id, FINGERPRINT, {})
    assert login == request
    assert code.code.encode() not in path.read_bytes()

    restarted_again = AuthCodeStore(path)
    record = restarted_again.consume_code(code.code, CLIENT, REDIRECT, VERIFIER)
    assert record.fingerprint == FINGERPRINT
    with pytest.raises(InvalidGrantError, match="replayed"):
        AuthCodeStore(path).consume_code(code.code, CLIENT, REDIRECT, VERIFIER)


def test_code_binding_failure_is_fail_closed_and_burns_code(tmp_path):
    store = AuthCodeStore(tmp_path / "state.db")
    request = _request(store)
    _, code = store.complete_login_request(request.request_id, FINGERPRINT, {})

    with pytest.raises(InvalidGrantError, match="binding"):
        store.consume_code(
            code.code, CLIENT, REDIRECT, "wrong-verifier-value-that-is-long-enough-123456"
        )
    with pytest.raises(InvalidGrantError, match="replayed"):
        store.consume_code(code.code, CLIENT, REDIRECT, VERIFIER)


def test_login_request_completion_is_one_use(tmp_path):
    store = AuthCodeStore(tmp_path / "state.db")
    request = _request(store)
    store.complete_login_request(request.request_id, FINGERPRINT, {})
    with pytest.raises(InvalidGrantError, match="unknown_request"):
        AuthCodeStore(store.path).complete_login_request(request.request_id, FINGERPRINT, {})


def test_rate_limit_survives_restart_without_storing_source(tmp_path):
    path = tmp_path / "state.db"
    AuthCodeStore(path).enforce_rate_limit("complete", "10.0.0.8:subject", limit=1)
    with pytest.raises(RateLimitExceededError):
        AuthCodeStore(path).enforce_rate_limit("complete", "10.0.0.8:subject", limit=1)
    assert b"10.0.0.8" not in path.read_bytes()


def test_access_token_currentness_and_revocation_survive_restart(tmp_path):
    path = tmp_path / "state.db"
    store = AuthCodeStore(path)
    store.register_access_token("token-jti", FINGERPRINT, CLIENT, 9_999_999_999)
    assert AuthCodeStore(path).access_token_current("token-jti", FINGERPRINT, CLIENT)
    assert AuthCodeStore(path).revoke_access_token("token-jti")
    assert not AuthCodeStore(path).access_token_current("token-jti", FINGERPRINT, CLIENT)
    assert b"token-jti" not in path.read_bytes()


@pytest.mark.parametrize("request_ttl", [0, 301])
def test_request_ttl_is_bounded(tmp_path, request_ttl):
    with pytest.raises(ValueError, match="between 1 and 300"):
        AuthCodeStore(tmp_path / "state.db", request_ttl=request_ttl)


@pytest.mark.parametrize("code_ttl", [0, 121])
def test_code_ttl_is_bounded(tmp_path, code_ttl):
    with pytest.raises(ValueError, match="between 1 and 120"):
        AuthCodeStore(tmp_path / "state.db", code_ttl=code_ttl)
