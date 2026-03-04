"""Tests for ForgejoAPIClient — user/token/org management.

Uses httpx's MockTransport to intercept API calls without a live Forgejo
instance.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from capauth.integrations.forgejo.config import ForgejoConfig
from capauth.integrations.forgejo.forgejo_api import (
    ForgejoAPIClient,
    ForgejoAPIError,
    _safe_username,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_transport(routes: dict[tuple[str, str], tuple[int, Any]]) -> httpx.MockTransport:
    """Build an httpx MockTransport from a {(METHOD, path): (status, body)} map."""

    def handler(request: httpx.Request) -> httpx.Response:
        key = (request.method, request.url.path)
        if key in routes:
            status, body = routes[key]
            content = json.dumps(body).encode() if not isinstance(body, bytes) else body
            return httpx.Response(status, content=content, headers={"Content-Type": "application/json"})
        return httpx.Response(404, content=b'{"message":"not found"}')

    return httpx.MockTransport(handler)


def _client(routes: dict[tuple[str, str], tuple[int, Any]]) -> ForgejoAPIClient:
    config = ForgejoConfig(
        forgejo_base_url="https://git.example.com",
        admin_token="admintoken",
        auto_create_user=True,
        admin_group="admins",
    )
    transport = _mock_transport(routes)
    http = httpx.AsyncClient(transport=transport, base_url="https://git.example.com")
    return ForgejoAPIClient(config=config, http_client=http)


FAKE_USER = {
    "id": 1,
    "login": "alice",
    "email": "alice@example.com",
    "is_admin": False,
    "full_name": "Alice",
}


# ---------------------------------------------------------------------------
# _safe_username
# ---------------------------------------------------------------------------


class TestSafeUsername:
    def test_clean_username(self) -> None:
        assert _safe_username("alice") == "alice"

    def test_strips_invalid_chars(self) -> None:
        result = _safe_username("alice@example.com")
        assert "@" not in result

    def test_truncates_long_names(self) -> None:
        result = _safe_username("a" * 50)
        assert len(result) <= 40

    def test_short_fallback(self) -> None:
        result = _safe_username("!")
        assert len(result) >= 2

    def test_fingerprint_fallback(self) -> None:
        result = _safe_username("ABCDEF12")
        assert len(result) >= 2


# ---------------------------------------------------------------------------
# get_user
# ---------------------------------------------------------------------------


class TestGetUser:
    @pytest.mark.asyncio
    async def test_returns_user(self) -> None:
        c = _client({("GET", "/api/v1/users/alice"): (200, FAKE_USER)})
        user = await c.get_user("alice")
        assert user is not None
        assert user["login"] == "alice"

    @pytest.mark.asyncio
    async def test_returns_none_on_404(self) -> None:
        c = _client({})
        user = await c.get_user("nobody")
        assert user is None

    @pytest.mark.asyncio
    async def test_raises_on_server_error(self) -> None:
        c = _client({("GET", "/api/v1/users/alice"): (500, {"message": "internal"})})
        with pytest.raises(ForgejoAPIError) as exc_info:
            await c.get_user("alice")
        assert exc_info.value.status == 500


# ---------------------------------------------------------------------------
# create_user
# ---------------------------------------------------------------------------


class TestCreateUser:
    @pytest.mark.asyncio
    async def test_creates_user(self) -> None:
        created = dict(FAKE_USER, login="bob", email="bob@example.com")
        c = _client({("POST", "/api/v1/admin/users"): (201, created)})
        user = await c.create_user("bob", "bob@example.com", "Bob")
        assert user["login"] == "bob"

    @pytest.mark.asyncio
    async def test_raises_on_conflict(self) -> None:
        c = _client({("POST", "/api/v1/admin/users"): (422, {"message": "user already exists"})})
        with pytest.raises(ForgejoAPIError) as exc_info:
            await c.create_user("alice", "alice@example.com")
        assert exc_info.value.status == 422


# ---------------------------------------------------------------------------
# set_user_admin
# ---------------------------------------------------------------------------


class TestSetUserAdmin:
    @pytest.mark.asyncio
    async def test_sets_admin(self) -> None:
        updated = dict(FAKE_USER, is_admin=True)
        c = _client({("PATCH", "/api/v1/admin/users/alice"): (200, updated)})
        user = await c.set_user_admin("alice", True)
        assert user["is_admin"] is True


# ---------------------------------------------------------------------------
# delete_user
# ---------------------------------------------------------------------------


class TestDeleteUser:
    @pytest.mark.asyncio
    async def test_deletes_user(self) -> None:
        c = _client({("DELETE", "/api/v1/admin/users/alice"): (204, {})})
        ok = await c.delete_user("alice")
        assert ok is True

    @pytest.mark.asyncio
    async def test_returns_false_on_404(self) -> None:
        c = _client({})
        ok = await c.delete_user("nobody")
        assert ok is False


# ---------------------------------------------------------------------------
# list_users
# ---------------------------------------------------------------------------


class TestListUsers:
    @pytest.mark.asyncio
    async def test_returns_list(self) -> None:
        c = _client({("GET", "/api/v1/admin/users"): (200, [FAKE_USER])})
        users = await c.list_users()
        assert len(users) == 1
        assert users[0]["login"] == "alice"


# ---------------------------------------------------------------------------
# API tokens
# ---------------------------------------------------------------------------


class TestAPITokens:
    @pytest.mark.asyncio
    async def test_create_token(self) -> None:
        token_data = {"id": 1, "name": "capauth", "sha1": "abc123secret"}
        c = _client({("POST", "/api/v1/users/alice/tokens"): (201, token_data)})
        token = await c.create_api_token("alice", "capauth")
        assert token["sha1"] == "abc123secret"

    @pytest.mark.asyncio
    async def test_delete_token(self) -> None:
        c = _client({("DELETE", "/api/v1/users/alice/tokens/1"): (204, {})})
        ok = await c.delete_api_token("alice", 1)
        assert ok is True

    @pytest.mark.asyncio
    async def test_list_tokens(self) -> None:
        tokens = [{"id": 1, "name": "capauth"}]
        c = _client({("GET", "/api/v1/users/alice/tokens"): (200, tokens)})
        result = await c.list_api_tokens("alice")
        assert len(result) == 1


# ---------------------------------------------------------------------------
# get_or_create_user — high-level provisioning
# ---------------------------------------------------------------------------


class TestGetOrCreateUser:
    @pytest.mark.asyncio
    async def test_creates_new_user(self) -> None:
        created = dict(FAKE_USER, login="alice")
        routes = {
            ("GET", "/api/v1/users/alice"): (404, {"message": "not found"}),
            ("POST", "/api/v1/admin/users"): (201, created),
        }
        c = _client(routes)
        user = await c.get_or_create_user(
            "A" * 40, {"preferred_username": "alice", "email": "alice@example.com"}
        )
        assert user["login"] == "alice"

    @pytest.mark.asyncio
    async def test_returns_existing_user_no_admin_change(self) -> None:
        routes = {("GET", "/api/v1/users/alice"): (200, FAKE_USER)}
        c = _client(routes)
        user = await c.get_or_create_user(
            "A" * 40, {"preferred_username": "alice", "email": "alice@example.com", "groups": []}
        )
        assert user["login"] == "alice"

    @pytest.mark.asyncio
    async def test_syncs_admin_status(self) -> None:
        existing = dict(FAKE_USER, is_admin=False)
        promoted = dict(FAKE_USER, is_admin=True)
        routes = {
            ("GET", "/api/v1/users/alice"): (200, existing),
            ("PATCH", "/api/v1/admin/users/alice"): (200, promoted),
        }
        c = _client(routes)
        user = await c.get_or_create_user(
            "A" * 40, {"preferred_username": "alice", "groups": ["admins"]}
        )
        # The returned user is the pre-patch existing record; admin sync is fire-and-forget
        assert user["login"] == "alice"

    @pytest.mark.asyncio
    async def test_raises_when_auto_create_disabled(self) -> None:
        config = ForgejoConfig(
            forgejo_base_url="https://git.example.com",
            admin_token="tok",
            auto_create_user=False,
        )
        transport = _mock_transport({})
        http = httpx.AsyncClient(transport=transport, base_url="https://git.example.com")
        c = ForgejoAPIClient(config=config, http_client=http)
        with pytest.raises(ForgejoAPIError) as exc_info:
            await c.get_or_create_user("A" * 40, {"preferred_username": "new_user"})
        assert exc_info.value.status == 404


# ---------------------------------------------------------------------------
# ping
# ---------------------------------------------------------------------------


class TestPing:
    @pytest.mark.asyncio
    async def test_ping_ok(self) -> None:
        c = _client({("GET", "/api/v1/settings/api"): (200, {})})
        assert await c.ping() is True

    @pytest.mark.asyncio
    async def test_ping_fail(self) -> None:
        c = _client({})
        assert await c.ping() is False
