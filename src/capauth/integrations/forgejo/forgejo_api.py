"""Forgejo REST API client for CapAuth user provisioning.

After a successful PGP login, CapAuth may need to:
  - Create the Forgejo user account (if it doesn't exist yet)
  - Sync admin status from CapAuth groups
  - Issue or rotate personal API tokens for the user
  - List or remove accounts during de-provisioning

All operations use the Forgejo REST API v1 with an admin-scope API token
configured via ``FORGEJO_ADMIN_TOKEN``.

Usage
-----
.. code-block:: python

    from capauth.integrations.forgejo.forgejo_api import ForgejoAPIClient
    from capauth.integrations.forgejo.config import ForgejoConfig

    client = ForgejoAPIClient(config=ForgejoConfig.from_env())

    # Ensure user exists (creates if missing)
    user = await client.get_or_create_user(
        fingerprint="ABCD1234...",
        claims={"preferred_username": "alice", "email": "alice@example.com"}
    )
"""

from __future__ import annotations

import logging
import re
from typing import Any, Optional

import httpx

from .config import ForgejoConfig

logger = logging.getLogger("capauth.forgejo.api")

# Forgejo usernames: 1-40 chars, alphanumeric, hyphens, underscores, dots
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,38}$")


def _safe_username(raw: str) -> str:
    """Derive a valid Forgejo username from a raw string.

    Strips invalid characters and truncates to 40 chars.
    Falls back to ``user_<hex>`` if the result is too short.
    """
    cleaned = re.sub(r"[^a-zA-Z0-9._-]", "-", raw).strip("-.")
    cleaned = re.sub(r"-{2,}", "-", cleaned)[:40]
    if not cleaned or len(cleaned) < 2:
        cleaned = f"user_{raw[:8].lower()}"
    return cleaned


class ForgejoAPIError(Exception):
    """Raised when the Forgejo API returns an unexpected response."""

    def __init__(self, status: int, body: str) -> None:
        self.status = status
        self.body = body
        super().__init__(f"Forgejo API error {status}: {body}")


class ForgejoAPIClient:
    """Async HTTP client for the Forgejo v1 REST API.

    Parameters
    ----------
    config:
        Runtime configuration including ``forgejo_base_url`` and
        ``admin_token``.
    http_client:
        Optional pre-built ``httpx.AsyncClient`` — useful for tests.
    """

    def __init__(
        self,
        config: Optional[ForgejoConfig] = None,
        http_client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self.config = config or ForgejoConfig.from_env()
        self._client = http_client  # may be None; created lazily per call

    @property
    def _base(self) -> str:
        return f"{self.config.forgejo_base_url}/api/v1"

    @property
    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.config.admin_token:
            headers["Authorization"] = f"token {self.config.admin_token}"
        return headers

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is not None:
            return self._client
        return httpx.AsyncClient(timeout=15.0)

    async def _request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> httpx.Response:
        url = f"{self._base}{path}"
        client = await self._get_client()
        own_client = self._client is None

        try:
            resp = await client.request(method, url, headers=self._headers, **kwargs)
        finally:
            if own_client:
                await client.aclose()

        return resp

    # ------------------------------------------------------------------
    # User management
    # ------------------------------------------------------------------

    async def get_user(self, username: str) -> Optional[dict[str, Any]]:
        """Return Forgejo user data or ``None`` if not found.

        Parameters
        ----------
        username:
            Forgejo username (login name).
        """
        resp = await self._request("GET", f"/users/{username}")
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            raise ForgejoAPIError(resp.status_code, resp.text)
        return resp.json()

    async def create_user(
        self,
        username: str,
        email: str,
        display_name: str = "",
        is_admin: bool = False,
        source_id: int = 0,
        login_name: str = "",
    ) -> dict[str, Any]:
        """Create a new Forgejo user account.

        Parameters
        ----------
        username:
            Login name (must be unique).
        email:
            Email address.
        display_name:
            Full name shown in the UI.
        is_admin:
            Whether to grant site-admin privileges.
        source_id:
            Authentication source ID (0 = local).
        login_name:
            External login identifier (fingerprint for CapAuth users).

        Returns
        -------
        dict
            The created user object from Forgejo.
        """
        import secrets as _secrets
        payload: dict[str, Any] = {
            "username": username,
            "email": email,
            "full_name": display_name or username,
            "login_name": login_name or username,
            "source_id": source_id,
            "password": _secrets.token_urlsafe(32),  # random; user never uses it
            "must_change_password": False,
            "send_notify": False,
        }
        if is_admin:
            payload["admin"] = True

        resp = await self._request("POST", "/admin/users", json=payload)
        if resp.status_code not in (200, 201):
            raise ForgejoAPIError(resp.status_code, resp.text)
        return resp.json()

    async def update_user(self, username: str, **fields: Any) -> dict[str, Any]:
        """Update fields on an existing Forgejo user.

        Accepts any fields from Forgejo's ``PATCH /admin/users/{username}`` body.
        """
        resp = await self._request("PATCH", f"/admin/users/{username}", json=fields)
        if resp.status_code != 200:
            raise ForgejoAPIError(resp.status_code, resp.text)
        return resp.json()

    async def set_user_admin(self, username: str, is_admin: bool) -> dict[str, Any]:
        """Grant or revoke site-admin for *username*."""
        return await self.update_user(username, admin=is_admin, source_id=0, login_name=username)

    async def delete_user(self, username: str, purge: bool = False) -> bool:
        """Delete a Forgejo user.

        Parameters
        ----------
        username:
            Login name to remove.
        purge:
            If True, also delete all user's repositories and data.

        Returns
        -------
        bool
            True on success, False if the user was not found.
        """
        params = {"purge": "true"} if purge else {}
        resp = await self._request("DELETE", f"/admin/users/{username}", params=params)
        if resp.status_code == 404:
            return False
        if resp.status_code not in (200, 204):
            raise ForgejoAPIError(resp.status_code, resp.text)
        return True

    async def list_users(self, limit: int = 50, page: int = 1) -> list[dict[str, Any]]:
        """List Forgejo users (paginated).

        Parameters
        ----------
        limit:
            Page size (max 50 per Forgejo defaults).
        page:
            1-based page number.
        """
        resp = await self._request("GET", "/admin/users", params={"limit": limit, "page": page})
        if resp.status_code != 200:
            raise ForgejoAPIError(resp.status_code, resp.text)
        return resp.json()

    # ------------------------------------------------------------------
    # Token management
    # ------------------------------------------------------------------

    async def create_api_token(
        self,
        username: str,
        token_name: str = "capauth",
        scopes: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """Create a personal API token for *username*.

        Parameters
        ----------
        username:
            The Forgejo user to create the token for.
        token_name:
            Display name for the token.
        scopes:
            Optional list of Forgejo token scopes.

        Returns
        -------
        dict
            ``{"id": ..., "name": ..., "sha1": ...}`` — ``sha1`` is the raw
            token value (shown only once by Forgejo).
        """
        payload: dict[str, Any] = {"name": token_name}
        if scopes:
            payload["scopes"] = scopes

        resp = await self._request("POST", f"/users/{username}/tokens", json=payload)
        if resp.status_code not in (200, 201):
            raise ForgejoAPIError(resp.status_code, resp.text)
        return resp.json()

    async def delete_api_token(self, username: str, token_id: int) -> bool:
        """Delete a personal API token by ID."""
        resp = await self._request("DELETE", f"/users/{username}/tokens/{token_id}")
        if resp.status_code == 404:
            return False
        if resp.status_code not in (200, 204):
            raise ForgejoAPIError(resp.status_code, resp.text)
        return True

    async def list_api_tokens(self, username: str) -> list[dict[str, Any]]:
        """List all personal API tokens for *username*."""
        resp = await self._request("GET", f"/users/{username}/tokens")
        if resp.status_code != 200:
            raise ForgejoAPIError(resp.status_code, resp.text)
        return resp.json()

    # ------------------------------------------------------------------
    # Organization / team management
    # ------------------------------------------------------------------

    async def add_org_member(self, org: str, username: str) -> bool:
        """Add *username* to Forgejo organization *org*."""
        resp = await self._request("PUT", f"/orgs/{org}/members/{username}")
        return resp.status_code in (200, 204)

    async def remove_org_member(self, org: str, username: str) -> bool:
        """Remove *username* from Forgejo organization *org*."""
        resp = await self._request("DELETE", f"/orgs/{org}/members/{username}")
        return resp.status_code in (200, 204)

    # ------------------------------------------------------------------
    # High-level: get or create user from CapAuth claims
    # ------------------------------------------------------------------

    async def get_or_create_user(
        self,
        fingerprint: str,
        claims: dict[str, Any],
    ) -> dict[str, Any]:
        """Ensure a Forgejo user exists for the given CapAuth identity.

        If ``config.auto_create_user`` is False and the user doesn't exist,
        raises ``ForgejoAPIError`` with status 404.

        The user's admin flag is synced from the CapAuth ``groups`` claim
        against ``config.admin_group``.

        Parameters
        ----------
        fingerprint:
            40-char PGP fingerprint — used as the stable external identifier.
        claims:
            OIDC claims from CapAuth (name, email, preferred_username, groups…).

        Returns
        -------
        dict
            The Forgejo user object (existing or newly created).
        """
        raw_username = claims.get(
            "preferred_username",
            claims.get("name", f"capauth_{fingerprint[:8].lower()}"),
        )
        username = _safe_username(raw_username)
        email = claims.get("email", f"{username}@capauth.local")
        display_name = claims.get("name", username)
        groups: list[str] = claims.get("groups", [])
        is_admin = self.config.admin_group in groups

        existing = await self.get_user(username)
        if existing:
            # Sync admin status
            if existing.get("is_admin") != is_admin:
                try:
                    await self.set_user_admin(username, is_admin)
                    logger.info("Synced admin=%s for %s", is_admin, username)
                except ForgejoAPIError as exc:
                    logger.warning("Admin sync failed for %s: %s", username, exc)
            return existing

        if not self.config.auto_create_user:
            raise ForgejoAPIError(404, f"User {username!r} not found and auto_create is disabled")

        user = await self.create_user(
            username=username,
            email=email,
            display_name=display_name,
            is_admin=is_admin,
            login_name=fingerprint,
        )
        logger.info("Created Forgejo user %s (fingerprint=%s...)", username, fingerprint[:8])
        return user

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    async def ping(self) -> bool:
        """Return True if the Forgejo API is reachable and the token is valid."""
        try:
            resp = await self._request("GET", "/settings/api")
            return resp.status_code == 200
        except Exception:
            return False
