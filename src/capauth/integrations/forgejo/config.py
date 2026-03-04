"""Forgejo CapAuth integration configuration.

All settings can be supplied via environment variables or by constructing
a ``ForgejoConfig`` directly in code.

Environment Variables
---------------------
CAPAUTH_BASE_URL         : Base URL of the CapAuth service (e.g. https://auth.example.com)
CAPAUTH_JWT_SECRET       : HS256 secret used to sign/verify JWTs (must match service)
FORGEJO_BASE_URL         : Base URL of the Forgejo instance (e.g. https://git.example.com)
FORGEJO_CLIENT_ID        : OAuth2 client ID registered in Forgejo (default: "capauth")
FORGEJO_CLIENT_SECRET    : OAuth2 client secret (any non-empty string works for HS256)
FORGEJO_ADMIN_TOKEN      : Forgejo API token with admin scope (for user provisioning)
FORGEJO_AUTO_CREATE_USER : Create Forgejo accounts on first CapAuth login (default: true)
FORGEJO_ADMIN_GROUP      : CapAuth group that maps to Forgejo admin role (default: "admins")
FORGEJO_AUTH_CODE_TTL    : Seconds before an auth code expires (default: 120)
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field


@dataclass
class ForgejoConfig:
    """Runtime configuration for the Forgejo CapAuth integration."""

    # CapAuth service settings
    capauth_base_url: str = ""
    capauth_jwt_secret: str = ""

    # Forgejo instance settings
    forgejo_base_url: str = ""
    client_id: str = "capauth"
    client_secret: str = ""

    # Forgejo admin API token — used to provision users and set admin flags
    admin_token: str = ""

    # Behaviour
    auto_create_user: bool = True
    admin_group: str = "admins"
    auth_code_ttl: int = 120  # seconds

    @classmethod
    def from_env(cls) -> "ForgejoConfig":
        """Load configuration from environment variables."""
        return cls(
            capauth_base_url=os.environ.get("CAPAUTH_BASE_URL", ""),
            capauth_jwt_secret=os.environ.get("CAPAUTH_JWT_SECRET", secrets.token_hex(32)),
            forgejo_base_url=os.environ.get("FORGEJO_BASE_URL", "").rstrip("/"),
            client_id=os.environ.get("FORGEJO_CLIENT_ID", "capauth"),
            client_secret=os.environ.get("FORGEJO_CLIENT_SECRET", "capauth-secret"),
            admin_token=os.environ.get("FORGEJO_ADMIN_TOKEN", ""),
            auto_create_user=os.environ.get("FORGEJO_AUTO_CREATE_USER", "true").lower() == "true",
            admin_group=os.environ.get("FORGEJO_ADMIN_GROUP", "admins"),
            auth_code_ttl=int(os.environ.get("FORGEJO_AUTH_CODE_TTL", "120")),
        )

    def validate(self) -> list[str]:
        """Return a list of validation errors; empty means config is valid."""
        errors: list[str] = []
        if not self.capauth_base_url:
            errors.append("CAPAUTH_BASE_URL is required")
        if not self.forgejo_base_url:
            errors.append("FORGEJO_BASE_URL is required")
        if not self.capauth_jwt_secret:
            errors.append("CAPAUTH_JWT_SECRET is required")
        return errors

    @property
    def oidc_discovery_url(self) -> str:
        """Full URL to CapAuth's OIDC discovery document."""
        return f"{self.capauth_base_url}/.well-known/openid-configuration"

    @property
    def forgejo_redirect_uri(self) -> str:
        """The redirect_uri Forgejo sends to the authorization endpoint."""
        return f"{self.forgejo_base_url}/user/oauth2/capauth/callback"
