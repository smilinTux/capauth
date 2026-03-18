"""Tests for ForgejoConfig."""

from __future__ import annotations

import pytest

from capauth.integrations.forgejo.config import ForgejoConfig


class TestForgejoConfig:
    def test_defaults(self) -> None:
        cfg = ForgejoConfig()
        assert cfg.client_id == "capauth"
        assert cfg.admin_group == "admins"
        assert cfg.auto_create_user is True
        assert cfg.auth_code_ttl == 120

    def test_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CAPAUTH_BASE_URL", "https://auth.example.com")
        monkeypatch.setenv("CAPAUTH_JWT_SECRET", "supersecret")
        monkeypatch.setenv("FORGEJO_BASE_URL", "https://git.example.com/")
        monkeypatch.setenv("FORGEJO_CLIENT_ID", "myforgejo")
        monkeypatch.setenv("FORGEJO_ADMIN_GROUP", "kings")
        monkeypatch.setenv("FORGEJO_AUTO_CREATE_USER", "false")
        monkeypatch.setenv("FORGEJO_AUTH_CODE_TTL", "60")

        cfg = ForgejoConfig.from_env()
        assert cfg.capauth_base_url == "https://auth.example.com"
        assert cfg.capauth_jwt_secret == "supersecret"
        # trailing slash stripped
        assert cfg.forgejo_base_url == "https://git.example.com"
        assert cfg.client_id == "myforgejo"
        assert cfg.admin_group == "kings"
        assert cfg.auto_create_user is False
        assert cfg.auth_code_ttl == 60

    def test_validate_missing_fields(self) -> None:
        cfg = ForgejoConfig()
        errors = cfg.validate()
        assert any("CAPAUTH_BASE_URL" in e for e in errors)
        assert any("FORGEJO_BASE_URL" in e for e in errors)

    def test_validate_ok(self) -> None:
        cfg = ForgejoConfig(
            capauth_base_url="https://auth.example.com",
            capauth_jwt_secret="secret",
            forgejo_base_url="https://git.example.com",
        )
        assert cfg.validate() == []

    def test_oidc_discovery_url(self) -> None:
        cfg = ForgejoConfig(capauth_base_url="https://auth.example.com")
        assert (
            cfg.oidc_discovery_url == "https://auth.example.com/.well-known/openid-configuration"
        )

    def test_forgejo_redirect_uri(self) -> None:
        cfg = ForgejoConfig(forgejo_base_url="https://git.example.com")
        assert cfg.forgejo_redirect_uri == "https://git.example.com/user/oauth2/capauth/callback"
