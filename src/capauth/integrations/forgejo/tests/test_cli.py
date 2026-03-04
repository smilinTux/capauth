"""Tests for the ``capauth forgejo`` CLI commands."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from capauth.integrations.forgejo.cli import cmd_config, cmd_ping, main
from capauth.integrations.forgejo.config import ForgejoConfig


@pytest.fixture
def config() -> ForgejoConfig:
    return ForgejoConfig(
        capauth_base_url="https://auth.example.com",
        capauth_jwt_secret="secret",
        forgejo_base_url="https://git.example.com",
        client_id="capauth",
        admin_group="admins",
    )


class TestCmdConfig:
    def test_prints_app_ini_snippet(self, config: ForgejoConfig, capsys: pytest.CaptureFixture) -> None:
        rc = cmd_config(config)
        out = capsys.readouterr().out
        assert "[oauth2.source.capauth]" in out
        assert "openidConnect" in out
        assert "https://auth.example.com/forgejo/.well-known/openid-configuration" in out
        assert "capauth_fingerprint" in out
        assert rc == 0

    def test_returns_1_on_missing_config(self, capsys: pytest.CaptureFixture) -> None:
        rc = cmd_config(ForgejoConfig())
        out = capsys.readouterr().out
        assert rc == 1
        assert "CAPAUTH_BASE_URL" in out


class TestCmdPing:
    def test_ping_success(self, config: ForgejoConfig, capsys: pytest.CaptureFixture) -> None:
        with patch(
            "capauth.integrations.forgejo.forgejo_api.ForgejoAPIClient.ping",
            new_callable=AsyncMock,
            return_value=True,
        ):
            rc = cmd_ping(config)
        out = capsys.readouterr().out
        assert rc == 0
        assert "reachable" in out

    def test_ping_failure(self, config: ForgejoConfig, capsys: pytest.CaptureFixture) -> None:
        with patch(
            "capauth.integrations.forgejo.forgejo_api.ForgejoAPIClient.ping",
            new_callable=AsyncMock,
            return_value=False,
        ):
            rc = cmd_ping(config)
        assert rc == 1


class TestMain:
    def test_config_subcommand(self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
        monkeypatch.setenv("CAPAUTH_BASE_URL", "https://auth.example.com")
        monkeypatch.setenv("CAPAUTH_JWT_SECRET", "secret")
        monkeypatch.setenv("FORGEJO_BASE_URL", "https://git.example.com")
        rc = main(["config"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "[oauth2.source.capauth]" in out

    def test_invalid_subcommand_exits(self) -> None:
        with pytest.raises(SystemExit):
            main(["nonexistent-command"])
