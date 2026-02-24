"""Tests for the capauth register CLI command."""

from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from capauth.cli import main


@pytest.fixture
def runner():
    """Provide a Click CliRunner for invoking commands."""
    return CliRunner()


def _mock_profile(name="Chef", email="chef@smilintux.org", fingerprint="ABCD1234" * 5):
    """Build a mock SovereignProfile matching the real structure."""
    profile = MagicMock()
    profile.entity.name = name
    profile.entity.email = email
    profile.entity.entity_type.value = "human"
    profile.key_info.fingerprint = fingerprint
    profile.storage.primary = "/tmp/test-capauth"
    profile.crypto_backend.value = "pgpy"
    profile.profile_id = "test-id-1234"
    profile.created.isoformat.return_value = "2026-02-22T00:00:00+00:00"
    profile.signature = "test-sig"
    return profile


def _patch_profile_and_pma(mock_profile, mock_request=None, pma_side_effect=None):
    """Return context managers that mock load_profile and create_request.

    The register command does lazy imports:
        from .profile import load_profile
        from .pma import create_request

    Because capauth.profile can't be imported on Python 3.14 (PGPy
    depends on removed imghdr), we inject mock modules into sys.modules.
    """
    if mock_request is None:
        mock_request = MagicMock()
        mock_request.request_id = "req-test-12345678"

    profile_mod = ModuleType("capauth.profile")
    if isinstance(mock_profile, Exception):
        profile_mod.load_profile = MagicMock(side_effect=mock_profile)
    else:
        profile_mod.load_profile = MagicMock(return_value=mock_profile)

    pma_mod = ModuleType("capauth.pma")
    if pma_side_effect:
        pma_mod.create_request = MagicMock(side_effect=pma_side_effect)
    else:
        pma_mod.create_request = MagicMock(return_value=mock_request)

    return patch.dict(
        sys.modules,
        {"capauth.profile": profile_mod, "capauth.pma": pma_mod},
    )


class TestRegisterHelp:
    """Test register command help and structure."""

    def test_help_output(self, runner):
        result = runner.invoke(main, ["register", "--help"])
        assert result.exit_code == 0
        assert "--org" in result.output
        assert "--name" in result.output
        assert "--title" in result.output
        assert "King" in result.output

    def test_name_required(self, runner):
        result = runner.invoke(main, ["register"], input="\n")
        assert result.exit_code != 0 or "name" in result.output.lower()


class TestRegisterCommand:
    """Test the register command with mocked profile."""

    def test_register_success(self, runner, tmp_path):
        with _patch_profile_and_pma(_mock_profile()):
            result = runner.invoke(
                main,
                [
                    "--home", str(tmp_path),
                    "register",
                    "--name", "TestKing",
                    "--org", "smilintux",
                    "--title", "King",
                    "--role", "Builder",
                ],
            )
            assert result.exit_code == 0, result.output
            assert "TestKing" in result.output
            assert "smilintux" in result.output

            registry_dir = tmp_path / "registry"
            assert registry_dir.exists()
            files = list(registry_dir.glob("*.yml"))
            assert len(files) == 1
            assert "smilintux-testking" in files[0].name

    def test_register_ai_entity(self, runner, tmp_path):
        with _patch_profile_and_pma(_mock_profile(name="Lumina", email="lumina@skworld.io")):
            result = runner.invoke(
                main,
                [
                    "--home", str(tmp_path),
                    "register",
                    "--name", "Lumina",
                    "--type", "ai",
                    "--title", "Queen",
                    "--role", "Partner",
                    "--human-partner", "Chef",
                ],
            )
            assert result.exit_code == 0, result.output
            assert "Lumina" in result.output
            assert "Queen" in result.output

    def test_register_with_projects_and_motto(self, runner, tmp_path):
        with _patch_profile_and_pma(_mock_profile()):
            result = runner.invoke(
                main,
                [
                    "--home", str(tmp_path),
                    "register",
                    "--name", "Chef",
                    "--projects", "SKForge,Cloud 9,SKComm",
                    "--motto", "stayCuriousANDkeepSmilin",
                ],
            )
            assert result.exit_code == 0, result.output

            import yaml

            files = list((tmp_path / "registry").glob("*.yml"))
            data = list(yaml.safe_load_all(files[0].read_text()))[0]
            assert data["motto"] == "stayCuriousANDkeepSmilin"
            assert "SKForge" in data["projects"]

    def test_register_no_profile_exits(self, runner, tmp_path):
        from capauth.exceptions import ProfileError

        with _patch_profile_and_pma(ProfileError("No profile found")):
            result = runner.invoke(
                main,
                [
                    "--home", str(tmp_path),
                    "register",
                    "--name", "Nobody",
                ],
            )
            assert result.exit_code == 1

    def test_register_pma_failure_still_creates_entry(self, runner, tmp_path):
        with _patch_profile_and_pma(
            _mock_profile(),
            pma_side_effect=Exception("PMA unavailable"),
        ):
            result = runner.invoke(
                main,
                [
                    "--home", str(tmp_path),
                    "register",
                    "--name", "Resilient",
                ],
            )
            assert result.exit_code == 0
            assert "PMA request skipped" in result.output

            files = list((tmp_path / "registry").glob("*.yml"))
            assert len(files) == 1

    def test_register_default_org_is_smilintux(self, runner, tmp_path):
        with _patch_profile_and_pma(_mock_profile()):
            result = runner.invoke(
                main,
                ["--home", str(tmp_path), "register", "--name", "DefaultOrg"],
            )
            assert result.exit_code == 0
            assert "smilintux" in result.output
