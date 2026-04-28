"""Tests for CapAuth home directory resolution."""

from __future__ import annotations

from pathlib import Path

from capauth import DEFAULT_CAPAUTH_DIR, LEGACY_CAPAUTH_DIR, resolve_capauth_home


def test_explicit_base_dir_wins(tmp_path: Path) -> None:
    """An explicit base directory should override defaults and env."""
    custom = tmp_path / "custom-capauth"
    assert resolve_capauth_home(custom) == custom


def test_env_override_wins(monkeypatch, tmp_path: Path) -> None:
    """CAPAUTH_HOME should take precedence over automatic defaults."""
    env_home = tmp_path / "env-capauth"
    monkeypatch.setenv("CAPAUTH_HOME", str(env_home))
    assert resolve_capauth_home() == env_home


def test_new_default_or_legacy_fallback() -> None:
    """Resolver should return one of the supported canonical homes."""
    resolved = resolve_capauth_home()
    assert resolved in {DEFAULT_CAPAUTH_DIR, LEGACY_CAPAUTH_DIR}
