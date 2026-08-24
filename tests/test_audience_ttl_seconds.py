"""Security boundary tests for bounded non-persistent audience tokens."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from capauth.cli import main
from capauth.tokens import mint_audience_token


def _home(tmp_path: Path) -> Path:
    home = tmp_path / ".skcapstone"
    identity = home / "identity"
    identity.mkdir(parents=True)
    (identity / "identity.json").write_text(
        json.dumps({"fingerprint": "AABBCCDDEE1122334455"}), encoding="utf-8"
    )
    return home


@pytest.mark.parametrize("ttl", [1, 300])
def test_bounded_seconds_are_signed_and_never_persist(tmp_path, monkeypatch, ttl):
    home = _home(tmp_path)
    monkeypatch.setattr("capauth.tokens._pgp_sign_payload", lambda payload, base: "signature")

    token = mint_audience_token(
        home,
        "jarvis@example",
        "skdashboard",
        ["skdashboard.read"],
        ttl_seconds=ttl,
        store=False,
    )

    assert (token.payload.expires_at - token.payload.issued_at).total_seconds() == ttl
    assert token.signature == "signature"
    assert not (home / "security" / "tokens").exists()


@pytest.mark.parametrize("ttl", [0, 301, True, 1.5, "60"])
def test_seconds_outside_bound_are_rejected(tmp_path, ttl):
    with pytest.raises(ValueError, match="integer between 1 and 300"):
        mint_audience_token(
            _home(tmp_path),
            "s",
            "skdashboard",
            ["skdashboard.read"],
            ttl_seconds=ttl,
            store=False,
        )


def test_seconds_reject_persistence_unsigned_and_hours(tmp_path):
    home = _home(tmp_path)
    common = (home, "s", "skdashboard", ["skdashboard.read"])
    with pytest.raises(ValueError, match="store=False"):
        mint_audience_token(*common, ttl_seconds=60)
    with pytest.raises(ValueError, match="must be signed"):
        mint_audience_token(*common, ttl_seconds=60, store=False, sign=False)
    with pytest.raises(ValueError, match="mutually exclusive"):
        mint_audience_token(*common, ttl_hours=1, ttl_seconds=60, store=False)


def test_existing_default_and_explicit_hours_remain(tmp_path):
    home = _home(tmp_path)
    default = mint_audience_token(home, "s", "a", ["r"], sign=False)
    explicit = mint_audience_token(home, "s", "a", ["r"], ttl_hours=6, sign=False)
    assert (default.payload.expires_at - default.payload.issued_at).total_seconds() == 3600
    assert (explicit.payload.expires_at - explicit.payload.issued_at).total_seconds() == 21600


def test_cli_seconds_is_signed_and_non_persistent(tmp_path, monkeypatch):
    home = _home(tmp_path)
    monkeypatch.setattr("capauth.tokens._pgp_sign_payload", lambda payload, base: "signature")

    result = CliRunner().invoke(
        main,
        [
            "--home",
            str(home),
            "token",
            "mint-audience",
            "--agent",
            "jarvis",
            "--audience",
            "skdashboard",
            "--scope",
            "skdashboard.read",
            "--ttl-seconds",
            "300",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Minted" in result.output
    assert not (home / "security" / "tokens").exists()


@pytest.mark.parametrize(
    "extra",
    [
        ["--ttl-seconds", "301"],
        ["--ttl-seconds", "60", "--ttl-hours", "1"],
        ["--ttl-seconds", "60", "--no-sign"],
    ],
)
def test_cli_rejects_unsafe_seconds_forms(tmp_path, extra):
    result = CliRunner().invoke(
        main,
        [
            "--home",
            str(_home(tmp_path)),
            "token",
            "mint-audience",
            "--agent",
            "jarvis",
            "--audience",
            "skdashboard",
            "--scope",
            "skdashboard.read",
            *extra,
        ],
    )
    assert result.exit_code != 0
