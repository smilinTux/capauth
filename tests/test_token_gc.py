"""Garbage collection for the token store.

``_store_token`` writes one file per issued token and nothing ever prunes them.
A short-TTL, high-rate mint path (the per-request operator-audience token) floods
``home/security/tokens`` (observed: 38k files / 153MB, all expired, none read).
``prune_expired_tokens`` removes the expired debris; a valid or non-expiring token
is kept, and an unreadable file is left alone (it may be a mid-write).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from capauth.tokens import (
    SignedToken,
    TokenPayload,
    TokenType,
    _store_token,
    prune_expired_tokens,
)


def _home(tmp_path: Path) -> Path:
    home = tmp_path / ".skcapstone"
    (home / "identity").mkdir(parents=True, exist_ok=True)
    return home


def _store(home: Path, subject: str, expires_at) -> None:
    payload = TokenPayload(
        token_id="",
        token_type=TokenType.CAPABILITY,
        issuer="AABB",
        subject=subject,
        capabilities=["skchat.inbox"],
        expires_at=expires_at,
    )
    # A distinct token_id per subject so files do not collide.
    from capauth.tokens import _compute_token_id

    payload.token_id = _compute_token_id(payload)
    _store_token(home, SignedToken(payload=payload))


def test_prune_removes_expired_keeps_valid_and_non_expiring(tmp_path):
    home = _home(tmp_path)
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    _store(home, "operator:expired", past)
    _store(home, "operator:valid", future)
    _store(home, "operator:forever", None)

    removed = prune_expired_tokens(home)

    assert removed == 1
    remaining = {p.name for p in (home / "security" / "tokens").glob("*.json")}
    assert len(remaining) == 2  # valid + non-expiring kept


def test_prune_empty_or_missing_store_returns_zero(tmp_path):
    home = _home(tmp_path)
    assert prune_expired_tokens(home) == 0  # no tokens dir yet


def test_prune_leaves_an_unparseable_file_alone(tmp_path):
    home = _home(tmp_path)
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    _store(home, "operator:expired", past)
    token_dir = home / "security" / "tokens"
    (token_dir / "garbage.json").write_text("{ not valid json", encoding="utf-8")

    removed = prune_expired_tokens(home)

    assert removed == 1  # only the expired token, not the garbage file
    assert (token_dir / "garbage.json").exists()
