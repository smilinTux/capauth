"""``store=False`` on the mint path (card e793b6bc).

Audience tokens are self-contained: they are verified by signature, never looked
up in the token store. Writing one file per mint is therefore pointless, and it
was the substrate of the 38k-file operator-audience flood. ``store=False`` lets a
caller mint a token without persisting it. The default stays ``store=True`` so
nothing else changes.
"""

from __future__ import annotations

from pathlib import Path

from capauth.tokens import issue_token, mint_audience_token


def _home(tmp_path: Path) -> Path:
    home = tmp_path / ".skcapstone"
    (home / "identity").mkdir(parents=True, exist_ok=True)
    (home / "identity" / "identity.json").write_text(
        '{"name":"t","fingerprint":"AABBCCDDEE1122334455","capauth_managed":true}',
        encoding="utf-8",
    )
    return home


def _stored(home: Path) -> list:
    token_dir = home / "security" / "tokens"
    return list(token_dir.glob("*.json")) if token_dir.is_dir() else []


def test_issue_token_store_false_writes_no_file(tmp_path):
    home = _home(tmp_path)
    tok = issue_token(home, "operator:x", ["skchat.inbox"], sign=False, store=False)
    assert tok.payload.token_id  # a real token is still returned
    assert _stored(home) == []


def test_issue_token_default_still_stores(tmp_path):
    home = _home(tmp_path)
    issue_token(home, "operator:x", ["skchat.inbox"], sign=False)
    assert len(_stored(home)) == 1


def test_mint_audience_token_store_false_writes_no_file(tmp_path):
    home = _home(tmp_path)
    tok = mint_audience_token(
        home=home,
        subject="operator:x",
        audience="skchat",
        scopes=["chat.read"],
        sign=False,
        store=False,
    )
    assert tok.payload.audience == "skchat"
    assert _stored(home) == []


def test_mint_audience_token_default_still_stores(tmp_path):
    home = _home(tmp_path)
    mint_audience_token(
        home=home,
        subject="operator:x",
        audience="skchat",
        scopes=["chat.read"],
        sign=False,
    )
    assert len(_stored(home)) == 1
