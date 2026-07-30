"""Tests for audience-scoped token minting (audience-mint, M1+/R4.2).

Covers the additive, backward-compatible ``TokenPayload.audience`` field plus
the ``mint_audience_token`` / ``verify_audience_token`` surface. All tests are
hermetic: they inject ``home`` via ``tmp_path`` and use ``sign=False`` so no
real gpg/FS-of-record is touched, mirroring test_tokens.py.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from capauth.tokens import (
    TokenPayload,
    TokenType,
    has_scope,
    import_token,
    issue_token,
    mint_audience_token,
    verify_audience_token,
    verify_token,
)


@pytest.fixture
def agent_home(tmp_path: Path) -> Path:
    """Create a minimal agent home with identity."""
    home = tmp_path / ".skcapstone"
    identity_dir = home / "identity"
    identity_dir.mkdir(parents=True)
    security_dir = home / "security"
    security_dir.mkdir(parents=True)

    identity = {
        "name": "TestAgent",
        "email": "test@skcapstone.local",
        "fingerprint": "AABBCCDDEE1122334455AABBCCDDEE1122334455",
        "capauth_managed": True,
    }
    (identity_dir / "identity.json").write_text(json.dumps(identity))
    return home


class TestMintAudienceToken:
    """Minting sets audience, scopes, type, and a short ttl."""

    def test_mint_sets_audience_and_scopes(self, agent_home: Path):
        token = mint_audience_token(
            home=agent_home,
            subject="chef-session",
            audience="skchat",
            scopes=["chat.read", "chat.send", "calls.join"],
            sign=False,
        )
        assert token.payload.audience == "skchat"
        assert token.payload.capabilities == ["chat.read", "chat.send", "calls.join"]
        assert token.payload.token_type == TokenType.CAPABILITY
        assert token.payload.subject == "chef-session"
        assert token.payload.token_id

    def test_mint_default_ttl_is_short(self, agent_home: Path):
        """Default ttl is one hour (the shell re-mints)."""
        token = mint_audience_token(
            home=agent_home,
            subject="s",
            audience="skcode",
            scopes=["skcode.stream"],
            sign=False,
        )
        assert token.payload.expires_at is not None
        delta = token.payload.expires_at - token.payload.issued_at
        assert 0.9 < delta.total_seconds() / 3600 < 1.1

    def test_mint_custom_ttl(self, agent_home: Path):
        token = mint_audience_token(
            home=agent_home,
            subject="s",
            audience="skchat",
            scopes=["chat.read"],
            ttl_hours=6,
            sign=False,
        )
        delta = token.payload.expires_at - token.payload.issued_at
        assert 5.9 < delta.total_seconds() / 3600 < 6.1

    def test_mint_persists_token(self, agent_home: Path):
        mint_audience_token(
            home=agent_home,
            subject="s",
            audience="skchat",
            scopes=["chat.read"],
            sign=False,
        )
        token_dir = agent_home / "security" / "tokens"
        assert token_dir.exists()
        assert len(list(token_dir.iterdir())) == 1

    def test_mint_carries_metadata(self, agent_home: Path):
        token = mint_audience_token(
            home=agent_home,
            subject="s",
            audience="skchat",
            scopes=["chat.read"],
            metadata={"module": "skchat", "grade": "A"},
            sign=False,
        )
        assert token.payload.metadata["module"] == "skchat"

    def test_mint_has_scope(self, agent_home: Path):
        token = mint_audience_token(
            home=agent_home,
            subject="s",
            audience="skcode",
            scopes=["skcode.stream", "skcode.inject"],
            sign=False,
        )
        assert has_scope(token, "skcode.stream")
        assert has_scope(token, "skcode.inject")
        assert not has_scope(token, "skcode.dispatch")


class TestVerifyAudienceToken:
    """verify_audience_token = verify_token PLUS audience match, fail-closed."""

    def test_passes_on_matching_audience(self, agent_home, monkeypatch):
        """When the signature/validity half passes, a matching audience passes."""
        token = mint_audience_token(
            home=agent_home,
            subject="s",
            audience="skchat",
            scopes=["chat.read"],
            sign=False,
        )
        # Stub the signature/validity half so we isolate the audience gate.
        monkeypatch.setattr("capauth.tokens.verify_token", lambda t, h=None: True)
        assert verify_audience_token(token, "skchat", home=agent_home)

    def test_fails_on_mismatched_audience(self, agent_home, monkeypatch):
        """A mismatched audience fails even if the signature is valid."""
        token = mint_audience_token(
            home=agent_home,
            subject="s",
            audience="skchat",
            scopes=["chat.read"],
            sign=False,
        )
        monkeypatch.setattr("capauth.tokens.verify_token", lambda t, h=None: True)
        assert not verify_audience_token(token, "skcode", home=agent_home)

    def test_fails_on_unscoped_token(self, agent_home, monkeypatch):
        """A legacy unscoped token (audience None) fails when audience required."""
        token = issue_token(
            home=agent_home,
            subject="s",
            capabilities=["chat.read"],
            sign=False,
        )
        assert token.payload.audience is None
        monkeypatch.setattr("capauth.tokens.verify_token", lambda t, h=None: True)
        assert not verify_audience_token(token, "skchat", home=agent_home)

    def test_fails_closed_when_signature_invalid(self, agent_home):
        """Even with a matching audience, an unsigned token fails verify_token."""
        token = mint_audience_token(
            home=agent_home,
            subject="s",
            audience="skchat",
            scopes=["chat.read"],
            sign=False,
        )
        # No signature present, real verify_token returns False -> fail closed.
        assert not verify_audience_token(token, "skchat", home=agent_home)


class TestBackwardCompat:
    """The audience field is additive and must not break legacy tokens."""

    def test_issue_token_has_none_audience(self, agent_home: Path):
        """A token minted without audience defaults to None and verifies via verify_token path."""
        token = issue_token(
            home=agent_home,
            subject="s",
            capabilities=["memory:read"],
            sign=False,
        )
        assert token.payload.audience is None
        # verify_token still governs it (unsigned -> False, but no exception).
        assert verify_token(token, agent_home) is False

    def test_legacy_id_unchanged_without_audience(self, agent_home: Path):
        """token_id for an unscoped token must match the pre-audience hash.

        The hash is issuer|subject|sorted(capabilities)|issued_at|type. Setting
        audience only folds into the id when non-None, so a None-audience token
        hashes identically to a legacy token with the same fields.
        """
        from capauth.tokens import _compute_token_id

        payload = TokenPayload(
            token_id="",
            token_type=TokenType.CAPABILITY,
            issuer="FP",
            subject="target",
            capabilities=["b", "a"],
        )
        legacy_expected = _compute_token_id(payload)

        # Recompute the id the pre-audience way (audience key absent from hash).
        import hashlib

        content = json.dumps(
            {
                "issuer": "FP",
                "subject": "target",
                "capabilities": ["a", "b"],
                "issued_at": payload.issued_at.isoformat(),
                "type": "capability",
            },
            sort_keys=True,
        )
        assert legacy_expected == hashlib.sha256(content.encode()).hexdigest()

    def test_audience_changes_id_when_set(self):
        """Two payloads identical but for audience get distinct ids."""
        from capauth.tokens import _compute_token_id

        base = dict(
            token_id="",
            token_type=TokenType.CAPABILITY,
            issuer="FP",
            subject="target",
            capabilities=["a"],
        )
        p_none = TokenPayload(**base)
        p_aud = TokenPayload(**base, audience="skchat")
        # Same issued_at is required for a fair comparison.
        p_aud.issued_at = p_none.issued_at
        assert _compute_token_id(p_none) != _compute_token_id(p_aud)

    def test_legacy_exported_json_without_audience_imports(self):
        """A previously-exported token JSON with no 'audience' key still imports."""
        legacy_json = json.dumps(
            {
                "skcapstone_token": "1.0",
                "payload": {
                    "token_id": "deadbeef",
                    "token_type": "capability",
                    "issuer": "FP",
                    "subject": "legacy-subject",
                    "capabilities": ["memory:read", "sync:pull"],
                    "issued_at": "2026-01-01T00:00:00+00:00",
                    "expires_at": None,
                    "not_before": None,
                    "metadata": {},
                },
                "signature": None,
            }
        )
        token = import_token(legacy_json)
        assert token.payload.subject == "legacy-subject"
        assert token.payload.audience is None
        assert token.payload.capabilities == ["memory:read", "sync:pull"]
