"""Tests for the capability token issuance system."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from capauth.tokens import (
    TokenPayload,
    TokenType,
    export_token,
    import_token,
    is_revoked,
    issue_token,
    list_tokens,
    revoke_token,
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


class TestTokenPayload:
    """Tests for the TokenPayload model."""

    def test_default_payload_is_active(self):
        """Fresh token should be active."""
        payload = TokenPayload(
            token_id="abc123",
            token_type=TokenType.CAPABILITY,
            issuer="fingerprint",
            subject="target",
            capabilities=["memory:read"],
        )
        assert payload.is_active
        assert not payload.is_expired

    def test_expired_payload(self):
        """Expired token should be inactive."""
        payload = TokenPayload(
            token_id="abc123",
            token_type=TokenType.CAPABILITY,
            issuer="fp",
            subject="target",
            capabilities=["*"],
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        assert payload.is_expired
        assert not payload.is_active

    def test_not_before_payload(self):
        """Token with future not_before should be inactive."""
        payload = TokenPayload(
            token_id="abc123",
            token_type=TokenType.CAPABILITY,
            issuer="fp",
            subject="target",
            capabilities=["*"],
            not_before=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        assert not payload.is_active

    def test_has_capability_exact(self):
        """Token should grant exact capability match."""
        payload = TokenPayload(
            token_id="abc",
            token_type=TokenType.CAPABILITY,
            issuer="fp",
            subject="target",
            capabilities=["memory:read", "sync:push"],
        )
        assert payload.has_capability("memory:read")
        assert payload.has_capability("sync:push")
        assert not payload.has_capability("memory:write")

    def test_has_capability_wildcard(self):
        """Token with ALL capability should grant everything."""
        payload = TokenPayload(
            token_id="abc",
            token_type=TokenType.CAPABILITY,
            issuer="fp",
            subject="target",
            capabilities=["*"],
        )
        assert payload.has_capability("memory:read")
        assert payload.has_capability("anything:here")


class TestTokenIssuance:
    """Tests for issuing and storing tokens."""

    def test_issue_creates_token(self, agent_home: Path):
        """Issue should create a token with correct fields."""
        token = issue_token(
            home=agent_home,
            subject="partner-agent",
            capabilities=["memory:read", "sync:pull"],
            sign=False,
        )
        assert token.payload.subject == "partner-agent"
        assert "memory:read" in token.payload.capabilities
        assert token.payload.issuer == "AABBCCDDEE1122334455AABBCCDDEE1122334455"
        assert token.payload.token_id

    def test_issue_stores_token(self, agent_home: Path):
        """Issued tokens should be persisted to disk."""
        issue_token(
            home=agent_home,
            subject="test",
            capabilities=["*"],
            sign=False,
        )
        token_dir = agent_home / "security" / "tokens"
        assert token_dir.exists()
        assert len(list(token_dir.iterdir())) == 1

    def test_issue_with_ttl(self, agent_home: Path):
        """Token with TTL should have expiry set."""
        token = issue_token(
            home=agent_home,
            subject="test",
            capabilities=["*"],
            ttl_hours=48,
            sign=False,
        )
        assert token.payload.expires_at is not None
        delta = token.payload.expires_at - token.payload.issued_at
        assert 47 < delta.total_seconds() / 3600 < 49

    def test_issue_no_expiry(self, agent_home: Path):
        """Token with ttl_hours=None should never expire."""
        token = issue_token(
            home=agent_home,
            subject="test",
            capabilities=["*"],
            ttl_hours=None,
            sign=False,
        )
        assert token.payload.expires_at is None
        assert not token.payload.is_expired

    def test_issue_with_metadata(self, agent_home: Path):
        """Token can carry custom metadata."""
        token = issue_token(
            home=agent_home,
            subject="test",
            capabilities=["*"],
            metadata={"platform": "cursor", "version": "0.1.0"},
            sign=False,
        )
        assert token.payload.metadata["platform"] == "cursor"


class TestTokenVerification:
    """Tests for token verification."""

    def test_unsigned_token_fails_verification(self, agent_home: Path):
        """Unsigned tokens should fail verification."""
        token = issue_token(
            home=agent_home,
            subject="test",
            capabilities=["*"],
            sign=False,
        )
        assert not verify_token(token, agent_home)

    def test_expired_token_fails_verification(self, agent_home: Path):
        """Expired tokens should fail verification."""
        token = issue_token(
            home=agent_home,
            subject="test",
            capabilities=["*"],
            ttl_hours=0,
            sign=False,
        )
        token.payload.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        assert not verify_token(token, agent_home)


class TestTokenRevocation:
    """Tests for token revocation."""

    def test_revoke_token(self, agent_home: Path):
        """Revoking a token should add it to the revocation list."""
        token = issue_token(
            home=agent_home,
            subject="test",
            capabilities=["*"],
            sign=False,
        )
        assert not is_revoked(agent_home, token.payload.token_id)
        revoke_token(agent_home, token.payload.token_id)
        assert is_revoked(agent_home, token.payload.token_id)

    def test_revoke_creates_file(self, agent_home: Path):
        """Revocation should create the revoked-tokens.json file."""
        revoke_token(agent_home, "fake-token-id")
        revoked_file = agent_home / "security" / "revoked-tokens.json"
        assert revoked_file.exists()

    def test_revoke_idempotent(self, agent_home: Path):
        """Revoking the same token twice should work."""
        assert revoke_token(agent_home, "same-id")
        assert revoke_token(agent_home, "same-id")


class TestTokenListAndExport:
    """Tests for listing and exporting tokens."""

    def test_list_tokens_empty(self, agent_home: Path):
        """Empty token store should return empty list."""
        assert list_tokens(agent_home) == []

    def test_list_tokens_returns_issued(self, agent_home: Path):
        """Listed tokens should include all issued tokens."""
        issue_token(home=agent_home, subject="a", capabilities=["*"], sign=False)
        issue_token(home=agent_home, subject="b", capabilities=["memory:read"], sign=False)
        tokens = list_tokens(agent_home)
        assert len(tokens) == 2

    def test_export_import_roundtrip(self, agent_home: Path):
        """Exported token should be importable."""
        original = issue_token(
            home=agent_home,
            subject="roundtrip",
            capabilities=["memory:read", "sync:push"],
            sign=False,
        )
        exported = export_token(original)
        imported = import_token(exported)
        assert imported.payload.subject == "roundtrip"
        assert imported.payload.capabilities == ["memory:read", "sync:push"]
        assert imported.payload.token_id == original.payload.token_id

    def test_import_invalid_json(self):
        """Invalid JSON should raise ValueError."""
        with pytest.raises(ValueError):
            import_token("not json")

    def test_import_wrong_format(self):
        """Non-token JSON should raise ValueError."""
        with pytest.raises(ValueError):
            import_token('{"foo": "bar"}')
