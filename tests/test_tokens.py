"""Tests for the capability token issuance system."""

from __future__ import annotations

import json
import secrets
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from capauth.tokens import (
    TokenPayload,
    TokenSigningError,
    TokenType,
    export_token,
    import_token,
    is_revoked,
    issue_token,
    list_tokens,
    revoke_token,
    signature_verifies,
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

    def test_verify_token_rejects_revoked_token(self, agent_home: Path, monkeypatch):
        """CR-3.4 P2: a signed, in-window token that has been REVOKED must fail
        verify_token (previously only the PDP consulted the revocation list)."""
        token = issue_token(
            home=agent_home,
            subject="test",
            capabilities=["*"],
            sign=False,
        )
        # Give it a passing signature (isolate the revocation gate from PGP).
        token.signature = "-----BEGIN PGP SIGNATURE-----\nstub\n-----END PGP SIGNATURE-----"
        monkeypatch.setattr("capauth.tokens._pgp_verify_signature", lambda p, s, h=None: True)
        # Not revoked yet -> passes.
        assert verify_token(token, agent_home) is True
        # Revoke it -> now rejected even though signature + time window are fine.
        revoke_token(agent_home, token.payload.token_id)
        assert verify_token(token, agent_home) is False

    def test_verify_token_passes_non_revoked_token(self, agent_home: Path, monkeypatch):
        """CR-3.4 P2: the revocation gate does not disturb a normal (non-revoked)
        token: a signed, in-window, unrevoked token still verifies."""
        token = issue_token(
            home=agent_home,
            subject="test",
            capabilities=["*"],
            sign=False,
        )
        token.signature = "-----BEGIN PGP SIGNATURE-----\nstub\n-----END PGP SIGNATURE-----"
        monkeypatch.setattr("capauth.tokens._pgp_verify_signature", lambda p, s, h=None: True)
        assert is_revoked(agent_home, token.payload.token_id) is False
        assert verify_token(token, agent_home) is True

    def test_verify_audience_token_rejects_revoked(self, agent_home: Path, monkeypatch):
        """CR-3.4 P2: revocation flows through verify_audience_token too (the
        skchat accept path), so a revoked audience token is rejected there."""
        from capauth.tokens import mint_audience_token, verify_audience_token

        token = mint_audience_token(
            home=agent_home,
            subject="operator:abc123",
            audience="skchat",
            scopes=["chat.read", "chat.send"],
            sign=False,
        )
        token.signature = "-----BEGIN PGP SIGNATURE-----\nstub\n-----END PGP SIGNATURE-----"
        monkeypatch.setattr("capauth.tokens._pgp_verify_signature", lambda p, s, h=None: True)
        assert verify_audience_token(token, "skchat", home=agent_home) is True
        revoke_token(agent_home, token.payload.token_id)
        assert verify_audience_token(token, "skchat", home=agent_home) is False


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


# ── signing invocation (regression: tokens were silently never signed) ────


def test_sign_payload_does_not_force_an_empty_passphrase_first(monkeypatch, tmp_path):
    """The FIRST gpg attempt must let gpg-agent mediate.

    Forcing ``--passphrase "" --pinentry-mode loopback`` makes gpg refuse an
    agent-managed key with "No passphrase given" rather than consulting the
    agent. That was the only invocation for a long time, so every token this
    fleet issued came out unsigned regardless of which key was configured, and
    nothing noticed because issue_token downgrades a signing failure to a
    warning and stores the token anyway.
    """
    from capauth import tokens as tok

    calls = []

    class _Result:
        returncode = 0
        stdout = "-----BEGIN PGP SIGNATURE-----\nx\n-----END PGP SIGNATURE-----\n"
        stderr = ""

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return _Result()

    monkeypatch.setattr(tok.shutil, "which", lambda _n: "/usr/bin/gpg")
    monkeypatch.delenv("CAPAUTH_GPG_PASSPHRASE_FILE", raising=False)
    monkeypatch.setattr(tok.subprocess, "run", fake_run)
    monkeypatch.setattr(tok, "_get_issuer_fingerprint", lambda _h: "DEADBEEF")

    payload = tok.TokenPayload(
        token_id="t",
        token_type=tok.TokenType.CAPABILITY,
        issuer="DEADBEEF",
        subject="probe@example.org",
        capabilities=["x"],
    )
    sig = tok._pgp_sign_payload(payload, tmp_path)

    assert sig is not None
    assert len(calls) == 1, "a working first attempt must not fall through"
    assert "--passphrase" not in calls[0]
    assert "loopback" not in calls[0]


def test_sign_payload_falls_back_to_loopback_when_the_agent_path_fails(monkeypatch, tmp_path):
    """A passphrase-less key with no usable agent (CI, cold bootstrap) still signs."""
    from capauth import tokens as tok

    calls = []

    class _Fail:
        returncode = 2
        stdout = ""
        stderr = "gpg: signing failed: No pinentry"

    class _Ok:
        returncode = 0
        stdout = "-----BEGIN PGP SIGNATURE-----\ny\n-----END PGP SIGNATURE-----\n"
        stderr = ""

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return _Fail() if len(calls) == 1 else _Ok()

    monkeypatch.setattr(tok.shutil, "which", lambda _n: "/usr/bin/gpg")
    monkeypatch.delenv("CAPAUTH_GPG_PASSPHRASE_FILE", raising=False)
    monkeypatch.setattr(tok.subprocess, "run", fake_run)
    monkeypatch.setattr(tok, "_get_issuer_fingerprint", lambda _h: "DEADBEEF")

    payload = tok.TokenPayload(
        token_id="t",
        token_type=tok.TokenType.CAPABILITY,
        issuer="DEADBEEF",
        subject="probe@example.org",
        capabilities=["x"],
    )
    sig = tok._pgp_sign_payload(payload, tmp_path)

    assert sig is not None
    assert len(calls) == 2
    assert "loopback" in calls[1]


def test_sign_payload_returns_none_when_every_attempt_fails(monkeypatch, tmp_path):
    """Signing failure must stay non-fatal, but must not invent a signature."""
    from capauth import tokens as tok

    class _Fail:
        returncode = 2
        stdout = ""
        stderr = "gpg: signing failed: No secret key"

    monkeypatch.setattr(tok.shutil, "which", lambda _n: "/usr/bin/gpg")
    monkeypatch.delenv("CAPAUTH_GPG_PASSPHRASE_FILE", raising=False)
    monkeypatch.setattr(tok.subprocess, "run", lambda cmd, **kw: _Fail())
    monkeypatch.setattr(tok, "_get_issuer_fingerprint", lambda _h: "DEADBEEF")

    payload = tok.TokenPayload(
        token_id="t",
        token_type=tok.TokenType.CAPABILITY,
        issuer="DEADBEEF",
        subject="probe@example.org",
        capabilities=["x"],
    )
    assert tok._pgp_sign_payload(payload, tmp_path) is None


def test_configured_passphrase_file_is_the_only_attempt_and_never_enters_logs(
    monkeypatch, tmp_path, caplog
):
    """A valid file uses one loopback attempt without exposing its contents."""
    from capauth import tokens as tok

    synthetic_secret = secrets.token_urlsafe(24)
    passphrase_file = tmp_path / "synthetic-passphrase"
    passphrase_file.write_text(synthetic_secret, encoding="utf-8")
    passphrase_file.chmod(0o600)
    calls = []

    class _Result:
        returncode = 0
        stdout = "-----BEGIN PGP SIGNATURE-----\nx\n-----END PGP SIGNATURE-----\n"
        stderr = ""

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return _Result()

    monkeypatch.setenv("CAPAUTH_GPG_PASSPHRASE_FILE", str(passphrase_file))
    monkeypatch.setattr(tok.shutil, "which", lambda _n: "/usr/bin/gpg")
    monkeypatch.setattr(tok.subprocess, "run", fake_run)
    monkeypatch.setattr(tok, "_get_issuer_fingerprint", lambda _h: "DEADBEEF")
    payload = tok.TokenPayload(
        token_id="t",
        token_type=tok.TokenType.CAPABILITY,
        issuer="DEADBEEF",
        subject="probe@example.org",
        capabilities=["x"],
    )

    assert tok._pgp_sign_payload(payload, tmp_path) is not None
    assert len(calls) == 1
    assert "--passphrase-file" in calls[0]
    assert "loopback" in calls[0]
    assert synthetic_secret not in " ".join(calls[0])
    assert synthetic_secret not in caplog.text


def test_configured_passphrase_failure_never_logs_gpg_stderr(monkeypatch, tmp_path, caplog):
    """Even adversarial subprocess output cannot copy a passphrase into logs."""
    from capauth import tokens as tok

    synthetic_secret = secrets.token_urlsafe(24)
    passphrase_file = tmp_path / "synthetic-passphrase"
    passphrase_file.write_text(synthetic_secret, encoding="utf-8")
    passphrase_file.chmod(0o600)

    class _Failure:
        returncode = 2
        stdout = ""
        stderr = f"gpg repeated sensitive input: {synthetic_secret}"

    monkeypatch.setenv("CAPAUTH_GPG_PASSPHRASE_FILE", str(passphrase_file))
    monkeypatch.setattr(tok.shutil, "which", lambda _n: "/usr/bin/gpg")
    monkeypatch.setattr(tok.subprocess, "run", lambda *_a, **_k: _Failure())
    monkeypatch.setattr(tok, "_get_issuer_fingerprint", lambda _h: "DEADBEEF")
    payload = tok.TokenPayload(
        token_id="t",
        token_type=tok.TokenType.CAPABILITY,
        issuer="DEADBEEF",
        subject="probe@example.org",
        capabilities=["x"],
    )

    assert tok._pgp_sign_payload(payload, tmp_path) is None
    assert synthetic_secret not in caplog.text
    assert str(passphrase_file) not in caplog.text
    assert "gpg exited 2" in caplog.text


@pytest.mark.parametrize("invalid_kind", ["missing", "insecure", "empty", "symlink"])
def test_invalid_configured_passphrase_file_fails_before_gpg(
    monkeypatch, tmp_path, agent_home, invalid_kind, caplog
):
    """Any configured but unusable secret file leaves issuance unavailable."""
    from capauth import tokens as tok

    synthetic_secret = secrets.token_urlsafe(24)
    passphrase_file = tmp_path / "synthetic-passphrase"
    if invalid_kind == "missing":
        pass
    elif invalid_kind == "insecure":
        passphrase_file.write_text(synthetic_secret, encoding="utf-8")
        passphrase_file.chmod(0o640)
    elif invalid_kind == "empty":
        passphrase_file.touch(mode=0o600)
    else:
        target = tmp_path / "synthetic-target"
        target.write_text(synthetic_secret, encoding="utf-8")
        target.chmod(0o600)
        passphrase_file.symlink_to(target)

    monkeypatch.setenv("CAPAUTH_GPG_PASSPHRASE_FILE", str(passphrase_file))
    monkeypatch.setattr(tok.shutil, "which", lambda _n: "/usr/bin/gpg")
    monkeypatch.setattr(
        tok.subprocess,
        "run",
        lambda *_a, **_k: pytest.fail("invalid passphrase file must fail before gpg"),
    )

    with pytest.raises(tok.TokenSigningError):
        tok.issue_token(agent_home, "probe@example.org", ["x"], sign=True)

    token_dir = agent_home / "security" / "tokens"
    assert not token_dir.exists() or not list(token_dir.iterdir())
    assert synthetic_secret not in caplog.text
    assert str(passphrase_file) not in caplog.text


@pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg is required for synthetic signing")
def test_synthetic_protected_key_signs_then_insecure_mode_fails(
    monkeypatch, tmp_path, agent_home, caplog
):
    """A real protected key proves success and a mode change proves sensitivity."""
    gnupg_home = tmp_path / "gnupg"
    gnupg_home.mkdir(mode=0o700)
    monkeypatch.setenv("GNUPGHOME", str(gnupg_home))
    synthetic_secret = secrets.token_urlsafe(24)
    passphrase_file = tmp_path / "synthetic-passphrase"
    passphrase_file.write_text(synthetic_secret, encoding="utf-8")
    passphrase_file.chmod(0o600)
    monkeypatch.setenv("CAPAUTH_GPG_PASSPHRASE_FILE", str(passphrase_file))
    uid = "CapAuth Passphrase File Test <passphrase-file@capauth.local>"
    subprocess.run(
        [
            "gpg",
            "--batch",
            "--quiet",
            "--pinentry-mode",
            "loopback",
            "--passphrase-file",
            str(passphrase_file),
            "--quick-generate-key",
            uid,
            "ed25519",
            "sign",
            "1d",
        ],
        capture_output=True,
        check=True,
        timeout=60,
    )
    listing = subprocess.run(
        ["gpg", "--batch", "--with-colons", "--list-secret-keys", uid],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    fingerprint = next(
        line.split(":")[9] for line in listing.stdout.splitlines() if line.startswith("fpr:")
    )
    identity_path = agent_home / "identity" / "identity.json"
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    identity["fingerprint"] = fingerprint
    identity_path.write_text(json.dumps(identity), encoding="utf-8")

    try:
        token = issue_token(agent_home, "probe@example.org", ["x"], sign=True, store=False)
        assert token.signature
        assert signature_verifies(token) is True

        passphrase_file.chmod(0o640)
        with pytest.raises(TokenSigningError):
            issue_token(agent_home, "probe@example.org", ["x"], sign=True, store=False)
        assert synthetic_secret not in caplog.text
    finally:
        subprocess.run(
            ["gpgconf", "--homedir", str(gnupg_home), "--kill", "gpg-agent"],
            capture_output=True,
            timeout=30,
        )
