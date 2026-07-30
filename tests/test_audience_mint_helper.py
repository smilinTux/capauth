"""Tests for the ergonomic agent audience-mint wrapper + CLI.

Covers ``capauth.tokens.mint_agent_audience_token`` (resolves subject from the
agent's identity, defaults scopes per audience) and the ``capauth token
mint-audience`` CLI command.

All tests are hermetic: ``home`` is injected via ``tmp_path``, ``sign=False`` so
no real gpg is touched, and the identity resolver is monkeypatched to a known
fqid so no real ``cluster.json`` / ``~/.skcapstone`` is read. The
signature/validity half of ``verify_audience_token`` is stubbed exactly as
test_audience_tokens.py does, isolating the audience gate.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from capauth.agent_identity import AgentIdentity
from capauth.cli import main
from capauth.tokens import (
    AUDIENCE_SCOPES,
    import_token,
    mint_agent_audience_token,
    verify_audience_token,
)

RESOLVED_FQID = "testagent@chef.skworld"


@pytest.fixture
def agent_home(tmp_path: Path) -> Path:
    """A minimal agent home with an identity (no gpg needed)."""
    home = tmp_path / ".skcapstone"
    identity_dir = home / "identity"
    identity_dir.mkdir(parents=True)
    (home / "security").mkdir(parents=True)
    identity = {
        "name": "TestAgent",
        "email": "test@skcapstone.local",
        "fingerprint": "AABBCCDDEE1122334455AABBCCDDEE1122334455",
        "capauth_managed": True,
    }
    (identity_dir / "identity.json").write_text(json.dumps(identity))
    return home


@pytest.fixture
def stub_identity(monkeypatch) -> AgentIdentity:
    """Resolve any agent to a known fqid so subject assertions are hermetic."""
    ident = AgentIdentity(
        agent="testagent",
        capauth_uri="capauth:testagent@skworld.io",
        fqid=RESOLVED_FQID,
        fingerprint=None,
    )
    monkeypatch.setattr("capauth.tokens.resolve_agent_identity", lambda a=None: ident)
    return ident


class TestMintAgentAudienceToken:
    def test_subject_is_resolved_fqid(self, agent_home, stub_identity):
        tok = mint_agent_audience_token(
            agent="testagent", audience="skchat", home=agent_home, sign=False
        )
        assert tok.payload.subject == RESOLVED_FQID

    def test_audience_and_default_scopes(self, agent_home, stub_identity):
        tok = mint_agent_audience_token(
            agent="testagent", audience="skchat", home=agent_home, sign=False
        )
        assert tok.payload.audience == "skchat"
        assert tok.payload.capabilities == AUDIENCE_SCOPES["skchat"]
        assert tok.payload.capabilities == [
            "chat.read",
            "chat.send",
            "calls.join",
            "spaces.join",
        ]

    def test_verify_audience_token_accepts(self, agent_home, stub_identity, monkeypatch):
        tok = mint_agent_audience_token(
            agent="testagent", audience="skchat", home=agent_home, sign=False
        )
        # Stub the signature/validity half; isolate the audience gate (hermetic).
        monkeypatch.setattr("capauth.tokens.verify_token", lambda t, h=None: True)
        assert verify_audience_token(tok, "skchat", home=agent_home)

    def test_explicit_scopes_override_default(self, agent_home, stub_identity):
        tok = mint_agent_audience_token(
            agent="testagent",
            audience="skchat",
            scopes=["chat.read"],
            home=agent_home,
            sign=False,
        )
        assert tok.payload.capabilities == ["chat.read"]

    def test_different_audience_honored(self, agent_home, stub_identity):
        tok = mint_agent_audience_token(
            agent="testagent",
            audience="skcode",
            scopes=["skcode.stream"],
            home=agent_home,
            sign=False,
        )
        assert tok.payload.audience == "skcode"
        assert tok.payload.capabilities == ["skcode.stream"]

    def test_skcode_default_scopes(self, agent_home, stub_identity):
        """skcode resolves its manifest-grounded default scopes with no scopes arg."""
        tok = mint_agent_audience_token(
            agent="testagent", audience="skcode", home=agent_home, sign=False
        )
        assert tok.payload.audience == "skcode"
        assert tok.payload.capabilities == AUDIENCE_SCOPES["skcode"]
        assert tok.payload.capabilities == [
            "skcode.stream",
            "skcode.inject",
            "skcode.dispatch",
        ]

    @pytest.mark.parametrize(
        "audience,expected",
        [
            ("skcomms", ["skcomms.read"]),
            ("skos", ["skos.read"]),
            ("skmemory", ["skmemory.read"]),
        ],
    )
    def test_provisional_audiences_default_scopes(
        self, agent_home, stub_identity, audience, expected
    ):
        """skcomms/skos/skmemory each mint with their provisional read scope."""
        tok = mint_agent_audience_token(
            agent="testagent", audience=audience, home=agent_home, sign=False
        )
        assert tok.payload.audience == audience
        assert tok.payload.capabilities == expected
        assert tok.payload.capabilities == AUDIENCE_SCOPES[audience]

    def test_explicit_scopes_override_new_audience(self, agent_home, stub_identity):
        """An explicit scopes arg still overrides the default for a new audience."""
        tok = mint_agent_audience_token(
            agent="testagent",
            audience="skmemory",
            scopes=["skmemory.read", "skmemory.write"],
            home=agent_home,
            sign=False,
        )
        assert tok.payload.capabilities == ["skmemory.read", "skmemory.write"]

    def test_unknown_audience_without_scopes_raises(self, agent_home, stub_identity):
        with pytest.raises(ValueError):
            mint_agent_audience_token(
                agent="testagent", audience="mystery", home=agent_home, sign=False
            )

    def test_default_ttl_is_one_hour(self, agent_home, stub_identity):
        tok = mint_agent_audience_token(
            agent="testagent", audience="skchat", home=agent_home, sign=False
        )
        delta = tok.payload.expires_at - tok.payload.issued_at
        assert 0.9 < delta.total_seconds() / 3600 < 1.1


class TestMintAudienceCLI:
    def test_prints_token_id(self, agent_home, stub_identity):
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["--home", str(agent_home), "token", "mint-audience", "--agent", "testagent",
             "--audience", "skchat", "--no-sign"],
        )
        assert result.exit_code == 0, result.output
        assert "Minted" in result.output
        assert RESOLVED_FQID in result.output

    def test_export_wire_roundtrips(self, agent_home, stub_identity, monkeypatch):
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["--home", str(agent_home), "token", "mint-audience", "--agent", "testagent",
             "--audience", "skchat", "--no-sign", "--export"],
        )
        assert result.exit_code == 0, result.output
        # The wire form is the last non-empty output line (plain click.echo).
        wire = result.output.strip().splitlines()[-1].strip()
        assert wire
        decoded = base64.urlsafe_b64decode(wire.encode("ascii")).decode("utf-8")
        tok = import_token(decoded)
        assert tok.payload.audience == "skchat"
        assert tok.payload.subject == RESOLVED_FQID
        monkeypatch.setattr("capauth.tokens.verify_token", lambda t, h=None: True)
        assert verify_audience_token(tok, "skchat", home=agent_home)

    def test_scope_flags_override(self, agent_home, stub_identity):
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["--home", str(agent_home), "token", "mint-audience", "--agent", "testagent",
             "--audience", "skchat", "--scope", "chat.read", "--scope", "chat.send",
             "--no-sign"],
        )
        assert result.exit_code == 0, result.output
        assert "chat.read, chat.send" in result.output
        assert "calls.join" not in result.output
