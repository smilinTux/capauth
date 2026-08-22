"""Tests for capauth.agent_identity — T1/T2 resolver.

Covers:
    - AgentIdentity dataclass basics
    - resolve_agent_identity with explicit agent name
    - resolve_agent_identity auto-resolution from env vars
    - fqid computation from cluster.json
    - fingerprint loading from profile.json
    - graceful fallback when cluster.json / profile absent
    - T2 delegation contract: callers get both capauth_uri + fqid
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from capauth.agent_identity import (
    AgentIdentity,
    _build_fqid,
    _load_cluster,
    resolve_agent_identity,
)


@pytest.fixture(autouse=True)
def _no_live_cluster(tmp_path: Path, monkeypatch):
    """Isolate every test from the host's real cluster.json.

    ``resolve_agent_identity`` reads ``/etc/skcapstone/cluster.json`` and
    ``~/.skcapstone/cluster.json`` by default; tests must never observe live
    operator/realm state. Tests that exercise cluster loading override
    ``_CLUSTER_LOOKUP`` themselves with their own tmp fixtures.
    """
    from capauth import agent_identity

    monkeypatch.setattr(agent_identity, "_CLUSTER_LOOKUP", [tmp_path / "no-live-cluster.json"])


# ---------------------------------------------------------------------------
# AgentIdentity dataclass
# ---------------------------------------------------------------------------


class TestAgentIdentity:
    def test_uri_alias(self):
        ident = AgentIdentity(agent="lumina", capauth_uri="capauth:lumina@skworld.io")
        assert ident.uri == ident.capauth_uri

    def test_to_dict_keys(self):
        ident = AgentIdentity(
            agent="lumina",
            capauth_uri="capauth:lumina@skworld.io",
            fqid="lumina@ops.example.test",
            fingerprint="AB" * 20,
        )
        d = ident.to_dict()
        assert set(d.keys()) == {"agent", "capauth_uri", "fqid", "fingerprint"}

    def test_optional_fields_default_none(self):
        ident = AgentIdentity(agent="x", capauth_uri="capauth:x@skworld.io")
        assert ident.fqid is None
        assert ident.fingerprint is None


# ---------------------------------------------------------------------------
# _build_fqid
# ---------------------------------------------------------------------------


class TestBuildFqid:
    def test_builds_from_cluster(self):
        cluster = {"realm": "example.test", "operator": "ops"}
        assert _build_fqid("agent", cluster) == "agent@ops.example.test"

    def test_none_when_cluster_none(self):
        assert _build_fqid("agent", None) is None

    def test_none_when_realm_missing(self):
        assert _build_fqid("agent", {"operator": "ops"}) is None

    def test_none_when_operator_missing(self):
        assert _build_fqid("agent", {"realm": "example.test"}) is None


# ---------------------------------------------------------------------------
# _load_cluster
# ---------------------------------------------------------------------------


class TestLoadCluster:
    def test_loads_from_tmp(self, tmp_path: Path):
        cluster_file = tmp_path / "cluster.json"
        cluster_file.write_text(json.dumps({"realm": "example.test", "operator": "ops"}))
        from capauth import agent_identity

        original = agent_identity._CLUSTER_LOOKUP
        try:
            agent_identity._CLUSTER_LOOKUP = [cluster_file]
            data = _load_cluster()
            assert data is not None
            assert data["realm"] == "example.test"
        finally:
            agent_identity._CLUSTER_LOOKUP = original

    def test_returns_none_when_absent(self, tmp_path: Path):
        from capauth import agent_identity

        original = agent_identity._CLUSTER_LOOKUP
        try:
            agent_identity._CLUSTER_LOOKUP = [tmp_path / "nonexistent.json"]
            assert _load_cluster() is None
        finally:
            agent_identity._CLUSTER_LOOKUP = original


# ---------------------------------------------------------------------------
# resolve_agent_identity — explicit agent
# ---------------------------------------------------------------------------


class TestResolveExplicit:
    def test_capauth_uri_always_present(self):
        ident = resolve_agent_identity("testbot")
        assert ident.capauth_uri == "capauth:testbot@skworld.io"
        assert ident.agent == "testbot"

    def test_fqid_with_cluster(self, tmp_path: Path):
        cluster_file = tmp_path / "cluster.json"
        cluster_file.write_text(json.dumps({"realm": "example.test", "operator": "ops"}))
        from capauth import agent_identity

        original = agent_identity._CLUSTER_LOOKUP
        try:
            agent_identity._CLUSTER_LOOKUP = [cluster_file]
            ident = resolve_agent_identity("agent")
            assert ident.fqid == "agent@ops.example.test"
        finally:
            agent_identity._CLUSTER_LOOKUP = original

    def test_fqid_none_when_cluster_malformed(self, tmp_path: Path):
        """A corrupt cluster.json yields fqid=None, never a fabricated value."""
        bad = tmp_path / "cluster.json"
        bad.write_text("{ not: valid json,,,")
        from capauth import agent_identity

        original = agent_identity._CLUSTER_LOOKUP
        try:
            agent_identity._CLUSTER_LOOKUP = [bad]
            assert resolve_agent_identity("agent").fqid is None
        finally:
            agent_identity._CLUSTER_LOOKUP = original

    def test_fqid_none_without_cluster(self, tmp_path: Path):
        from capauth import agent_identity

        original = agent_identity._CLUSTER_LOOKUP
        try:
            agent_identity._CLUSTER_LOOKUP = [tmp_path / "no.json"]
            ident = resolve_agent_identity("lumina")
            assert ident.fqid is None
        finally:
            agent_identity._CLUSTER_LOOKUP = original

    def test_fingerprint_from_profile_json(self, tmp_path: Path):
        fake_fp = "A" * 40
        profile_dir = tmp_path / "identity"
        profile_dir.mkdir(parents=True)
        profile_json = profile_dir / "profile.json"
        profile_json.write_text(json.dumps({"key_info": {"fingerprint": fake_fp}}))
        from capauth import agent_identity

        original_fn = agent_identity._agent_capauth_dir
        try:
            agent_identity._agent_capauth_dir = lambda _a: tmp_path
            ident = resolve_agent_identity("dummy")
            assert ident.fingerprint == fake_fp
        finally:
            agent_identity._agent_capauth_dir = original_fn

    def test_fingerprint_none_when_no_profile(self, tmp_path: Path):
        from capauth import agent_identity

        original_fn = agent_identity._agent_capauth_dir
        try:
            # Point to a dir with no profile.json
            agent_identity._agent_capauth_dir = lambda _a: tmp_path / "empty"
            # Also patch skcapstone home to avoid picking up real profiles
            with patch.object(
                agent_identity,
                "SKCAPSTONE_HOME",
                tmp_path,
            ):
                ident = resolve_agent_identity("ghost")
                assert ident.fingerprint is None
        finally:
            agent_identity._agent_capauth_dir = original_fn

    def test_local_fallback_for_empty_agent(self):
        ident = resolve_agent_identity("")
        assert ident.agent == "local"
        assert ident.capauth_uri == "capauth:local@skworld.io"

    def test_template_agent_becomes_local(self):
        ident = resolve_agent_identity("lumina-template")
        assert ident.agent == "local"


# ---------------------------------------------------------------------------
# resolve_agent_identity — auto-resolution from env
# ---------------------------------------------------------------------------


class TestResolveAutoEnv:
    def test_reads_skagent_env(self):
        with patch.dict(os.environ, {"SKAGENT": "jarvis"}, clear=False):
            ident = resolve_agent_identity(None)
        assert ident.agent == "jarvis"

    def test_falls_back_to_skcapstone_agent(self):
        env = {"SKCAPSTONE_AGENT": "herald"}
        with patch.dict(os.environ, env, clear=False):
            # Remove SKAGENT to ensure legacy fallback
            env_without_skagent = {
                k: v for k, v in {**os.environ, **env}.items() if k != "SKAGENT"
            }
            with patch.dict(os.environ, env_without_skagent, clear=True):
                ident = resolve_agent_identity(None)
                assert ident.agent in ("herald", "local")  # local if skmemory returns something

    def test_local_when_no_env(self):
        # Strip all agent env vars; skmemory may or may not be installed
        env_clean = {
            k: v
            for k, v in os.environ.items()
            if k not in ("SKAGENT", "SKCAPSTONE_AGENT", "SKMEMORY_AGENT")
        }
        with patch.dict(os.environ, env_clean, clear=True):
            with patch(
                "capauth.agent_identity._resolve_active_agent_name",
                return_value=None,
            ):
                ident = resolve_agent_identity(None)
                assert ident.agent == "local"
                assert ident.capauth_uri == "capauth:local@skworld.io"


# ---------------------------------------------------------------------------
# Public __init__ re-export
# ---------------------------------------------------------------------------


class TestPublicExport:
    def test_importable_from_capauth(self):
        from capauth import AgentIdentity as AI
        from capauth import resolve_agent_identity as rai

        assert AI is AgentIdentity
        assert callable(rai)

    def test_resolve_returns_agent_identity_instance(self):
        from capauth import resolve_agent_identity as rai

        result = rai("opus")
        assert isinstance(result, AgentIdentity)
        assert result.capauth_uri == "capauth:opus@skworld.io"


# ===========================================================================
# Additional edge cases: resolver fallbacks + dual-URI corners
# ===========================================================================


class TestLoadClusterEdges:
    def test_malformed_json_returns_none(self, tmp_path: Path):
        """A corrupt cluster.json is swallowed (logged) → None, never raises."""
        bad = tmp_path / "cluster.json"
        bad.write_text("{ not: valid json,,,")
        from capauth import agent_identity

        original = agent_identity._CLUSTER_LOOKUP
        try:
            agent_identity._CLUSTER_LOOKUP = [bad]
            assert _load_cluster() is None
        finally:
            agent_identity._CLUSTER_LOOKUP = original

    def test_first_existing_path_wins(self, tmp_path: Path):
        """Lookup honours search-path order: the first existing file is used."""
        first = tmp_path / "first.json"
        second = tmp_path / "second.json"
        first.write_text(json.dumps({"realm": "alpha.test", "operator": "ops"}))
        second.write_text(json.dumps({"realm": "beta.test", "operator": "ops"}))
        from capauth import agent_identity

        original = agent_identity._CLUSTER_LOOKUP
        try:
            agent_identity._CLUSTER_LOOKUP = [first, second]
            assert _load_cluster()["realm"] == "alpha.test"
        finally:
            agent_identity._CLUSTER_LOOKUP = original

    def test_falls_through_missing_to_present(self, tmp_path: Path):
        """A missing first path is skipped; the next existing one is loaded."""
        missing = tmp_path / "nope.json"
        present = tmp_path / "present.json"
        present.write_text(json.dumps({"realm": "example.test", "operator": "ops"}))
        from capauth import agent_identity

        original = agent_identity._CLUSTER_LOOKUP
        try:
            agent_identity._CLUSTER_LOOKUP = [missing, present]
            assert _load_cluster()["operator"] == "ops"
        finally:
            agent_identity._CLUSTER_LOOKUP = original


class TestBuildFqidEdges:
    def test_empty_string_realm_is_falsy_none(self):
        """An empty realm string is treated as missing → None (no `agent@op.`)."""
        from capauth.agent_identity import _build_fqid

        assert _build_fqid("agent", {"realm": "", "operator": "ops"}) is None

    def test_empty_string_operator_is_falsy_none(self):
        from capauth.agent_identity import _build_fqid

        assert _build_fqid("agent", {"realm": "example.test", "operator": ""}) is None

    def test_agent_name_embedded(self):
        from capauth.agent_identity import _build_fqid

        assert (
            _build_fqid("jarvis", {"realm": "example.test", "operator": "ops"})
            == "jarvis@ops.example.test"
        )

    def test_arbitrary_cluster_values(self):
        """Any operator/realm pair flows through verbatim — no deployment
        assumptions baked into the builder."""
        from capauth.agent_identity import _build_fqid

        cluster = {"realm": "example.test", "operator": "fleet9"}
        assert _build_fqid("worker", cluster) == "worker@fleet9.example.test"


class TestAgentCapauthDir:
    def test_prefers_per_agent_layout(self, tmp_path: Path, monkeypatch):
        """When ~/.skcapstone/agents/<agent>/capauth exists it wins over legacy."""
        from capauth import agent_identity

        per_agent = tmp_path / "agents" / "lumina" / "capauth"
        per_agent.mkdir(parents=True)
        monkeypatch.setattr(agent_identity, "SKCAPSTONE_HOME", tmp_path)
        assert agent_identity._agent_capauth_dir("lumina") == per_agent

    def test_falls_back_to_legacy_single_agent(self, tmp_path: Path, monkeypatch):
        """No per-agent dir → legacy ~/.skcapstone/capauth path returned."""
        from capauth import agent_identity

        monkeypatch.setattr(agent_identity, "SKCAPSTONE_HOME", tmp_path)
        assert agent_identity._agent_capauth_dir("ghost") == tmp_path / "capauth"


class TestLoadFingerprintEdges:
    def _isolate(self, monkeypatch, tmp_path: Path, capauth_dir: Path):
        """Point both the capauth dir and SKCAPSTONE_HOME at scratch space."""
        from capauth import agent_identity

        monkeypatch.setattr(agent_identity, "SKCAPSTONE_HOME", tmp_path)
        monkeypatch.setattr(agent_identity, "_agent_capauth_dir", lambda _a: capauth_dir)
        return agent_identity

    def test_v6_64hex_fingerprint_accepted(self, tmp_path: Path, monkeypatch):
        """A 64-char (v6) fingerprint from profile.json is surfaced."""
        capauth_dir = tmp_path / "ca"
        (capauth_dir / "identity").mkdir(parents=True)
        fp = "C" * 64
        (capauth_dir / "identity" / "profile.json").write_text(
            json.dumps({"key_info": {"fingerprint": fp}})
        )
        ai = self._isolate(monkeypatch, tmp_path, capauth_dir)
        assert ai._load_fingerprint("dummy") == fp

    def test_wrong_length_fingerprint_rejected(self, tmp_path: Path, monkeypatch):
        """A 12-char junk fingerprint is not v4/v6 → rejected (None)."""
        capauth_dir = tmp_path / "ca"
        (capauth_dir / "identity").mkdir(parents=True)
        (capauth_dir / "identity" / "profile.json").write_text(
            json.dumps({"key_info": {"fingerprint": "DEADBEEF1234"}})
        )
        ai = self._isolate(monkeypatch, tmp_path, capauth_dir)
        assert ai._load_fingerprint("dummy") is None

    def test_malformed_profile_json_swallowed(self, tmp_path: Path, monkeypatch):
        """A corrupt profile.json doesn't raise; resolution returns None."""
        capauth_dir = tmp_path / "ca"
        (capauth_dir / "identity").mkdir(parents=True)
        (capauth_dir / "identity" / "profile.json").write_text("{bad json")
        ai = self._isolate(monkeypatch, tmp_path, capauth_dir)
        assert ai._load_fingerprint("dummy") is None

    def test_identity_json_requires_capauth_managed(self, tmp_path: Path, monkeypatch):
        """A real-looking fp in identity.json WITHOUT capauth_managed is a placeholder → None."""
        capauth_dir = tmp_path / "ca-empty"  # no profile.json here
        ai = self._isolate(monkeypatch, tmp_path, capauth_dir)
        id_dir = tmp_path / "agents" / "ghost" / "identity"
        id_dir.mkdir(parents=True)
        (id_dir / "identity.json").write_text(
            json.dumps({"fingerprint": "F" * 40})  # no capauth_managed flag
        )
        assert ai._load_fingerprint("ghost") is None

    def test_malformed_identity_json_swallowed(self, tmp_path: Path, monkeypatch):
        """A corrupt identity.json is logged and skipped → None (no raise)."""
        capauth_dir = tmp_path / "ca-empty"
        ai = self._isolate(monkeypatch, tmp_path, capauth_dir)
        id_dir = tmp_path / "agents" / "broken" / "identity"
        id_dir.mkdir(parents=True)
        (id_dir / "identity.json").write_text("{not-json")
        assert ai._load_fingerprint("broken") is None

    def test_identity_json_capauth_managed_accepted(self, tmp_path: Path, monkeypatch):
        """capauth_managed=True promotes the identity.json fingerprint to real."""
        capauth_dir = tmp_path / "ca-empty"
        ai = self._isolate(monkeypatch, tmp_path, capauth_dir)
        id_dir = tmp_path / "agents" / "lumina" / "identity"
        id_dir.mkdir(parents=True)
        fp = "0" * 40
        (id_dir / "identity.json").write_text(
            json.dumps({"fingerprint": fp, "capauth_managed": True})
        )
        assert ai._load_fingerprint("lumina") == fp


class TestResolveDualUri:
    def test_to_dict_roundtrip_all_fields(self, tmp_path: Path, monkeypatch):
        """A fully resolved identity serialises both URIs + fingerprint."""
        from capauth import agent_identity

        cluster_file = tmp_path / "cluster.json"
        cluster_file.write_text(json.dumps({"realm": "example.test", "operator": "ops"}))
        capauth_dir = tmp_path / "ca"
        (capauth_dir / "identity").mkdir(parents=True)
        fp = "D" * 40
        (capauth_dir / "identity" / "profile.json").write_text(
            json.dumps({"key_info": {"fingerprint": fp}})
        )
        monkeypatch.setattr(agent_identity, "_CLUSTER_LOOKUP", [cluster_file])
        monkeypatch.setattr(agent_identity, "SKCAPSTONE_HOME", tmp_path)
        monkeypatch.setattr(agent_identity, "_agent_capauth_dir", lambda _a: capauth_dir)

        d = resolve_agent_identity("lumina").to_dict()
        assert d == {
            "agent": "lumina",
            "capauth_uri": "capauth:lumina@skworld.io",
            "fqid": "lumina@ops.example.test",
            "fingerprint": fp,
        }


class TestResolveActiveAgentName:
    def test_template_env_value_is_skipped(self):
        """A *-template SKAGENT value is never returned verbatim (skipped)."""
        from capauth import agent_identity

        env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("SKAGENT", "SKCAPSTONE_AGENT", "SKMEMORY_AGENT")
        }
        env["SKAGENT"] = "lumina-template"
        with patch.dict(os.environ, env, clear=True):
            name = agent_identity._resolve_active_agent_name()
        # The template value must not leak through the env chain; it either falls
        # through to skmemory (a real name) or to None — but never the template.
        assert name != "lumina-template"
        # And resolve_agent_identity floors a template SKAGENT to "local".
        with patch.dict(os.environ, env, clear=True):
            with patch.object(agent_identity, "_resolve_active_agent_name", return_value=None):
                assert resolve_agent_identity(None).agent == "local"

    def test_skmemory_agent_legacy_fallback(self):
        """Only SKMEMORY_AGENT set → it is used (primary/legacy chain)."""
        from capauth import agent_identity

        env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("SKAGENT", "SKCAPSTONE_AGENT", "SKMEMORY_AGENT")
        }
        env["SKMEMORY_AGENT"] = "sentinel"
        with patch.dict(os.environ, env, clear=True):
            assert agent_identity._resolve_active_agent_name() == "sentinel"


class TestConfidentialityDelegation:
    """AgentIdentity confidentiality shims delegate honestly (no overclaim)."""

    def test_classical_suite_when_no_prekey(self, tmp_path: Path, monkeypatch):
        """With no published hybrid prekey, the suite is the classical wrap."""
        monkeypatch.setenv("SKCHAT_HOME", str(tmp_path))  # empty → no prekey
        ident = AgentIdentity(agent="nobody", capauth_uri="capauth:nobody@skworld.io")
        assert ident.hybrid_prekey_available() is False
        assert ident.confidentiality_suite() == "x25519-pgp-wrap-v1"
