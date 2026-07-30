"""Tests for the trust web visualization module."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

# The trust-web graph is built from a fully initialized skcapstone agent home
# (identity, tokens, coordination board, sync seeds, FEBs). Those builders live
# in skcapstone, so skip the whole module when the sibling package is absent
# (e.g. capauth's standalone CI job). The moved module itself,
# capauth.trust.graph, has no skcapstone dependency.
pytest.importorskip("skcapstone")

from skcapstone.coordination import Board, Task  # noqa: E402
from skcapstone.pillars.identity import generate_identity  # noqa: E402
from skcapstone.pillars.memory import initialize_memory  # noqa: E402
from skcapstone.pillars.security import initialize_security  # noqa: E402
from skcapstone.pillars.sync import initialize_sync  # noqa: E402
from skcapstone.pillars.trust import initialize_trust, record_trust_state  # noqa: E402
from skcapstone.tokens import issue_token  # noqa: E402

from capauth.trust.graph import (  # noqa: E402
    FORMATTERS,
    TrustEdge,
    TrustGraph,
    TrustNode,
    build_trust_graph,
    format_dot,
    format_json,
    format_table,
)


def _init_agent(home: Path, name: str = "graph-test") -> None:
    """Set up a full agent for testing."""
    generate_identity(home, name)
    initialize_memory(home)
    initialize_trust(home)
    initialize_security(home)
    initialize_sync(home)
    manifest = {
        "name": name,
        "version": "0.1.0",
        "created_at": "2026-01-01T00:00:00Z",
        "connectors": [],
    }
    (home / "manifest.json").write_text(json.dumps(manifest))
    (home / "config").mkdir(exist_ok=True)
    (home / "config" / "config.yaml").write_text(yaml.dump({"agent_name": name}))


class TestBuildGraph:
    """Tests for build_trust_graph() data gathering."""

    def test_self_node_from_identity(self, tmp_agent_home: Path):
        """The local agent appears as the central node."""
        _init_agent(tmp_agent_home, "opus")
        graph = build_trust_graph(tmp_agent_home)

        assert graph.agent_name == "opus"
        assert any(n.id == "opus" for n in graph.nodes)

    def test_token_creates_edge(self, tmp_agent_home: Path):
        """Issuing a token creates a trust edge to the subject."""
        _init_agent(tmp_agent_home, "issuer-agent")
        issue_token(
            tmp_agent_home,
            subject="peer-agent",
            capabilities=["memory:read"],
        )

        graph = build_trust_graph(tmp_agent_home)
        token_edges = [e for e in graph.edges if e.edge_type == "token"]
        assert len(token_edges) >= 1
        assert any(e.target == "peer-agent" for e in token_edges)

    def test_entanglement_creates_feb_edge(self, tmp_agent_home: Path):
        """FEB entanglement creates a deep trust bond edge."""
        _init_agent(tmp_agent_home, "entangled-agent")
        record_trust_state(
            tmp_agent_home,
            depth=9.0,
            trust_level=0.95,
            love_intensity=0.9,
            entangled=True,
        )

        graph = build_trust_graph(tmp_agent_home)
        feb_edges = [e for e in graph.edges if e.edge_type == "feb"]
        assert len(feb_edges) >= 1
        assert any(e.target == "human-partner" for e in feb_edges)

    def test_coord_agents_appear(self, tmp_agent_home: Path):
        """Coordination board collaborators appear as nodes."""
        _init_agent(tmp_agent_home, "coord-test")
        board = Board(tmp_agent_home)
        board.ensure_dirs()

        task = Task(title="Test collab", created_by="jarvis")
        board.create_task(task)
        board.claim_task("jarvis", task.id)
        board.complete_task("jarvis", task.id)

        graph = build_trust_graph(tmp_agent_home)
        assert any(n.id == "jarvis" for n in graph.nodes)
        coord_edges = [e for e in graph.edges if e.edge_type == "coord"]
        assert len(coord_edges) >= 1

    def test_empty_home_no_crash(self, tmp_agent_home: Path):
        """Building a graph from a minimal home doesn't crash."""
        graph = build_trust_graph(tmp_agent_home)
        assert isinstance(graph, TrustGraph)
        assert graph.nodes == [] or len(graph.nodes) >= 0

    def test_sync_seeds_create_peer_edges(self, tmp_agent_home: Path):
        """Sync seeds in the archive create peer edges."""
        _init_agent(tmp_agent_home, "sync-graph")
        archive = tmp_agent_home / "sync" / "archive"
        archive.mkdir(parents=True, exist_ok=True)

        seed = {
            "agent_name": "remote-lumina",
            "source_host": "lumina-box",
            "created_at": "2026-02-01T00:00:00Z",
        }
        (archive / "remote-lumina.seed.json").write_text(json.dumps(seed))

        graph = build_trust_graph(tmp_agent_home)
        assert any(n.id == "remote-lumina" for n in graph.nodes)
        sync_edges = [e for e in graph.edges if e.edge_type == "sync"]
        assert len(sync_edges) >= 1

    def test_manifest_operator_creates_human_link(self, tmp_agent_home: Path):
        """Manifest operator metadata appears as an explicit trust relationship."""
        _init_agent(tmp_agent_home, "operator-graph")
        manifest_path = tmp_agent_home / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["operator"] = {
            "name": "Casey",
            "fingerprint": "FP1234567890",
            "relationship": "human-operator",
            "entity_type": "human",
        }
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        graph = build_trust_graph(tmp_agent_home)

        assert any(n.label == "Casey" for n in graph.nodes)
        assert any(e.edge_type == "operator" and e.label == "human-operator" for e in graph.edges)


class TestFormatDot:
    """Tests for DOT format output."""

    def test_valid_dot_syntax(self, tmp_agent_home: Path):
        """DOT output has proper digraph structure."""
        _init_agent(tmp_agent_home, "dot-test")
        graph = build_trust_graph(tmp_agent_home)
        dot = format_dot(graph)

        assert dot.startswith("digraph trust_web {")
        assert dot.strip().endswith("}")

    def test_nodes_in_dot(self, tmp_agent_home: Path):
        """Nodes appear as quoted identifiers in DOT."""
        _init_agent(tmp_agent_home, "dot-nodes")
        graph = build_trust_graph(tmp_agent_home)
        dot = format_dot(graph)
        assert '"dot-nodes"' in dot


class TestFormatJson:
    """Tests for JSON format output."""

    def test_valid_json(self, tmp_agent_home: Path):
        """JSON output is parseable."""
        _init_agent(tmp_agent_home, "json-test")
        graph = build_trust_graph(tmp_agent_home)
        output = format_json(graph)

        parsed = json.loads(output)
        assert "nodes" in parsed
        assert "edges" in parsed
        assert "stats" in parsed
        assert parsed["agent"] == "json-test"

    def test_stats_counts(self, tmp_agent_home: Path):
        """Stats section has correct counts."""
        _init_agent(tmp_agent_home)
        issue_token(tmp_agent_home, subject="svc", capabilities=["*"])
        graph = build_trust_graph(tmp_agent_home)
        parsed = json.loads(format_json(graph))

        assert parsed["stats"]["nodes"] == len(graph.nodes)
        assert parsed["stats"]["edges"] == len(graph.edges)


class TestFormatTable:
    """Tests for plain text table output."""

    def test_contains_header(self, tmp_agent_home: Path):
        """Table output has a header with agent name."""
        _init_agent(tmp_agent_home, "table-test")
        graph = build_trust_graph(tmp_agent_home)
        table = format_table(graph)

        assert "Trust Web: table-test" in table
        assert "Nodes" in table
        assert "Edges" in table

    def test_strength_bars(self, tmp_agent_home: Path):
        """Edges show strength visualization."""
        graph = TrustGraph(agent_name="test")
        graph.add_node(TrustNode(id="a", label="A"))
        graph.add_node(TrustNode(id="b", label="B"))
        graph.add_edge(TrustEdge(source="a", target="b", edge_type="token", strength=0.8))

        table = format_table(graph)
        assert "#" in table


class TestFormattersRegistry:
    """Tests for the FORMATTERS dict."""

    def test_all_registered(self):
        """All three formatters are registered."""
        assert "dot" in FORMATTERS
        assert "json" in FORMATTERS
        assert "table" in FORMATTERS

    def test_all_callable(self):
        """All formatters are callable."""
        for name, fn in FORMATTERS.items():
            assert callable(fn)
