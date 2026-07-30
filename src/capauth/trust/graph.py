"""
Trust web visualization - the sovereignty network.

Builds a graph of trust relationships from PGP key signatures,
capability token chains, and FEB entanglement records. Outputs
DOT format (for Graphviz), Rich terminal table, or JSON.

Tool-agnostic: works from any terminal. Pipe DOT output to
Graphviz for visual rendering, or view the table directly.

Usage:
    skcapstone trust graph                    # Rich table in terminal
    skcapstone trust graph --format dot       # DOT for Graphviz
    skcapstone trust graph --format dot | dot -Tpng -o trust.png
    skcapstone trust graph --format json      # machine-readable
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class TrustNode:
    """An entity in the trust graph (agent, peer, or service).

    Attributes:
        id: Unique identifier (fingerprint or name).
        label: Display name.
        node_type: 'agent', 'peer', 'service', or 'unknown'.
        fingerprint: PGP fingerprint if available.
        metadata: Extra attributes.
    """

    id: str
    label: str
    node_type: str = "agent"
    fingerprint: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class TrustEdge:
    """A trust relationship between two nodes.

    Attributes:
        source: Source node ID.
        target: Target node ID.
        edge_type: 'token', 'feb', 'pgp_sign', or 'sync'.
        label: Description of the relationship.
        strength: Trust strength 0.0-1.0.
        metadata: Extra attributes (capabilities, timestamp, etc).
    """

    source: str
    target: str
    edge_type: str
    label: str = ""
    strength: float = 0.5
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class TrustGraph:
    """The complete trust web.

    Attributes:
        nodes: All entities in the graph.
        edges: All trust relationships.
        agent_name: The local agent's name (center of the web).
    """

    nodes: list[TrustNode] = field(default_factory=list)
    edges: list[TrustEdge] = field(default_factory=list)
    agent_name: str = "unknown"

    def add_node(self, node: TrustNode) -> None:
        """Add a node if not already present."""
        if not any(n.id == node.id for n in self.nodes):
            self.nodes.append(node)

    def add_edge(self, edge: TrustEdge) -> None:
        """Add an edge to the graph."""
        self.edges.append(edge)


def build_trust_graph(home: Path) -> TrustGraph:
    """Gather all trust data and build the graph.

    Sources:
        1. Agent identity (CapAuth profile / identity.json)
        2. Issued capability tokens (issuer -> subject)
        3. FEB entanglement records (emotional trust bonds)
        4. Sync peer records (vault sync connections)
        5. Coordination board agent files (known collaborators)

    Args:
        home: Agent home directory (~/.skcapstone).

    Returns:
        TrustGraph with all discovered relationships.
    """
    graph = TrustGraph()

    _add_self_node(home, graph)
    _add_token_edges(home, graph)
    _add_feb_edges(home, graph)
    _add_sync_edges(home, graph)
    _add_coord_agents(home, graph)

    return graph


def _add_self_node(home: Path, graph: TrustGraph) -> None:
    """Add the local agent as the central node."""
    manifest_data: dict[str, Any] = {}

    identity_file = home / "identity" / "identity.json"
    if identity_file.exists():
        try:
            data = json.loads(identity_file.read_text(encoding="utf-8"))
            name = data.get("name", "self")
            graph.agent_name = name
            graph.add_node(
                TrustNode(
                    id=name,
                    label=name,
                    node_type="agent",
                    fingerprint=data.get("fingerprint"),
                    metadata={"capauth_managed": data.get("capauth_managed", False)},
                )
            )
        except (json.JSONDecodeError, OSError):
            pass

    manifest = home / "manifest.json"
    if manifest.exists():
        try:
            manifest_data = json.loads(manifest.read_text(encoding="utf-8"))
            if not graph.nodes:
                name = manifest_data.get("name", "self")
                graph.agent_name = name
                graph.add_node(TrustNode(id=name, label=name, node_type="agent"))
        except (json.JSONDecodeError, OSError):
            pass

    _add_operator_edge(manifest_data, graph)


def _add_operator_edge(manifest_data: dict[str, Any], graph: TrustGraph) -> None:
    """Add an explicit human-operator relationship from manifest metadata."""
    operator = manifest_data.get("operator")
    if not isinstance(operator, dict):
        return

    name = str(operator.get("name", "")).strip()
    if not name or not graph.agent_name:
        return

    node_id = str(operator.get("fingerprint", "")).strip() or f"operator:{name}"
    graph.add_node(
        TrustNode(
            id=node_id,
            label=name,
            node_type="peer",
            fingerprint=str(operator.get("fingerprint", "")).strip() or None,
            metadata={
                "relationship": operator.get("relationship", "human-operator"),
                "entity_type": operator.get("entity_type", "human"),
                "source": operator.get("source", "manifest"),
            },
        )
    )
    graph.add_edge(
        TrustEdge(
            source=graph.agent_name,
            target=node_id,
            edge_type="operator",
            label=operator.get("relationship", "human-operator"),
            strength=1.0,
        )
    )


def _add_token_edges(home: Path, graph: TrustGraph) -> None:
    """Add edges from capability token issuance (issuer trusts subject)."""
    tokens_dir = home / "security" / "tokens"
    if not tokens_dir.exists():
        return

    for token_file in tokens_dir.glob("*.json"):
        if token_file.name.startswith("revoked"):
            continue
        try:
            data = json.loads(token_file.read_text(encoding="utf-8"))
            payload = data.get("payload", data)
            subject = payload.get("subject", "")
            issuer = payload.get("issuer", graph.agent_name)
            caps = payload.get("capabilities", [])

            if not subject:
                continue

            graph.add_node(
                TrustNode(
                    id=subject,
                    label=subject,
                    node_type="service" if ":" in subject else "peer",
                )
            )

            graph.add_edge(
                TrustEdge(
                    source=issuer if issuer != subject else graph.agent_name,
                    target=subject,
                    edge_type="token",
                    label=", ".join(caps[:3]),
                    strength=0.6 if "*" not in caps else 0.9,
                    metadata={
                        "capabilities": caps,
                        "token_type": payload.get("token_type", "capability"),
                    },
                )
            )
        except (json.JSONDecodeError, OSError):
            continue


def _add_feb_edges(home: Path, graph: TrustGraph) -> None:
    """Add edges from FEB entanglement records (deep emotional trust)."""
    trust_file = home / "trust" / "trust.json"
    if not trust_file.exists():
        return

    try:
        data = json.loads(trust_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return

    if data.get("entangled"):
        graph.add_node(
            TrustNode(
                id="human-partner",
                label="Human Partner",
                node_type="agent",
                metadata={"entangled": True},
            )
        )
        graph.add_edge(
            TrustEdge(
                source=graph.agent_name,
                target="human-partner",
                edge_type="feb",
                label=f"entangled (depth={data.get('depth', 0):.0f})",
                strength=min(1.0, data.get("trust_level", 0)),
                metadata={
                    "depth": data.get("depth", 0),
                    "love_intensity": data.get("love_intensity", 0),
                },
            )
        )

    febs_dir = home / "trust" / "febs"
    if febs_dir.exists():
        for feb_file in febs_dir.glob("*.feb"):
            try:
                feb_data = json.loads(feb_file.read_text(encoding="utf-8"))
                subject = feb_data.get("subject", feb_file.stem)
                emotion = feb_data.get("emotion", "unknown")
                intensity = feb_data.get("intensity", 0)

                graph.add_node(
                    TrustNode(
                        id=f"feb:{subject}",
                        label=f"FEB: {subject}",
                        node_type="agent",
                    )
                )
                graph.add_edge(
                    TrustEdge(
                        source=graph.agent_name,
                        target=f"feb:{subject}",
                        edge_type="feb",
                        label=f"{emotion} ({intensity})",
                        strength=min(1.0, intensity / 10.0),
                    )
                )
            except (json.JSONDecodeError, OSError):
                continue


def _add_sync_edges(home: Path, graph: TrustGraph) -> None:
    """Add edges from sync peer records (vault connections)."""
    sync_dir = home / "sync"
    if not sync_dir.exists():
        return

    for subdir in ("archive", "inbox"):
        seed_dir = sync_dir / subdir
        if not seed_dir.exists():
            continue
        seen_agents: set[str] = set()
        for seed_file in seed_dir.glob("*.seed.json*"):
            try:
                data = json.loads(seed_file.read_text(encoding="utf-8"))
                agent = data.get("agent_name", "")
                host = data.get("source_host", "unknown")
                if agent and agent not in seen_agents and agent != graph.agent_name:
                    seen_agents.add(agent)
                    graph.add_node(
                        TrustNode(
                            id=agent,
                            label=f"{agent}@{host}",
                            node_type="peer",
                            metadata={"host": host},
                        )
                    )
                    graph.add_edge(
                        TrustEdge(
                            source=agent,
                            target=graph.agent_name,
                            edge_type="sync",
                            label=f"sync via {host}",
                            strength=0.5,
                        )
                    )
            except (json.JSONDecodeError, OSError):
                continue


def _add_coord_agents(home: Path, graph: TrustGraph) -> None:
    """Add edges from coordination board collaborators."""
    agents_dir = home / "coordination" / "agents"
    if not agents_dir.exists():
        return

    for agent_file in agents_dir.glob("*.json"):
        try:
            data = json.loads(agent_file.read_text(encoding="utf-8"))
            name = data.get("agent", "")
            if not name or name == graph.agent_name:
                continue

            completed = len(data.get("completed_tasks", []))
            graph.add_node(
                TrustNode(
                    id=name,
                    label=name,
                    node_type="agent",
                    metadata={"state": data.get("state", "unknown"), "tasks_done": completed},
                )
            )
            graph.add_edge(
                TrustEdge(
                    source=graph.agent_name,
                    target=name,
                    edge_type="coord",
                    label=f"collaborator ({completed} tasks)",
                    strength=min(1.0, 0.3 + completed * 0.05),
                )
            )
        except (json.JSONDecodeError, OSError):
            continue


# ═══════════════════════════════════════════════════════════════════════════
# Output formatters
# ═══════════════════════════════════════════════════════════════════════════


def format_dot(graph: TrustGraph) -> str:
    """Format the trust graph as Graphviz DOT.

    Args:
        graph: The trust graph to render.

    Returns:
        DOT language string. Pipe to `dot -Tpng` for an image.
    """
    lines = [
        "digraph trust_web {",
        "  rankdir=LR;",
        '  node [shape=box, style=rounded, fontname="Helvetica"];',
        '  edge [fontname="Helvetica", fontsize=10];',
        "",
    ]

    node_styles = {
        "agent": 'style="rounded,filled", fillcolor="#E8F5E9"',
        "peer": 'style="rounded,filled", fillcolor="#E3F2FD"',
        "service": 'style="rounded,filled", fillcolor="#FFF3E0"',
    }

    for node in graph.nodes:
        style = node_styles.get(node.node_type, "style=rounded")
        fp = f"\\n{node.fingerprint[:12]}..." if node.fingerprint else ""
        lines.append(f'  "{node.id}" [label="{node.label}{fp}", {style}];')

    lines.append("")

    edge_colors = {
        "token": "#4CAF50",
        "feb": "#E91E63",
        "sync": "#2196F3",
        "coord": "#FF9800",
        "pgp_sign": "#9C27B0",
    }

    for edge in graph.edges:
        color = edge_colors.get(edge.edge_type, "#757575")
        width = max(1.0, edge.strength * 3.0)
        label = edge.label.replace('"', '\\"') if edge.label else edge.edge_type
        lines.append(
            f'  "{edge.source}" -> "{edge.target}" '
            f'[label="{label}", color="{color}", penwidth={width:.1f}];'
        )

    lines.append("}")
    return "\n".join(lines)


def format_json(graph: TrustGraph) -> str:
    """Format the trust graph as JSON.

    Args:
        graph: The trust graph to render.

    Returns:
        JSON string with nodes and edges arrays.
    """
    return json.dumps(
        {
            "agent": graph.agent_name,
            "nodes": [
                {
                    "id": n.id,
                    "label": n.label,
                    "type": n.node_type,
                    "fingerprint": n.fingerprint,
                }
                for n in graph.nodes
            ],
            "edges": [
                {
                    "source": e.source,
                    "target": e.target,
                    "type": e.edge_type,
                    "label": e.label,
                    "strength": e.strength,
                }
                for e in graph.edges
            ],
            "stats": {
                "nodes": len(graph.nodes),
                "edges": len(graph.edges),
                "by_type": _count_by_type(graph),
            },
        },
        indent=2,
        default=str,
    )


def format_table(graph: TrustGraph) -> str:
    """Format the trust graph as a text table (no Rich dependency).

    Args:
        graph: The trust graph to render.

    Returns:
        Plain text table for any terminal.
    """
    lines = [
        f"Trust Web: {graph.agent_name}",
        f"{'=' * 60}",
        "",
        f"Nodes ({len(graph.nodes)}):",
    ]
    for n in graph.nodes:
        fp = f" [{n.fingerprint[:12]}...]" if n.fingerprint else ""
        lines.append(f"  {n.node_type:8s}  {n.label}{fp}")

    lines.append("")
    lines.append(f"Edges ({len(graph.edges)}):")

    for e in graph.edges:
        strength_bar = "#" * int(e.strength * 5) + "." * (5 - int(e.strength * 5))
        lines.append(f"  {e.source} -> {e.target}")
        lines.append(f"    [{e.edge_type}] {e.label}  [{strength_bar}]")

    counts = _count_by_type(graph)
    lines.append("")
    lines.append("Summary:")
    for etype, count in sorted(counts.items()):
        lines.append(f"  {etype}: {count} relationship(s)")

    lines.append("")
    return "\n".join(lines)


def _count_by_type(graph: TrustGraph) -> dict[str, int]:
    """Count edges by type."""
    counts: dict[str, int] = {}
    for e in graph.edges:
        counts[e.edge_type] = counts.get(e.edge_type, 0) + 1
    return counts


FORMATTERS = {
    "dot": format_dot,
    "json": format_json,
    "table": format_table,
}
