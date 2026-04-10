"""Attack graph visualisation using Graphviz DOT format.

Exports the NetworkX attack graph as a Graphviz DOT file and optionally
renders it to PNG/SVG.  Chosen attack path edges are highlighted with
bold lines and CVSS-derived colours.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Optional

import networkx as nx

from graph.models import AttackEdge, Host

logger = logging.getLogger(__name__)

# Node colour palette.
_COLOR_ATTACKER    = "#4CAF50"  # Green — attacker-controlled start node.
_COLOR_COMPROMISED = "#FF9800"  # Orange — compromised intermediate node.
_COLOR_GOAL        = "#F44336"  # Red — target/goal node.
_COLOR_UNREACHED   = "#2196F3"  # Blue — undiscovered / not compromised.
_COLOR_TEXT_LIGHT  = "white"

# CVSS thresholds for edge colour.
_CVSS_HIGH   = 7.0
_CVSS_MEDIUM = 4.0


def export_graphviz(
    graph: nx.DiGraph,
    output_path: str,
    start_ip: Optional[str] = None,
    goal_ip: Optional[str] = None,
    highlight_path: Optional[list[AttackEdge]] = None,
    render: bool = True,
) -> str:
    """Export the attack graph to a Graphviz DOT file and render it.

    Args:
        graph: Directed attack graph with ``Host`` data on nodes and
            ``AttackEdge`` data on edges.
        output_path: Destination path for the ``.dot`` file (without
            extension).  PNG/SVG are rendered alongside it.
        start_ip: IP of the attacker's starting node (coloured green).
        goal_ip: IP of the goal node (coloured red).
        highlight_path: Optional list of ``AttackEdge`` objects forming
            the chosen attack path (rendered bold).
        render: If ``True`` and ``dot`` is on PATH, render the DOT to
            PNG via Graphviz.  Silently skips if Graphviz is absent.

    Returns:
        Path to the generated ``.dot`` file.
    """
    highlighted_edges: set[tuple[str, str]] = set()
    if highlight_path:
        for edge in highlight_path:
            highlighted_edges.add((edge.source_host, edge.target_host))

    lines: list[str] = [
        "digraph attack_graph {",
        '    rankdir=LR;',
        '    node [shape=box, style=filled, fontname="Courier"];',
        '    edge [fontname="Courier", fontsize=9];',
        "",
    ]

    # Node definitions.
    for node_id, node_data in graph.nodes(data=True):
        host: Optional[Host] = node_data.get("data")
        label_lines = [node_id]
        if host:
            if host.hostname and host.hostname != node_id:
                label_lines.append(host.hostname)
            if host.role and host.role != "unknown":
                label_lines.append(f"[{host.role}]")

        if node_id == goal_ip:
            label_lines.append("[GOAL]")
            fill = _COLOR_GOAL
        elif node_id == start_ip:
            fill = _COLOR_ATTACKER
        elif highlight_path and any(
            e.target_host == node_id for e in highlight_path
        ):
            fill = _COLOR_COMPROMISED
        else:
            fill = _COLOR_UNREACHED

        label = "\\n".join(label_lines)
        lines.append(
            f'    "{node_id}" [label="{label}", '
            f'fillcolor="{fill}", fontcolor="{_COLOR_TEXT_LIGHT}"];'
        )

    lines.append("")

    # Edge definitions.
    for src, tgt, edge_data in graph.edges(data=True):
        edge: Optional[AttackEdge] = edge_data.get("data")
        if edge is None:
            continue

        label = f"{edge.cve_id}\\nCVSS: {edge.cvss_score:.1f}"
        color = _cvss_to_color(edge.cvss_score)
        penwidth = "3" if (src, tgt) in highlighted_edges else "1"
        style = "bold" if (src, tgt) in highlighted_edges else "solid"

        lines.append(
            f'    "{src}" -> "{tgt}" ['
            f'label="{label}", color="{color}", '
            f'penwidth={penwidth}, style={style}];'
        )

    lines += ["}", ""]

    dot_content = "\n".join(lines)
    dot_path = Path(output_path).with_suffix(".dot")
    dot_path.parent.mkdir(parents=True, exist_ok=True)
    dot_path.write_text(dot_content)
    logger.info("DOT file written to %s", dot_path)

    if render:
        _render_dot(dot_path)

    return str(dot_path)


def _render_dot(dot_path: Path) -> None:
    """Render a DOT file to PNG using the Graphviz ``dot`` CLI.

    Silently skips if Graphviz is not installed.

    Args:
        dot_path: Path to the ``.dot`` file.
    """
    png_path = dot_path.with_suffix(".png")
    try:
        subprocess.run(
            ["dot", "-Tpng", str(dot_path), "-o", str(png_path)],
            check=True,
            capture_output=True,
            timeout=15,
        )
        logger.info("Graph rendered to %s", png_path)
    except FileNotFoundError:
        logger.debug("Graphviz 'dot' not found — skipping PNG render.")
    except subprocess.CalledProcessError as exc:
        logger.warning("Graphviz render failed: %s", exc.stderr.decode(errors="replace")[:200])


def _cvss_to_color(cvss_score: float) -> str:
    """Map a CVSS score to a colour string for edge rendering.

    Args:
        cvss_score: CVSS v3 base score in [0.0, 10.0].

    Returns:
        Hex colour string.
    """
    if cvss_score >= _CVSS_HIGH:
        return "#F44336"   # Red — critical/high.
    if cvss_score >= _CVSS_MEDIUM:
        return "#FF9800"   # Orange — medium.
    return "#4CAF50"       # Green — low.
