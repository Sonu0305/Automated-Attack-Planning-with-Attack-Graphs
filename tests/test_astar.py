"""Unit tests for planners/astar_planner.py and planners/detection_aware.py.

Uses hand-crafted graphs so tests are deterministic without any
external dependencies.
"""

from __future__ import annotations

import sys
from pathlib import Path

import networkx as nx
import pytest

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from graph.models import AttackEdge
from planners.astar_planner import AStarPlanner
from planners.base_planner import NoPlanFoundError
from planners.detection_aware import DetectionAwarePlanner


# ---------------------------------------------------------------------------
# Graph builders
# ---------------------------------------------------------------------------


def _make_edge(src: str, tgt: str, cvss: float, detect: float = 0.5, cve: str = "") -> AttackEdge:
    """Create a minimal AttackEdge for testing.

    Args:
        src: Source host IP.
        tgt: Target host IP.
        cvss: CVSS score.
        detect: Detection weight.
        cve: CVE ID (auto-generated if empty).

    Returns:
        ``AttackEdge`` instance.
    """
    return AttackEdge(
        source_host=src,
        target_host=tgt,
        cve_id=cve or f"CVE-TEST-{src[-1]}{tgt[-1]}",
        exploit_module=f"exploit/test/{src[-1]}_{tgt[-1]}",
        preconditions=["has_network_access"],
        postconditions=["has_shell_on_target"],
        cvss_score=cvss,
        detection_weight=detect,
    )


def build_test_graph_linear() -> nx.DiGraph:
    """Build: A→B (CVSS=9.0) and A→C→B (CVSS=5.0+5.0).

    Optimal A* path is A→B (cost=1.0 vs 5.0+5.0=10.0).

    Returns:
        Directed graph with three nodes.
    """
    G = nx.DiGraph()
    G.add_node("A")
    G.add_node("B")
    G.add_node("C")
    G.add_edge("A", "B", data=_make_edge("A", "B", cvss=9.0, cve="CVE-2017-0144"))
    G.add_edge("A", "C", data=_make_edge("A", "C", cvss=5.0, cve="CVE-2018-10933"))
    G.add_edge("C", "B", data=_make_edge("C", "B", cvss=5.0, cve="CVE-2021-3156"))
    return G


def build_test_graph_detection() -> nx.DiGraph:
    """Build: A→B (CVSS=9.0, detect=0.9) and A→C→B (CVSS=6.0, detect=0.1).

    For detection-aware planner with alpha=beta=0.5:
      A→B: 0.5×1.0 + 0.5×9.0 = 5.0
      A→C→B: 0.5×4.0+0.5×1.0 + 0.5×4.0+0.5×1.0 = 5.0 (tied, but lower detect)
    Stealthiest path is A→C→B.

    Returns:
        Directed graph.
    """
    G = nx.DiGraph()
    for node in ("A", "B", "C"):
        G.add_node(node)
    G.add_edge("A", "B", data=_make_edge("A", "B", cvss=9.0, detect=0.9, cve="CVE-2017-0144"))
    G.add_edge("A", "C", data=_make_edge("A", "C", cvss=6.0, detect=0.1, cve="CVE-2018-10933"))
    G.add_edge("C", "B", data=_make_edge("C", "B", cvss=6.0, detect=0.1, cve="CVE-2021-3156"))
    return G


# ---------------------------------------------------------------------------
# AStarPlanner tests
# ---------------------------------------------------------------------------


class TestAStarPlanner:
    """Tests for the classical A* planner."""

    def test_finds_optimal_single_hop(self):
        """A* must prefer A→B over A→C→B when A→B has higher CVSS."""
        G = build_test_graph_linear()
        planner = AStarPlanner()
        path = planner.plan(G, start="A", goal="B")

        assert len(path) == 1, f"Expected 1-hop path, got {len(path)} hops."
        assert path[0].source_host == "A"
        assert path[0].target_host == "B"

    def test_raises_no_plan_found_error_on_disconnected_graph(self):
        """A* must raise NoPlanFoundError when nodes are disconnected."""
        G = nx.DiGraph()
        G.add_node("A")
        G.add_node("B")  # No edge — disconnected.

        with pytest.raises(NoPlanFoundError):
            AStarPlanner().plan(G, "A", "B")

    def test_raises_no_plan_found_error_on_missing_node(self):
        """A* must raise NoPlanFoundError for unknown start or goal."""
        G = build_test_graph_linear()

        with pytest.raises(NoPlanFoundError):
            AStarPlanner().plan(G, "Z", "B")

        with pytest.raises(NoPlanFoundError):
            AStarPlanner().plan(G, "A", "Z")

    def test_path_is_list_of_attack_edges(self):
        """Return type must be list[AttackEdge]."""
        G = build_test_graph_linear()
        path = AStarPlanner().plan(G, "A", "B")

        assert isinstance(path, list)
        for edge in path:
            assert isinstance(edge, AttackEdge)

    def test_path_is_connected(self):
        """Consecutive edges must share source/target IPs."""
        G = build_test_graph_linear()
        path = AStarPlanner().plan(G, "A", "B")

        for i in range(len(path) - 1):
            assert path[i].target_host == path[i + 1].source_host, (
                f"Path not connected at step {i}"
            )

    def test_multi_hop_path(self):
        """When A→B is removed, A* must find the 2-hop A→C→B path."""
        G = nx.DiGraph()
        for node in ("A", "B", "C"):
            G.add_node(node)
        G.add_edge("A", "C", data=_make_edge("A", "C", cvss=7.0, cve="CVE-2018-10933"))
        G.add_edge("C", "B", data=_make_edge("C", "B", cvss=8.0, cve="CVE-2017-0144"))

        path = AStarPlanner().plan(G, "A", "B")
        assert len(path) == 2
        assert path[0].target_host == "C"
        assert path[1].target_host == "B"

    def test_edge_cost_function(self):
        """edge_cost must return 10 - cvss_score."""
        planner = AStarPlanner()
        edge = _make_edge("A", "B", cvss=7.5)
        assert planner.edge_cost(edge) == pytest.approx(2.5)

    def test_edge_cost_zero_for_max_cvss(self):
        """CVSS 10.0 edge must have zero cost."""
        planner = AStarPlanner()
        edge = _make_edge("A", "B", cvss=10.0)
        assert planner.edge_cost(edge) == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# DetectionAwarePlanner tests
# ---------------------------------------------------------------------------


class TestDetectionAwarePlanner:
    """Tests for the multi-objective detection-aware planner."""

    def test_plan_returns_valid_path(self):
        """Detection-aware plan must return a valid connected path."""
        G = build_test_graph_detection()
        planner = DetectionAwarePlanner(alpha=0.5, beta=0.5)
        path = planner.plan(G, "A", "B")

        assert len(path) >= 1
        assert path[-1].target_host == "B"

    def test_pure_stealth_mode_prefers_low_detection(self):
        """With alpha=0, beta=1 the planner should pick the stealthiest path."""
        G = build_test_graph_detection()
        planner = DetectionAwarePlanner(alpha=0.0, beta=1.0)
        path = planner.plan(G, "A", "B")

        total_detect = sum(e.detection_weight for e in path)
        # Direct A→B has detection=0.9; indirect A→C→B has 0.1+0.1=0.2.
        assert total_detect < 0.5, f"Expected low detection path, got {total_detect}"

    def test_plan_pareto_returns_three_paths(self):
        """plan_pareto must return dict with 'fastest', 'stealthiest', 'balanced'."""
        G = build_test_graph_detection()
        planner = DetectionAwarePlanner()
        result = planner.plan_pareto(G, "A", "B")

        assert set(result.keys()) == {"fastest", "stealthiest", "balanced"}
        for label, path in result.items():
            assert len(path) >= 1, f"{label} path is empty"
            assert path[-1].target_host == "B"

    def test_plan_pareto_labels_true_objective_paths(self):
        """Pareto labels should reflect fastest, stealthiest, and combined-cost paths."""
        G = nx.DiGraph()
        for node in ("A", "B", "C", "D", "E"):
            G.add_node(node)

        G.add_edge("A", "B", data=_make_edge("A", "B", cvss=9.8, detect=0.95, cve="CVE-FAST"))
        G.add_edge("A", "C", data=_make_edge("A", "C", cvss=8.8, detect=0.15, cve="CVE-BAL-1"))
        G.add_edge("C", "B", data=_make_edge("C", "B", cvss=8.8, detect=0.15, cve="CVE-BAL-2"))
        G.add_edge("A", "D", data=_make_edge("A", "D", cvss=7.0, detect=0.01, cve="CVE-STEALTH-1"))
        G.add_edge("D", "E", data=_make_edge("D", "E", cvss=7.0, detect=0.01, cve="CVE-STEALTH-2"))
        G.add_edge("E", "B", data=_make_edge("E", "B", cvss=7.0, detect=0.01, cve="CVE-STEALTH-3"))

        result = DetectionAwarePlanner().plan_pareto(G, "A", "B")

        assert [edge.cve_id for edge in result["fastest"]] == ["CVE-FAST"]
        assert [edge.cve_id for edge in result["balanced"]] == ["CVE-BAL-1", "CVE-BAL-2"]
        assert [edge.cve_id for edge in result["stealthiest"]] == [
            "CVE-STEALTH-1",
            "CVE-STEALTH-2",
            "CVE-STEALTH-3",
        ]

    def test_raises_no_plan_found_on_disconnected(self):
        """DetectionAwarePlanner must raise NoPlanFoundError on no path."""
        G = nx.DiGraph()
        G.add_node("A")
        G.add_node("B")

        with pytest.raises(NoPlanFoundError):
            DetectionAwarePlanner().plan(G, "A", "B")

    def test_combined_cost(self):
        """Combined cost formula: alpha*(10-cvss) + beta*detect*10."""
        planner = DetectionAwarePlanner(alpha=0.5, beta=0.5)
        edge = _make_edge("A", "B", cvss=9.0, detect=0.9)
        cost_fn = planner._make_cost_fn(0.5, 0.5)
        expected = 0.5 * (10 - 9.0) + 0.5 * 0.9 * 10
        assert cost_fn(edge) == pytest.approx(expected)
