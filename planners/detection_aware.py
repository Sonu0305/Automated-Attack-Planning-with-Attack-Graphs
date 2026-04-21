"""Detection-aware multi-objective Pareto planner (Novel Extension 1).

Extends the classical A* planner by adding a configurable IDS detection
penalty term to the edge cost function.  Also exposes ``plan_pareto()``
which returns three named Pareto-optimal paths: fastest, stealthiest, and
balanced.

Research gap addressed:
    Wang et al. (2024) optimises only for exploit difficulty (CVSS).  No
    existing open-source planner simultaneously minimises both exploit
    difficulty AND IDS detection probability.
"""

from __future__ import annotations

import logging
from typing import Callable

import networkx as nx

from graph.models import AttackEdge
from planners.base_planner import BasePlanner, NoPlanFoundError

logger = logging.getLogger(__name__)

_MAX_CANDIDATE_PATHS = 20


class DetectionAwarePlanner(BasePlanner):
    """Multi-objective planner balancing exploit ease and stealth.

    The combined edge cost is:

        cost(e) = alpha × (10 - e.cvss_score) + beta × e.detection_weight × 10

    where ``alpha`` controls exploit-difficulty weight and ``beta``
    controls IDS-detection weight.  Setting ``alpha=1, beta=0`` reduces
    to the classical A* planner; ``alpha=0, beta=1`` gives the stealthiest
    path.

    Attributes:
        alpha: Weight for exploit difficulty component.  Default 0.5.
        beta: Weight for IDS detection component.  Default 0.5.

    Examples:
        Easy exploit, highly detectable (CVSS=9.0, detect=0.9):
            cost = 0.5×1.0 + 0.5×9.0 = 5.0  — penalised for detection

        Hard exploit, stealthy (CVSS=4.0, detect=0.1):
            cost = 0.5×6.0 + 0.5×1.0 = 3.5  — preferred despite lower CVSS

        Easy exploit, stealthy (CVSS=8.5, detect=0.15):
            cost = 0.5×1.5 + 0.5×1.5 = 1.5  — ideal path
    """

    def __init__(self, alpha: float = 0.5, beta: float = 0.5) -> None:
        """Initialise the planner with objective weights.

        Args:
            alpha: Exploit-difficulty weight (0.0–1.0).
            beta: IDS-detection weight (0.0–1.0).
        """
        self.alpha = alpha
        self.beta = beta

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def plan(
        self, graph: nx.DiGraph, start: str, goal: str
    ) -> list[AttackEdge]:
        """Find the combined-cost-optimal path from ``start`` to ``goal``.

        Uses A* with the detection-aware combined cost function.

        Args:
            graph: Directed attack graph.
            start: Attacker-controlled start host IP.
            goal: Target host IP.

        Returns:
            Ordered list of ``AttackEdge`` objects.

        Raises:
            NoPlanFoundError: If no path exists.
        """
        if start not in graph:
            raise NoPlanFoundError(f"Start node '{start}' not in graph.")
        if goal not in graph:
            raise NoPlanFoundError(f"Goal node '{goal}' not in graph.")

        cost_fn = self._make_cost_fn(self.alpha, self.beta)
        try:
            node_path: list[str] = nx.astar_path(
                graph,
                source=start,
                target=goal,
                heuristic=lambda u, v: 0.0,
                weight=lambda u, v, d: cost_fn(d["data"]),
            )
        except nx.NetworkXNoPath:
            raise NoPlanFoundError(
                f"No path from '{start}' to '{goal}' (alpha={self.alpha}, beta={self.beta})."
            )

        path = self.path_nodes_to_edges(graph, node_path)
        exploit_cost = sum(10.0 - e.cvss_score for e in path)
        detect_cost = sum(e.detection_weight for e in path)
        logger.info(
            "DetectionAware path: %d steps, exploit_cost=%.2f, detect_cost=%.2f",
            len(path),
            exploit_cost,
            detect_cost,
        )
        return path

    def plan_pareto(
        self, graph: nx.DiGraph, start: str, goal: str
    ) -> dict[str, list[AttackEdge]]:
        """Return three named Pareto-optimal paths.

        Generates up to ``_MAX_CANDIDATE_PATHS`` simple paths between
        ``start`` and ``goal``, scores each on both cost axes, selects
        the Pareto-optimal front, and returns the three best-labelled
        paths.

        The three returned paths are:
        - ``"fastest"``: lowest total exploit cost (highest CVSS sum).
        - ``"stealthiest"``: lowest total detection weight.
        - ``"balanced"``: lowest combined cost at alpha=beta=0.5.

        Args:
            graph: Directed attack graph.
            start: Attacker-controlled start host IP.
            goal: Target host IP.

        Returns:
            Dict with keys ``"fastest"``, ``"stealthiest"``,
            ``"balanced"``, each mapping to an ordered list of
            ``AttackEdge`` objects.

        Raises:
            NoPlanFoundError: If no path exists between start and goal.
        """
        if start not in graph:
            raise NoPlanFoundError(f"Start node '{start}' not in graph.")
        if goal not in graph:
            raise NoPlanFoundError(f"Goal node '{goal}' not in graph.")

        # Gather objective-specific candidates first so labels stay truthful
        # even when the combined-cost path generator would rank them low.
        candidates: list[list[AttackEdge]] = []
        for alpha, beta in ((1.0, 0.0), (0.0, 1.0), (0.5, 0.5)):
            try:
                node_path = nx.shortest_path(
                    graph,
                    start,
                    goal,
                    weight=lambda u, v, d, a=alpha, b=beta: self._make_cost_fn(a, b)(d["data"]),
                )
                path = self.path_nodes_to_edges(graph, node_path)
                if path and not _path_already_in_candidates(path, candidates):
                    candidates.append(path)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                pass

        # Add a bounded set of combined-cost simple paths for extra Pareto
        # diversity without making large graphs explode combinatorially.
        try:
            path_gen = nx.shortest_simple_paths(
                graph, start, goal,
                weight=lambda u, v, d: self._make_cost_fn(0.5, 0.5)(d["data"]),
            )
            for node_path in path_gen:
                path = self.path_nodes_to_edges(graph, node_path)
                if not _path_already_in_candidates(path, candidates):
                    candidates.append(path)
                if len(candidates) >= _MAX_CANDIDATE_PATHS:
                    break
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            if not candidates:
                raise NoPlanFoundError(f"No path from '{start}' to '{goal}'.")

        if not candidates:
            raise NoPlanFoundError(f"No candidates found from '{start}' to '{goal}'.")

        # Score each candidate on both axes.
        scored: list[tuple[float, float, list[AttackEdge]]] = []
        for path in candidates:
            ec = sum(10.0 - e.cvss_score for e in path)
            dc = sum(e.detection_weight for e in path)
            scored.append((ec, dc, path))

        # Select Pareto-optimal front (non-dominated on both axes).
        pareto = _pareto_front(scored)

        # Label: fastest = lowest exploit cost.
        fastest_path = min(pareto, key=lambda t: t[0])[2]
        # Stealthiest = lowest detection cost.
        stealthiest_path = min(pareto, key=lambda t: t[1])[2]
        # Balanced = same alpha=beta=0.5 combined cost used by plan().
        balanced_path = min(pareto, key=lambda t: 0.5 * t[0] + 5.0 * t[1])[2]

        _log_pareto_table(fastest_path, stealthiest_path, balanced_path)

        return {
            "fastest": fastest_path,
            "stealthiest": stealthiest_path,
            "balanced": balanced_path,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_cost_fn(
        self, alpha: float, beta: float
    ) -> Callable[[AttackEdge], float]:
        """Return a cost function closed over the given weights.

        Args:
            alpha: Exploit-difficulty weight.
            beta: Detection weight.

        Returns:
            Callable that maps an ``AttackEdge`` to a float cost.
        """
        def cost(edge: AttackEdge) -> float:
            return alpha * (10.0 - edge.cvss_score) + beta * edge.detection_weight * 10.0
        return cost


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _pareto_front(
    scored: list[tuple[float, float, list[AttackEdge]]]
) -> list[tuple[float, float, list[AttackEdge]]]:
    """Filter a list of (exploit_cost, detect_cost, path) to Pareto-optimal.

    A solution dominates another if it is not worse on either objective
    and strictly better on at least one.

    Args:
        scored: List of ``(exploit_cost, detect_cost, path)`` tuples.

    Returns:
        Subset of ``scored`` that are non-dominated.
    """
    pareto: list[tuple[float, float, list[AttackEdge]]] = []
    for candidate in scored:
        dominated = False
        for other in scored:
            if other is candidate:
                continue
            if other[0] <= candidate[0] and other[1] <= candidate[1]:
                if other[0] < candidate[0] or other[1] < candidate[1]:
                    dominated = True
                    break
        if not dominated:
            pareto.append(candidate)
    return pareto if pareto else scored[:3]


def _path_already_in_candidates(
    path: list[AttackEdge],
    candidates: list[list[AttackEdge]],
) -> bool:
    """Return True when an equivalent source-target-CVE path is present."""
    signature = [(edge.source_host, edge.target_host, edge.cve_id) for edge in path]
    for candidate in candidates:
        candidate_signature = [
            (edge.source_host, edge.target_host, edge.cve_id)
            for edge in candidate
        ]
        if candidate_signature == signature:
            return True
    return False


def _log_pareto_table(
    fastest: list[AttackEdge],
    stealthiest: list[AttackEdge],
    balanced: list[AttackEdge],
) -> None:
    """Log a formatted table of the three Pareto paths.

    Args:
        fastest: Path optimised for exploit ease.
        stealthiest: Path optimised for stealth.
        balanced: Path balancing both objectives.
    """
    rows = [
        ("Fastest", fastest),
        ("Stealthiest", stealthiest),
        ("Balanced", balanced),
    ]
    lines = [
        "┌─────────────┬───────────────┬────────────────┬──────────────┐",
        "│    Path     │ Total Exploit │ Total Detection│  # of Steps  │",
        "│             │     Cost      │     Cost       │              │",
        "├─────────────┼───────────────┼────────────────┼──────────────┤",
    ]
    for label, path in rows:
        ec = sum(10.0 - e.cvss_score for e in path)
        dc = sum(e.detection_weight for e in path)
        lines.append(
            f"│ {label:<11} │ {ec:^13.1f} │ {dc:^14.1f} │ {len(path):^12} │"
        )
    lines.append("└─────────────┴───────────────┴────────────────┴──────────────┘")
    for line in lines:
        logger.info(line)
