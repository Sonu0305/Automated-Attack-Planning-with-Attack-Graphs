"""Classical A* attack planner based on Wang et al. (2024).

Uses NetworkX's built-in A* implementation with a CVSS-derived edge cost
function.  Higher CVSS scores correspond to easier exploits and therefore
lower path cost, naturally directing the planner toward the most
exploitable routes.

Reference:
    Wang et al. (2024). A Red Team automated testing modeling and online
    planning method for post-penetration. Computers & Security.
    https://doi.org/10.1016/j.cose.2024.102505
"""

from __future__ import annotations

import logging

import networkx as nx

from graph.models import AttackEdge
from planners.base_planner import BasePlanner, NoPlanFoundError

logger = logging.getLogger(__name__)


class AStarPlanner(BasePlanner):
    """Greedy A* planner that minimises total exploit difficulty.

    The heuristic is an admissible zero function (Dijkstra-equivalent),
    meaning the algorithm is guaranteed to find the globally optimal path
    with respect to the CVSS-based cost metric.

    Cost function:
        edge_cost = 10.0 - cvss_score

        CVSS:  0    1    2    3    4    5    6    7    8    9   10
        Cost: 10.0  9.0  8.0  7.0  6.0  5.0  4.0  3.0  2.0  1.0  0.0
               ^                                                     ^
            Hardest                                              Easiest
    """

    def plan(
        self, graph: nx.DiGraph, start: str, goal: str
    ) -> list[AttackEdge]:
        """Find the lowest-cost attack path from ``start`` to ``goal``.

        Args:
            graph: Directed attack graph with ``AttackEdge`` data on
                each edge under the ``"data"`` key.
            start: IP address of the attacker-controlled start host.
            goal: IP address of the target host.

        Returns:
            Ordered list of ``AttackEdge`` objects forming the optimal
            path.

        Raises:
            NoPlanFoundError: If no path exists between ``start`` and
                ``goal``.
        """
        if start not in graph:
            raise NoPlanFoundError(f"Start node '{start}' not in graph.")
        if goal not in graph:
            raise NoPlanFoundError(f"Goal node '{goal}' not in graph.")

        try:
            node_path: list[str] = nx.astar_path(
                graph,
                source=start,
                target=goal,
                heuristic=lambda u, v: 0.0,  # admissible null heuristic
                weight=lambda u, v, d: self.edge_cost(d["data"]),
            )
        except nx.NetworkXNoPath:
            raise NoPlanFoundError(
                f"No exploitable path from '{start}' to '{goal}' in the attack graph."
            )
        except nx.NodeNotFound as exc:
            raise NoPlanFoundError(str(exc)) from exc

        path = self.path_nodes_to_edges(graph, node_path)
        total_cost = sum(self.edge_cost(e) for e in path)
        logger.info(
            "A* found path: %d steps, total exploit cost=%.2f",
            len(path),
            total_cost,
        )
        return path
