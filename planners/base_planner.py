"""Abstract base class for all attack planners.

Every planner in the system inherits from ``BasePlanner`` and must
implement the ``plan()`` method.  Shared cost functions and graph
traversal helpers live here so they do not need to be duplicated.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

import networkx as nx

from graph.models import AttackEdge


class NoPlanFoundError(Exception):
    """Raised when a planner cannot find a path from start to goal.

    Attributes:
        message: Human-readable description of why no path was found.
    """


class BasePlanner(ABC):
    """Abstract base class for attack path planners.

    All concrete planner implementations must override ``plan()``.
    The helper methods ``edge_cost()`` and ``path_nodes_to_edges()``
    are available to subclasses and provide consistent behaviour.
    """

    @abstractmethod
    def plan(
        self, graph: nx.DiGraph, start: str, goal: str
    ) -> list[AttackEdge]:
        """Compute an ordered attack path from ``start`` to ``goal``.

        Args:
            graph: Directed attack graph with ``AttackEdge`` data on
                edges (accessible via ``graph.edges[u, v]["data"]``).
            start: IP address of the initially-controlled host.
            goal: IP address of the target host to compromise.

        Returns:
            Ordered list of ``AttackEdge`` objects forming the attack
            path from ``start`` to ``goal``.

        Raises:
            NoPlanFoundError: If no path exists from ``start`` to
                ``goal`` in the current graph.
        """

    def edge_cost(self, edge: AttackEdge) -> float:
        """Default exploit-difficulty cost function.

        Maps CVSS score to edge cost so that easy-to-exploit edges
        (high CVSS) have low cost and hard-to-exploit edges (low CVSS)
        have high cost.

        Cost = 10.0 - cvss_score
        Range: 0.0 (CVSS=10, trivially exploitable) to
               10.0 (CVSS=0, theoretically impossible).

        Args:
            edge: The ``AttackEdge`` to cost.

        Returns:
            Float cost in the range [0.0, 10.0].
        """
        return 10.0 - edge.cvss_score

    def path_nodes_to_edges(
        self, graph: nx.DiGraph, node_path: list[str]
    ) -> list[AttackEdge]:
        """Convert an ordered list of host IPs to ``AttackEdge`` objects.

        Args:
            graph: Directed attack graph.
            node_path: Ordered list of host IP strings representing
                successive nodes in the attack path.

        Returns:
            Ordered list of ``AttackEdge`` objects corresponding to the
            edges between consecutive nodes in ``node_path``.

        Raises:
            KeyError: If an edge between consecutive nodes does not exist
                or lacks a ``"data"`` attribute.
        """
        edges: list[AttackEdge] = []
        for i in range(len(node_path) - 1):
            src, tgt = node_path[i], node_path[i + 1]
            edge_data = graph.edges[src, tgt]["data"]
            edges.append(edge_data)
        return edges
