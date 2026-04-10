"""Reinforcement-learning guided attack planner (Novel Extension 2).

Loads a pre-trained Q-table (produced by ``rl/trainer.py``) and performs
a greedy rollout from start to goal, at each step selecting the action
with the highest Q-value for the current state.

Reference:
    Novel extension building on BountyHunter (Mödersheim et al., 2025):
    https://arxiv.org/abs/2512.15275
"""

from __future__ import annotations

import logging
import pickle
from collections import defaultdict
from pathlib import Path

import networkx as nx

from graph.models import AttackEdge
from planners.base_planner import BasePlanner, NoPlanFoundError

logger = logging.getLogger(__name__)

_MAX_STEPS = 20  # Safety cap to prevent infinite loops.


class RLPlanner(BasePlanner):
    """Greedy rollout planner driven by a pre-trained Q-table.

    The Q-table maps ``(state_tuple, cve_id) → float`` where
    ``state_tuple = (current_host_ip, frozenset(compromised_ips))``.

    Attributes:
        qtable_path: Path to the pickle file containing the Q-table.
        q_table: Loaded Q-value dictionary.
    """

    def __init__(self, qtable_path: str = "qtable.pkl") -> None:
        """Load the pre-trained Q-table from disk.

        Args:
            qtable_path: Path to the pickle file produced by
                ``rl/trainer.py``.

        Raises:
            FileNotFoundError: If the pickle file does not exist, with a
                helpful message on how to train.
        """
        self.qtable_path = qtable_path
        path = Path(qtable_path)
        if not path.exists():
            raise FileNotFoundError(
                f"Q-table not found at '{qtable_path}'. "
                "Train the agent first:\n"
                "  python main.py train-rl --graph graph.pkl --episodes 5000"
            )
        with open(path, "rb") as fh:
            raw: dict = pickle.load(fh)
        self.q_table: defaultdict[tuple, float] = defaultdict(float, raw)
        logger.info(
            "RL planner loaded Q-table from '%s' (%d entries).",
            qtable_path,
            len(raw),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def plan(
        self, graph: nx.DiGraph, start: str, goal: str
    ) -> list[AttackEdge]:
        """Greedily follow the highest Q-value actions from start to goal.

        At each step the agent enumerates all edges from the current host
        and selects the one with the maximum Q-value in the current state.

        Args:
            graph: Directed attack graph.
            start: IP of the attacker's starting host.
            goal: IP of the target host to compromise.

        Returns:
            Ordered list of ``AttackEdge`` objects forming the path.

        Raises:
            NoPlanFoundError: If the agent reaches a dead end or the
                maximum step limit is exceeded.
        """
        if start not in graph:
            raise NoPlanFoundError(f"Start node '{start}' not in graph.")
        if goal not in graph:
            raise NoPlanFoundError(f"Goal node '{goal}' not in graph.")

        current_host = start
        compromised: frozenset[str] = frozenset({start})
        path: list[AttackEdge] = []
        visited_states: set[tuple] = set()

        for _ in range(_MAX_STEPS):
            if current_host == goal:
                break

            state = (current_host, compromised)
            if state in visited_states:
                raise NoPlanFoundError(
                    f"RL agent entered a cycle at host '{current_host}'."
                )
            visited_states.add(state)

            available = [
                data["data"]
                for _, _, data in graph.out_edges(current_host, data=True)
                if "data" in data
            ]

            if not available:
                raise NoPlanFoundError(
                    f"RL agent reached dead end at '{current_host}' — no outgoing edges."
                )

            best_edge = max(
                available,
                key=lambda e: self.q_table[(state, e.cve_id)],
            )

            path.append(best_edge)
            current_host = best_edge.target_host
            compromised = compromised | {current_host}

        if current_host != goal:
            raise NoPlanFoundError(
                f"RL agent did not reach goal '{goal}' within {_MAX_STEPS} steps."
            )

        logger.info("RL greedy rollout: %d steps to goal.", len(path))
        return path
