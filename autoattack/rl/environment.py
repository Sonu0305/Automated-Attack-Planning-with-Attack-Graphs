"""Gymnasium-compatible simulated attack environment (Novel Extension 2).

``AttackEnv`` wraps a NetworkX attack graph as a reinforcement learning
environment.  Exploit success is probabilistic (modelled by CVSS score)
and IDS detection incurs a reward penalty.

Reference:
    Mödersheim et al. (2025). Bounty Hunter: Autonomous, Comprehensive
    Emulation of Multi-Faceted Adversaries. USENIX SecAD.
    https://arxiv.org/abs/2512.15275
"""

from __future__ import annotations

import random
from typing import Any

import gymnasium as gym
import networkx as nx
import numpy as np

from graph.models import AttackEdge

# Reward shaping constants.
_STEP_PENALTY = -1.0
_EXPLOIT_FAIL_PENALTY = -2.0
_IDS_ALERT_PENALTY = -3.0
_GOAL_REWARD = +10.0
_MAX_STEPS = 25


class AttackEnv(gym.Env):
    """Simulated network attack environment as a Gymnasium Env.

    The observation is the index of the current host in the graph's node
    list.  Actions are indices into the list of all edges in the graph.
    At each step the chosen edge's exploit is attempted with probability
    proportional to its CVSS score; IDS detection is similarly
    probabilistic.

    Attributes:
        graph: The underlying attack graph.
        start: IP of the attacker's starting host.
        goal: IP of the target host.
        observation_space: Discrete space over all host nodes.
        action_space: Discrete space over all graph edges.
    """

    metadata: dict[str, Any] = {"render_modes": []}

    def __init__(
        self, graph: nx.DiGraph, start: str, goal: str
    ) -> None:
        """Initialise the attack environment.

        Args:
            graph: Directed attack graph with ``AttackEdge`` data.
            start: IP address of the attacker's initial host.
            goal: IP address of the target host to compromise.
        """
        super().__init__()

        self.graph = graph
        self.start = start
        self.goal = goal

        self._nodes: list[str] = list(graph.nodes())
        self._node_index: dict[str, int] = {ip: i for i, ip in enumerate(self._nodes)}

        # Build a flat edge list for action indexing.
        self._edges: list[AttackEdge] = [
            data["data"]
            for _, _, data in graph.edges(data=True)
            if "data" in data
        ]

        self.observation_space = gym.spaces.Discrete(len(self._nodes))
        self.action_space = gym.spaces.Discrete(max(len(self._edges), 1))

        # Mutable state — reset before each episode.
        self.current_host: str = start
        self.compromised: set[str] = {start}
        self.steps_taken: int = 0

    # ------------------------------------------------------------------
    # Gymnasium interface
    # ------------------------------------------------------------------

    def reset(
        self,
        *,
        seed: int | None = None,
        options: dict | None = None,
    ) -> tuple[int, dict]:
        """Reset the environment to the initial state.

        Args:
            seed: Optional RNG seed for reproducibility.
            options: Unused; present for Gymnasium compatibility.

        Returns:
            Tuple of ``(observation, info)`` where observation is the
            integer index of the start host.
        """
        super().reset(seed=seed)
        if seed is not None:
            random.seed(seed)
        self.current_host = self.start
        self.compromised = {self.start}
        self.steps_taken = 0
        return self._state(), {}

    def step(
        self, action: int | AttackEdge
    ) -> tuple[int, float, bool, bool, dict]:
        """Execute one attack action in the environment.

        Accepts either an integer action index or a direct ``AttackEdge``.
        Exploit success is sampled from ``Bernoulli(cvss/10)``; IDS
        detection is sampled from ``Bernoulli(detection_weight)``.

        Args:
            action: Integer index into ``self._edges``, or an
                ``AttackEdge`` object directly.

        Returns:
            Tuple of ``(observation, reward, terminated, truncated, info)``.
        """
        self.steps_taken += 1
        reward = _STEP_PENALTY

        if isinstance(action, int):
            if action >= len(self._edges):
                # Invalid action — penalise and stay put.
                return self._state(), _EXPLOIT_FAIL_PENALTY, False, True, {}
            edge = self._edges[action]
        else:
            edge = action

        # Only allow edges from the current host.
        if edge.source_host != self.current_host:
            return self._state(), _EXPLOIT_FAIL_PENALTY, False, False, {}

        # Probabilistic exploit success.
        success_prob = edge.cvss_score / 10.0
        if random.random() < success_prob:
            self.compromised.add(edge.target_host)
            self.current_host = edge.target_host
        else:
            reward += _EXPLOIT_FAIL_PENALTY

        # IDS detection penalty.
        if random.random() < edge.detection_weight:
            reward += _IDS_ALERT_PENALTY

        # Check termination conditions.
        terminated = self.current_host == self.goal
        truncated = self.steps_taken >= _MAX_STEPS

        if terminated:
            reward += _GOAL_REWARD

        info: dict[str, Any] = {
            "current_host": self.current_host,
            "compromised": list(self.compromised),
            "steps": self.steps_taken,
        }
        return self._state(), reward, terminated, truncated, info

    def get_available_edges(self) -> list[AttackEdge]:
        """Return edges available from the current host.

        Args:
            None

        Returns:
            List of ``AttackEdge`` objects whose ``source_host`` is the
            current host.
        """
        result: list[AttackEdge] = []
        for edge in self._edges:
            if edge.source_host == self.current_host:
                result.append(edge)
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _state(self) -> int:
        """Return the current observation (integer node index).

        Returns:
            Integer index of ``self.current_host`` in the node list.
        """
        return self._node_index.get(self.current_host, 0)

    def state_tuple(self) -> tuple[str, frozenset[str]]:
        """Return a hashable state representation for Q-table lookup.

        Returns:
            Tuple of ``(current_host_ip, frozenset_of_compromised_ips)``.
        """
        return (self.current_host, frozenset(self.compromised))
