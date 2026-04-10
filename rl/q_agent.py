"""Tabular Q-learning agent for attack graph navigation.

Implements epsilon-greedy action selection and Q-table updates over
the ``AttackEnv`` simulated environment.  The Q-table is indexed by
``(state_tuple, action_cve_id)`` pairs, where ``state_tuple`` is
``(current_host_ip, frozenset(compromised_ips))``.
"""

from __future__ import annotations

import logging
import random
from collections import defaultdict
from typing import Optional

from graph.models import AttackEdge
from rl.environment import AttackEnv

logger = logging.getLogger(__name__)


class QAgent:
    """Tabular Q-learning agent with epsilon-greedy exploration.

    The Q-table maps ``(state_tuple, cve_id)`` → float value.  State
    tuples are hashable ``(current_host, frozenset(compromised))`` pairs.

    Attributes:
        epsilon: Current exploration probability.
        epsilon_min: Floor for epsilon decay.
        epsilon_decay: Multiplicative decay applied per episode.
        learning_rate: Q-update step size (alpha).
        gamma: Discount factor for future rewards.
        q_table: Defaultdict mapping state-action pairs to Q-values.
    """

    def __init__(
        self,
        learning_rate: float = 0.1,
        gamma: float = 0.95,
        epsilon: float = 1.0,
        epsilon_decay: float = 0.9995,
        epsilon_min: float = 0.05,
    ) -> None:
        """Initialise the Q-agent hyperparameters.

        Args:
            learning_rate: Alpha — step size for Q-value updates.
            gamma: Discount factor for future rewards.
            epsilon: Initial exploration probability.
            epsilon_decay: Multiplicative factor applied to epsilon after
                each episode.
            epsilon_min: Minimum value epsilon can decay to.
        """
        self.learning_rate = learning_rate
        self.gamma = gamma
        self.epsilon = epsilon
        self.epsilon_decay = epsilon_decay
        self.epsilon_min = epsilon_min
        self.q_table: defaultdict[tuple, float] = defaultdict(float)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def select_action(
        self,
        state: tuple,
        available_actions: list[AttackEdge],
    ) -> Optional[AttackEdge]:
        """Select an action using epsilon-greedy policy.

        Args:
            state: Hashable state tuple from ``env.state_tuple()``.
            available_actions: List of ``AttackEdge`` objects available
                from the current host.

        Returns:
            Selected ``AttackEdge``, or ``None`` if no actions available.
        """
        if not available_actions:
            return None

        if random.random() < self.epsilon:
            return random.choice(available_actions)

        # Exploit: pick action with highest Q-value.
        return max(
            available_actions,
            key=lambda edge: self.q_table[(state, edge.cve_id)],
        )

    def update(
        self,
        state: tuple,
        action: AttackEdge,
        reward: float,
        next_state: tuple,
        next_available: list[AttackEdge],
        done: bool,
    ) -> None:
        """Apply the Q-learning update rule.

        Q(s,a) ← Q(s,a) + α [r + γ max_a' Q(s',a') - Q(s,a)]

        Args:
            state: State tuple before the action.
            action: The ``AttackEdge`` that was executed.
            reward: Scalar reward received.
            next_state: State tuple after the action.
            next_available: Available actions from ``next_state``.
            done: Whether the episode terminated.
        """
        key = (state, action.cve_id)
        current_q = self.q_table[key]

        if done or not next_available:
            target = reward
        else:
            best_next = max(
                self.q_table[(next_state, edge.cve_id)]
                for edge in next_available
            )
            target = reward + self.gamma * best_next

        self.q_table[key] += self.learning_rate * (target - current_q)

    def decay_epsilon(self) -> None:
        """Apply one step of epsilon decay after an episode.

        Clamps epsilon to ``epsilon_min`` from below.
        """
        self.epsilon = max(self.epsilon_min, self.epsilon * self.epsilon_decay)

    def load_q_table(self, data: dict) -> None:
        """Replace the Q-table with loaded data.

        Args:
            data: Dict of ``{(state, cve_id): float}`` Q-values.
        """
        self.q_table = defaultdict(float, data)
        logger.info("Q-table loaded: %d state-action pairs.", len(data))

    def get_q_table_dict(self) -> dict:
        """Return the Q-table as a plain dict for serialisation.

        Returns:
            Plain dict copy of the Q-table.
        """
        return dict(self.q_table)
