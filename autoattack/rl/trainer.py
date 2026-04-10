"""Training loop for the Q-learning attack agent.

Runs the agent against ``AttackEnv`` for a configurable number of
episodes, prints periodic progress, and serialises the trained Q-table
to a pickle file for later use by ``RLPlanner``.
"""

from __future__ import annotations

import logging
import pickle
from pathlib import Path

import networkx as nx

from rl.environment import AttackEnv
from rl.q_agent import QAgent

logger = logging.getLogger(__name__)

_LOG_INTERVAL = 500  # Print stats every N episodes.


def train(
    graph: nx.DiGraph,
    start: str,
    goal: str,
    episodes: int = 5000,
    learning_rate: float = 0.1,
    gamma: float = 0.95,
    epsilon_start: float = 1.0,
    epsilon_decay: float = 0.9995,
    epsilon_min: float = 0.05,
    output_path: str = "qtable.pkl",
) -> dict:
    """Train a Q-learning agent on the attack environment.

    Runs ``episodes`` training episodes with epsilon-greedy exploration,
    printing a progress summary every ``_LOG_INTERVAL`` episodes.  The
    final Q-table is saved to ``output_path`` as a pickle file.

    Args:
        graph: Directed attack graph for the environment.
        start: IP of the attacker's starting host.
        goal: IP of the target host.
        episodes: Total number of training episodes.
        learning_rate: Q-update step size (alpha).
        gamma: Discount factor for future rewards.
        epsilon_start: Initial exploration probability.
        epsilon_decay: Per-episode multiplicative decay for epsilon.
        epsilon_min: Minimum epsilon floor.
        output_path: Path to save the serialised Q-table pickle.

    Returns:
        The trained Q-table as a plain dict.
    """
    env = AttackEnv(graph, start, goal)
    agent = QAgent(
        learning_rate=learning_rate,
        gamma=gamma,
        epsilon=epsilon_start,
        epsilon_decay=epsilon_decay,
        epsilon_min=epsilon_min,
    )

    recent_rewards: list[float] = []
    recent_successes: list[bool] = []

    for episode in range(1, episodes + 1):
        _, _ = env.reset()
        state = env.state_tuple()
        episode_reward = 0.0
        done = False
        truncated = False

        while not done and not truncated:
            available = env.get_available_edges()
            action = agent.select_action(state, available)

            if action is None:
                break

            _, reward, done, truncated, _ = env.step(action)
            next_state = env.state_tuple()
            next_available = env.get_available_edges()

            agent.update(
                state, action, reward, next_state, next_available, done or truncated
            )
            state = next_state
            episode_reward += reward

        agent.decay_epsilon()
        recent_rewards.append(episode_reward)
        recent_successes.append(env.current_host == goal)

        # Keep only the last LOG_INTERVAL results for rolling stats.
        if len(recent_rewards) > _LOG_INTERVAL:
            recent_rewards.pop(0)
            recent_successes.pop(0)

        if episode % _LOG_INTERVAL == 0 or episode == episodes:
            avg_reward = sum(recent_rewards) / len(recent_rewards)
            success_rate = sum(recent_successes) / len(recent_successes) * 100
            print(
                f"Episode {episode:>5}/{episodes} | "
                f"Avg Reward: {avg_reward:>6.1f} | "
                f"Epsilon: {agent.epsilon:.3f} | "
                f"Success Rate: {success_rate:>3.0f}%"
            )

    # Serialise the Q-table.
    q_dict = agent.get_q_table_dict()
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb") as fh:
        pickle.dump(q_dict, fh)

    print(
        f"Q-table saved to {output_path} ({len(q_dict):,} state-action pairs)"
    )
    logger.info("Training complete. Q-table saved to %s", output_path)
    return q_dict
