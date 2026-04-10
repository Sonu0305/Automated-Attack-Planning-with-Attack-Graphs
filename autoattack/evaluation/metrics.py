"""Evaluation metrics for comparing attack planner performance.

All functions operate on lists of ``RunResult`` objects produced by
``executor/playbook_runner.py``.  The ``compare_planners()`` function
assembles a ``pandas.DataFrame`` suitable for reporting and dashboard
generation.
"""

from __future__ import annotations

import logging
from typing import Optional

import pandas as pd

from graph.models import RunResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Individual metric functions
# ---------------------------------------------------------------------------


def success_rate(results: list[RunResult]) -> float:
    """Compute the fraction of runs where the goal host was reached.

    Args:
        results: List of ``RunResult`` objects from repeated planner runs.

    Returns:
        Float in [0.0, 1.0].  Returns 0.0 if the list is empty.
    """
    if not results:
        return 0.0
    return sum(1 for r in results if r.goal_reached) / len(results)


def avg_steps(results: list[RunResult]) -> float:
    """Compute the mean number of steps across successful runs.

    Args:
        results: List of ``RunResult`` objects.

    Returns:
        Mean step count for successful runs.  Returns 0.0 if there are
        no successful runs.
    """
    successful = [r for r in results if r.goal_reached]
    if not successful:
        return 0.0
    return sum(r.total_steps for r in successful) / len(successful)


def avg_detection_events(results: list[RunResult]) -> float:
    """Compute the mean number of IDS alerts per run (including failures).

    Args:
        results: List of ``RunResult`` objects.

    Returns:
        Mean IDS alert count per run.  Returns 0.0 if the list is empty.
    """
    if not results:
        return 0.0
    return sum(r.total_alerts for r in results) / len(results)


def avg_duration(results: list[RunResult]) -> float:
    """Compute the mean wall-clock duration across all runs (seconds).

    Args:
        results: List of ``RunResult`` objects.

    Returns:
        Mean duration in seconds.  Returns 0.0 if the list is empty.
    """
    if not results:
        return 0.0
    return sum(r.total_duration_seconds for r in results) / len(results)


def step_optimality(results: list[RunResult], optimal_steps: int) -> float:
    """Compute step optimality ratio versus a known optimal path length.

    A ratio of 1.0 means the planner always finds the optimal path.
    Lower ratios indicate suboptimal paths.

    Args:
        results: List of ``RunResult`` objects.
        optimal_steps: Known minimum number of steps to goal.

    Returns:
        Ratio ``optimal_steps / avg_steps`` in successful runs, or 0.0
        if there are no successful runs.
    """
    mean = avg_steps(results)
    if mean == 0.0:
        return 0.0
    return optimal_steps / mean


# ---------------------------------------------------------------------------
# Comparison function
# ---------------------------------------------------------------------------


def compare_planners(
    all_results: dict[str, list[RunResult]],
    optimal_steps: Optional[int] = None,
) -> pd.DataFrame:
    """Build a comparison DataFrame for all planners.

    Args:
        all_results: Dict mapping planner name → list of ``RunResult``.
        optimal_steps: Optional known-optimal step count for step
            optimality calculation.

    Returns:
        ``pandas.DataFrame`` indexed by planner name with columns:
        ``success_rate``, ``avg_steps``, ``avg_alerts``,
        ``avg_duration``, ``runs``, and optionally ``step_optimality``.
    """
    rows = []
    for planner_name, results in all_results.items():
        row: dict = {
            "planner": planner_name,
            "success_rate": f"{success_rate(results):.1%}",
            "avg_steps": f"{avg_steps(results):.1f}",
            "avg_alerts": f"{avg_detection_events(results):.1f}",
            "avg_duration": f"{avg_duration(results):.1f}s",
            "runs": len(results),
        }
        if optimal_steps is not None:
            row["step_optimality"] = f"{step_optimality(results, optimal_steps):.2f}"
        rows.append(row)

    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows).set_index("planner")
    _log_comparison_table(df)
    return df


def _log_comparison_table(df: pd.DataFrame) -> None:
    """Pretty-print the comparison table to the logger.

    Args:
        df: Comparison DataFrame from ``compare_planners()``.
    """
    col_width = 14
    header_parts = [f"{'Planner':<20}"]
    header_parts += [f"{col:>{col_width}}" for col in df.columns]
    separator = "─" * (20 + col_width * len(df.columns) + len(df.columns))

    logger.info(separator)
    logger.info("".join(header_parts))
    logger.info(separator)
    for planner, row in df.iterrows():
        line = f"{planner:<20}" + "".join(
            f"{str(v):>{col_width}}" for v in row
        )
        logger.info(line)
    logger.info(separator)
