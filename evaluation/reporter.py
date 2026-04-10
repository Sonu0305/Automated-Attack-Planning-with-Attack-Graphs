"""Evaluation report generator.

Produces three output formats from a set of planner run results:
1. ``report.json`` — machine-readable full result data.
2. ``report.md`` — human-readable Markdown with tables and ASCII charts.
3. ``dashboard.html`` — interactive Plotly dashboard (delegated to
   ``visualization/dashboard.py``).
"""

from __future__ import annotations

import dataclasses
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from evaluation.metrics import (
    avg_detection_events,
    avg_duration,
    avg_steps,
    success_rate,
    compare_planners,
)
from graph.models import RunResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_report(
    all_results: dict[str, list[RunResult]],
    output_dir: str,
    pareto_paths: Optional[dict] = None,
    rl_training_history: Optional[list[dict]] = None,
    realism_scores: Optional[dict[str, dict]] = None,
) -> dict[str, str]:
    """Generate all evaluation report artefacts.

    Args:
        all_results: Dict mapping planner name → list of RunResult.
        output_dir: Directory to write report files into.
        pareto_paths: Optional dict from ``DetectionAwarePlanner.plan_pareto()``.
        rl_training_history: Optional list of RL training episode dicts.
        realism_scores: Optional dict mapping planner name → realism
            score dict from ``LogCollector.compute_realism_score()``.

    Returns:
        Dict mapping ``"json"``, ``"markdown"``, ``"dashboard"`` to the
        absolute paths of the generated files.
    """
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = _write_json(all_results, out_dir)
    md_path = _write_markdown(all_results, out_dir, pareto_paths, realism_scores)
    dashboard_path = _write_dashboard(all_results, out_dir, pareto_paths, rl_training_history)

    return {
        "json": json_path,
        "markdown": md_path,
        "dashboard": dashboard_path,
    }


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------


def _write_json(
    all_results: dict[str, list[RunResult]],
    out_dir: Path,
) -> str:
    """Serialise all run results to report.json.

    Args:
        all_results: Dict mapping planner name → list of RunResult.
        out_dir: Output directory.

    Returns:
        Absolute path to the written file.
    """
    out: dict = {"generated_at": datetime.now(timezone.utc).isoformat(), "planners": {}}
    for planner, results in all_results.items():
        out["planners"][planner] = [dataclasses.asdict(r) for r in results]

    path = out_dir / "report.json"
    path.write_text(json.dumps(out, indent=2, default=str))
    logger.info("report.json written to %s", path)
    return str(path)


# ---------------------------------------------------------------------------
# Markdown output
# ---------------------------------------------------------------------------


def _write_markdown(
    all_results: dict[str, list[RunResult]],
    out_dir: Path,
    pareto_paths: Optional[dict],
    realism_scores: Optional[dict[str, dict]],
) -> str:
    """Generate a human-readable Markdown evaluation report.

    Args:
        all_results: Dict mapping planner name → list of RunResult.
        out_dir: Output directory.
        pareto_paths: Optional Pareto planner paths dict.
        realism_scores: Optional realism score dicts per planner.

    Returns:
        Absolute path to the written report.md.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    lines: list[str] = [
        "# AutoAttack — Evaluation Report",
        f"Generated: {now}",
        "",
        "## Executive Summary",
    ]

    total_runs = sum(len(v) for v in all_results.values())
    best_planner = max(all_results, key=lambda p: success_rate(all_results[p]))
    stealthiest = min(all_results, key=lambda p: avg_detection_events(all_results[p]))
    fastest = min(all_results, key=lambda p: avg_steps(all_results[p]))

    lines += [
        f"- Total runs: {total_runs} ({len(list(all_results))} planners × {total_runs // max(1, len(all_results))} runs)",
        f"- Best planner: **{best_planner}** ({success_rate(all_results[best_planner]):.1%} success rate)",
        f"- Stealthiest planner: **{stealthiest}** (avg {avg_detection_events(all_results[stealthiest]):.1f} IDS alerts/run)",
        f"- Fastest planner: **{fastest}** (avg {avg_steps(all_results[fastest]):.1f} steps, {avg_duration(all_results[fastest]):.1f}s)",
        "",
        "## Planner Comparison Table",
        "",
    ]

    # Markdown table.
    df = compare_planners(all_results)
    lines.append("| Planner | " + " | ".join(df.columns) + " |")
    lines.append("|" + "---|" * (len(df.columns) + 1))
    for planner, row in df.iterrows():
        lines.append(f"| {planner} | " + " | ".join(str(v) for v in row) + " |")

    lines += ["", "## ASCII Bar Charts", ""]
    lines.append(ascii_bar_chart(
        {p: success_rate(r) * 100 for p, r in all_results.items()},
        title="Success Rate by Planner (%)",
    ))

    lines += ["", ascii_bar_chart(
        {p: avg_detection_events(r) for p, r in all_results.items()},
        title="Avg IDS Alerts per Run",
    )]

    if pareto_paths is not None:
        lines += ["", "## Pareto Frontier Analysis", ""]
        lines.append(
            "| Path | Total Exploit Cost | Total Detection Cost | # Steps |"
        )
        lines.append("|---|---|---|---|")
        for label, path in pareto_paths.items():
            ec = sum(10.0 - e.cvss_score for e in path)
            dc = sum(e.detection_weight for e in path)
            lines.append(f"| {label} | {ec:.1f} | {dc:.2f} | {len(path)} |")

    if realism_scores is not None:
        lines += ["", "## Log Realism Scores", ""]
        lines.append("| Planner | Realism Score | Timing Entropy | Cmd Length | Unique Ratio | Error Rate |")
        lines.append("|---|---|---|---|---|---|")
        for planner, scores in realism_scores.items():
            lines.append(
                f"| {planner} | {scores.get('realism_score', 0):.4f} | "
                f"{scores.get('timing_entropy', 0):.2f} | "
                f"{scores.get('cmd_length_mean', 0):.1f} | "
                f"{scores.get('unique_ratio', 0):.2f} | "
                f"{scores.get('error_rate', 0):.2f} |"
            )

    lines += [
        "",
        "## Raw Data",
        "",
        "Machine-readable results: [report.json](report.json)",
        "",
        "Interactive dashboard: [dashboard.html](dashboard.html)",
    ]

    path = out_dir / "report.md"
    path.write_text("\n".join(lines))
    logger.info("report.md written to %s", path)
    return str(path)


# ---------------------------------------------------------------------------
# Dashboard output
# ---------------------------------------------------------------------------


def _write_dashboard(
    all_results: dict[str, list[RunResult]],
    out_dir: Path,
    pareto_paths: Optional[dict],
    rl_training_history: Optional[list[dict]],
) -> str:
    """Delegate dashboard generation to visualization/dashboard.py.

    Args:
        all_results: Planner results dict.
        out_dir: Output directory.
        pareto_paths: Optional Pareto paths dict.
        rl_training_history: Optional RL training history.

    Returns:
        Absolute path to dashboard.html.
    """
    from visualization.dashboard import generate_html_dashboard  # deferred import

    dashboard_path = str(out_dir / "dashboard.html")
    generate_html_dashboard(
        all_results=all_results,
        output_path=dashboard_path,
        pareto_paths=pareto_paths,
        rl_training_history=rl_training_history,
    )
    return dashboard_path


# ---------------------------------------------------------------------------
# Reusable ASCII chart helper
# ---------------------------------------------------------------------------


def ascii_bar_chart(
    values: dict[str, float],
    title: str,
    width: int = 40,
) -> str:
    """Render an ASCII horizontal bar chart.

    Args:
        values: Dict mapping label → numeric value.
        title: Chart title displayed above the bars.
        width: Maximum bar width in characters.

    Returns:
        Multi-line string ready to embed in Markdown or a terminal.
    """
    if not values:
        return f"{title}\n(no data)\n"

    max_val = max(values.values()) or 1.0
    max_label_len = max(len(k) for k in values)
    separator = "━" * (max_label_len + width + 12)

    lines = [title, separator]
    for label, val in values.items():
        bar_len = int((val / max_val) * width)
        bar = "█" * bar_len
        lines.append(f"{label:<{max_label_len}} {bar:<{width}} {val:>6.1f}")
    lines.append(separator)
    return "\n".join(lines)
