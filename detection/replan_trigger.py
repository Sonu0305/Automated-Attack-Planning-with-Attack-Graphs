"""Dynamic mid-run replanning trigger (Novel Extension 3).

Monitors IDS alert counts during step execution.  When the alert count
exceeds the configured threshold, packages the current execution context
and calls ``LLMPlanner.plan_with_context()`` to generate an alternative
route.

Research gap addressed:
    All existing planners are static — they plan once and execute.  This
    module combines LLM replanning with real-time IDS feedback for fully
    adaptive execution.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Optional

import networkx as nx

from detection.ids_monitor import IDSMonitor
from graph.models import AttackEdge

if TYPE_CHECKING:
    from planners.llm_planner import LLMPlanner

logger = logging.getLogger(__name__)


class ReplanTrigger:
    """Watches IDS alert counts and triggers LLM replanning on threshold breach.

    Attributes:
        monitor: ``IDSMonitor`` instance providing live alert data.
        llm_planner: ``LLMPlanner`` instance used for replanning.
        threshold: Number of IDS alerts that triggers a replan.
    """

    def __init__(
        self,
        monitor: IDSMonitor,
        llm_planner: "LLMPlanner",
        threshold: int = 3,
    ) -> None:
        """Initialise the trigger.

        Args:
            monitor: Running ``IDSMonitor`` watching the IDS log.
            llm_planner: Configured ``LLMPlanner`` for replanning.
            threshold: Alert count per step that triggers replanning.
        """
        self.monitor = monitor
        self.llm_planner = llm_planner
        self.threshold = threshold
        self._replan_count = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_and_replan(
        self,
        current_state: dict,
        graph: nx.DiGraph,
        current_host: str,
        goal: str,
        step_start_time: float,
    ) -> Optional[list[AttackEdge]]:
        """Check IDS alert count and replan if threshold is exceeded.

        Args:
            current_state: Dict describing execution context:
                - ``completed_steps``: List of completed step dicts.
                - ``failed_step``: Dict of the failed/alerted step.
                - ``new_info``: String describing new intelligence.
                - ``remaining_goal``: Target host IP.
            graph: Current attack graph.
            current_host: IP of the currently compromised host.
            goal: Target host IP.
            step_start_time: Unix epoch float when the step started;
                only alerts after this time are counted.

        Returns:
            New ``list[AttackEdge]`` if replanning was triggered,
            ``None`` if alert count is below threshold and the current
            plan should continue.
        """
        recent_alerts = self.monitor.get_alerts_since(step_start_time)
        alert_count = len(recent_alerts)

        if alert_count < self.threshold:
            return None

        self._replan_count += 1
        alert_summaries = [
            f"{a.rule_msg} ({a.src_ip} → {a.dst_ip})" for a in recent_alerts[:5]
        ]
        alert_text = "; ".join(alert_summaries)

        logger.warning(
            "[REPLAN #%d] %d IDS alerts detected (threshold=%d). Triggering LLM replan.",
            self._replan_count,
            alert_count,
            self.threshold,
        )

        # Enrich current_state with fresh alert data.
        enriched_state = dict(current_state)
        enriched_state["new_info"] = (
            f"IDS detected {alert_count} alerts: {alert_text}. "
            "Generate an alternative path that avoids the detected activity."
        )
        enriched_state["remaining_goal"] = goal

        try:
            new_path = self.llm_planner.plan_with_context(
                graph, current_host, goal, enriched_state
            )
            logger.info(
                "[REPLAN] New path generated: %d steps from '%s' to '%s'.",
                len(new_path),
                current_host,
                goal,
            )
            return new_path
        except Exception as exc:
            logger.error("[REPLAN] LLM replanning failed: %s — continuing original plan.", exc)
            return None

    @property
    def replan_count(self) -> int:
        """Total number of replan triggers fired in this session.

        Returns:
            Integer count of replanning events.
        """
        return self._replan_count
