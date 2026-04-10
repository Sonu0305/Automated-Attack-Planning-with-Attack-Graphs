"""AttackMate-style YAML playbook generator and runner.

Generates a human-readable YAML playbook from a planner output path,
then executes each step through the appropriate executor backend.
Inter-step delays are sampled from a Gaussian distribution to mimic
realistic human operator timing patterns.

Reference:
    Cramer et al. (2025). AttackMate: Realistic Emulation and Automation
    of Cyber Attack Scenarios. IEEE S&P.
    https://arxiv.org/abs/2601.14108
"""

from __future__ import annotations

import json
import logging
import random
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

from graph.models import AttackEdge, ExecutionResult
from executor.base_executor import BaseExecutor

logger = logging.getLogger(__name__)

_MIN_DELAY = 0.5
_MAX_DELAY = 15.0
_DELAY_STD  = 0.8


class PlaybookRunner:
    """Generate and execute YAML attack playbooks.

    Each step in the playbook is executed through the appropriate
    executor.  Gaussian-distributed delays are applied before and after
    each step to simulate human-like timing.  A JSONL execution log is
    written to ``execution_log.jsonl``.

    Attributes:
        msf_executor: Optional Metasploit executor for ``metasploit``-type steps.
        ssh_executor: Optional SSH executor for ``shell`` and ``pivot`` steps.
        log_dir: Directory path for the execution log file.
        replan_trigger: Optional ``ReplanTrigger`` for mid-run replanning.
    """

    def __init__(
        self,
        msf_executor: Optional[BaseExecutor] = None,
        ssh_executor: Optional[BaseExecutor] = None,
        log_dir: str = "results",
        replan_trigger: Optional[object] = None,
    ) -> None:
        """Initialise the playbook runner.

        Args:
            msf_executor: Configured ``MetasploitExecutor``.
            ssh_executor: Configured ``SSHExecutor``.
            log_dir: Directory where execution_log.jsonl is written.
            replan_trigger: Optional ``ReplanTrigger`` instance.
        """
        self.msf_executor = msf_executor
        self.ssh_executor = ssh_executor
        self.log_dir = Path(log_dir)
        self.replan_trigger = replan_trigger

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_playbook(
        self,
        path: list[AttackEdge],
        config: dict,
        planner_name: str = "astar",
    ) -> str:
        """Serialise a planner output path to a YAML playbook file.

        The generated playbook is written to a timestamped file in
        ``self.log_dir`` and its path is returned.

        Args:
            path: Ordered list of ``AttackEdge`` objects from the planner.
            config: Config dict with at least an ``attacker_ip`` key.
            planner_name: Name of the planner used, for metadata.

        Returns:
            Path string of the generated YAML file.
        """
        now = datetime.now(timezone.utc)
        ts = now.strftime("%Y%m%d_%H%M%S")
        attacker_ip = config.get("attacker_ip", "192.168.56.10")

        steps = []
        for edge in path:
            # Reconnaissance step.
            steps.append(
                {
                    "name": f"Reconnaissance on {edge.target_host}",
                    "type": "shell",
                    "command": f"nmap -sV -p {self._edge_port(edge)} {edge.target_host}",
                    "delay_before": round(random.gauss(2.5, _DELAY_STD), 2),
                    "delay_after": round(random.gauss(1.0, _DELAY_STD / 2), 2),
                    "log_output": True,
                }
            )
            # Exploit step.
            steps.append(
                {
                    "name": f"Exploit {edge.cve_id} on {edge.target_host}",
                    "type": "metasploit",
                    "module": edge.exploit_module,
                    "options": {
                        "RHOSTS": edge.target_host,
                        "LHOST": attacker_ip,
                    },
                    "delay_before": round(random.gauss(5.0, _DELAY_STD), 2),
                    "delay_after": round(random.gauss(2.0, _DELAY_STD / 2), 2),
                    "log_output": True,
                    "on_failure": "replan",
                }
            )

        playbook = {
            "metadata": {
                "generated_at": now.isoformat(),
                "planner": planner_name,
                "total_steps": len(steps),
            },
            "steps": steps,
        }

        self.log_dir.mkdir(parents=True, exist_ok=True)
        out_path = self.log_dir / f"playbook_{ts}.yaml"
        out_path.write_text(yaml.dump(playbook, default_flow_style=False, sort_keys=False))
        logger.info("Playbook written to %s", out_path)
        return str(out_path)

    def run(
        self,
        path: list[AttackEdge],
        graph: Optional[object] = None,
        goal: Optional[str] = None,
    ) -> list[ExecutionResult]:
        """Execute all steps in the attack path.

        For each edge, applies a Gaussian delay, dispatches to the
        appropriate executor, appends to the JSONL log, and optionally
        checks the replan trigger.

        Args:
            path: Ordered list of ``AttackEdge`` objects.
            graph: NetworkX DiGraph (passed to replan trigger if set).
            goal: Target host IP (passed to replan trigger if set).

        Returns:
            List of ``ExecutionResult`` objects in step order.
        """
        self.log_dir.mkdir(parents=True, exist_ok=True)
        log_file = self.log_dir / "execution_log.jsonl"
        results: list[ExecutionResult] = []

        completed_steps: list[dict] = []

        for i, edge in enumerate(path):
            step_label = f"Step {i + 1}/{len(path)}: {edge.cve_id} → {edge.target_host}"
            logger.info("[EXEC] %s", step_label)

            # Human-like pre-step delay.
            delay = float(
                max(_MIN_DELAY, min(_MAX_DELAY, random.gauss(3.0, _DELAY_STD)))
            )
            time.sleep(delay)

            step_start = time.time()
            result = self._dispatch(edge)
            results.append(result)

            # Append to JSONL log.
            log_entry: dict = {
                "timestamp": step_start,
                "step": step_label,
                "module": edge.exploit_module,
                "target": edge.target_host,
                "cve_id": edge.cve_id,
                "success": result.success,
                "duration": round(result.duration_seconds, 2),
                "output_preview": result.output[:200],
            }
            with open(log_file, "a") as fh:
                fh.write(json.dumps(log_entry) + "\n")

            if result.success:
                completed_steps.append(
                    {"source": edge.source_host, "target": edge.target_host, "cve_id": edge.cve_id}
                )
                logger.info("[EXEC] ✓ SUCCESS — %s", step_label)
            else:
                logger.warning("[EXEC] ✗ FAILED — %s", step_label)
                # Check replan trigger on failure.
                if self.replan_trigger is not None and graph is not None and goal is not None:
                    current_state = {
                        "completed_steps": completed_steps,
                        "failed_step": {
                            "source": edge.source_host,
                            "target": edge.target_host,
                            "cve_id": edge.cve_id,
                            "error": result.output[-200:],
                        },
                        "new_info": "",
                        "remaining_goal": goal,
                    }
                    new_path = self.replan_trigger.check_and_replan(
                        current_state, graph, edge.target_host, goal, step_start
                    )
                    if new_path is not None:
                        logger.info("[EXEC] Replanning: substituting remaining path.")
                        remaining = self.run(new_path, graph, goal)
                        results.extend(remaining)
                        return results

            # Post-step delay.
            post_delay = float(
                max(_MIN_DELAY, min(_MAX_DELAY, random.gauss(1.5, _DELAY_STD / 2)))
            )
            time.sleep(post_delay)

        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _dispatch(self, edge: AttackEdge) -> ExecutionResult:
        """Select and invoke the right executor for an attack step.

        Metasploit-module edges go to ``msf_executor``; everything else
        falls back to ``ssh_executor`` or a simulated dry-run.

        Args:
            edge: Attack step to execute.

        Returns:
            ``ExecutionResult`` from the executor.
        """
        if self.msf_executor is not None and edge.exploit_module.startswith("exploit/"):
            return self.msf_executor.execute_step(edge)
        if self.ssh_executor is not None:
            return self.ssh_executor.execute_step(edge)

        # Dry-run simulation (no executors configured).
        logger.debug("[DRY-RUN] Simulating step: %s", edge.cve_id)
        return ExecutionResult(
            success=True,
            session_id="sim-session",
            output=f"[DRY-RUN] {edge.cve_id} on {edge.target_host} simulated successfully.",
            duration_seconds=random.gauss(5.0, 1.0),
        )

    @staticmethod
    def _edge_port(edge: AttackEdge) -> str:
        """Derive a port string from edge preconditions for nmap recon.

        Args:
            edge: Attack edge.

        Returns:
            Port number string, or ``"*"`` if not determinable.
        """
        for pre in edge.preconditions:
            if "port_" in pre and "_open" in pre:
                return pre.replace("port_", "").replace("_open", "")
        return "*"
