"""LLM-guided attack planner based on Incalmo (Singer et al., 2025).

Serialises the attack graph to a text description, asks an LLM (OpenAI
GPT-4o by default) to produce a JSON attack plan, validates every step
against the actual graph edges, and retries with error feedback on
failure.

Supports mid-run replanning via ``plan_with_context()`` which includes
prior execution context (completed steps, failed step, IDS alert info)
in the prompt.

Reference:
    Singer et al. (2025). Incalmo: An Autonomous LLM-assisted System for
    Red Teaming Multi-Host Networks. USENIX Security.
    https://arxiv.org/abs/2501.16466
"""

from __future__ import annotations

import json
import logging
import time
from typing import Optional

import networkx as nx

from graph.models import AttackEdge
from planners.base_planner import BasePlanner, NoPlanFoundError

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are a red team attack planner. Given a network attack graph, output a \
JSON array of attack steps from the start IP to the goal IP.

Each step must be a JSON object with exactly these keys:
  "source_ip"      – IP of the already-compromised host
  "target_ip"      – IP of the host to exploit
  "cve_id"         – CVE identifier of the vulnerability
  "exploit_module" – Metasploit module path
  "reason"         – One-sentence justification

Rules:
1. Only use edges that EXIST in the graph description below.
2. The path must be CONNECTED: source_ip of step N+1 equals target_ip of step N.
3. The first step must start from the start IP.
4. The last step must reach the goal IP.
5. Output ONLY the raw JSON array. No prose, no markdown, no code fences.
"""

_RETRY_PROMPT_TEMPLATE = """\
Your previous response was invalid:
Error: {error}

Fix the JSON and output ONLY the corrected JSON array.\
"""


class LLMPlanner(BasePlanner):
    """GPT-4o guided planner that calls the OpenAI Chat Completions API.

    Attributes:
        model: OpenAI model identifier.
        max_retries: Maximum number of parse/validation retry attempts.
    """

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4o",
        max_retries: int = 3,
    ) -> None:
        """Initialise the LLM planner with API credentials.

        Args:
            api_key: OpenAI API key.
            model: Chat model identifier, e.g. ``"gpt-4o"``.
            max_retries: How many times to retry on bad JSON or invalid
                edges before raising ``NoPlanFoundError``.
        """
        import openai  # deferred import — optional dependency

        self._client = openai.OpenAI(api_key=api_key)
        self.model = model
        self.max_retries = max_retries

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def plan(
        self, graph: nx.DiGraph, start: str, goal: str
    ) -> list[AttackEdge]:
        """Ask the LLM to plan an attack path from ``start`` to ``goal``.

        Args:
            graph: Directed attack graph.
            start: Attacker-controlled start host IP.
            goal: Target host IP.

        Returns:
            Ordered list of ``AttackEdge`` objects.

        Raises:
            NoPlanFoundError: If the LLM cannot produce a valid plan
                within ``max_retries`` attempts.
        """
        graph_text = _serialise_graph(graph)
        user_msg = (
            f"Attack graph:\n{graph_text}\n\n"
            f"Plan an attack from {start} to {goal}."
        )
        messages = [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ]
        return self._call_with_retry(graph, start, goal, messages)

    def plan_with_context(
        self,
        graph: nx.DiGraph,
        start: str,
        goal: str,
        current_state: dict,
    ) -> list[AttackEdge]:
        """Replan mid-run incorporating completed steps and IDS feedback.

        The ``current_state`` dict includes:
        - ``completed_steps``: List of ``{source, target, cve_id}`` dicts.
        - ``failed_step``: ``{source, target, cve_id, error}`` or ``None``.
        - ``new_info``: String summary of new intelligence (e.g. IDS alerts).
        - ``remaining_goal``: IP of the still-unreached goal.

        Args:
            graph: Directed attack graph.
            start: Current attacker-controlled host IP.
            goal: Target host IP.
            current_state: Dict describing execution context so far.

        Returns:
            New ordered list of ``AttackEdge`` objects from ``start`` to
            ``goal``.

        Raises:
            NoPlanFoundError: If the LLM cannot produce a valid plan.
        """
        graph_text = _serialise_graph(graph)
        user_msg = (
            f"Attack graph:\n{graph_text}\n\n"
            f"Plan an attack from {start} to {goal}."
        )
        context_msg = (
            "Current execution context:\n"
            + json.dumps(current_state, indent=2)
            + "\n\nGenerate a NEW plan that avoids the failed/detected route."
        )
        messages = [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
            {"role": "user", "content": context_msg},
        ]
        return self._call_with_retry(graph, start, goal, messages)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _call_with_retry(
        self,
        graph: nx.DiGraph,
        start: str,
        goal: str,
        messages: list[dict],
    ) -> list[AttackEdge]:
        """Call the LLM API and retry on parse/validation failures.

        Args:
            graph: Attack graph for edge validation.
            start: Expected source of the first step.
            goal: Expected target of the last step.
            messages: Initial message list to send to the API.

        Returns:
            Validated list of ``AttackEdge`` objects.

        Raises:
            NoPlanFoundError: After all retries are exhausted.
        """
        last_error = "Unknown error"
        for attempt in range(self.max_retries):
            raw = self._call_api(messages)
            try:
                steps = _parse_json_steps(raw)
                path = _validate_and_map(steps, graph, start, goal)
                logger.info(
                    "LLM produced valid plan: %d steps (attempt %d)",
                    len(path),
                    attempt + 1,
                )
                return path
            except (json.JSONDecodeError, ValueError, NoPlanFoundError) as exc:
                last_error = str(exc)
                logger.warning(
                    "LLM plan attempt %d/%d invalid: %s",
                    attempt + 1,
                    self.max_retries,
                    last_error,
                )
                # Append error feedback and LLM's bad output to the thread.
                messages.append({"role": "assistant", "content": raw})
                messages.append(
                    {
                        "role": "user",
                        "content": _RETRY_PROMPT_TEMPLATE.format(error=last_error),
                    }
                )
                if attempt < self.max_retries - 1:
                    time.sleep(1)

        raise NoPlanFoundError(
            f"LLM could not produce a valid plan after {self.max_retries} attempts. "
            f"Last error: {last_error}"
        )

    def _call_api(self, messages: list[dict]) -> str:
        """Make a single OpenAI Chat Completions API call.

        Args:
            messages: Full message history for the API call.

        Returns:
            Raw text content of the first choice's message.

        Raises:
            NoPlanFoundError: If the API call fails or returns empty content.
        """
        try:
            response = self._client.chat.completions.create(
                model=self.model,
                messages=messages,  # type: ignore[arg-type]
                temperature=0.2,
                timeout=60,
            )
            content = response.choices[0].message.content or ""
            return content.strip()
        except Exception as exc:
            raise NoPlanFoundError(f"OpenAI API error: {exc}") from exc


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _serialise_graph(graph: nx.DiGraph) -> str:
    """Convert the attack graph to a compact text description for the LLM.

    Args:
        graph: Directed attack graph.

    Returns:
        Multi-line string listing hosts and attack edges.
    """
    lines: list[str] = []

    for node_id, node_data in graph.nodes(data=True):
        host = node_data.get("data")
        if host is not None:
            svc_names = ", ".join(s.name for s in host.services) if host.services else "none"
            lines.append(f"HOST {host.ip} ({host.os}): services=[{svc_names}]")
        else:
            lines.append(f"HOST {node_id}")

    for src, tgt, edge_data in graph.edges(data=True):
        edge: AttackEdge = edge_data.get("data")
        if edge is not None:
            lines.append(
                f"EDGE {src}->{tgt}: CVE={edge.cve_id}, "
                f"module={edge.exploit_module}, CVSS={edge.cvss_score:.1f}, "
                f"service={edge.service_name}"
            )

    return "\n".join(lines)


def _parse_json_steps(raw: str) -> list[dict]:
    """Extract a JSON array of attack steps from LLM output.

    Strips markdown code fences if present before parsing.

    Args:
        raw: Raw text content from the LLM.

    Returns:
        List of step dicts.

    Raises:
        json.JSONDecodeError: If the content cannot be parsed.
        ValueError: If the parsed value is not a list.
    """
    text = raw.strip()
    # Strip markdown code fences.
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(
            line for line in lines if not line.startswith("```")
        ).strip()

    steps = json.loads(text)
    if not isinstance(steps, list):
        raise ValueError("LLM output is not a JSON array.")
    return steps


def _validate_and_map(
    steps: list[dict],
    graph: nx.DiGraph,
    start: str,
    goal: str,
) -> list[AttackEdge]:
    """Validate LLM step dicts and map them to AttackEdge objects.

    Checks that every ``(source_ip, target_ip)`` pair exists as an edge
    in the graph and that the CVE ID matches.

    Args:
        steps: List of step dicts from the LLM.
        graph: Attack graph for validation.
        start: Expected source IP of the first step.
        goal: Expected target IP of the last step.

    Returns:
        Ordered list of validated ``AttackEdge`` objects.

    Raises:
        ValueError: If any step references a non-existent edge.
        NoPlanFoundError: If the path does not start at ``start`` or
            end at ``goal``.
    """
    if not steps:
        raise NoPlanFoundError("LLM returned an empty plan.")

    required_keys = {"source_ip", "target_ip", "cve_id", "exploit_module"}
    for i, step in enumerate(steps):
        missing = required_keys - set(step.keys())
        if missing:
            raise ValueError(f"Step {i} missing keys: {missing}")

    if steps[0]["source_ip"] != start:
        raise NoPlanFoundError(
            f"Plan starts at '{steps[0]['source_ip']}', expected '{start}'."
        )
    if steps[-1]["target_ip"] != goal:
        raise NoPlanFoundError(
            f"Plan ends at '{steps[-1]['target_ip']}', expected '{goal}'."
        )

    path: list[AttackEdge] = []
    for step in steps:
        src = step["source_ip"]
        tgt = step["target_ip"]
        cve = step["cve_id"]

        if not graph.has_edge(src, tgt):
            raise ValueError(f"Edge {src}->{tgt} does not exist in the graph.")

        edge: AttackEdge = graph.edges[src, tgt]["data"]
        if edge.cve_id != cve:
            # Accept if the module matches instead — LLM may swap cve/module.
            if edge.exploit_module != step.get("exploit_module", ""):
                raise ValueError(
                    f"Edge {src}->{tgt} has CVE {edge.cve_id}, not {cve}."
                )
        path.append(edge)

    return path
