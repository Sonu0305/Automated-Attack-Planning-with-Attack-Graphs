"""Unit tests for planners/llm_planner.py.

All Groq API calls are mocked so tests run without network access or
a real API key.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import networkx as nx
import pytest

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from graph.models import AttackEdge
from planners.base_planner import NoPlanFoundError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_edge(src: str, tgt: str, cvss: float = 9.0) -> AttackEdge:
    """Create a minimal AttackEdge for test graphs.

    Args:
        src: Source host IP.
        tgt: Target host IP.
        cvss: CVSS score.

    Returns:
        ``AttackEdge`` instance.
    """
    return AttackEdge(
        source_host=src,
        target_host=tgt,
        cve_id="CVE-2017-0144",
        exploit_module="exploit/windows/smb/ms17_010_eternalblue",
        preconditions=["has_network_access"],
        postconditions=["has_shell_on_target"],
        cvss_score=cvss,
        detection_weight=0.5,
        service_name="smb",
    )


def build_test_graph() -> nx.DiGraph:
    """Build a minimal 2-node attack graph for LLM planner tests.

    Returns:
        DiGraph with an edge 192.168.56.10→192.168.56.30.
    """
    G = nx.DiGraph()
    G.add_node("192.168.56.10")
    G.add_node("192.168.56.30")
    G.add_edge(
        "192.168.56.10",
        "192.168.56.30",
        data=_make_edge("192.168.56.10", "192.168.56.30"),
    )
    return G


def _mock_response(content: str) -> MagicMock:
    """Create a minimal mock object matching the Groq chat response.

    Args:
        content: The text content of the first choice's message.

    Returns:
        MagicMock with the required attribute tree.
    """
    mock = MagicMock()
    mock.choices[0].message.content = content
    return mock


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestLLMPlanner:
    """Tests for LLMPlanner with mocked Groq calls."""

    START = "192.168.56.10"
    GOAL  = "192.168.56.30"

    _VALID_STEP = json.dumps([
        {
            "source_ip": "192.168.56.10",
            "target_ip": "192.168.56.30",
            "cve_id": "CVE-2017-0144",
            "exploit_module": "exploit/windows/smb/ms17_010_eternalblue",
            "reason": "SMBv1 is enabled and unpatched.",
        }
    ])

    def _make_planner(self):
        """Return an LLMPlanner with a mocked Groq client.

        Returns:
            Tuple of ``(LLMPlanner, mock_create)``.
        """
        with patch("planners.llm_planner.Groq") as mock_groq_cls:
            from planners.llm_planner import LLMPlanner
            planner = LLMPlanner(api_key="test-key-not-real", max_retries=3)
            return planner, planner._client.chat.completions.create

    @patch("planners.llm_planner.Groq")
    def test_parses_valid_json_response(self, mock_groq_cls):
        """LLMPlanner must return AttackEdge list from a valid JSON response."""
        from planners.llm_planner import LLMPlanner

        planner = LLMPlanner(api_key="test-key")
        planner._client.chat.completions.create.return_value = _mock_response(
            self._VALID_STEP
        )

        G = build_test_graph()
        path = planner.plan(G, self.START, self.GOAL)

        assert len(path) == 1
        assert path[0].cve_id == "CVE-2017-0144"
        assert path[0].source_host == self.START
        assert path[0].target_host == self.GOAL

    @patch("planners.llm_planner.Groq")
    def test_retries_on_invalid_json(self, mock_groq_cls):
        """LLMPlanner must retry when the first response is not valid JSON."""
        from planners.llm_planner import LLMPlanner

        planner = LLMPlanner(api_key="test-key", max_retries=3)
        planner._client.chat.completions.create.side_effect = [
            _mock_response("not valid json at all {{"),
            _mock_response(self._VALID_STEP),
        ]

        G = build_test_graph()
        path = planner.plan(G, self.START, self.GOAL)

        assert planner._client.chat.completions.create.call_count == 2
        assert len(path) == 1

    @patch("planners.llm_planner.Groq")
    def test_raises_after_max_retries(self, mock_groq_cls):
        """LLMPlanner must raise NoPlanFoundError after exhausting all retries."""
        from planners.llm_planner import LLMPlanner

        planner = LLMPlanner(api_key="test-key", max_retries=2)
        planner._client.chat.completions.create.return_value = _mock_response(
            "not json"
        )

        G = build_test_graph()
        with pytest.raises(NoPlanFoundError):
            planner.plan(G, self.START, self.GOAL)

        assert planner._client.chat.completions.create.call_count == 2

    @patch("planners.llm_planner.Groq")
    def test_rejects_hallucinated_edges(self, mock_groq_cls):
        """LLMPlanner must retry when the response contains non-existent edges."""
        from planners.llm_planner import LLMPlanner

        hallucinated = json.dumps([
            {
                "source_ip": "192.168.56.10",
                "target_ip": "10.0.0.99",  # Not in graph.
                "cve_id": "CVE-2021-99999",
                "exploit_module": "exploit/fake/not_real",
                "reason": "Hallucinated edge.",
            }
        ])
        planner = LLMPlanner(api_key="test-key", max_retries=2)
        planner._client.chat.completions.create.return_value = _mock_response(
            hallucinated
        )

        G = build_test_graph()
        with pytest.raises(NoPlanFoundError):
            planner.plan(G, self.START, self.GOAL)

    @patch("planners.llm_planner.Groq")
    def test_strips_markdown_fences(self, mock_groq_cls):
        """LLMPlanner must handle JSON wrapped in markdown code fences."""
        from planners.llm_planner import LLMPlanner

        fenced = f"```json\n{self._VALID_STEP}\n```"
        planner = LLMPlanner(api_key="test-key")
        planner._client.chat.completions.create.return_value = _mock_response(fenced)

        G = build_test_graph()
        path = planner.plan(G, self.START, self.GOAL)
        assert len(path) == 1

    @patch("planners.llm_planner.Groq")
    def test_plan_with_context_includes_state(self, mock_groq_cls):
        """plan_with_context must include current_state in the API messages."""
        from planners.llm_planner import LLMPlanner

        planner = LLMPlanner(api_key="test-key")
        planner._client.chat.completions.create.return_value = _mock_response(
            self._VALID_STEP
        )

        G = build_test_graph()
        state = {
            "completed_steps": [],
            "failed_step": None,
            "new_info": "IDS alert triggered on 192.168.56.10",
            "remaining_goal": self.GOAL,
        }
        path = planner.plan_with_context(G, self.START, self.GOAL, state)

        # Check that the context was included in the messages sent.
        call_args = planner._client.chat.completions.create.call_args
        messages = call_args.kwargs.get("messages")
        if messages is None and call_args.args:
            messages = call_args.args[0]
        if messages is None:
            messages = []
        message_contents = [m.get("content", "") for m in (messages or [])]
        assert any("IDS alert" in c for c in message_contents)

        assert len(path) == 1

    @patch("planners.llm_planner.Groq", None)
    def test_offline_fallback_runs_without_groq_or_api_key(self):
        """LLMPlanner must still produce a valid path in offline fallback mode."""
        from planners.llm_planner import LLMPlanner

        planner = LLMPlanner(api_key="")
        G = build_test_graph()

        path = planner.plan(G, self.START, self.GOAL)

        assert planner.backend == "offline"
        assert len(path) == 1
        assert path[0].source_host == self.START
        assert path[0].target_host == self.GOAL
