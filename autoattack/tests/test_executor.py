"""Unit tests for executor/metasploit_executor.py and executor/playbook_runner.py.

All Metasploit RPC calls are mocked.  Tests validate the polling logic,
session-open detection, and failure handling.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from graph.models import AttackEdge, ExecutionResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_edge(
    src: str = "192.168.56.10",
    tgt: str = "192.168.56.30",
    cvss: float = 9.3,
    cve: str = "CVE-2017-0144",
    module: str = "exploit/windows/smb/ms17_010_eternalblue",
) -> AttackEdge:
    """Create a test AttackEdge.

    Args:
        src: Source host.
        tgt: Target host.
        cvss: CVSS score.
        cve: CVE identifier.
        module: Metasploit module path.

    Returns:
        ``AttackEdge`` instance.
    """
    return AttackEdge(
        source_host=src,
        target_host=tgt,
        cve_id=cve,
        exploit_module=module,
        preconditions=["has_network_access", "port_445_open"],
        postconditions=["has_shell_on_target", "is_admin"],
        cvss_score=cvss,
        detection_weight=0.92,
        service_name="smb",
    )


def _mock_msf_client(console_output: str) -> MagicMock:
    """Build a mock pymetasploit3 MsfRpcClient.

    The mock console's read() method returns the given output string
    wrapped in the expected dict format.

    Args:
        console_output: Output string the mock console will return.

    Returns:
        MagicMock mimicking MsfRpcClient.
    """
    mock_client = MagicMock()
    mock_console = MagicMock()
    mock_console.cid = "mock-console-1"
    mock_console.read.return_value = {"data": console_output}
    mock_client.consoles.console.return_value = mock_console
    mock_client.sessions.list = {}
    return mock_client


# ---------------------------------------------------------------------------
# MetasploitExecutor tests
# ---------------------------------------------------------------------------


class TestMetasploitExecutor:
    """Tests for MetasploitExecutor with mocked pymetasploit3."""

    @patch("pymetasploit3.msfrpc.MsfRpcClient")
    def test_execute_step_success_meterpreter(self, mock_msf_cls):
        """Executor must detect Meterpreter session open → success=True."""
        from executor.metasploit_executor import MetasploitExecutor

        output = "Meterpreter session 1 opened (192.168.56.10:4444 -> 192.168.56.30:49152)"
        mock_msf_cls.return_value = _mock_msf_client(output)

        executor = MetasploitExecutor(
            {"password": "test", "host": "127.0.0.1", "port": 55553}
        )
        edge = _make_edge()
        result = executor.execute_step(edge)

        assert result.success is True
        assert result.session_id == "1"

    @patch("pymetasploit3.msfrpc.MsfRpcClient")
    def test_execute_step_failure_no_session(self, mock_msf_cls):
        """Executor must return success=False when exploit completes without session."""
        from executor.metasploit_executor import MetasploitExecutor

        output = "Exploit completed, but no session was created."
        mock_msf_cls.return_value = _mock_msf_client(output)

        executor = MetasploitExecutor(
            {"password": "test", "host": "127.0.0.1", "port": 55553}
        )
        edge = _make_edge()
        result = executor.execute_step(edge)

        assert result.success is False
        assert result.session_id is None

    @patch("pymetasploit3.msfrpc.MsfRpcClient")
    def test_execute_step_failure_connection_refused(self, mock_msf_cls):
        """Executor must return success=False on 'Connection refused'."""
        from executor.metasploit_executor import MetasploitExecutor

        output = "Connection refused by 192.168.56.30:445"
        mock_msf_cls.return_value = _mock_msf_client(output)

        executor = MetasploitExecutor(
            {"password": "test", "host": "127.0.0.1", "port": 55553}
        )
        result = executor.execute_step(_make_edge())

        assert result.success is False

    @patch("pymetasploit3.msfrpc.MsfRpcClient")
    def test_result_has_duration(self, mock_msf_cls):
        """ExecutionResult must have a positive duration_seconds."""
        from executor.metasploit_executor import MetasploitExecutor

        output = "Exploit completed, but no session was created."
        mock_msf_cls.return_value = _mock_msf_client(output)

        executor = MetasploitExecutor({"password": "test", "host": "127.0.0.1", "port": 55553})
        result = executor.execute_step(_make_edge())

        assert result.duration_seconds >= 0.0

    @patch("pymetasploit3.msfrpc.MsfRpcClient")
    def test_get_sessions_empty(self, mock_msf_cls):
        """get_sessions must return an empty list when no sessions exist."""
        from executor.metasploit_executor import MetasploitExecutor

        mock_client = MagicMock()
        mock_client.sessions.list = {}
        mock_msf_cls.return_value = mock_client

        executor = MetasploitExecutor({"password": "test"})
        sessions = executor.get_sessions()
        assert sessions == []

    @patch("pymetasploit3.msfrpc.MsfRpcClient")
    def test_get_sessions_with_active_session(self, mock_msf_cls):
        """get_sessions must return correct dicts for active sessions."""
        from executor.metasploit_executor import MetasploitExecutor

        mock_client = MagicMock()
        mock_client.sessions.list = {
            "1": {"type": "meterpreter", "target_host": "192.168.56.30"}
        }
        mock_msf_cls.return_value = mock_client

        executor = MetasploitExecutor({"password": "test"})
        sessions = executor.get_sessions()

        assert len(sessions) == 1
        assert sessions[0]["id"] == "1"
        assert sessions[0]["target"] == "192.168.56.30"


# ---------------------------------------------------------------------------
# PlaybookRunner tests
# ---------------------------------------------------------------------------


class TestPlaybookRunner:
    """Tests for PlaybookRunner's playbook generation and dry-run execution."""

    def test_generate_playbook_creates_yaml_file(self, tmp_path):
        """generate_playbook must create a YAML file in the log directory."""
        from executor.playbook_runner import PlaybookRunner

        runner = PlaybookRunner(log_dir=str(tmp_path))
        path_edges = [_make_edge()]
        yaml_path = runner.generate_playbook(
            path_edges,
            config={"attacker_ip": "192.168.56.10"},
            planner_name="astar",
        )

        assert Path(yaml_path).exists()
        content = Path(yaml_path).read_text()
        assert "CVE-2017-0144" in content
        assert "192.168.56.30" in content

    def test_run_dry_returns_results(self, tmp_path):
        """run() without executors configured must still return ExecutionResult list."""
        from executor.playbook_runner import PlaybookRunner

        runner = PlaybookRunner(log_dir=str(tmp_path))
        path_edges = [_make_edge()]
        results = runner.run(path_edges)

        assert len(results) == 1
        assert isinstance(results[0], ExecutionResult)

    def test_run_writes_jsonl_log(self, tmp_path):
        """run() must append entries to execution_log.jsonl."""
        from executor.playbook_runner import PlaybookRunner

        runner = PlaybookRunner(log_dir=str(tmp_path))
        runner.run([_make_edge()])

        log_file = tmp_path / "execution_log.jsonl"
        assert log_file.exists()
        lines = [l for l in log_file.read_text().splitlines() if l.strip()]
        assert len(lines) >= 1

        entry = json.loads(lines[0])
        assert "step" in entry
        assert "success" in entry
        assert "duration" in entry

    def test_edge_port_helper_smb(self):
        """_edge_port must extract '445' from SMB edge preconditions."""
        from executor.playbook_runner import PlaybookRunner

        edge = _make_edge()
        assert PlaybookRunner._edge_port(edge) == "445"
