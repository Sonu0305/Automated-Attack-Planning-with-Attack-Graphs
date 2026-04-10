"""SSH executor with human-like PTY interaction (AttackMate-style).

Uses Paramiko to establish an SSH connection and optionally invoke a PTY
channel with character-by-character typing to simulate realistic human
operator behaviour.  Gaussian-distributed delays between characters and
between commands mimic the timing patterns found in human penetration
testing sessions.

Reference:
    Cramer et al. (2025). AttackMate: Realistic Emulation and Automation
    of Cyber Attack Scenarios. IEEE S&P.
"""

from __future__ import annotations

import logging
import random
import time
from typing import Optional

from graph.models import AttackEdge, ExecutionResult
from executor.base_executor import BaseExecutor

logger = logging.getLogger(__name__)

_CONNECT_TIMEOUT = 15  # seconds
_COMMAND_TIMEOUT = 30  # seconds


class SSHExecutor(BaseExecutor):
    """Execute commands on remote hosts via SSH with human-like timing.

    Attributes:
        hostname: Target host IP or FQDN.
        username: SSH username.
        password: SSH password (used if no key provided).
        key_filename: Path to a private key file for key-based auth.
        human_typing: If ``True``, simulate character-by-character typing.
    """

    def __init__(
        self,
        hostname: str,
        username: str,
        password: Optional[str] = None,
        key_filename: Optional[str] = None,
        port: int = 22,
        human_typing: bool = True,
    ) -> None:
        """Initialise the SSH executor.

        Args:
            hostname: Target IP or hostname.
            username: SSH username.
            password: SSH password. Mutually exclusive with key_filename.
            key_filename: Path to SSH private key file.
            port: SSH port number.
            human_typing: Whether to add character-level typing delays.
        """
        import paramiko  # deferred import

        self.hostname = hostname
        self.username = username
        self.password = password
        self.key_filename = key_filename
        self.port = port
        self.human_typing = human_typing

        self._ssh = paramiko.SSHClient()
        self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._connected = False

    # ------------------------------------------------------------------
    # BaseExecutor interface
    # ------------------------------------------------------------------

    def setup(self) -> None:
        """Establish the SSH connection.

        Raises:
            ConnectionError: If the SSH connection fails.
        """
        try:
            self._ssh.connect(
                hostname=self.hostname,
                port=self.port,
                username=self.username,
                password=self.password,
                key_filename=self.key_filename,
                timeout=_CONNECT_TIMEOUT,
            )
            self._connected = True
            logger.info("SSH connected to %s@%s:%d", self.username, self.hostname, self.port)
        except Exception as exc:
            raise ConnectionError(f"SSH connection to {self.hostname} failed: {exc}") from exc

    def teardown(self) -> None:
        """Close the SSH connection."""
        if self._connected:
            self._ssh.close()
            self._connected = False
            logger.info("SSH disconnected from %s", self.hostname)

    def execute_step(self, edge: AttackEdge) -> ExecutionResult:
        """Execute an SSH-based attack step.

        For SSH-based exploits, runs the exploit's associated shell
        command through an interactive channel.

        Args:
            edge: Attack edge; the command is inferred from postconditions
                and description.

        Returns:
            ``ExecutionResult`` with success, output, and timing.
        """
        command = self._infer_command(edge)
        return self.run_command(command)

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def run_command(self, command: str, timeout: int = _COMMAND_TIMEOUT) -> ExecutionResult:
        """Run a shell command over SSH and capture output.

        Args:
            command: Shell command string to execute.
            timeout: Seconds to wait for command completion.

        Returns:
            ``ExecutionResult`` with success, output, and duration.
        """
        if not self._connected:
            self.setup()

        start = time.time()
        try:
            if self.human_typing:
                output = self._run_with_pty(command, timeout)
            else:
                stdin, stdout, stderr = self._ssh.exec_command(command, timeout=timeout)
                stdout.channel.recv_exit_status()
                output = stdout.read().decode(errors="replace")
                err = stderr.read().decode(errors="replace")
                if err:
                    output += f"\n[STDERR] {err}"

            duration = time.time() - start
            success = "error" not in output.lower() and "permission denied" not in output.lower()
            return ExecutionResult(
                success=success,
                session_id=None,
                output=output,
                duration_seconds=duration,
            )
        except Exception as exc:
            duration = time.time() - start
            logger.error("SSH command error on %s: %s", self.hostname, exc)
            return ExecutionResult(
                success=False,
                session_id=None,
                output=f"SSH error: {exc}",
                duration_seconds=duration,
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_with_pty(self, command: str, timeout: int) -> str:
        """Run a command via a PTY channel with simulated typing delays.

        Args:
            command: Shell command to execute.
            timeout: Maximum seconds to wait for output.

        Returns:
            Captured output string.
        """
        channel = self._ssh.invoke_shell()
        channel.settimeout(timeout)

        # Wait for the initial prompt.
        time.sleep(0.5)
        _ = self._drain(channel)

        # Type the command character by character.
        for char in command:
            channel.send(char)
            # Human inter-keystroke delay: ~80ms mean, 30ms std.
            delay = max(0.02, random.gauss(0.08, 0.03))
            time.sleep(delay)

        # Send Enter.
        channel.send("\n")

        # Collect output until prompt reappears or timeout.
        output_parts: list[str] = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            if channel.recv_ready():
                chunk = channel.recv(4096).decode(errors="replace")
                output_parts.append(chunk)
                if chunk.endswith("$ ") or chunk.endswith("# "):
                    break
            else:
                time.sleep(0.1)

        channel.close()
        return "".join(output_parts)

    @staticmethod
    def _drain(channel: object) -> str:
        """Read and discard any pending data from an SSH channel.

        Args:
            channel: Paramiko channel.

        Returns:
            Discarded data as a string.
        """
        buf: list[str] = []
        time.sleep(0.2)
        while channel.recv_ready():  # type: ignore[union-attr]
            buf.append(channel.recv(4096).decode(errors="replace"))  # type: ignore[union-attr]
        return "".join(buf)

    @staticmethod
    def _infer_command(edge: AttackEdge) -> str:
        """Derive a shell command from an AttackEdge description.

        Args:
            edge: The attack edge.

        Returns:
            A shell command string appropriate for the edge's service.
        """
        # Simple heuristic mapping service type to command.
        service = edge.service_name.lower()
        if "sudo" in edge.exploit_module:
            return "sudo -l && sudo /bin/bash -i"
        if service == "ssh":
            return f"ssh-keyscan {edge.target_host}"
        return f"echo 'Executed {edge.cve_id} on {edge.target_host}'"
