"""CALDERA REST API executor adapter.

Dispatches attack abilities to a running MITRE CALDERA server via its
REST API.  Maps ``AttackEdge`` objects to CALDERA ability IDs and
monitors operation status until completion.

Reference:
    MITRE CALDERA: https://caldera.mitre.org/
"""

from __future__ import annotations

import logging
import time
from typing import Optional

import requests

from graph.models import AttackEdge, ExecutionResult
from executor.base_executor import BaseExecutor

logger = logging.getLogger(__name__)

_POLL_INTERVAL = 3.0   # seconds between operation status polls
_POLL_TIMEOUT = 120.0  # maximum seconds to wait for operation

# Maps CVE IDs to approximate CALDERA ability IDs (ATT&CK technique mapping).
_CVE_TO_ABILITY: dict[str, str] = {
    "CVE-2017-0144": "0a0a62b0-6ae2-4e4e-8f0a-0a0a0a0a0a01",  # SMB lateral movement
    "CVE-2021-44228": "0a0a62b0-6ae2-4e4e-8f0a-0a0a0a0a0a02",  # Log4Shell RCE
    "CVE-2021-3156":  "0a0a62b0-6ae2-4e4e-8f0a-0a0a0a0a0a03",  # Sudo privesc
    "CVE-2019-0708":  "0a0a62b0-6ae2-4e4e-8f0a-0a0a0a0a0a04",  # BlueKeep RCE
    "CVE-2018-10933": "0a0a62b0-6ae2-4e4e-8f0a-0a0a0a0a0a05",  # libssh auth bypass
}

_DEFAULT_ABILITY = "0a0a62b0-6ae2-4e4e-8f0a-0a0a0a0a0a00"


class CalderaExecutor(BaseExecutor):
    """Execute CALDERA abilities via the REST API.

    Attributes:
        base_url: CALDERA server base URL.
        api_key: CALDERA REST API key.
        adversary_id: CALDERA adversary profile to use.
    """

    def __init__(self, config: dict) -> None:
        """Initialise the CALDERA executor.

        Args:
            config: Dict with keys:
                - ``url`` (str): CALDERA server URL, e.g. ``"http://localhost:8888"``.
                - ``api_key`` (str): REST API key.
                - ``adversary_id`` (str): Adversary profile ID.

        Raises:
            ConnectionError: If the CALDERA server is unreachable.
        """
        self.base_url = config.get("url", "http://localhost:8888").rstrip("/")
        self.api_key = config["api_key"]
        self.adversary_id = config.get("adversary_id", "ad-hoc")

        self._session = requests.Session()
        self._session.headers.update(
            {"KEY": self.api_key, "Content-Type": "application/json"}
        )

        # Verify connectivity.
        try:
            resp = self._session.get(f"{self.base_url}/api/v2/health", timeout=5)
            resp.raise_for_status()
            logger.info("Connected to CALDERA at %s", self.base_url)
        except requests.exceptions.RequestException as exc:
            raise ConnectionError(
                f"Cannot connect to CALDERA at {self.base_url}: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # BaseExecutor interface
    # ------------------------------------------------------------------

    def execute_step(self, edge: AttackEdge) -> ExecutionResult:
        """Dispatch a CALDERA ability for the given attack edge.

        Creates a new operation, monitors it to completion, and returns
        the aggregated result.

        Args:
            edge: Attack edge to execute.

        Returns:
            ``ExecutionResult`` with success flag, output, and timing.
        """
        ability_id = _CVE_TO_ABILITY.get(edge.cve_id, _DEFAULT_ABILITY)
        start_time = time.time()

        try:
            operation_id = self._start_operation(
                ability_id=ability_id,
                target_ip=edge.target_host,
            )
            if operation_id is None:
                return ExecutionResult(
                    success=False,
                    session_id=None,
                    output="Failed to create CALDERA operation.",
                    duration_seconds=time.time() - start_time,
                )

            success, output = self._wait_for_operation(operation_id)
            duration = time.time() - start_time

            return ExecutionResult(
                success=success,
                session_id=operation_id if success else None,
                output=output,
                duration_seconds=duration,
            )

        except Exception as exc:
            logger.error("CALDERA execution error for %s: %s", edge.cve_id, exc)
            return ExecutionResult(
                success=False,
                session_id=None,
                output=f"CALDERA error: {exc}",
                duration_seconds=time.time() - start_time,
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _start_operation(
        self, ability_id: str, target_ip: str
    ) -> Optional[str]:
        """Create a new CALDERA operation targeting a specific host.

        Args:
            ability_id: CALDERA ability UUID to execute.
            target_ip: Target host IP (used in operation name).

        Returns:
            Operation ID string, or ``None`` on failure.
        """
        payload = {
            "name": f"autoattack-{target_ip}-{ability_id[:8]}",
            "adversary": {"adversary_id": self.adversary_id},
            "auto_close": True,
            "state": "running",
        }
        try:
            resp = self._session.post(
                f"{self.base_url}/api/v2/operations",
                json=payload,
                timeout=10,
            )
            resp.raise_for_status()
            return resp.json().get("id")
        except requests.exceptions.RequestException as exc:
            logger.error("Failed to start CALDERA operation: %s", exc)
            return None

    def _wait_for_operation(
        self, operation_id: str
    ) -> tuple[bool, str]:
        """Poll an operation until it completes or the timeout elapses.

        Args:
            operation_id: CALDERA operation ID to monitor.

        Returns:
            Tuple of ``(success: bool, output: str)``.
        """
        deadline = time.time() + _POLL_TIMEOUT
        output_lines: list[str] = []

        while time.time() < deadline:
            try:
                resp = self._session.get(
                    f"{self.base_url}/api/v2/operations/{operation_id}",
                    timeout=5,
                )
                resp.raise_for_status()
                data = resp.json()
                state = data.get("state", "")
                output_lines.append(f"State: {state}")

                if state == "finished":
                    facts = data.get("collected_facts", [])
                    output_lines.extend(
                        f"Fact: {f.get('name')} = {f.get('value')}" for f in facts
                    )
                    return True, "\n".join(output_lines)

                if state in ("failed", "cleanup"):
                    return False, "\n".join(output_lines)

            except requests.exceptions.RequestException as exc:
                logger.warning("CALDERA poll error: %s", exc)

            time.sleep(_POLL_INTERVAL)

        return False, "CALDERA operation timed out.\n" + "\n".join(output_lines)
