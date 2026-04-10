"""Core data models for the AutoAttack system.

All domain objects are immutable-friendly dataclasses that flow through
every layer of the pipeline: graph construction → planning → execution →
evaluation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Service:
    """A network service discovered on a host during scanning.

    Attributes:
        port: TCP/UDP port number.
        protocol: Transport protocol, either "tcp" or "udp".
        name: Service identifier, e.g. "ssh", "smb", "http".
        version: Detected version string, e.g. "OpenSSH 7.4".
        cves: List of CVE identifiers associated with this service/version.
    """

    port: int
    protocol: str
    name: str
    version: str
    cves: list[str] = field(default_factory=list)


@dataclass
class Host:
    """A host discovered in the network scan.

    Attributes:
        ip: IPv4 address string.
        hostname: Reverse-DNS or NetBIOS hostname.
        os: Operating system family, "linux" or "windows".
        services: List of open services on this host.
        role: Logical role in the network topology.
    """

    ip: str
    hostname: str
    os: str
    services: list[Service] = field(default_factory=list)
    role: str = "unknown"


@dataclass
class AttackEdge:
    """A directed exploit step from one host to another in the attack graph.

    Each edge represents one exploitable vulnerability that, if successfully
    executed, transitions the attacker from controlling ``source_host`` to
    also controlling ``target_host``.

    Attributes:
        source_host: IP address of the already-compromised source host.
        target_host: IP address of the target host to exploit.
        cve_id: CVE identifier for the vulnerability being exploited.
        exploit_module: Metasploit module path, e.g.
            ``"exploit/windows/smb/ms17_010_eternalblue"``.
        preconditions: Facts that must be true before this edge can fire,
            e.g. ``["has_network_access", "port_445_open"]``.
        postconditions: Facts gained after successful exploitation,
            e.g. ``["has_shell_on_target", "is_admin"]``.
        cvss_score: CVSS v3 base score in the range 0.0–10.0.
        detection_weight: Probability (0.0–1.0) of IDS detecting this
            exploit, sourced from ``ids_cost_model.py``.
        service_name: Human-readable service label, e.g. "smb".
        description: Free-form description of the attack step.
    """

    source_host: str
    target_host: str
    cve_id: str
    exploit_module: str
    preconditions: list[str]
    postconditions: list[str]
    cvss_score: float
    detection_weight: float
    service_name: str = ""
    description: str = ""


@dataclass
class ExecutionResult:
    """The outcome of executing a single attack step.

    Attributes:
        success: Whether the exploit produced a usable session or effect.
        session_id: Metasploit/CALDERA session identifier, if opened.
        output: Raw console output from the executor.
        duration_seconds: Wall-clock time the step took to execute.
        alerts_triggered: Number of IDS alerts fired during this step.
    """

    success: bool
    session_id: Optional[str]
    output: str
    duration_seconds: float
    alerts_triggered: int = 0


@dataclass
class RunResult:
    """Aggregated result of a complete planner run from start to goal.

    Attributes:
        planner_name: Identifier for the planner used, e.g. "astar".
        path: Ordered list of AttackEdge objects forming the executed path.
        goal_reached: Whether the final goal host was compromised.
        total_steps: Total number of steps attempted (including failures).
        successful_steps: Number of steps that succeeded.
        total_duration_seconds: Wall-clock time for the entire run.
        total_alerts: Total IDS alerts accumulated across all steps.
        execution_log: Per-step log entries with keys:
            ``step``, ``result``, ``timestamp``.
    """

    planner_name: str
    path: list[AttackEdge]
    goal_reached: bool
    total_steps: int
    successful_steps: int
    total_duration_seconds: float
    total_alerts: int
    execution_log: list[dict] = field(default_factory=list)
