"""Real-time IDS log monitor for Snort and Suricata.

Tails the IDS log file in a background thread, parsing each new line
into an ``Alert`` dataclass.  Supports Snort fast.log and Suricata
eve.json formats.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

# Snort fast.log pattern:
# 01/01-12:34:56.789 [**] [1:1000001:1] ET SCAN Nmap [**] {TCP} 192.168.56.10:54321 -> 192.168.56.20:445
_SNORT_PATTERN = re.compile(
    r"(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)"
    r".*?\[\*\*\]\s*(?:\[\d+:\d+:\d+\]\s*)?(.+?)\s*\[\*\*\]"
    r".*?\{(\w+)\}\s*([\d.]+):\d+\s*->\s*([\d.]+):\d+",
    re.DOTALL,
)

_SEVERITY_KEYWORDS: dict[str, int] = {
    "critical": 1,
    "high":     2,
    "medium":   3,
    "low":      4,
    "scan":     3,
    "exploit":  1,
    "shellcode": 1,
    "trojan":   2,
    "policy":   4,
    "info":     5,
}


@dataclass
class Alert:
    """A single IDS alert parsed from the log.

    Attributes:
        timestamp: Unix epoch float of when the alert fired.
        rule_msg: Human-readable Snort/Suricata rule message.
        protocol: Transport protocol, e.g. "TCP", "UDP".
        src_ip: Source IP of the offending traffic.
        dst_ip: Destination IP of the offending traffic.
        severity: Integer severity 1 (critical) – 5 (informational).
        raw: Raw log line.
    """

    timestamp: float
    rule_msg: str
    protocol: str
    src_ip: str
    dst_ip: str
    severity: int = 3
    raw: str = ""


class IDSMonitor:
    """Background log-tailer that converts IDS alerts to ``Alert`` objects.

    Supports Snort fast.log (``log_format="fast"``) and Suricata eve.json
    (``log_format="eve"``).  Alerting starts only after ``start_monitoring()``
    is called and stops when ``stop_monitoring()`` is called.

    Attributes:
        log_path: Path to the IDS log file.
        log_format: Either ``"fast"`` (Snort) or ``"eve"`` (Suricata).
    """

    def __init__(self, log_path: str, log_format: str = "fast") -> None:
        """Initialise the monitor.

        Args:
            log_path: Filesystem path to the Snort/Suricata log file.
            log_format: ``"fast"`` for Snort fast.log or ``"eve"`` for
                Suricata eve.json.
        """
        self.log_path = log_path
        self.log_format = log_format.lower()
        self._alerts: list[Alert] = []
        self._running = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start_monitoring(self) -> None:
        """Launch the background log-tailing thread.

        Safe to call multiple times; a second call is a no-op if the
        thread is already running.
        """
        if self._thread is not None and self._thread.is_alive():
            logger.debug("IDSMonitor already running.")
            return

        self._running.set()
        self._thread = threading.Thread(
            target=self._tail_log,
            daemon=True,
            name="ids-monitor",
        )
        self._thread.start()
        logger.info("IDSMonitor started on '%s' (format=%s).", self.log_path, self.log_format)

    def stop_monitoring(self) -> None:
        """Signal the background thread to stop and wait for it.

        Blocks until the thread terminates (up to 2 seconds).
        """
        self._running.clear()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        logger.info("IDSMonitor stopped.")

    def get_alerts_since(self, timestamp: float) -> list[Alert]:
        """Return all alerts with a timestamp after ``timestamp``.

        Args:
            timestamp: Unix epoch float.  Only alerts fired after this
                time are returned.

        Returns:
            Filtered list of ``Alert`` objects.
        """
        with self._lock:
            return [a for a in self._alerts if a.timestamp > timestamp]

    def get_all_alerts(self) -> list[Alert]:
        """Return a copy of all alerts collected so far.

        Returns:
            List of all ``Alert`` objects.
        """
        with self._lock:
            return list(self._alerts)

    def clear_alerts(self) -> None:
        """Discard all buffered alerts."""
        with self._lock:
            self._alerts.clear()

    # ------------------------------------------------------------------
    # Internal: log tailing
    # ------------------------------------------------------------------

    def _tail_log(self) -> None:
        """Background thread target: seek to EOF and tail new lines."""
        try:
            with open(self.log_path, encoding="utf-8", errors="replace") as fh:
                fh.seek(0, 2)  # Seek to end of file.
                while self._running.is_set():
                    line = fh.readline()
                    if line:
                        alert = self._parse_line(line.strip())
                        if alert is not None:
                            with self._lock:
                                self._alerts.append(alert)
                    else:
                        time.sleep(0.1)
        except FileNotFoundError:
            logger.warning("IDS log file not found: %s — monitoring disabled.", self.log_path)

    def _parse_line(self, line: str) -> Optional[Alert]:
        """Parse one log line into an ``Alert``.

        Dispatches to the format-specific parser.

        Args:
            line: A single stripped log line.

        Returns:
            ``Alert`` instance, or ``None`` if the line does not match.
        """
        if not line:
            return None
        if self.log_format == "eve":
            return self._parse_eve(line)
        return self._parse_snort_fast(line)

    def _parse_snort_fast(self, line: str) -> Optional[Alert]:
        """Parse a Snort fast.log line.

        Args:
            line: Single log line.

        Returns:
            ``Alert`` or ``None``.
        """
        match = _SNORT_PATTERN.search(line)
        if not match:
            return None

        ts_str, rule_msg, protocol, src_ip, dst_ip = match.groups()
        try:
            dt = datetime.strptime(ts_str, "%m/%d-%H:%M:%S.%f").replace(
                year=datetime.utcnow().year
            )
            timestamp = dt.timestamp()
        except ValueError:
            timestamp = time.time()

        return Alert(
            timestamp=timestamp,
            rule_msg=rule_msg.strip(),
            protocol=protocol,
            src_ip=src_ip,
            dst_ip=dst_ip,
            severity=_classify_severity(rule_msg),
            raw=line,
        )

    def _parse_eve(self, line: str) -> Optional[Alert]:
        """Parse a Suricata eve.json line.

        Args:
            line: Single log line containing a JSON object.

        Returns:
            ``Alert`` or ``None``.
        """
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return None

        if obj.get("event_type") not in ("alert", "drop"):
            return None

        # Parse ISO timestamp.
        ts_str: str = obj.get("timestamp", "")
        try:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            timestamp = dt.timestamp()
        except (ValueError, AttributeError):
            timestamp = time.time()

        alert_obj = obj.get("alert", {})
        rule_msg = alert_obj.get("signature", "Unknown")
        protocol = obj.get("proto", "TCP").upper()
        src_ip = obj.get("src_ip", "0.0.0.0")
        dst_ip = obj.get("dest_ip", "0.0.0.0")
        severity_raw = alert_obj.get("severity", 3)

        return Alert(
            timestamp=timestamp,
            rule_msg=rule_msg,
            protocol=protocol,
            src_ip=src_ip,
            dst_ip=dst_ip,
            severity=int(severity_raw),
            raw=line,
        )


# ---------------------------------------------------------------------------
# Module-level helper
# ---------------------------------------------------------------------------


def _classify_severity(rule_msg: str) -> int:
    """Heuristically assign a severity level from a rule message string.

    Args:
        rule_msg: The IDS rule message text.

    Returns:
        Integer severity 1 (critical) – 5 (informational).
    """
    lower = rule_msg.lower()
    for keyword, severity in sorted(_SEVERITY_KEYWORDS.items(), key=lambda kv: kv[1]):
        if keyword in lower:
            return severity
    return 3  # Medium default.
