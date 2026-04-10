"""CVE enrichment via the NIST NVD REST API v2.0.

Queries NVD for CVE data associated with service/version pairs, caches
results in a local SQLite database for 7 days, and maps known CVEs to
their Metasploit exploit modules.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL_DAYS = 7
REQUEST_TIMEOUT = 10
MAX_RETRIES = 3

# Maps known high-value CVE IDs to their Metasploit exploit modules.
EXPLOIT_MAP: dict[str, str] = {
    "CVE-2017-0144": "exploit/windows/smb/ms17_010_eternalblue",
    "CVE-2021-44228": "exploit/multi/misc/log4shell_header_injection",
    "CVE-2021-3156": "exploit/linux/local/sudo_baron_samedit",
    "CVE-2019-0708": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
    "CVE-2018-10933": "exploit/linux/ssh/libssh_auth_bypass",
    "CVE-2014-6271": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
    "CVE-2003-0201": "exploit/linux/samba/trans2open",
    "CVE-2021-41773": "exploit/multi/http/apache_path_traversal_rce",
    "CVE-2021-27928": "exploit/linux/mysql/mysql_yassl_hello",
}


class CVEEnricher:
    """Enriches service/version pairs with CVE data from the NVD API.

    Results are cached in a local SQLite database to avoid redundant API
    calls and to respect NVD rate limits.

    Attributes:
        cache_db: Path to the SQLite cache database file.
        api_key: Optional NVD API key for higher rate limits.
    """

    def __init__(
        self,
        cache_db: str = "cve_cache.db",
        api_key: Optional[str] = None,
    ) -> None:
        """Initialise the enricher and create the cache schema if needed.

        Args:
            cache_db: Filesystem path to the SQLite cache file.
            api_key: NVD API key (optional; raises rate-limit to 50 req/30s).
        """
        self.cache_db = cache_db
        self.api_key = api_key
        self._init_cache()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def lookup(self, service: str, version: str) -> list[tuple[str, float]]:
        """Return CVE IDs and CVSS scores for a service/version pair.

        Checks the local cache first; only calls NVD if the entry is
        absent or older than ``CACHE_TTL_DAYS`` days.

        Args:
            service: Service name, e.g. "ssh", "smb", "http".
            version: Detected version string, e.g. "OpenSSH 7.4".

        Returns:
            List of ``(cve_id, cvss_score)`` tuples, up to 10 entries.
            Returns an empty list if the API is unreachable and the cache
            is empty.
        """
        cached = self._get_cached(service, version)
        if cached is not None:
            logger.debug("CVE cache hit for %s %s (%d entries)", service, version, len(cached))
            return cached

        results = self._fetch_nvd(service, version)
        self._store_cache(service, version, results)
        return results

    def train_from_logs(
        self,
        alert_log_path: str,
        execution_log_path: str,
        output_path: str = "detection_scores.json",
    ) -> None:
        """Update detection weights from co-occurring IDS alerts and exploits.

        Parses both log files by timestamp. For each exploit run, counts
        IDS alerts within a ±30-second window, then updates the running
        average detection score.  Serialises the result to
        ``detection_scores.json``.

        Args:
            alert_log_path: Path to the Snort/Suricata alert log.
            execution_log_path: Path to the JSONL execution log.
            output_path: Destination path for the updated JSON score file.
        """
        try:
            exec_entries = self._load_jsonl(execution_log_path)
            alert_entries = self._load_snort_alerts(alert_log_path)
        except FileNotFoundError as exc:
            logger.error("Log file not found: %s", exc)
            return

        scores: dict[str, list[float]] = {}
        for entry in exec_entries:
            module = entry.get("module", "")
            ts = float(entry.get("timestamp", 0))
            window_alerts = [
                a for a in alert_entries if abs(a["timestamp"] - ts) <= 30
            ]
            detection_rate = min(1.0, len(window_alerts) / 5.0)
            scores.setdefault(module, []).append(detection_rate)

        averaged = {mod: sum(vals) / len(vals) for mod, vals in scores.items()}

        existing: dict[str, float] = {}
        path = Path(output_path)
        if path.exists():
            try:
                existing = json.loads(path.read_text())
            except json.JSONDecodeError:
                pass

        existing.update(averaged)
        path.write_text(json.dumps(existing, indent=2))
        logger.info("Detection scores written to %s (%d modules)", output_path, len(existing))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _init_cache(self) -> None:
        """Create the SQLite cache table if it does not already exist."""
        with sqlite3.connect(self.cache_db) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cve_cache (
                    service     TEXT NOT NULL,
                    version     TEXT NOT NULL,
                    cve_id      TEXT NOT NULL,
                    score       REAL NOT NULL,
                    cached_at   TEXT NOT NULL,
                    PRIMARY KEY (service, version, cve_id)
                )
                """
            )

    def _get_cached(
        self, service: str, version: str
    ) -> Optional[list[tuple[str, float]]]:
        """Retrieve cached entries if they are within TTL.

        Args:
            service: Service name key.
            version: Version string key.

        Returns:
            List of ``(cve_id, score)`` tuples, or ``None`` if the cache
            is empty or all entries are expired.
        """
        cutoff = (datetime.utcnow() - timedelta(days=CACHE_TTL_DAYS)).isoformat()
        with sqlite3.connect(self.cache_db) as conn:
            rows = conn.execute(
                """
                SELECT cve_id, score FROM cve_cache
                WHERE service = ? AND version = ? AND cached_at > ?
                """,
                (service, version, cutoff),
            ).fetchall()
        if not rows:
            return None
        return [(row[0], row[1]) for row in rows]

    def _store_cache(
        self, service: str, version: str, results: list[tuple[str, float]]
    ) -> None:
        """Persist CVE results to the SQLite cache.

        Args:
            service: Service name key.
            version: Version string key.
            results: List of ``(cve_id, score)`` tuples to persist.
        """
        now = datetime.utcnow().isoformat()
        with sqlite3.connect(self.cache_db) as conn:
            conn.executemany(
                """
                INSERT OR REPLACE INTO cve_cache
                    (service, version, cve_id, score, cached_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                [(service, version, cve_id, score, now) for cve_id, score in results],
            )

    def _fetch_nvd(self, service: str, version: str) -> list[tuple[str, float]]:
        """Call the NVD API with exponential backoff retry logic.

        Args:
            service: Service name to search.
            version: Version string to search.

        Returns:
            List of ``(cve_id, cvss_score)`` tuples (up to 10).  Returns
            an empty list if all retries are exhausted.
        """
        keyword = f"{service} {version}".strip()
        params: dict[str, str | int] = {
            "keywordSearch": keyword,
            "resultsPerPage": 10,
        }
        headers: dict[str, str] = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        for attempt in range(MAX_RETRIES):
            try:
                resp = requests.get(
                    NVD_API_URL,
                    params=params,
                    headers=headers,
                    timeout=REQUEST_TIMEOUT,
                )
                resp.raise_for_status()
                return self._parse_nvd_response(resp.json())
            except requests.exceptions.RequestException as exc:
                wait = 2 ** attempt
                logger.warning(
                    "NVD API attempt %d/%d failed: %s — retrying in %ds",
                    attempt + 1,
                    MAX_RETRIES,
                    exc,
                    wait,
                )
                if attempt < MAX_RETRIES - 1:
                    time.sleep(wait)

        logger.error("NVD API unavailable after %d retries for '%s'", MAX_RETRIES, keyword)
        return []

    def _parse_nvd_response(self, data: dict) -> list[tuple[str, float]]:
        """Extract CVE IDs and CVSS scores from an NVD API v2.0 response.

        Prefers CVSS v3.1 scores; falls back to v2.0 if v3.x is absent.

        Args:
            data: Parsed JSON response from the NVD CVE API.

        Returns:
            List of ``(cve_id, cvss_score)`` tuples.
        """
        results: list[tuple[str, float]] = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id: str = cve.get("id", "")
            score = self._extract_score(cve.get("metrics", {}))
            if cve_id and score > 0.0:
                results.append((cve_id, score))
        return results

    @staticmethod
    def _extract_score(metrics: dict) -> float:
        """Extract the best available CVSS base score from NVD metrics.

        Args:
            metrics: The ``metrics`` dict from a CVE record.

        Returns:
            CVSS base score as a float, or 0.0 if none found.
        """
        for key in ("cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(key, [])
            if entries:
                return float(entries[0].get("cvssData", {}).get("baseScore", 0.0))
        # Fall back to v2
        v2_entries = metrics.get("cvssMetricV2", [])
        if v2_entries:
            return float(v2_entries[0].get("cvssData", {}).get("baseScore", 0.0))
        return 0.0

    @staticmethod
    def _load_jsonl(path: str) -> list[dict]:
        """Parse a JSON Lines file into a list of dicts.

        Args:
            path: Filesystem path to the JSONL file.

        Returns:
            List of parsed JSON objects.
        """
        results: list[dict] = []
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return results

    @staticmethod
    def _load_snort_alerts(path: str) -> list[dict]:
        """Parse Snort fast.log lines into timestamp-keyed dicts.

        Args:
            path: Filesystem path to the Snort fast.log.

        Returns:
            List of dicts with at least a ``timestamp`` key (epoch float).
        """
        import re

        pattern = re.compile(
            r"(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+).*?\[\*\*\] (.+?) \[\*\*\]"
        )
        alerts: list[dict] = []
        with open(path) as fh:
            for line in fh:
                match = pattern.search(line)
                if match:
                    ts_str, msg = match.group(1), match.group(2)
                    try:
                        dt = datetime.strptime(ts_str, "%m/%d-%H:%M:%S.%f").replace(
                            year=datetime.utcnow().year
                        )
                        alerts.append({"timestamp": dt.timestamp(), "msg": msg.strip()})
                    except ValueError:
                        continue
        return alerts
