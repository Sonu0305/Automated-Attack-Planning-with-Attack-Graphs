"""Log collection and human-realism scoring (Novel Extension 4).

Collects IDS alert logs and execution JSONL during a run, then scores
the generated command log against a human-baseline feature vector using
cosine similarity across five forensic features.

Research gap addressed:
    AttackMate 2025 generates realistic logs but provides no automated
    realism scoring against human baselines.
"""

from __future__ import annotations

import json
import logging
import math
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Human-baseline feature vector derived from red team exercise observations.
# Features: [timing_entropy, cmd_length_mean, unique_ratio, duration_min, error_rate]
_HUMAN_BASELINE = [2.8, 42.0, 0.72, 18.0, 0.12]


class LogCollector:
    """Collect IDS and execution logs during a run for analysis.

    Attributes:
        run_dir: Directory where logs for the current run are stored.
    """

    def __init__(self, run_dir: str) -> None:
        """Initialise the collector for a specific run directory.

        Args:
            run_dir: Path to the directory containing run artefacts.
        """
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self._start_time: float = time.time()

    # ------------------------------------------------------------------
    # IDS alert collection
    # ------------------------------------------------------------------

    def collect_ids_alerts(
        self,
        alerts: list[object],
        output_file: str = "ids_alerts.json",
    ) -> str:
        """Serialise IDS alerts to a JSON file.

        Args:
            alerts: List of ``Alert`` dataclass instances.
            output_file: Filename within ``run_dir``.

        Returns:
            Absolute path to the written JSON file.
        """
        alert_dicts = []
        for alert in alerts:
            alert_dicts.append(
                {
                    "timestamp": getattr(alert, "timestamp", 0.0),
                    "rule_msg": getattr(alert, "rule_msg", ""),
                    "protocol": getattr(alert, "protocol", ""),
                    "src_ip": getattr(alert, "src_ip", ""),
                    "dst_ip": getattr(alert, "dst_ip", ""),
                    "severity": getattr(alert, "severity", 3),
                }
            )

        out_path = self.run_dir / output_file
        out_path.write_text(json.dumps(alert_dicts, indent=2))
        logger.info("IDS alerts written to %s (%d alerts)", out_path, len(alert_dicts))
        return str(out_path)

    # ------------------------------------------------------------------
    # Realism scoring
    # ------------------------------------------------------------------

    def compute_realism_score(
        self,
        execution_log_path: Optional[str] = None,
    ) -> dict[str, float]:
        """Compute a 5-feature realism score for the execution log.

        Compares the generated log's feature vector against the human
        baseline using cosine similarity.

        The five forensic features are:
        1. Inter-command timing entropy (Shannon entropy of delay distribution).
        2. Mean command length (mean character count of commands).
        3. Unique command ratio (distinct commands / total commands).
        4. Session duration in minutes.
        5. Error rate (failed steps / total steps).

        Args:
            execution_log_path: Path to the JSONL execution log.  If
                ``None``, defaults to ``<run_dir>/execution_log.jsonl``.

        Returns:
            Dict with keys ``features`` (list), ``realism_score`` (float
            in [0, 1]), and per-feature values.
        """
        if execution_log_path is None:
            execution_log_path = str(self.run_dir / "execution_log.jsonl")

        entries = self._load_jsonl(execution_log_path)
        if not entries:
            return {"realism_score": 0.0, "features": [0.0] * 5}

        features = self._extract_features(entries)
        score = _cosine_similarity(features, _HUMAN_BASELINE)
        score = max(0.0, min(1.0, score))

        result = {
            "realism_score": round(score, 4),
            "timing_entropy": round(features[0], 3),
            "cmd_length_mean": round(features[1], 2),
            "unique_ratio": round(features[2], 3),
            "duration_min": round(features[3], 2),
            "error_rate": round(features[4], 3),
            "features": features,
        }
        logger.info(
            "Realism score: %.4f (entropy=%.2f, cmd_len=%.1f, unique=%.2f, "
            "duration=%.1f min, errors=%.2f)",
            score,
            features[0], features[1], features[2], features[3], features[4],
        )
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_features(self, entries: list[dict]) -> list[float]:
        """Compute the 5-element feature vector from execution log entries.

        Args:
            entries: List of JSONL dicts from the execution log.

        Returns:
            List of 5 floats: [timing_entropy, cmd_length_mean,
            unique_ratio, duration_min, error_rate].
        """
        # Feature 1: Inter-command timing entropy.
        timestamps = [e.get("timestamp", 0.0) for e in entries]
        delays = [
            timestamps[i + 1] - timestamps[i]
            for i in range(len(timestamps) - 1)
            if timestamps[i + 1] > timestamps[i]
        ]
        timing_entropy = _shannon_entropy(delays) if delays else 0.0

        # Feature 2: Command length distribution mean.
        commands = [e.get("step", "") for e in entries]
        lengths = [len(c) for c in commands]
        cmd_length_mean = sum(lengths) / len(lengths) if lengths else 0.0

        # Feature 3: Unique command ratio.
        unique_ratio = len(set(commands)) / len(commands) if commands else 0.0

        # Feature 4: Session duration in minutes.
        if timestamps:
            total_seconds = max(timestamps) - min(timestamps)
        else:
            total_seconds = time.time() - self._start_time
        duration_min = total_seconds / 60.0

        # Feature 5: Error rate.
        total = len(entries)
        failed = sum(1 for e in entries if not e.get("success", True))
        error_rate = failed / total if total > 0 else 0.0

        return [timing_entropy, cmd_length_mean, unique_ratio, duration_min, error_rate]

    @staticmethod
    def _load_jsonl(path: str) -> list[dict]:
        """Parse a JSONL file into a list of dicts.

        Args:
            path: Filesystem path to the JSONL file.

        Returns:
            List of parsed JSON objects.
        """
        results: list[dict] = []
        try:
            with open(path) as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            results.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except FileNotFoundError:
            logger.warning("Execution log not found: %s", path)
        return results


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _shannon_entropy(values: list[float]) -> float:
    """Compute the Shannon entropy of a list of continuous values.

    Bins values into 10 equal-width buckets before computing entropy.

    Args:
        values: List of non-negative float values.

    Returns:
        Shannon entropy in bits.
    """
    if not values:
        return 0.0
    min_v, max_v = min(values), max(values)
    if max_v == min_v:
        return 0.0

    bins = 10
    bucket_size = (max_v - min_v) / bins
    counts: list[int] = [0] * bins
    for v in values:
        idx = min(int((v - min_v) / bucket_size), bins - 1)
        counts[idx] += 1

    total = len(values)
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            entropy -= p * math.log2(p)
    return entropy


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute cosine similarity between two equal-length vectors.

    Args:
        a: First feature vector.
        b: Second feature vector (baseline).

    Returns:
        Cosine similarity in [−1, 1] (clipped to [0, 1] for realism
        scoring).
    """
    if len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)
