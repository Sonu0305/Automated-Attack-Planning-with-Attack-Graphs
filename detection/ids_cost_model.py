"""IDS detection probability model for Metasploit exploit modules.

Maps exploit module paths to empirically-derived IDS detection
probabilities.  Values are based on Snort/Suricata signature coverage
for each exploit type.  Unknown modules fall back to heuristic scoring
based on module path keywords.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Detection score lookup table
# ---------------------------------------------------------------------------
# Values represent the probability (0.0–1.0) that Snort/Suricata will
# generate at least one alert when this module is executed in a
# standard lab environment with default rulesets.

DETECTION_SCORES: dict[str, float] = {
    # ── Highly detectable — well-known signatures ──────────────────────
    "exploit/windows/smb/ms17_010_eternalblue":      0.92,
    "exploit/windows/smb/ms17_010_psexec":           0.88,
    "exploit/windows/rdp/cve_2019_0708_bluekeep_rce": 0.85,
    "auxiliary/scanner/portscan/tcp":                0.95,
    "auxiliary/scanner/smb/smb_ms17_010":            0.80,
    "exploit/multi/http/apache_path_traversal_rce":  0.72,
    # ── Moderately detectable ──────────────────────────────────────────
    "exploit/multi/handler":                         0.35,
    "exploit/linux/http/apache_mod_cgi_bash":        0.55,
    "exploit/multi/http/apache_mod_cgi_bash_env_exec": 0.58,
    "exploit/multi/misc/log4shell_header_injection": 0.60,
    "exploit/multi/http/jenkins_script_console":     0.40,
    "exploit/linux/mysql/mysql_yassl_hello":         0.45,
    # ── Lower detection (slow, protocol-conforming) ────────────────────
    "exploit/unix/ssh/libssh_auth_bypass":           0.20,
    "exploit/linux/ssh/libssh_auth_bypass":          0.20,
    "exploit/linux/local/sudo_baron_samedit":        0.15,
    "exploit/linux/samba/trans2open":                0.65,
}

DEFAULT_SCORE: float = 0.50


# ---------------------------------------------------------------------------
# Public function
# ---------------------------------------------------------------------------


def score_action(exploit_module: str, service: str = "") -> float:
    """Return the IDS detection probability for an exploit module.

    Looks up the module path prefix in ``DETECTION_SCORES``.  Falls back
    to keyword-based heuristics for unknown modules.

    Args:
        exploit_module: Metasploit module path, e.g.
            ``"exploit/windows/smb/ms17_010_eternalblue"``.
        service: Optional service name hint (unused at present, reserved
            for future fine-grained scoring).

    Returns:
        Detection probability in the range [0.0, 1.0].
    """
    # Exact-prefix match.
    for key, score in DETECTION_SCORES.items():
        if exploit_module.startswith(key):
            return score

    # Heuristic fallbacks based on module path keywords.
    module_lower = exploit_module.lower()
    if "scanner" in module_lower:
        return 0.75
    if "brute" in module_lower or "login" in module_lower:
        return 0.65
    if "auxiliary" in module_lower:
        return 0.60
    if "local" in module_lower:
        # Local privilege escalation is harder to detect remotely.
        return 0.25

    logger.debug("Unknown module '%s' — using default score %.2f", exploit_module, DEFAULT_SCORE)
    return DEFAULT_SCORE
