"""Unit tests for graph/enricher.py local fallback behaviour."""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from graph.enricher import CVEEnricher


def test_local_fingerprint_resolves_fixture_ssh_version(tmp_path):
    """Known OpenSSH fixture versions should resolve without hitting NVD."""
    enricher = CVEEnricher(cache_db=str(tmp_path / "cve_cache.db"))

    results = enricher.lookup("ssh", "OpenSSH 7.4p1")

    assert ("CVE-2018-10933", 9.8) in results


def test_local_fingerprint_resolves_windows_smbv1(tmp_path):
    """Known SMBv1 demo lab versions should map to EternalBlue CVE locally."""
    enricher = CVEEnricher(cache_db=str(tmp_path / "cve_cache.db"))

    results = enricher.lookup("smb", "Microsoft Windows SMBv1")

    assert ("CVE-2017-0144", 9.3) in results
