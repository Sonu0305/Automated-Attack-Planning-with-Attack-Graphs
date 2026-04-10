"""Unit tests for graph/builder.py.

Uses the Nmap XML fixture at tests/fixtures/scan_fixture.xml and a mock
CVEEnricher that returns fixed CVE data without making API calls.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import networkx as nx
import pytest

# Ensure the autoattack package root is on sys.path when running tests
# from the tests/ directory.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from graph.builder import build_graph, infer_preconditions, infer_postconditions
from graph.models import Service

FIXTURE_XML = str(Path(__file__).parent / "fixtures" / "scan_fixture.xml")


# ---------------------------------------------------------------------------
# Mock enricher
# ---------------------------------------------------------------------------


class MockCVEEnricher:
    """Returns canned CVE data without touching the NVD API.

    Maps (service, version) pairs to fixed CVE/CVSS results so that
    tests are deterministic and network-independent.
    """

    _MOCK_DATA: dict[tuple[str, str], list[tuple[str, float]]] = {
        ("ssh",  "OpenSSH 7.4p1"):           [("CVE-2018-10933", 9.8)],
        ("http", "Apache httpd 2.4.49"):     [("CVE-2021-41773", 9.8)],
        ("smb",  "Samba smbd 4.15.0"):       [("CVE-2003-0201", 7.5)],
        ("smb",  "Microsoft Windows SMBv1"): [("CVE-2017-0144", 9.3)],
        ("rdp",  "Microsoft Terminal Services RDP_8.0"): [("CVE-2019-0708", 9.8)],
    }

    def lookup(self, service: str, version: str) -> list[tuple[str, float]]:
        """Return canned CVE results for the given (service, version) pair.

        Args:
            service: Service name string.
            version: Version string.

        Returns:
            List of ``(cve_id, cvss_score)`` tuples.
        """
        key = (service.lower(), version)
        # Fuzzy match on version prefix.
        for (svc, ver), result in self._MOCK_DATA.items():
            if service.lower() == svc and version.startswith(ver.split()[0]):
                return result
        return self._MOCK_DATA.get((service.lower(), version), [])


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_build_graph_from_fixture():
    """Graph built from the fixture XML must have 3 nodes and ≥2 edges."""
    enricher = MockCVEEnricher()
    graph = build_graph(FIXTURE_XML, enricher)

    assert graph.number_of_nodes() == 3, (
        f"Expected 3 hosts, got {graph.number_of_nodes()}"
    )
    assert graph.number_of_edges() >= 2, (
        f"Expected ≥2 attack edges, got {graph.number_of_edges()}"
    )


def test_all_edges_have_valid_cvss():
    """Every AttackEdge in the graph must have a CVSS score in [0, 10]."""
    enricher = MockCVEEnricher()
    graph = build_graph(FIXTURE_XML, enricher)

    for src, tgt, data in graph.edges(data=True):
        edge = data["data"]
        assert 0.0 <= edge.cvss_score <= 10.0, (
            f"Edge {src}→{tgt} has invalid CVSS {edge.cvss_score}"
        )


def test_all_edges_have_valid_detection_weight():
    """Every AttackEdge must have detection_weight in [0.0, 1.0]."""
    enricher = MockCVEEnricher()
    graph = build_graph(FIXTURE_XML, enricher)

    for src, tgt, data in graph.edges(data=True):
        edge = data["data"]
        assert 0.0 <= edge.detection_weight <= 1.0, (
            f"Edge {src}→{tgt} detection_weight={edge.detection_weight} out of range"
        )


def test_all_edges_have_exploit_module():
    """Every AttackEdge must have a non-empty exploit_module."""
    enricher = MockCVEEnricher()
    graph = build_graph(FIXTURE_XML, enricher)

    for src, tgt, data in graph.edges(data=True):
        edge = data["data"]
        assert edge.exploit_module != "", (
            f"Edge {src}→{tgt} missing exploit_module"
        )


def test_no_self_loops():
    """No host should have an attack edge to itself."""
    enricher = MockCVEEnricher()
    graph = build_graph(FIXTURE_XML, enricher)

    self_loops = [(u, v) for u, v in graph.edges() if u == v]
    assert self_loops == [], f"Self-loops found: {self_loops}"


def test_node_data_is_host():
    """Every graph node must carry a Host dataclass in its 'data' attribute."""
    from graph.models import Host

    enricher = MockCVEEnricher()
    graph = build_graph(FIXTURE_XML, enricher)

    for node_id, node_data in graph.nodes(data=True):
        host = node_data.get("data")
        assert isinstance(host, Host), (
            f"Node '{node_id}' data is not a Host: {type(host)}"
        )
        assert host.ip == node_id


def test_missing_file_raises():
    """build_graph must raise FileNotFoundError for a non-existent XML."""
    with pytest.raises((FileNotFoundError, OSError)):
        build_graph("/nonexistent/path/scan.xml", MockCVEEnricher())


def test_infer_preconditions_smb():
    """SMB service preconditions should include port and network access."""
    svc = Service(port=445, protocol="tcp", name="smb", version="SMBv1")
    preconditions = infer_preconditions(svc)
    assert "has_network_access" in preconditions
    assert "port_445_open" in preconditions


def test_infer_postconditions_ssh():
    """SSH postconditions should include has_shell_on_target."""
    svc = Service(port=22, protocol="tcp", name="ssh", version="OpenSSH 7.4")
    postconditions = infer_postconditions(svc)
    assert "has_shell_on_target" in postconditions


def test_infer_postconditions_smb():
    """SMB postconditions should include is_admin."""
    svc = Service(port=445, protocol="tcp", name="smb", version="SMBv1")
    postconditions = infer_postconditions(svc)
    assert "is_admin" in postconditions
