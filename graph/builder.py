"""Attack graph construction from Nmap XML scan output.

Parses an Nmap XML file, enriches discovered services with CVE data via
``CVEEnricher``, infers pre- and post-conditions using a rule engine, and
assembles a directed ``networkx.DiGraph`` where nodes are host IPs and
edges are exploitable ``AttackEdge`` objects.
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from typing import Optional

import networkx as nx

from graph.enricher import CVEEnricher, EXPLOIT_MAP
from graph.models import AttackEdge, Host, Service

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Precondition / postcondition rule tables
# ---------------------------------------------------------------------------

# Preconditions per service type.  The port number is filled in dynamically.
_PRECONDITION_TEMPLATES: dict[str, list[str]] = {
    "smb": ["has_network_access", "port_{port}_open"],
    "ssh": ["has_network_access", "port_{port}_open"],
    "http": ["has_network_access", "port_{port}_open", "http_service_running"],
    "https": ["has_network_access", "port_{port}_open", "http_service_running"],
    "rdp": ["has_network_access", "port_3389_open"],
    "mysql": ["has_network_access", "port_{port}_open"],
    "mssql": ["has_network_access", "port_{port}_open"],
    "ftp": ["has_network_access", "port_{port}_open"],
    "telnet": ["has_network_access", "port_{port}_open"],
}

_POSTCONDITION_MAP: dict[str, list[str]] = {
    "smb": ["has_shell_on_target", "is_admin"],
    "ssh": ["has_shell_on_target"],
    "http": ["has_webshell_on_target"],
    "https": ["has_webshell_on_target"],
    "rdp": ["has_rdp_session", "is_admin"],
    "mysql": ["has_db_access"],
    "mssql": ["has_db_access", "is_admin"],
    "ftp": ["has_file_access"],
    "telnet": ["has_shell_on_target"],
}

_DEFAULT_PRECONDITIONS = ["has_network_access"]
_DEFAULT_POSTCONDITIONS = ["has_access_on_target"]


# ---------------------------------------------------------------------------
# Public function
# ---------------------------------------------------------------------------


def build_graph(
    nmap_xml_path: str,
    enricher: CVEEnricher,
    ids_cost_fn: Optional[object] = None,
) -> nx.DiGraph:
    """Build an attack graph from an Nmap XML scan file.

    Parses all hosts and open ports from the Nmap XML, enriches each
    service with CVE data, then creates directed ``AttackEdge`` objects
    for every (source_host, target_host) pair where the target has at
    least one exploitable CVE in ``EXPLOIT_MAP``.

    Args:
        nmap_xml_path: Path to the Nmap XML output file.
        enricher: Initialised ``CVEEnricher`` instance.
        ids_cost_fn: Optional callable ``(module: str) -> float`` for
            detection weights.  Defaults to importing
            ``detection.ids_cost_model.score_action``.

    Returns:
        Directed ``networkx.DiGraph`` where:
        - Each node is a host IP string with a ``data`` attribute holding
          the ``Host`` dataclass.
        - Each edge has a ``data`` attribute holding an ``AttackEdge``.
    """
    if ids_cost_fn is None:
        try:
            from detection.ids_cost_model import score_action as ids_cost_fn  # type: ignore
        except ImportError:
            ids_cost_fn = lambda module: 0.5  # noqa: E731

    hosts = _parse_nmap_xml(nmap_xml_path)
    logger.info("Parsed %d hosts from %s", len(hosts), nmap_xml_path)

    # Enrich each host's services with CVE data.
    for host in hosts:
        for service in host.services:
            cves = enricher.lookup(service.name, service.version)
            service.cves = [cve_id for cve_id, _ in cves]

    graph = nx.DiGraph()

    # Add host nodes.
    for host in hosts:
        graph.add_node(host.ip, data=host)

    # Add attack edges.
    edge_count = 0
    for source in hosts:
        for target in hosts:
            if source.ip == target.ip:
                continue
            for service in target.services:
                cves = enricher.lookup(service.name, service.version)
                for cve_id, cvss_score in cves:
                    if cve_id not in EXPLOIT_MAP:
                        continue
                    module = EXPLOIT_MAP[cve_id]
                    edge = AttackEdge(
                        source_host=source.ip,
                        target_host=target.ip,
                        cve_id=cve_id,
                        exploit_module=module,
                        preconditions=infer_preconditions(service),
                        postconditions=infer_postconditions(service),
                        cvss_score=cvss_score,
                        detection_weight=ids_cost_fn(module),  # type: ignore[operator]
                        service_name=service.name,
                        description=(
                            f"Exploit {cve_id} on {target.ip} via {service.name} "
                            f"(CVSS {cvss_score:.1f})"
                        ),
                    )
                    # Keep the highest-CVSS edge if duplicates exist.
                    if graph.has_edge(source.ip, target.ip):
                        existing: AttackEdge = graph.edges[source.ip, target.ip]["data"]
                        if cvss_score <= existing.cvss_score:
                            continue
                    graph.add_edge(source.ip, target.ip, data=edge)
                    edge_count += 1

    logger.info(
        "Built attack graph: %d nodes, %d edges", graph.number_of_nodes(), edge_count
    )
    return graph


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def infer_preconditions(service: Service) -> list[str]:
    """Map a service to its required preconditions.

    Args:
        service: The target service being exploited.

    Returns:
        List of precondition strings with the port number interpolated.
    """
    templates = _PRECONDITION_TEMPLATES.get(service.name.lower(), _DEFAULT_PRECONDITIONS)
    return [t.format(port=service.port) for t in templates]


def infer_postconditions(service: Service) -> list[str]:
    """Map a service to the access conditions gained after exploitation.

    Args:
        service: The target service being exploited.

    Returns:
        List of postcondition strings.
    """
    return _POSTCONDITION_MAP.get(service.name.lower(), _DEFAULT_POSTCONDITIONS)


def _parse_nmap_xml(nmap_xml_path: str) -> list[Host]:
    """Parse an Nmap XML file into a list of Host dataclass instances.

    Args:
        nmap_xml_path: Path to the Nmap ``-oX`` output file.

    Returns:
        List of ``Host`` objects for every host with status "up".

    Raises:
        FileNotFoundError: If the XML file does not exist.
        ET.ParseError: If the file is not valid XML.
    """
    tree = ET.parse(nmap_xml_path)
    root = tree.getroot()

    hosts: list[Host] = []

    for host_elem in root.findall("host"):
        status = host_elem.find("status")
        if status is None or status.get("state") != "up":
            continue

        ip = _extract_ip(host_elem)
        if not ip:
            continue

        hostname = _extract_hostname(host_elem)
        os_name = _extract_os(host_elem)
        services = _extract_services(host_elem)

        hosts.append(
            Host(
                ip=ip,
                hostname=hostname or ip,
                os=os_name,
                services=services,
            )
        )

    return hosts


def _extract_ip(host_elem: ET.Element) -> Optional[str]:
    """Extract the IPv4 address from a <host> element.

    Args:
        host_elem: XML ``<host>`` element.

    Returns:
        IPv4 address string, or ``None`` if not found.
    """
    for addr in host_elem.findall("address"):
        if addr.get("addrtype") == "ipv4":
            return addr.get("addr")
    return None


def _extract_hostname(host_elem: ET.Element) -> Optional[str]:
    """Extract the primary hostname from a <host> element.

    Args:
        host_elem: XML ``<host>`` element.

    Returns:
        Hostname string, or ``None`` if the element is absent.
    """
    hostnames = host_elem.find("hostnames")
    if hostnames is not None:
        hn = hostnames.find("hostname")
        if hn is not None:
            return hn.get("name")
    return None


def _extract_os(host_elem: ET.Element) -> str:
    """Extract the most likely OS family from osmatch data.

    Args:
        host_elem: XML ``<host>`` element.

    Returns:
        ``"windows"`` or ``"linux"`` based on the best osmatch name.
    """
    os_elem = host_elem.find("os")
    if os_elem is not None:
        matches = os_elem.findall("osmatch")
        if matches:
            best = max(matches, key=lambda m: int(m.get("accuracy", "0")))
            name = (best.get("name") or "").lower()
            if "windows" in name:
                return "windows"
    return "linux"


def _extract_services(host_elem: ET.Element) -> list[Service]:
    """Extract open services from a <host> element's <ports> section.

    Args:
        host_elem: XML ``<host>`` element.

    Returns:
        List of ``Service`` objects for every port with state "open".
    """
    services: list[Service] = []
    ports_elem = host_elem.find("ports")
    if ports_elem is None:
        return services

    for port_elem in ports_elem.findall("port"):
        state_elem = port_elem.find("state")
        if state_elem is None or state_elem.get("state") != "open":
            continue

        portid = int(port_elem.get("portid", "0"))
        protocol = port_elem.get("protocol", "tcp")

        svc_elem = port_elem.find("service")
        if svc_elem is not None:
            name = svc_elem.get("name", "unknown")
            product = svc_elem.get("product", "")
            version_str = svc_elem.get("version", "")
            version = f"{product} {version_str}".strip()
        else:
            name = "unknown"
            version = ""

        services.append(
            Service(
                port=portid,
                protocol=protocol,
                name=name,
                version=version,
            )
        )

    return services
