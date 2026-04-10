"""Neo4j persistence layer for the attack graph.

Stores hosts as ``(:Host)`` nodes and attack steps as ``[:EXPLOITS]``
relationships.  Provides two Cypher-based path queries: shortest path
(by hop count) and stealthiest path (lowest total detection weight).
"""

from __future__ import annotations

import logging
from typing import Optional

import networkx as nx
from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable

from graph.models import AttackEdge, Host

logger = logging.getLogger(__name__)


class Neo4jStore:
    """Persist and query the attack graph in a Neo4j database.

    Attributes:
        uri: Bolt URI for the Neo4j instance.
        user: Database username.
        _driver: Internal ``neo4j.Driver`` instance.
    """

    def __init__(self, uri: str, user: str, password: str) -> None:
        """Connect to Neo4j and verify connectivity.

        Args:
            uri: Bolt URI, e.g. ``"bolt://localhost:7687"``.
            user: Neo4j username.
            password: Neo4j password.

        Raises:
            ServiceUnavailable: If Neo4j is unreachable.
        """
        self.uri = uri
        self.user = user
        self._driver = GraphDatabase.driver(uri, auth=(user, password))
        try:
            self._driver.verify_connectivity()
            logger.info("Connected to Neo4j at %s", uri)
        except ServiceUnavailable as exc:
            logger.error("Cannot connect to Neo4j at %s: %s", uri, exc)
            raise

    def close(self) -> None:
        """Close the Neo4j driver connection pool."""
        self._driver.close()

    # ------------------------------------------------------------------
    # Write operations
    # ------------------------------------------------------------------

    def store_graph(self, graph: nx.DiGraph) -> None:
        """Persist all hosts and attack edges from a NetworkX graph.

        Creates or merges ``(:Host)`` nodes and ``[:EXPLOITS]``
        relationships.  Existing nodes/relationships are updated in-place
        via ``MERGE``.

        Args:
            graph: Directed attack graph produced by ``build_graph()``.
        """
        with self._driver.session() as session:
            # Upsert host nodes.
            for node_id, node_data in graph.nodes(data=True):
                host: Host = node_data.get("data", Host(ip=node_id, hostname=node_id, os="unknown"))
                session.execute_write(self._merge_host, host)

            # Upsert attack edges.
            for src, tgt, edge_data in graph.edges(data=True):
                edge: AttackEdge = edge_data.get("data")
                if edge is not None:
                    session.execute_write(self._create_edge, edge)

        logger.info(
            "Stored graph to Neo4j: %d nodes, %d edges",
            graph.number_of_nodes(),
            graph.number_of_edges(),
        )

    def clear(self) -> None:
        """Delete all nodes and relationships from the database.

        Use with caution — this wipes the entire graph database.
        """
        with self._driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")
        logger.warning("Neo4j database cleared.")

    # ------------------------------------------------------------------
    # Query operations
    # ------------------------------------------------------------------

    def query_shortest_path(self, start: str, goal: str) -> list[dict]:
        """Find the shortest path (fewest hops) between two hosts.

        Args:
            start: Source host IP address.
            goal: Goal host IP address.

        Returns:
            List of relationship property dicts along the shortest path,
            or an empty list if no path exists.
        """
        cypher = """
        MATCH path = shortestPath(
            (a:Host {ip: $start})-[:EXPLOITS*]->(b:Host {ip: $goal})
        )
        RETURN [rel IN relationships(path) | properties(rel)] AS edges
        """
        with self._driver.session() as session:
            result = session.run(cypher, start=start, goal=goal)
            record = result.single()
            if record is None:
                return []
            return record["edges"]

    def query_stealthiest_path(self, start: str, goal: str) -> list[dict]:
        """Find the path with the lowest cumulative detection weight.

        Args:
            start: Source host IP address.
            goal: Goal host IP address.

        Returns:
            List of relationship property dicts along the stealthiest
            path, or an empty list if no path exists.
        """
        cypher = """
        MATCH path = (a:Host {ip: $start})-[:EXPLOITS*]->(b:Host {ip: $goal})
        WITH path,
             REDUCE(s = 0.0, r IN relationships(path) | s + r.detection) AS total_detection
        ORDER BY total_detection ASC
        LIMIT 1
        RETURN [rel IN relationships(path) | properties(rel)] AS edges
        """
        with self._driver.session() as session:
            result = session.run(cypher, start=start, goal=goal)
            record = result.single()
            if record is None:
                return []
            return record["edges"]

    def get_all_hosts(self) -> list[dict]:
        """Return all host nodes stored in the database.

        Returns:
            List of dicts with host properties (ip, hostname, os, role).
        """
        with self._driver.session() as session:
            result = session.run("MATCH (h:Host) RETURN properties(h) AS props")
            return [record["props"] for record in result]

    # ------------------------------------------------------------------
    # Static transaction functions
    # ------------------------------------------------------------------

    @staticmethod
    def _merge_host(tx: object, host: Host) -> None:
        """Merge a Host node into Neo4j (upsert).

        Args:
            tx: Active Neo4j write transaction.
            host: Host dataclass to persist.
        """
        tx.run(  # type: ignore[attr-defined]
            """
            MERGE (h:Host {ip: $ip})
            SET h.hostname = $hostname,
                h.os       = $os,
                h.role     = $role
            """,
            ip=host.ip,
            hostname=host.hostname,
            os=host.os,
            role=host.role,
        )

    @staticmethod
    def _create_edge(tx: object, edge: AttackEdge) -> None:
        """Create an EXPLOITS relationship in Neo4j.

        Args:
            tx: Active Neo4j write transaction.
            edge: AttackEdge dataclass to persist.
        """
        tx.run(  # type: ignore[attr-defined]
            """
            MATCH (a:Host {ip: $source}), (b:Host {ip: $target})
            CREATE (a)-[:EXPLOITS {
                cve_id:    $cve_id,
                module:    $module,
                cvss:      $cvss,
                detection: $detection,
                service:   $service
            }]->(b)
            """,
            source=edge.source_host,
            target=edge.target_host,
            cve_id=edge.cve_id,
            module=edge.exploit_module,
            cvss=edge.cvss_score,
            detection=edge.detection_weight,
            service=edge.service_name,
        )
