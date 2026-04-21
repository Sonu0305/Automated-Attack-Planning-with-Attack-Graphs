#!/usr/bin/env python3
"""Generate and run a large synthetic AutoAttack benchmark.

This script creates a safe, local-only attack graph with hundreds of
synthetic devices. It is meant for algorithm comparison, not for touching a
real network. The graph deliberately contains multiple competing corridors:

- fast but noisy
- balanced
- long but stealthy
- many decoy routes

The output is a self-contained example bundle with graph pickle, planner
paths, timing metrics, Markdown/HTML reports, and SVG visualizations.
"""

from __future__ import annotations

import argparse
import html
import json
import math
import pickle
import random
import statistics
import sys
import time
from pathlib import Path
from typing import Callable

import networkx as nx

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from graph.models import AttackEdge, Host, Service
from planners.astar_planner import AStarPlanner
from planners.detection_aware import DetectionAwarePlanner
from planners.llm_planner import LLMPlanner
from planners.rl_planner import RLPlanner

DEFAULT_DEVICES = 600
DEFAULT_ZONES = 12
DEFAULT_SEED = 20260421
DEFAULT_REPEATS = 25

START_IP = "10.60.0.1"
GOAL_ROLE = "crown_jewel"

RouteMap = dict[str, list[AttackEdge]]


def build_huge_graph(
    devices: int = DEFAULT_DEVICES,
    zones: int = DEFAULT_ZONES,
    seed: int = DEFAULT_SEED,
) -> tuple[nx.DiGraph, str, str, dict[str, list[str]]]:
    """Build a deterministic synthetic graph with several competing routes."""
    if devices < 120:
        raise ValueError("Use at least 120 devices for the huge benchmark.")
    if zones < 4:
        raise ValueError("Use at least 4 zones for meaningful route diversity.")

    rng = random.Random(seed)
    graph = nx.DiGraph()
    per_zone = math.ceil(devices / zones)
    node_ids: list[str] = []
    by_zone: dict[int, list[str]] = {zone: [] for zone in range(zones)}

    services = [
        ("http", 80, "Apache synthetic"),
        ("ssh", 22, "OpenSSH synthetic"),
        ("smb", 445, "SMB synthetic"),
        ("rdp", 3389, "RDP synthetic"),
        ("mysql", 3306, "MySQL synthetic"),
        ("k8s", 6443, "Kubernetes API synthetic"),
    ]

    for idx in range(devices):
        zone = min(idx // per_zone, zones - 1)
        slot = len(by_zone[zone]) + 1
        ip = f"10.60.{zone}.{slot}"
        service_name, port, version = services[(idx + zone) % len(services)]
        role = "attacker" if ip == START_IP else f"zone_{zone}_device"
        host = Host(
            ip=ip,
            hostname=f"z{zone:02d}-device-{slot:03d}",
            os="linux" if (idx + zone) % 3 else "windows",
            role=role,
            services=[
                Service(
                    port=port,
                    protocol="tcp",
                    name=service_name,
                    version=version,
                    cves=[f"CVE-2026-{9000 + idx}"],
                )
            ],
        )
        graph.add_node(ip, data=host, zone=zone, slot=slot)
        node_ids.append(ip)
        by_zone[zone].append(ip)

    start = START_IP
    goal = by_zone[zones - 1][-1]
    graph.nodes[goal]["data"].role = GOAL_ROLE

    def node(zone: int, slot: int) -> str:
        zone = max(0, min(zone, zones - 1))
        slot = max(1, min(slot, len(by_zone[zone])))
        return by_zone[zone][slot - 1]

    # Random forward-only decoy fabric. It makes the graph large without
    # making RL impossible or creating cycles that dominate path generation.
    edge_counter = 0
    for zone in range(zones - 1):
        for src in by_zone[zone]:
            fanout = 3 if zone < zones - 2 else 2
            for _ in range(fanout):
                hop = 1 if rng.random() < 0.85 else 2
                target_zone = min(zone + hop, zones - 1)
                tgt = rng.choice(by_zone[target_zone])
                edge_counter += 1
                _add_edge(
                    graph,
                    src,
                    tgt,
                    cve_id=f"CVE-2026-D{edge_counter:05d}",
                    cvss=round(rng.uniform(4.2, 7.4), 1),
                    detection=round(rng.uniform(0.34, 0.88), 2),
                    service=rng.choice(["http", "ssh", "smb", "rdp", "mysql", "k8s"]),
                    description="Decoy enterprise edge",
                )

    # Three explicit corridors. These are added last so they win if a random
    # edge accidentally uses the same source/target pair.
    fast_nodes = [
        start,
        node(2, 6),
        node(4, 12),
        node(6, 18),
        node(8, 24),
        node(10, 30),
        goal,
    ]
    balanced_nodes = [
        start,
        node(1, 5),
        node(2, 10),
        node(3, 15),
        node(4, 20),
        node(5, 25),
        node(6, 30),
        node(7, 35),
        node(8, 40),
        node(9, 45),
        node(10, 48),
        goal,
    ]
    stealth_nodes = [
        start,
        node(0, 40),
        node(1, 42),
        node(2, 44),
        node(3, 46),
        node(4, 48),
        node(5, 50),
        node(6, 47),
        node(7, 44),
        node(8, 41),
        node(9, 38),
        node(10, 35),
        node(11, 32),
        goal,
    ]

    _add_route(
        graph,
        fast_nodes,
        cve_prefix="CVE-2026-F",
        cvss=9.8,
        detection=0.95,
        service="rdp",
        description="Fast but very noisy route",
    )
    _add_route(
        graph,
        balanced_nodes,
        cve_prefix="CVE-2026-B",
        cvss=8.7,
        detection=0.14,
        service="http",
        description="Balanced pivot route",
    )
    _add_route(
        graph,
        stealth_nodes,
        cve_prefix="CVE-2026-S",
        cvss=7.5,
        detection=0.02,
        service="ssh",
        description="Long low-detection route",
    )

    routes = {
        "fast_corridor": fast_nodes,
        "balanced_corridor": balanced_nodes,
        "stealth_corridor": stealth_nodes,
    }
    return graph, start, goal, routes


def run_benchmark(
    graph: nx.DiGraph,
    start: str,
    goal: str,
    routes: dict[str, list[str]],
    output_dir: Path,
    repeats: int,
) -> dict:
    """Run all planners and write benchmark artifacts."""
    output_dir.mkdir(parents=True, exist_ok=True)
    paths_dir = output_dir / "paths"
    visuals_dir = output_dir / "visuals"
    paths_dir.mkdir(exist_ok=True)
    visuals_dir.mkdir(exist_ok=True)

    graph_path = output_dir / "huge_graph.pkl"
    with graph_path.open("wb") as fh:
        pickle.dump(graph, fh)

    qtable_path = output_dir / "qtable.pkl"
    seeded_rl_path = _nodes_to_edges(graph, routes["balanced_corridor"])
    _write_seeded_qtable(seeded_rl_path, start, qtable_path)

    astar = AStarPlanner()
    detection = DetectionAwarePlanner(alpha=0.5, beta=0.5)
    rl = RLPlanner(qtable_path=str(qtable_path))
    llm = LLMPlanner(api_key="")

    timings: dict[str, dict] = {}
    paths: RouteMap = {}

    timings["astar"], paths["astar"] = _time_path(
        "astar", lambda: astar.plan(graph, start, goal), repeats
    )
    timings["detection_combined"], paths["detection_combined"] = _time_path(
        "detection_combined", lambda: detection.plan(graph, start, goal), repeats
    )
    timings["rl_seeded"], paths["rl_seeded"] = _time_path(
        "rl_seeded", lambda: rl.plan(graph, start, goal), repeats
    )
    timings["llm_offline"], paths["llm_offline"] = _time_path(
        "llm_offline", lambda: llm.plan(graph, start, goal), repeats
    )

    pareto_timing, pareto_paths = _time_value(
        "detection_pareto", lambda: detection.plan_pareto(graph, start, goal), repeats
    )
    timings["detection_pareto"] = pareto_timing
    paths["detection_fastest"] = pareto_paths["fastest"]
    paths["detection_stealthiest"] = pareto_paths["stealthiest"]
    paths["detection_pareto_balanced"] = pareto_paths["balanced"]

    summary = {
        "benchmark": {
            "devices": graph.number_of_nodes(),
            "attack_edges": graph.number_of_edges(),
            "zones": len({data["zone"] for _, data in graph.nodes(data=True)}),
            "start": start,
            "goal": goal,
            "repeats": repeats,
        },
        "timings_ms": timings,
        "paths": {
            name: _path_metrics(path)
            for name, path in paths.items()
        },
    }

    for name, path in paths.items():
        (paths_dir / f"{name}_path.json").write_text(
            json.dumps(_path_to_json(path), indent=2)
        )

    (output_dir / "benchmark_summary.json").write_text(json.dumps(summary, indent=2))
    _write_config(output_dir / "config.yaml", start, goal, qtable_path)
    _write_commands(output_dir / "commands.md", graph_path, output_dir, start, goal)
    _write_report(output_dir / "README.md", summary)
    _write_dashboard(output_dir / "dashboard.html", summary)
    _write_visuals(visuals_dir, graph, routes, summary)
    return summary


def _add_route(
    graph: nx.DiGraph,
    nodes: list[str],
    cve_prefix: str,
    cvss: float,
    detection: float,
    service: str,
    description: str,
) -> None:
    for idx, (src, tgt) in enumerate(zip(nodes, nodes[1:]), start=1):
        _add_edge(
            graph,
            src,
            tgt,
            cve_id=f"{cve_prefix}{idx:04d}",
            cvss=cvss,
            detection=detection,
            service=service,
            description=description,
        )


def _add_edge(
    graph: nx.DiGraph,
    src: str,
    tgt: str,
    cve_id: str,
    cvss: float,
    detection: float,
    service: str,
    description: str,
) -> None:
    port_by_service = {
        "http": 80,
        "ssh": 22,
        "smb": 445,
        "rdp": 3389,
        "mysql": 3306,
        "k8s": 6443,
    }
    module_service = service if service != "k8s" else "http"
    edge = AttackEdge(
        source_host=src,
        target_host=tgt,
        cve_id=cve_id,
        exploit_module=f"exploit/synthetic/{module_service}/{cve_id.lower().replace('-', '_')}",
        preconditions=["has_network_access", f"port_{port_by_service.get(service, 443)}_open"],
        postconditions=["has_shell_on_target"],
        cvss_score=cvss,
        detection_weight=detection,
        service_name=service,
        description=description,
    )
    graph.add_edge(src, tgt, data=edge)


def _nodes_to_edges(graph: nx.DiGraph, nodes: list[str]) -> list[AttackEdge]:
    return [graph.edges[src, tgt]["data"] for src, tgt in zip(nodes, nodes[1:])]


def _write_seeded_qtable(path: list[AttackEdge], start: str, output_path: Path) -> None:
    """Write a deterministic Q-table that represents a learned balanced policy."""
    q_table: dict[tuple, float] = {}
    compromised = frozenset({start})
    for idx, edge in enumerate(path):
        state = (edge.source_host, compromised)
        q_table[(state, edge.cve_id)] = 100.0 - idx
        compromised = compromised | {edge.target_host}
    with output_path.open("wb") as fh:
        pickle.dump(q_table, fh)


def _time_path(
    label: str,
    func: Callable[[], list[AttackEdge]],
    repeats: int,
) -> tuple[dict, list[AttackEdge]]:
    stats, path = _time_value(label, func, repeats)
    return stats, path


def _time_value(label: str, func: Callable[[], object], repeats: int) -> tuple[dict, object]:
    durations: list[float] = []
    value = None
    for _ in range(max(1, repeats)):
        start = time.perf_counter()
        value = func()
        durations.append((time.perf_counter() - start) * 1000)
    assert value is not None
    return (
        {
            "label": label,
            "runs": len(durations),
            "mean": round(statistics.mean(durations), 4),
            "median": round(statistics.median(durations), 4),
            "min": round(min(durations), 4),
            "max": round(max(durations), 4),
        },
        value,
    )


def _path_metrics(path: list[AttackEdge]) -> dict:
    exploit_cost = sum(10.0 - edge.cvss_score for edge in path)
    detection_cost = sum(edge.detection_weight for edge in path)
    combined_cost = sum(
        0.5 * (10.0 - edge.cvss_score) + 0.5 * edge.detection_weight * 10.0
        for edge in path
    )
    return {
        "steps": len(path),
        "exploit_cost": round(exploit_cost, 3),
        "detection_cost": round(detection_cost, 3),
        "combined_cost": round(combined_cost, 3),
        "route": [
            f"{edge.source_host}->{edge.target_host} ({edge.cve_id})"
            for edge in path
        ],
    }


def _path_to_json(path: list[AttackEdge]) -> list[dict]:
    return [
        {
            "source": edge.source_host,
            "target": edge.target_host,
            "cve_id": edge.cve_id,
            "module": edge.exploit_module,
            "cvss": edge.cvss_score,
            "detection_weight": edge.detection_weight,
            "service": edge.service_name,
        }
        for edge in path
    ]


def _write_config(config_path: Path, start: str, goal: str, qtable_path: Path) -> None:
    config_path.write_text(
        f"""# Huge benchmark config.
# Uses offline LLM fallback by default so the 600-device example is free to run.

lab:
  attacker_ip: "{start}"
  network: "10.60.0.0/16"
  hosts: []
  goal: "{goal}"

metasploit:
  host: "127.0.0.1"
  port: 55553
  password: ""

groq:
  api_key: ""
  model: "llama-3.3-70b-versatile"
  max_retries: 1

neo4j:
  uri: "bolt://localhost:7687"
  user: "neo4j"
  password: ""

ids:
  type: "snort"
  log_path: "auto"
  alert_threshold: 3

planner:
  default: "astar"
  detection_alpha: 0.5
  detection_beta: 0.5
  rl_qtable_path: "{qtable_path.as_posix()}"
  rl_episodes: 0

evaluation:
  runs_per_planner: 1
  output_dir: "{config_path.parent.as_posix()}"
  generate_dashboard: true
"""
    )


def _write_commands(
    path: Path,
    graph_path: Path,
    output_dir: Path,
    start: str,
    goal: str,
) -> None:
    graph_arg = graph_path.as_posix()
    config_arg = (output_dir / "config.yaml").as_posix()
    path.write_text(
        f"""# Huge benchmark commands

Regenerate the full benchmark:

```bash
python3 scripts/huge_benchmark.py --devices 600 --repeats 25 --output {output_dir.as_posix()}
```

Run individual planners against the generated graph:

```bash
python3 main.py --config {config_arg} plan --graph {graph_arg} --planner astar --start {start} --goal {goal}
python3 main.py --config {config_arg} plan --graph {graph_arg} --planner detection --start {start} --goal {goal} --select stealthiest
python3 main.py --config {config_arg} plan --graph {graph_arg} --planner rl --start {start} --goal {goal}
python3 main.py --config {config_arg} plan --graph {graph_arg} --planner llm --start {start} --goal {goal}
```

The bundled config intentionally uses offline LLM fallback. Add a Groq API key
to that config only if you explicitly want to test live LLM latency on the
large serialized graph.
"""
    )


def _write_report(path: Path, summary: dict) -> None:
    lines = [
        "# Huge 600-Device Benchmark",
        "",
        "Synthetic, local-only benchmark for comparing planner behavior on a large attack graph.",
        "",
        "## Scale",
        "",
        f"- Devices: `{summary['benchmark']['devices']}`",
        f"- Attack edges: `{summary['benchmark']['attack_edges']}`",
        f"- Zones: `{summary['benchmark']['zones']}`",
        f"- Start: `{summary['benchmark']['start']}`",
        f"- Goal: `{summary['benchmark']['goal']}`",
        f"- Timing repeats per planner: `{summary['benchmark']['repeats']}`",
        "",
        "## Planner Results",
        "",
        "| Planner/view | Steps | Exploit cost | Detection cost | Combined cost | Mean planning time |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for label, metrics in summary["paths"].items():
        timing_key = _timing_key_for_path(label)
        timing = summary["timings_ms"].get(timing_key, {})
        lines.append(
            f"| `{label}` | {metrics['steps']} | {metrics['exploit_cost']} | "
            f"{metrics['detection_cost']} | {metrics['combined_cost']} | "
            f"{timing.get('mean', 0)} ms |"
        )
    lines += [
        "",
        "## Visuals",
        "",
        "![Topology overview](visuals/topology_overview.svg)",
        "",
        "![Planner path length](visuals/path_lengths.svg)",
        "",
        "![Planning runtime](visuals/planning_runtime.svg)",
        "",
        "![Detection cost](visuals/detection_cost.svg)",
        "",
        "## Files",
        "",
        "- `huge_graph.pkl`: generated graph",
        "- `qtable.pkl`: deterministic learned-policy table for the RL planner",
        "- `benchmark_summary.json`: complete metrics",
        "- `commands.md`: reproducible commands",
        "- `paths/*.json`: selected paths per planner/view",
        "- `dashboard.html`: self-contained static report",
    ]
    path.write_text("\n".join(lines) + "\n")


def _write_dashboard(path: Path, summary: dict) -> None:
    rows = []
    for label, metrics in summary["paths"].items():
        timing_key = _timing_key_for_path(label)
        timing = summary["timings_ms"].get(timing_key, {})
        rows.append(
            "<tr>"
            f"<td>{html.escape(label)}</td>"
            f"<td>{metrics['steps']}</td>"
            f"<td>{metrics['exploit_cost']}</td>"
            f"<td>{metrics['detection_cost']}</td>"
            f"<td>{metrics['combined_cost']}</td>"
            f"<td>{timing.get('mean', 0)} ms</td>"
            "</tr>"
        )
    path.write_text(
        f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>AutoAttack Huge Benchmark</title>
  <style>
    body {{ font-family: Segoe UI, sans-serif; margin: 2rem; background: #0f172a; color: #e2e8f0; }}
    h1, h2 {{ color: #38bdf8; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1rem 0 2rem; }}
    th, td {{ border: 1px solid #334155; padding: 0.6rem; text-align: left; }}
    th {{ background: #1e293b; }}
    img {{ max-width: 100%; background: white; border-radius: 12px; margin: 1rem 0; }}
    .card {{ background: #111827; border: 1px solid #334155; border-radius: 14px; padding: 1rem; margin-bottom: 1rem; }}
  </style>
</head>
<body>
  <h1>AutoAttack Huge Benchmark</h1>
  <div class="card">
    <p><strong>{summary['benchmark']['devices']}</strong> devices,
    <strong>{summary['benchmark']['attack_edges']}</strong> attack edges,
    <strong>{summary['benchmark']['zones']}</strong> zones.</p>
  </div>
  <h2>Planner Results</h2>
  <table>
    <thead><tr><th>Planner/view</th><th>Steps</th><th>Exploit cost</th><th>Detection cost</th><th>Combined cost</th><th>Mean planning time</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
  <h2>Visuals</h2>
  <img src="visuals/topology_overview.svg" alt="Topology overview">
  <img src="visuals/path_lengths.svg" alt="Path lengths">
  <img src="visuals/planning_runtime.svg" alt="Planning runtime">
  <img src="visuals/detection_cost.svg" alt="Detection cost">
</body>
</html>
"""
    )


def _write_visuals(
    out_dir: Path,
    graph: nx.DiGraph,
    routes: dict[str, list[str]],
    summary: dict,
) -> None:
    _write_topology_svg(out_dir / "topology_overview.svg", graph, routes)
    _write_bar_svg(
        out_dir / "path_lengths.svg",
        "Path length by planner/view",
        {name: metrics["steps"] for name, metrics in summary["paths"].items()},
        "steps",
    )
    _write_bar_svg(
        out_dir / "planning_runtime.svg",
        "Mean planning runtime",
        {name: metrics["mean"] for name, metrics in summary["timings_ms"].items()},
        "ms",
    )
    _write_bar_svg(
        out_dir / "detection_cost.svg",
        "Total detection cost",
        {name: metrics["detection_cost"] for name, metrics in summary["paths"].items()},
        "cost",
    )


def _write_bar_svg(path: Path, title: str, values: dict[str, float], unit: str) -> None:
    width = 1040
    row_h = 34
    left = 260
    right = 140
    top = 58
    height = top + row_h * len(values) + 40
    max_val = max(values.values()) or 1.0
    colors = ["#2563eb", "#dc2626", "#16a34a", "#f59e0b", "#7c3aed", "#0891b2", "#db2777"]
    parts = [
        _svg_header(width, height),
        f'<rect width="{width}" height="{height}" fill="#f8fafc"/>',
        f'<text x="24" y="34" font-size="24" font-family="Segoe UI" font-weight="700" fill="#0f172a">{html.escape(title)}</text>',
    ]
    for idx, (name, value) in enumerate(values.items()):
        y = top + idx * row_h
        bar_w = (width - left - right) * (float(value) / max_val)
        color = colors[idx % len(colors)]
        parts += [
            f'<text x="24" y="{y + 21}" font-size="14" font-family="Segoe UI" fill="#334155">{html.escape(name)}</text>',
            f'<rect x="{left}" y="{y}" width="{bar_w:.1f}" height="22" rx="6" fill="{color}"/>',
            f'<text x="{left + bar_w + 10:.1f}" y="{y + 17}" font-size="13" font-family="Segoe UI" fill="#0f172a">{value:g} {html.escape(unit)}</text>',
        ]
    parts.append("</svg>")
    path.write_text("\n".join(parts))


def _write_topology_svg(
    path: Path,
    graph: nx.DiGraph,
    routes: dict[str, list[str]],
) -> None:
    width = 1220
    height = 720
    zone_count = max(data["zone"] for _, data in graph.nodes(data=True)) + 1
    max_slot = max(data["slot"] for _, data in graph.nodes(data=True))
    x_gap = (width - 140) / max(1, zone_count - 1)
    y_gap = (height - 150) / max(1, max_slot - 1)

    def coord(node: str) -> tuple[float, float]:
        data = graph.nodes[node]
        return 70 + data["zone"] * x_gap, 95 + (data["slot"] - 1) * y_gap

    route_colors = {
        "fast_corridor": "#dc2626",
        "balanced_corridor": "#2563eb",
        "stealth_corridor": "#16a34a",
    }

    parts = [
        _svg_header(width, height),
        f'<rect width="{width}" height="{height}" fill="#f8fafc"/>',
        '<text x="24" y="34" font-size="24" font-family="Segoe UI" font-weight="700" fill="#0f172a">600-device synthetic network fabric</text>',
        '<text x="24" y="58" font-size="14" font-family="Segoe UI" fill="#475569">Dots are devices; colored lines are the competing benchmark corridors.</text>',
    ]

    for zone in range(zone_count):
        x = 70 + zone * x_gap
        parts.append(f'<line x1="{x:.1f}" y1="82" x2="{x:.1f}" y2="{height - 42}" stroke="#e2e8f0" stroke-width="1"/>')
        parts.append(f'<text x="{x - 18:.1f}" y="{height - 18}" font-size="12" font-family="Segoe UI" fill="#64748b">Z{zone}</text>')

    route_nodes = {node for route in routes.values() for node in route}
    for node, data in graph.nodes(data=True):
        x, y = coord(node)
        fill = "#0f172a" if node in route_nodes else "#cbd5e1"
        radius = 3.4 if node in route_nodes else 2.0
        parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{radius}" fill="{fill}" opacity="0.92"/>')

    for route_name, nodes in routes.items():
        color = route_colors[route_name]
        points = " ".join(f"{coord(node)[0]:.1f},{coord(node)[1]:.1f}" for node in nodes)
        parts.append(f'<polyline points="{points}" fill="none" stroke="{color}" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round" opacity="0.88"/>')

    legend_y = 88
    for idx, (label, color) in enumerate(route_colors.items()):
        x = 760 + idx * 145
        parts.append(f'<rect x="{x}" y="{legend_y - 13}" width="18" height="6" rx="3" fill="{color}"/>')
        parts.append(f'<text x="{x + 26}" y="{legend_y - 6}" font-size="12" font-family="Segoe UI" fill="#334155">{html.escape(label)}</text>')

    parts.append("</svg>")
    path.write_text("\n".join(parts))


def _svg_header(width: int, height: int) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'width="{width}" height="{height}" viewBox="0 0 {width} {height}">'
    )


def _timing_key_for_path(path_label: str) -> str:
    if path_label.startswith("detection_") and path_label != "detection_combined":
        return "detection_pareto"
    if path_label == "rl_seeded":
        return "rl_seeded"
    if path_label == "llm_offline":
        return "llm_offline"
    return path_label


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate a huge AutoAttack benchmark.")
    parser.add_argument("--devices", type=int, default=DEFAULT_DEVICES)
    parser.add_argument("--zones", type=int, default=DEFAULT_ZONES)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--repeats", type=int, default=DEFAULT_REPEATS)
    parser.add_argument("--output", default="examples/huge_benchmark")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    out_dir = Path(args.output)
    graph, start, goal, routes = build_huge_graph(
        devices=args.devices,
        zones=args.zones,
        seed=args.seed,
    )
    summary = run_benchmark(
        graph=graph,
        start=start,
        goal=goal,
        routes=routes,
        output_dir=out_dir,
        repeats=args.repeats,
    )
    print(f"Huge benchmark written to {out_dir}")
    print(
        f"Devices={summary['benchmark']['devices']} "
        f"Edges={summary['benchmark']['attack_edges']} "
        f"Start={summary['benchmark']['start']} "
        f"Goal={summary['benchmark']['goal']}"
    )
    for name, metrics in summary["paths"].items():
        timing = summary["timings_ms"].get(_timing_key_for_path(name), {})
        print(
            f"{name:28} steps={metrics['steps']:>2} "
            f"detect={metrics['detection_cost']:>5} "
            f"mean={timing.get('mean', 0):>8} ms"
        )


if __name__ == "__main__":
    main()
