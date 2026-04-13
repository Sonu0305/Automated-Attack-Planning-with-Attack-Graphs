"""AutoAttack v1.0 — CLI entrypoint.

Commands:
    scan      Parse an Nmap XML file and build the attack graph.
    plan      Run a planner against the attack graph.
    execute   Execute a planned path against the lab.
    evaluate  Run all planners for N repetitions and produce reports.
    train-rl  Train the Q-learning agent on the attack graph.
    dashboard Generate the evaluation dashboard from saved results.

All configuration is read from ``config.yaml`` with env-var substitution
for secrets.  No values are hardcoded.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import pickle
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("autoattack")
console = Console()


# ---------------------------------------------------------------------------
# Config dataclass
# ---------------------------------------------------------------------------


@dataclass
class LabHost:
    """Configuration for a single lab host."""
    ip: str
    hostname: str
    os: str
    role: str = "unknown"


@dataclass
class MetasploitConfig:
    """Metasploit RPC connection settings."""
    host: str = "127.0.0.1"
    port: int = 55553
    password: str = ""
    attacker_ip: str = "127.0.0.1"


@dataclass
class GroqConfig:
    """Groq API settings."""
    api_key: str = ""
    model: str = "llama-3.3-70b-versatile"
    max_retries: int = 3


@dataclass
class Neo4jConfig:
    """Neo4j connection settings."""
    uri: str = "bolt://localhost:7687"
    user: str = "neo4j"
    password: str = ""


@dataclass
class IDSConfig:
    """IDS monitoring settings."""
    type: str = "snort"
    log_path: str = "auto"
    alert_threshold: int = 3


@dataclass
class PlannerConfig:
    """Planner settings."""
    default: str = "astar"
    detection_alpha: float = 0.5
    detection_beta: float = 0.5
    rl_qtable_path: str = "qtable.pkl"
    rl_episodes: int = 5000


@dataclass
class EvaluationConfig:
    """Evaluation run settings."""
    runs_per_planner: int = 20
    output_dir: str = "./results/"
    generate_dashboard: bool = True


@dataclass
class Config:
    """Top-level configuration loaded from config.yaml."""
    attacker_ip: str = "192.168.56.10"
    network: str = "192.168.56.0/24"
    goal: str = "192.168.56.30"
    hosts: list[LabHost] = field(default_factory=list)
    metasploit: MetasploitConfig = field(default_factory=MetasploitConfig)
    groq: GroqConfig = field(default_factory=GroqConfig)
    neo4j: Neo4jConfig = field(default_factory=Neo4jConfig)
    ids: IDSConfig = field(default_factory=IDSConfig)
    planner: PlannerConfig = field(default_factory=PlannerConfig)
    evaluation: EvaluationConfig = field(default_factory=EvaluationConfig)


def load_config(path: str = "config.yaml") -> Config:
    """Load and parse config.yaml, substituting ${ENV_VAR} placeholders.

    Args:
        path: Filesystem path to the config.yaml file.

    Returns:
        Populated ``Config`` dataclass instance.

    Raises:
        FileNotFoundError: If the config file does not exist.
        yaml.YAMLError: If the file is not valid YAML.
    """
    raw = Path(path).read_text()

    # Substitute ${VAR} with environment variables.
    import re
    def _sub(match: re.Match) -> str:
        var = match.group(1)
        return os.environ.get(var, match.group(0))

    raw = re.sub(r"\$\{([^}]+)\}", _sub, raw)
    data = yaml.safe_load(raw)

    lab = data.get("lab", {})
    msf_raw = data.get("metasploit", {})
    groq_raw = data.get("groq", {})
    neo_raw = data.get("neo4j", {})
    ids_raw = data.get("ids", {})
    plan_raw = data.get("planner", {})
    eval_raw = data.get("evaluation", {})

    hosts = [
        LabHost(
            ip=h["ip"],
            hostname=h.get("hostname", h["ip"]),
            os=h.get("os", "linux"),
            role=h.get("role", "unknown"),
        )
        for h in lab.get("hosts", [])
    ]

    return Config(
        attacker_ip=lab.get("attacker_ip", "192.168.56.10"),
        network=lab.get("network", "192.168.56.0/24"),
        goal=lab.get("goal", "192.168.56.30"),
        hosts=hosts,
        metasploit=MetasploitConfig(
            host=msf_raw.get("host", "127.0.0.1"),
            port=int(msf_raw.get("port", 55553)),
            password=msf_raw.get("password", ""),
            attacker_ip=lab.get("attacker_ip", "127.0.0.1"),
        ),
        groq=GroqConfig(
            api_key=groq_raw.get("api_key", ""),
            model=groq_raw.get("model", "llama-3.3-70b-versatile"),
            max_retries=int(groq_raw.get("max_retries", 3)),
        ),
        neo4j=Neo4jConfig(
            uri=neo_raw.get("uri", "bolt://localhost:7687"),
            user=neo_raw.get("user", "neo4j"),
            password=neo_raw.get("password", ""),
        ),
        ids=IDSConfig(
            type=ids_raw.get("type", "snort"),
            log_path=_resolve_ids_log_path(ids_raw.get("log_path", "auto")),
            alert_threshold=int(ids_raw.get("alert_threshold", 3)),
        ),
        planner=PlannerConfig(
            default=plan_raw.get("default", "astar"),
            detection_alpha=float(plan_raw.get("detection_alpha", 0.5)),
            detection_beta=float(plan_raw.get("detection_beta", 0.5)),
            rl_qtable_path=plan_raw.get("rl_qtable_path", "qtable.pkl"),
            rl_episodes=int(plan_raw.get("rl_episodes", 5000)),
        ),
        evaluation=EvaluationConfig(
            runs_per_planner=int(eval_raw.get("runs_per_planner", 20)),
            output_dir=eval_raw.get("output_dir", "./results/"),
            generate_dashboard=bool(eval_raw.get("generate_dashboard", True)),
        ),
    )


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------


def cmd_scan(args: argparse.Namespace, cfg: Config) -> None:
    """Parse an Nmap XML file and build + persist the attack graph.

    Args:
        args: Parsed CLI arguments (expects ``args.nmap_xml``).
        cfg: Loaded configuration.
    """
    from graph.builder import build_graph
    from graph.enricher import CVEEnricher

    console.print(Panel(
        "[bold cyan]AutoAttack v1.0[/] — Automated Attack Graph Planner",
        style="cyan",
    ))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        t1 = progress.add_task("[cyan]Loading CVE enricher...", total=None)
        enricher = CVEEnricher(api_key=os.environ.get("NVD_API_KEY"))
        progress.update(t1, completed=1, total=1)

        t2 = progress.add_task("[cyan]Building attack graph from Nmap XML...", total=None)
        graph = build_graph(args.nmap_xml, enricher)
        progress.update(t2, completed=1, total=1)

        if args.save:
            t3 = progress.add_task("[cyan]Saving graph...", total=None)
            _ensure_parent_dir(args.save)
            with open(args.save, "wb") as fh:
                pickle.dump(graph, fh)
            progress.update(t3, completed=1, total=1)

    n_nodes = graph.number_of_nodes()
    n_edges = graph.number_of_edges()

    console.print(f"\n[bold green][*][/] Loading attack graph from {args.nmap_xml}")
    console.print(f"    ├── Nodes: [bold]{n_nodes}[/] hosts")
    console.print(f"    ├── Edges: [bold]{n_edges}[/] attack paths")
    console.print(f"    └── Goal: [bold]{cfg.goal}[/] (Target)\n")


def cmd_plan(args: argparse.Namespace, cfg: Config) -> None:
    """Run a planner against the attack graph and display the path.

    Args:
        args: Parsed CLI arguments.
        cfg: Loaded configuration.
    """
    planner_name = args.planner or cfg.planner.default
    graph = _load_graph(args.graph)
    planner = _make_planner(planner_name, cfg)
    start = args.start or cfg.attacker_ip
    goal = args.goal or cfg.goal

    console.print(f"\n[bold green][*][/] Running planner: [bold]{planner_name}[/]")

    with console.status("[cyan]Planning attack path...[/]"):
        if hasattr(planner, "plan_pareto") and planner_name == "detection":
            paths = planner.plan_pareto(graph, start, goal)
            _print_pareto_paths(paths, cfg)
            path = paths.get(args.select or "balanced", paths.get("balanced"))
        else:
            path = planner.plan(graph, start, goal)
            _print_path(path, planner_name)

    if args.save_path:
        _ensure_parent_dir(args.save_path)
        path_data = [
            {
                "source": e.source_host,
                "target": e.target_host,
                "cve_id": e.cve_id,
                "module": e.exploit_module,
            }
            for e in path
        ]
        Path(args.save_path).write_text(json.dumps(path_data, indent=2))
        console.print(f"\n[green][*][/] Path saved to: [bold]{args.save_path}[/]")


def cmd_execute(args: argparse.Namespace, cfg: Config) -> None:
    """Execute a planned attack path against the lab.

    Args:
        args: Parsed CLI arguments.
        cfg: Loaded configuration.
    """
    from executor.playbook_runner import PlaybookRunner
    from graph.models import RunResult

    graph = _load_graph(args.graph)
    planner_name = args.planner or cfg.planner.default
    planner = _make_planner(planner_name, cfg)
    start = args.start or cfg.attacker_ip
    goal = args.goal or cfg.goal

    path = planner.plan(graph, start, goal)

    runner = PlaybookRunner(log_dir=cfg.evaluation.output_dir)
    playbook_path = runner.generate_playbook(
        path, {"attacker_ip": cfg.attacker_ip}, planner_name
    )
    console.print(f"\n[green][*][/] Generating playbook... → [bold]{playbook_path}[/]")

    if not args.yes:
        answer = console.input("\n[bold yellow][*] Execute? (y/N): [/]").strip().lower()
        if answer != "y":
            console.print("[yellow]Aborted.[/]")
            return

    console.print("[green][*][/] Starting execution with PlaybookRunner...\n")
    results = runner.run(path, graph, goal)

    for i, (edge, result) in enumerate(zip(path, results), start=1):
        icon = "[bold green]✓ SUCCESS[/]" if result.success else "[bold red]✗ FAILED[/]"
        preview = result.output.splitlines()[0][:60] if result.output else ""
        console.print(
            f"    Step {i}/{len(path)} {icon}  "
            f"{edge.source_host} → {edge.target_host} via {edge.cve_id}  "
            f"({result.duration_seconds:.1f}s)  — {preview}"
        )

    # Summarise.
    successes = sum(1 for r in results if r.success)
    total_time = sum(r.duration_seconds for r in results)
    total_alerts = sum(r.alerts_triggered for r in results)

    if results and results[-1].success:
        console.print(f"\n[bold green][+] GOAL REACHED: {goal}[/]")
    else:
        console.print(f"\n[bold red][-] GOAL NOT REACHED: {goal}[/]")

    console.print(
        f"[green][+][/] Total time: {total_time:.1f}s | "
        f"Steps: {len(results)} | "
        f"IDS alerts: {total_alerts} | "
        f"Sessions: {successes}"
    )


def cmd_evaluate(args: argparse.Namespace, cfg: Config) -> None:
    """Run all planners for N repetitions and generate reports.

    Args:
        args: Parsed CLI arguments.
        cfg: Loaded configuration.
    """
    from executor.playbook_runner import PlaybookRunner
    from evaluation.metrics import compare_planners
    from evaluation.reporter import generate_report
    from graph.models import RunResult

    graph = _load_graph(args.graph)
    start = cfg.attacker_ip
    goal = cfg.goal
    n_runs = args.runs or cfg.evaluation.runs_per_planner
    out_dir = args.output or cfg.evaluation.output_dir

    planner_names = ["astar", "detection", "llm", "rl"]
    all_results: dict[str, list[RunResult]] = {}

    console.print(f"\n[bold green][*][/] Evaluating {len(planner_names)} planners × {n_runs} runs\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        for planner_name in planner_names:
            task = progress.add_task(
                f"[cyan]{planner_name:<15}[/]", total=n_runs
            )
            results: list[RunResult] = []

            try:
                planner = _make_planner(planner_name, cfg)
            except Exception as exc:
                console.print(f"[yellow]  Skipping {planner_name}: {exc}[/]")
                progress.update(task, completed=n_runs)
                continue

            runner = PlaybookRunner(log_dir=out_dir)

            for run_i in range(n_runs):
                run_start = time.time()
                try:
                    path = planner.plan(graph, start, goal)
                    exec_results = runner.run(path)
                    goal_reached = any(r.success for r in exec_results[-1:])
                    total_alerts = sum(r.alerts_triggered for r in exec_results)
                    results.append(RunResult(
                        planner_name=planner_name,
                        path=path,
                        goal_reached=goal_reached,
                        total_steps=len(exec_results),
                        successful_steps=sum(1 for r in exec_results if r.success),
                        total_duration_seconds=time.time() - run_start,
                        total_alerts=total_alerts,
                    ))
                except Exception as exc:
                    results.append(RunResult(
                        planner_name=planner_name,
                        path=[],
                        goal_reached=False,
                        total_steps=0,
                        successful_steps=0,
                        total_duration_seconds=time.time() - run_start,
                        total_alerts=0,
                    ))
                progress.update(task, advance=1)

            all_results[planner_name] = results

    # Print comparison table.
    df = compare_planners(all_results)
    table = Table(title="Planner Evaluation Results", style="cyan")
    table.add_column("Planner", style="bold")
    for col in df.columns:
        table.add_column(col)
    for planner, row in df.iterrows():
        table.add_row(str(planner), *[str(v) for v in row])
    console.print(table)

    # Generate report artefacts.
    paths = generate_report(all_results, out_dir)
    console.print(f"\n[green][*][/] Results saved to: [bold]{out_dir}[/]")
    for kind, p in paths.items():
        console.print(f"    ├── {kind}: {p}")


def cmd_train_rl(args: argparse.Namespace, cfg: Config) -> None:
    """Train the Q-learning RL agent on the attack graph.

    Args:
        args: Parsed CLI arguments.
        cfg: Loaded configuration.
    """
    from rl.trainer import train

    graph = _load_graph(args.graph)
    start = cfg.attacker_ip
    goal = cfg.goal
    episodes = args.episodes or cfg.planner.rl_episodes
    output = args.output or cfg.planner.rl_qtable_path

    console.print(f"\n[bold green][*][/] Training RL agent for [bold]{episodes:,}[/] episodes\n")
    train(
        graph=graph,
        start=start,
        goal=goal,
        episodes=episodes,
        output_path=output,
    )
    console.print(f"\n[green][+][/] Q-table saved to: [bold]{output}[/]")


def cmd_dashboard(args: argparse.Namespace, cfg: Config) -> None:
    """Generate the evaluation dashboard from saved results.

    Args:
        args: Parsed CLI arguments.
        cfg: Loaded configuration.
    """
    from visualization.dashboard import generate_html_dashboard
    from graph.models import RunResult

    out_dir = args.output or cfg.evaluation.output_dir
    json_path = Path(out_dir) / "report.json"

    all_results: dict[str, list[RunResult]] = {}
    if json_path.exists():
        import dataclasses
        raw = json.loads(json_path.read_text())
        # Re-hydrate results (simplified — just create empty RunResults for dashboard).
        for planner, runs in raw.get("planners", {}).items():
            rehydrated = []
            for r in runs:
                rehydrated.append(RunResult(
                    planner_name=r.get("planner_name", planner),
                    path=[],
                    goal_reached=bool(r.get("goal_reached", False)),
                    total_steps=int(r.get("total_steps", 0)),
                    successful_steps=int(r.get("successful_steps", 0)),
                    total_duration_seconds=float(r.get("total_duration_seconds", 0)),
                    total_alerts=int(r.get("total_alerts", 0)),
                    execution_log=r.get("execution_log", []),
                ))
            all_results[planner] = rehydrated
    else:
        # Generate synthetic data for demo purposes.
        console.print("[yellow][!] No report.json found — generating demo dashboard.[/]")
        all_results = _generate_demo_results()

    dashboard_path = generate_html_dashboard(
        all_results=all_results,
        output_path=str(Path(out_dir) / "dashboard.html"),
    )
    console.print(f"\n[green][+][/] Dashboard written to: [bold]{dashboard_path}[/]")
    console.print("[green][+][/] Open in a browser to view.")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _load_graph(graph_path: Optional[str]) -> object:
    """Load a pickled NetworkX attack graph from disk.

    Args:
        graph_path: Path to the pickle file.

    Returns:
        Loaded ``nx.DiGraph``.

    Raises:
        SystemExit: If the file does not exist.
    """
    if not graph_path or not Path(graph_path).exists():
        console.print(
            f"[bold red]Error:[/] Graph file not found: {graph_path}\n"
            f"Run: [bold]{_python_command_hint()} main.py scan --nmap-xml scan.xml --save graph.pkl[/]"
        )
        sys.exit(1)
    with open(graph_path, "rb") as fh:
        return pickle.load(fh)


def _make_planner(name: str, cfg: Config) -> object:
    """Instantiate a planner by name using config values.

    Args:
        name: Planner identifier: ``"astar"``, ``"detection"``,
            ``"llm"``, or ``"rl"``.
        cfg: Loaded configuration.

    Returns:
        Configured planner instance.

    Raises:
        ValueError: If the planner name is unknown.
    """
    if name == "astar":
        from planners.astar_planner import AStarPlanner
        return AStarPlanner()

    if name == "detection":
        from planners.detection_aware import DetectionAwarePlanner
        return DetectionAwarePlanner(alpha=cfg.planner.detection_alpha, beta=cfg.planner.detection_beta)

    if name == "llm":
        from planners.llm_planner import LLMPlanner
        return LLMPlanner(api_key=cfg.groq.api_key, model=cfg.groq.model, max_retries=cfg.groq.max_retries)

    if name == "rl":
        from planners.rl_planner import RLPlanner
        return RLPlanner(qtable_path=cfg.planner.rl_qtable_path)

    raise ValueError(f"Unknown planner '{name}'. Choose: astar, detection, llm, rl.")


def _print_path(path: list, planner_name: str) -> None:
    """Pretty-print a linear attack path.

    Args:
        path: List of ``AttackEdge`` objects.
        planner_name: Name label for the header.
    """
    console.print(f"\n[bold green][+][/] Attack path found ({planner_name}, {len(path)} steps):\n")
    for i, edge in enumerate(path, 1):
        console.print(
            f"    Step {i}/{len(path)}: "
            f"{edge.source_host} → {edge.target_host} "
            f"via [bold]{edge.cve_id}[/] "
            f"(CVSS {edge.cvss_score:.1f}, detect={edge.detection_weight:.2f})"
        )


def _print_pareto_paths(paths: dict, cfg: Config) -> None:
    """Pretty-print the three Pareto-optimal paths.

    Args:
        paths: Dict with keys ``"fastest"``, ``"stealthiest"``, ``"balanced"``.
        cfg: Loaded configuration.
    """
    console.print("\n[bold green][+][/] Pareto-optimal paths found:\n")
    labels = {
        "fastest": "FASTEST PATH",
        "stealthiest": "STEALTHIEST PATH",
        "balanced": "BALANCED PATH",
    }
    prefixes = {"fastest": "┌─", "stealthiest": "├─", "balanced": "└─"}
    connectors = {"fastest": "│", "stealthiest": "│", "balanced": " "}

    for key, label in labels.items():
        path = paths.get(key, [])
        if not path:
            continue
        ec = sum(10.0 - e.cvss_score for e in path)
        dc = sum(e.detection_weight for e in path)
        header = f"{prefixes[key]} {label} ({len(path)} steps, exploit_cost={ec:.1f}, detect_cost={dc:.2f})"
        if key == "stealthiest":
            header += " ← SELECTED"
        console.print(f"    {header}")
        for i, edge in enumerate(path, 1):
            console.print(
                f"    {connectors[key]}   Step {i}: "
                f"{edge.source_host} → {edge.target_host} "
                f"via {edge.cve_id} "
                f"(CVSS {edge.cvss_score:.1f}, detect={edge.detection_weight:.2f})"
            )
        console.print(f"    {connectors[key]}")


def _execute_with_progress(
    runner: object,
    path: list,
    graph: object,
    goal: str,
) -> list:
    """Execute a path showing per-step progress bars.

    Args:
        runner: ``PlaybookRunner`` instance.
        path: List of ``AttackEdge`` objects.
        graph: Attack graph.
        goal: Target host IP.

    Returns:
        List of ``ExecutionResult`` objects.
    """
    from executor.playbook_runner import PlaybookRunner

    results = []
    for i, edge in enumerate(path):
        step_label = f"Step {i + 1}/{len(path)}"
        start = time.time()
        result = runner._dispatch(edge)  # type: ignore[attr-defined]
        results.append(result)
        duration = time.time() - start
        icon = "[bold green]✓ SUCCESS[/]" if result.success else "[bold red]✗ FAILED[/]"
        console.print(
            f"    {step_label} [{'█' * 10}] {duration:>5.1f}s {icon}"
            f"  — {result.output.splitlines()[0][:60] if result.output else ''}"
        )
        if not result.success:
            console.print("    [bold yellow]⚠  Checking replan trigger...[/]")
    return results


def _ensure_parent_dir(path_str: str) -> None:
    """Create the parent directory for an output path if needed."""
    parent = Path(path_str).expanduser().resolve().parent
    parent.mkdir(parents=True, exist_ok=True)


def _python_command_hint() -> str:
    """Return the most likely Python launcher for the current platform."""
    return "py -3" if os.name == "nt" else "python3"


def _is_wsl() -> bool:
    """Detect whether the current process is running inside WSL."""
    release = platform.release().lower()
    return "microsoft" in release or "wsl" in release


def _resolve_ids_log_path(configured_path: str) -> str:
    """Resolve the IDS log path for Windows or WSL/local demo environments.

    If ``configured_path`` is ``"auto"`` or empty, choose the first
    existing candidate for the current platform and otherwise fall back
    to a repo-local path that is safe on both Windows and WSL.
    """
    if configured_path and configured_path.lower() != "auto":
        return configured_path

    repo_default = Path("logs") / "snort" / "fast.log"

    candidates = [repo_default]
    if os.name == "nt":
        candidates = [
            Path("C:/Snort/log/alert_fast.txt"),
            Path("C:/Program Files/Snort/log/alert_fast.txt"),
            repo_default,
        ]
    elif _is_wsl():
        candidates = [
            Path("/var/log/snort/fast.log"),
            repo_default,
        ]
    else:
        candidates = [repo_default]

    for candidate in candidates:
        if candidate.exists():
            return str(candidate)

    return str(repo_default)


def _generate_demo_results() -> dict:
    """Generate synthetic RunResult data for demo dashboard rendering.

    Returns:
        Dict mapping planner name → list of RunResult.
    """
    from graph.models import RunResult

    demo: dict = {}
    stats = {
        "astar":      (0.85, 3.2, 4.1, 28.5),
        "detection":  (0.80, 4.1, 1.2, 34.2),
        "llm":        (0.90, 3.6, 3.8, 42.1),
        "rl":         (0.75, 4.8, 2.9, 36.7),
    }
    import random as rnd
    for planner, (sr, steps, alerts, dur) in stats.items():
        results = []
        for _ in range(20):
            results.append(RunResult(
                planner_name=planner,
                path=[],
                goal_reached=rnd.random() < sr,
                total_steps=max(1, int(rnd.gauss(steps, 0.5))),
                successful_steps=max(1, int(rnd.gauss(steps * sr, 0.3))),
                total_duration_seconds=max(5.0, rnd.gauss(dur, 5.0)),
                total_alerts=max(0, int(rnd.gauss(alerts, 0.5))),
            ))
        demo[planner] = results
    return demo


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser.

    Returns:
        Configured ``argparse.ArgumentParser``.
    """
    parser = argparse.ArgumentParser(
        prog="autoattack",
        description="AutoAttack v1.0 — Automated Attack Graph Planner",
    )
    parser.add_argument(
        "--config", default="config.yaml", help="Path to config.yaml (default: config.yaml)"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    scan_p = sub.add_parser("scan", help="Parse Nmap XML and build attack graph.")
    scan_p.add_argument("--nmap-xml", dest="nmap_xml", required=True, help="Path to Nmap XML file.")
    scan_p.add_argument("--save", default="graph.pkl", help="Save graph to pickle file.")

    # plan
    plan_p = sub.add_parser("plan", help="Run a planner against the attack graph.")
    plan_p.add_argument("--graph", required=True, help="Path to graph pickle.")
    plan_p.add_argument("--planner", default=None, help="astar|detection|llm|rl")
    plan_p.add_argument("--start", default=None, help="Attacker start IP.")
    plan_p.add_argument("--goal", default=None, help="Target goal IP.")
    plan_p.add_argument("--select", default="balanced", help="For detection planner: fastest|stealthiest|balanced.")
    plan_p.add_argument("--save-path", dest="save_path", default=None, help="Save path JSON to file.")

    # execute
    exec_p = sub.add_parser("execute", help="Execute a planned path against the lab.")
    exec_p.add_argument("--graph", required=True, help="Path to graph pickle.")
    exec_p.add_argument("--planner", default=None)
    exec_p.add_argument("--start", default=None)
    exec_p.add_argument("--goal", default=None)
    exec_p.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompt.")

    # evaluate
    eval_p = sub.add_parser("evaluate", help="Run all planners and generate reports.")
    eval_p.add_argument("--graph", required=True)
    eval_p.add_argument("--runs", type=int, default=None, help="Runs per planner.")
    eval_p.add_argument("--output", default=None, help="Output directory.")

    # train-rl
    rl_p = sub.add_parser("train-rl", help="Train the Q-learning RL agent.")
    rl_p.add_argument("--graph", required=True)
    rl_p.add_argument("--episodes", type=int, default=None)
    rl_p.add_argument("--output", default=None, help="Output Q-table path.")

    # dashboard
    dash_p = sub.add_parser("dashboard", help="Generate evaluation dashboard HTML.")
    dash_p.add_argument("--output", default=None, help="Output directory.")

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Parse CLI arguments, load config, and dispatch to command handler."""
    parser = build_parser()
    args = parser.parse_args()

    try:
        cfg = load_config(args.config)
    except FileNotFoundError:
        console.print(f"[bold red]Config file not found:[/] {args.config}")
        sys.exit(1)
    except Exception as exc:
        console.print(f"[bold red]Config error:[/] {exc}")
        sys.exit(1)

    dispatch = {
        "scan":      cmd_scan,
        "plan":      cmd_plan,
        "execute":   cmd_execute,
        "evaluate":  cmd_evaluate,
        "train-rl":  cmd_train_rl,
        "dashboard": cmd_dashboard,
    }

    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    try:
        handler(args, cfg)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/]")
        sys.exit(0)
    except Exception as exc:
        console.print(f"\n[bold red]Error:[/] {exc}")
        logger.exception("Unhandled exception in command '%s'", args.command)
        sys.exit(1)


if __name__ == "__main__":
    main()
