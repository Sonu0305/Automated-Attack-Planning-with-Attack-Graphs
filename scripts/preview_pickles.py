#!/usr/bin/env python3
"""Generate a visual HTML preview for pickle files in this repository."""

from __future__ import annotations

import argparse
import html
import math
import pickle
import re
import sys
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Render a self-contained HTML preview for all .pkl files."
    )
    parser.add_argument("--root", default=str(REPO_ROOT), help="Root directory to scan.")
    parser.add_argument(
        "--output",
        default=str(REPO_ROOT / "results" / "pkl_preview.html"),
        help="Destination HTML file.",
    )
    args = parser.parse_args()

    root = Path(args.root).resolve()
    output = Path(args.output).resolve()
    paths = sorted(root.rglob("*.pkl"), key=lambda p: p.as_posix())

    sections: list[str] = []
    rows: list[dict[str, str]] = []

    for idx, path in enumerate(paths):
        rel = path.relative_to(root).as_posix()
        section_id = f"pkl-{idx}"
        result = load_pickle(path)
        size = path.stat().st_size

        if result["ok"]:
            obj = result["value"]
            kind = classify(obj)
            body = render_object(obj, rel)
            type_name = f"{type(obj).__module__}.{type(obj).__name__}"
            note = kind
        else:
            body = render_error(result["error"])
            type_name = "load error"
            note = "error"

        rows.append(
            {
                "file": f'<a href="#{section_id}">{esc(rel)}</a>',
                "kind": esc(note),
                "type": esc(type_name),
                "size": human_bytes(size),
            }
        )

        sections.append(
            f"""
            <section class="panel" id="{section_id}">
              <div class="panel-head">
                <div>
                  <p class="eyebrow">{esc(note)}</p>
                  <h2>{esc(rel)}</h2>
                </div>
                <span class="pill">{human_bytes(size)}</span>
              </div>
              <p class="type-line">{esc(type_name)}</p>
              {body}
            </section>
            """
        )

    summary = table(
        rows,
        ["file", "kind", "type", "size"],
        empty="No pickle files found under this root.",
        raw_columns={"file"},
    )
    document = assemble_html(root, output, len(paths), summary, "\n".join(sections))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(document, encoding="utf-8")
    print(output)
    return 0


def load_pickle(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as fh:
            return {"ok": True, "value": pickle.load(fh)}
    except UnicodeDecodeError:
        try:
            with path.open("rb") as fh:
                return {"ok": True, "value": pickle.load(fh, encoding="latin1")}
        except Exception as exc:  # pragma: no cover - defensive CLI behavior.
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    except Exception as exc:  # pragma: no cover - defensive CLI behavior.
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def classify(obj: Any) -> str:
    if is_graph(obj):
        return "NetworkX graph"
    if hasattr(obj, "shape") and hasattr(obj, "dtype"):
        return "array"
    if isinstance(obj, dict):
        if obj and all(is_qtable_key(k) for k in list(obj.keys())[:10]):
            return "Q-table"
        return "dict"
    if isinstance(obj, (list, tuple)):
        return "sequence"
    return "object"


def render_object(obj: Any, rel_path: str) -> str:
    if is_graph(obj):
        return render_graph(obj)
    if hasattr(obj, "shape") and hasattr(obj, "dtype"):
        return render_array(obj)
    if isinstance(obj, dict):
        return render_dict(obj)
    if isinstance(obj, (list, tuple)):
        return render_sequence(obj)
    return f"<pre>{esc(short_repr(obj, 4000))}</pre>"


def is_graph(obj: Any) -> bool:
    return all(hasattr(obj, attr) for attr in ("nodes", "edges", "number_of_nodes", "number_of_edges"))


def is_qtable_key(key: Any) -> bool:
    return (
        isinstance(key, tuple)
        and len(key) == 2
        and isinstance(key[0], tuple)
        and len(key[0]) == 2
    )


def render_graph(graph: Any) -> str:
    node_count = graph.number_of_nodes()
    edge_count = graph.number_of_edges()
    edge_rows = graph_edge_rows(graph, limit=18)
    node_rows = graph_node_rows(graph, limit=18)
    cvss_values = [row["_cvss"] for row in edge_rows if row["_cvss"] is not None]
    detection_values = [row["_detection"] for row in edge_rows if row["_detection"] is not None]

    density = 0.0
    if node_count > 1:
        density = edge_count / (node_count * (node_count - 1))

    metrics = [
        {"label": "Nodes", "value": str(node_count)},
        {"label": "Edges", "value": str(edge_count)},
        {"label": "Density", "value": f"{density:.4f}"},
        {
            "label": "Avg CVSS",
            "value": f"{sum(cvss_values) / len(cvss_values):.2f}" if cvss_values else "n/a",
        },
        {
            "label": "Avg detection",
            "value": f"{sum(detection_values) / len(detection_values):.2f}"
            if detection_values
            else "n/a",
        },
    ]

    display_edge_rows = [
        {k: v for k, v in row.items() if not k.startswith("_")} for row in edge_rows
    ]
    svg = graph_svg(graph)
    return f"""
      <div class="metrics">{''.join(metric_card(m['label'], m['value']) for m in metrics)}</div>
      <div class="viz">{svg}</div>
      <div class="split">
        <div>
          <h3>Nodes</h3>
          {table(node_rows, ["node", "hostname", "role", "os", "services"])}
        </div>
        <div>
          <h3>Edges</h3>
          {table(display_edge_rows, ["source", "target", "cve", "cvss", "detection", "service"])}
        </div>
      </div>
    """


def graph_node_rows(graph: Any, limit: int) -> list[dict[str, str]]:
    rows = []
    for node_id, data in list(graph.nodes(data=True))[:limit]:
        host = data.get("data") if isinstance(data, dict) else None
        services = getattr(host, "services", []) if host is not None else []
        service_names = []
        for svc in services[:4]:
            name = getattr(svc, "name", "")
            port = getattr(svc, "port", "")
            service_names.append(f"{name}:{port}" if port != "" else str(name))
        if len(services) > 4:
            service_names.append(f"+{len(services) - 4}")
        rows.append(
            {
                "node": str(node_id),
                "hostname": str(getattr(host, "hostname", "")),
                "role": str(getattr(host, "role", data.get("role", "") if isinstance(data, dict) else "")),
                "os": str(getattr(host, "os", "")),
                "services": ", ".join(service_names),
            }
        )
    return rows


def graph_edge_rows(graph: Any, limit: int) -> list[dict[str, Any]]:
    rows = []
    for source, target, data in list(graph.edges(data=True))[:limit]:
        edge = data.get("data") if isinstance(data, dict) else None
        cvss = as_float(getattr(edge, "cvss_score", None))
        detection = as_float(getattr(edge, "detection_weight", None))
        rows.append(
            {
                "source": str(source),
                "target": str(target),
                "cve": str(getattr(edge, "cve_id", "")),
                "cvss": f"{cvss:.1f}" if cvss is not None else "",
                "detection": f"{detection:.2f}" if detection is not None else "",
                "service": str(getattr(edge, "service_name", "")),
                "_cvss": cvss,
                "_detection": detection,
            }
        )
    return rows


def graph_svg(graph: Any) -> str:
    width = 1120
    height = 560
    pad = 52
    node_count = graph.number_of_nodes()
    positions = graph_positions(graph, width, height, pad)
    large = node_count > 80
    radius = 3.8 if large else 15
    edge_opacity = "0.18" if large else "0.55"
    node_opacity = "0.74" if large else "0.96"

    parts = [
        f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="Graph preview">',
        "<defs>",
        '<marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">',
        '<path d="M 0 0 L 10 5 L 0 10 z" fill="#334155"></path>',
        "</marker>",
        "</defs>",
        f'<rect width="{width}" height="{height}" rx="8" fill="#f8fafc" stroke="#cbd5e1"></rect>',
    ]

    for source, target, data in graph.edges(data=True):
        if source not in positions or target not in positions:
            continue
        edge = data.get("data") if isinstance(data, dict) else None
        cvss = as_float(getattr(edge, "cvss_score", 0.0)) or 0.0
        color = cvss_color(cvss)
        x1, y1 = positions[source]
        x2, y2 = positions[target]
        marker = ' marker-end="url(#arrow)"' if not large else ""
        title = esc(
            f"{source} -> {target} {getattr(edge, 'cve_id', '')} CVSS {cvss:.1f}"
        )
        parts.append(
            f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
            f'stroke="{color}" stroke-width="{1.5 if not large else 0.7}" '
            f'stroke-opacity="{edge_opacity}"{marker}><title>{title}</title></line>'
        )

    for node_id, data in graph.nodes(data=True):
        x, y = positions[node_id]
        host = data.get("data") if isinstance(data, dict) else None
        role = str(getattr(host, "role", data.get("role", "") if isinstance(data, dict) else "")).lower()
        os_name = str(getattr(host, "os", "")).lower()
        fill = node_color(role, os_name)
        title_bits = [
            str(node_id),
            str(getattr(host, "hostname", "")),
            str(getattr(host, "role", "")),
            str(getattr(host, "os", "")),
        ]
        title = esc(" | ".join(bit for bit in title_bits if bit))
        parts.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{radius}" fill="{fill}" '
            f'stroke="#0f172a" stroke-width="{0.6 if large else 1.2}" '
            f'fill-opacity="{node_opacity}"><title>{title}</title></circle>'
        )
        if not large:
            label = str(node_id)
            parts.append(
                f'<text x="{x:.1f}" y="{y + 31:.1f}" text-anchor="middle" '
                f'font-size="11" fill="#0f172a">{esc(label)}</text>'
            )

    parts.append(legend_svg(width, height))
    parts.append("</svg>")
    return "\n".join(parts)


def graph_positions(graph: Any, width: int, height: int, pad: int) -> dict[Any, tuple[float, float]]:
    nodes = list(graph.nodes(data=True))
    if all(isinstance(data, dict) and "zone" in data and "slot" in data for _, data in nodes):
        zones = sorted({int(data["zone"]) for _, data in nodes})
        max_zone = max(zones) if zones else 0
        zone_slots: dict[int, list[int]] = {}
        for _, data in nodes:
            zone_slots.setdefault(int(data["zone"]), []).append(int(data["slot"]))
        max_slot_by_zone = {
            zone: max(slots) if slots else 1 for zone, slots in zone_slots.items()
        }
        out = {}
        for node_id, data in nodes:
            zone = int(data["zone"])
            slot = int(data["slot"])
            x = pad + (width - 2 * pad) * (zone / max(max_zone, 1))
            y = pad + (height - 2 * pad) * (slot / (max_slot_by_zone[zone] + 1))
            out[node_id] = (x, y)
        return out

    try:
        import networkx as nx

        raw = nx.spring_layout(graph, seed=42, iterations=120)
        return normalize_positions(raw, width, height, pad)
    except Exception:
        out = {}
        total = max(len(nodes), 1)
        cx = width / 2
        cy = height / 2
        radius = min(width, height) * 0.38
        for idx, (node_id, _) in enumerate(nodes):
            angle = (2 * math.pi * idx) / total
            out[node_id] = (cx + radius * math.cos(angle), cy + radius * math.sin(angle))
        return out


def normalize_positions(
    raw: dict[Any, Any], width: int, height: int, pad: int
) -> dict[Any, tuple[float, float]]:
    xs = [float(pos[0]) for pos in raw.values()]
    ys = [float(pos[1]) for pos in raw.values()]
    min_x, max_x = min(xs), max(xs)
    min_y, max_y = min(ys), max(ys)
    dx = max(max_x - min_x, 1e-9)
    dy = max(max_y - min_y, 1e-9)
    out = {}
    for node_id, pos in raw.items():
        x = pad + (float(pos[0]) - min_x) / dx * (width - 2 * pad)
        y = pad + (float(pos[1]) - min_y) / dy * (height - 2 * pad)
        out[node_id] = (x, y)
    return out


def legend_svg(width: int, height: int) -> str:
    items = [
        ("attacker", "#15803d"),
        ("goal", "#dc2626"),
        ("windows", "#d97706"),
        ("linux/other", "#2563eb"),
        ("edge CVSS low/high", "#64748b"),
    ]
    x = 24
    y = height - 26
    parts = []
    for label, color in items:
        parts.append(f'<circle cx="{x}" cy="{y}" r="6" fill="{color}"></circle>')
        parts.append(
            f'<text x="{x + 12}" y="{y + 4}" font-size="12" fill="#334155">{esc(label)}</text>'
        )
        x += 118 if label != "edge CVSS low/high" else 150
    return "\n".join(parts)


def render_dict(obj: dict[Any, Any]) -> str:
    rows = []
    numeric_values = []
    qtable_like = obj and all(is_qtable_key(k) for k in list(obj.keys())[: min(len(obj), 10)])

    for key, value in obj.items():
        numeric = as_float(value)
        if numeric is not None:
            numeric_values.append(numeric)
        if qtable_like:
            state, action = key
            current = state[0]
            visited = state[1]
            visited_list = sorted(str(v) for v in visited) if isinstance(visited, frozenset) else [str(visited)]
            rows.append(
                {
                    "state": str(current),
                    "visited": ", ".join(visited_list),
                    "action": str(action),
                    "value": f"{numeric:.4g}" if numeric is not None else short_repr(value, 120),
                    "_numeric": numeric,
                }
            )
        else:
            rows.append(
                {
                    "key": short_repr(key, 140),
                    "value": short_repr(value, 220),
                    "_numeric": numeric,
                }
            )

    rows = sorted(
        rows,
        key=lambda row: row["_numeric"] if row["_numeric"] is not None else -math.inf,
        reverse=True,
    )
    metrics = [
        metric_card("Entries", str(len(obj))),
        metric_card(
            "Min value",
            f"{min(numeric_values):.4g}" if numeric_values else "n/a",
        ),
        metric_card(
            "Max value",
            f"{max(numeric_values):.4g}" if numeric_values else "n/a",
        ),
    ]
    table_rows = [{k: v for k, v in row.items() if not k.startswith("_")} for row in rows[:40]]
    columns = ["state", "visited", "action", "value"] if qtable_like else ["key", "value"]
    return f"""
      <div class="metrics">{''.join(metrics)}</div>
      {bar_svg(rows[:24]) if numeric_values else ""}
      {table(table_rows, columns)}
    """


def bar_svg(rows: list[dict[str, Any]]) -> str:
    numeric = [row["_numeric"] for row in rows if row.get("_numeric") is not None]
    if not numeric:
        return ""
    width = 1120
    row_h = 26
    height = 64 + row_h * len(rows)
    min_v = min(numeric)
    max_v = max(numeric)
    label_w = 355
    bar_max = width - label_w - 90
    parts = [
        f'<svg class="bar-chart" viewBox="0 0 {width} {height}" role="img" aria-label="Q-table values">',
        f'<rect width="{width}" height="{height}" rx="8" fill="#f8fafc" stroke="#cbd5e1"></rect>',
        '<text x="24" y="34" font-size="18" font-weight="700" fill="#0f172a">Top numeric entries</text>',
    ]
    for idx, row in enumerate(rows):
        value = row.get("_numeric")
        if value is None:
            continue
        y = 58 + idx * row_h
        t = 1.0 if max_v == min_v else (value - min_v) / (max_v - min_v)
        bar_w = max(3, t * bar_max)
        label = row.get("action") or row.get("key") or row.get("state") or "entry"
        parts.append(
            f'<text x="24" y="{y + 16}" font-size="12" fill="#334155">{esc(short_repr(label, 48))}</text>'
        )
        parts.append(
            f'<rect x="{label_w}" y="{y}" width="{bar_w:.1f}" height="18" rx="4" '
            f'fill="{value_color(value, min_v, max_v)}"></rect>'
        )
        parts.append(
            f'<text x="{label_w + bar_w + 8:.1f}" y="{y + 14}" font-size="12" '
            f'fill="#0f172a">{value:.4g}</text>'
        )
    parts.append("</svg>")
    return '<div class="viz">' + "\n".join(parts) + "</div>"


def render_array(obj: Any) -> str:
    shape = tuple(int(v) for v in getattr(obj, "shape", ()))
    dtype = str(getattr(obj, "dtype", ""))
    size = int(getattr(obj, "size", 0))
    metrics = [
        metric_card("Shape", " x ".join(str(v) for v in shape) or "scalar"),
        metric_card("Dtype", dtype),
        metric_card("Items", str(size)),
    ]

    values = flatten_array(obj)
    numeric_values = [v for v in values if isinstance(v, (int, float))]
    if numeric_values:
        metrics.extend(
            [
                metric_card("Min", f"{min(numeric_values):.4g}"),
                metric_card("Max", f"{max(numeric_values):.4g}"),
            ]
        )

    return f"""
      <div class="metrics">{''.join(metrics)}</div>
      {array_svg(obj)}
      <pre>{esc(short_repr(obj, 1600))}</pre>
    """


def flatten_array(obj: Any, limit: int = 10000) -> list[Any]:
    try:
        return [as_builtin(v) for v in obj.ravel()[:limit]]
    except Exception:
        return []


def array_svg(obj: Any) -> str:
    try:
        import numpy as np

        arr = np.asarray(obj)
        if arr.ndim == 0:
            return ""
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        elif arr.ndim > 2:
            arr = arr.reshape(arr.shape[0], -1)
        rows = min(arr.shape[0], 45)
        cols = min(arr.shape[1], 80)
        shown = arr[:rows, :cols]
        numeric = shown.astype(float, copy=False)
    except Exception:
        return ""

    min_v = float(numeric.min()) if numeric.size else 0.0
    max_v = float(numeric.max()) if numeric.size else 1.0
    cell = 12
    left = 48
    top = 44
    width = left + cols * cell + 24
    height = top + rows * cell + 32
    parts = [
        f'<svg class="array-heatmap" viewBox="0 0 {width} {height}" role="img" aria-label="Array heatmap">',
        f'<rect width="{width}" height="{height}" rx="8" fill="#f8fafc" stroke="#cbd5e1"></rect>',
        '<text x="18" y="28" font-size="16" font-weight="700" fill="#0f172a">Array heatmap preview</text>',
    ]
    for r in range(rows):
        for c in range(cols):
            value = float(numeric[r, c])
            parts.append(
                f'<rect x="{left + c * cell}" y="{top + r * cell}" width="{cell - 1}" '
                f'height="{cell - 1}" fill="{value_color(value, min_v, max_v)}">'
                f'<title>row {r}, col {c}: {value:.4g}</title></rect>'
            )
    parts.append("</svg>")
    return '<div class="viz">' + "\n".join(parts) + "</div>"


def render_sequence(obj: Any) -> str:
    rows = [
        {"index": str(idx), "value": short_repr(value, 220)}
        for idx, value in enumerate(list(obj)[:50])
    ]
    return f"""
      <div class="metrics">{metric_card("Items", str(len(obj)))}</div>
      {table(rows, ["index", "value"])}
    """


def render_error(error: str) -> str:
    return f'<div class="error-box">{esc(error)}</div>'


def table(
    rows: list[dict[str, Any]],
    columns: list[str],
    empty: str = "No rows to preview.",
    raw_columns: set[str] | None = None,
) -> str:
    raw_columns = raw_columns or set()
    if not rows:
        return f'<p class="muted">{esc(empty)}</p>'
    head = "".join(f"<th>{esc(col)}</th>" for col in columns)
    body_parts = []
    for row in rows:
        cells = []
        for col in columns:
            value = str(row.get(col, ""))
            cells.append(f"<td>{value if col in raw_columns else esc(value)}</td>")
        body_parts.append("<tr>" + "".join(cells) + "</tr>")
    return f"""
      <div class="table-wrap">
        <table>
          <thead><tr>{head}</tr></thead>
          <tbody>{''.join(body_parts)}</tbody>
        </table>
      </div>
    """


def metric_card(label: str, value: str) -> str:
    return f'<div class="metric"><span>{esc(label)}</span><strong>{esc(value)}</strong></div>'


def assemble_html(root: Path, output: Path, count: int, summary: str, sections: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Pickle Preview</title>
  <style>
    :root {{
      color-scheme: light;
      --ink: #0f172a;
      --muted: #475569;
      --line: #cbd5e1;
      --panel: #ffffff;
      --soft: #f8fafc;
      --blue: #2563eb;
      --green: #15803d;
      --orange: #d97706;
      --red: #dc2626;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: var(--ink);
      background: #e2e8f0;
      letter-spacing: 0;
    }}
    header {{
      padding: 32px clamp(18px, 4vw, 56px) 24px;
      background: #0f172a;
      color: #f8fafc;
    }}
    header h1 {{
      margin: 0 0 8px;
      font-size: clamp(28px, 5vw, 48px);
      line-height: 1.04;
      letter-spacing: 0;
    }}
    header p {{
      margin: 0;
      color: #cbd5e1;
      max-width: 1100px;
    }}
    main {{
      width: min(1280px, calc(100vw - 28px));
      margin: 18px auto 48px;
    }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: clamp(16px, 3vw, 28px);
      margin: 18px 0;
      box-shadow: 0 14px 28px rgba(15, 23, 42, 0.08);
    }}
    .panel-head {{
      display: flex;
      gap: 16px;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 8px;
    }}
    h2 {{
      margin: 0;
      font-size: clamp(18px, 3vw, 28px);
      line-height: 1.18;
      overflow-wrap: anywhere;
      letter-spacing: 0;
    }}
    h3 {{
      margin: 18px 0 10px;
      font-size: 16px;
      letter-spacing: 0;
    }}
    .eyebrow {{
      margin: 0 0 6px;
      text-transform: uppercase;
      color: var(--blue);
      font-size: 12px;
      font-weight: 800;
    }}
    .type-line, .muted {{
      color: var(--muted);
      margin: 0 0 14px;
      overflow-wrap: anywhere;
    }}
    .pill {{
      flex: 0 0 auto;
      display: inline-flex;
      align-items: center;
      min-height: 30px;
      border-radius: 999px;
      padding: 5px 12px;
      background: #e0f2fe;
      color: #075985;
      font-weight: 800;
      font-size: 13px;
      white-space: nowrap;
    }}
    .metrics {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(132px, 1fr));
      gap: 10px;
      margin: 14px 0 16px;
    }}
    .metric {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px 12px;
      background: var(--soft);
    }}
    .metric span {{
      display: block;
      color: var(--muted);
      font-size: 12px;
      margin-bottom: 4px;
    }}
    .metric strong {{
      font-size: 21px;
      line-height: 1;
    }}
    .viz {{
      width: 100%;
      overflow-x: auto;
      margin: 14px 0;
    }}
    svg {{
      width: 100%;
      min-width: 760px;
      max-height: 720px;
      display: block;
    }}
    .bar-chart {{
      max-height: none;
    }}
    .array-heatmap {{
      width: auto;
      max-width: 100%;
      min-width: 360px;
    }}
    .split {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 18px;
    }}
    .table-wrap {{
      overflow-x: auto;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fff;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }}
    th, td {{
      text-align: left;
      vertical-align: top;
      padding: 9px 10px;
      border-bottom: 1px solid #e2e8f0;
      overflow-wrap: anywhere;
    }}
    th {{
      background: #f1f5f9;
      color: #334155;
      font-size: 12px;
      text-transform: uppercase;
    }}
    tr:last-child td {{ border-bottom: 0; }}
    pre {{
      overflow: auto;
      padding: 14px;
      border-radius: 8px;
      background: #0f172a;
      color: #e2e8f0;
      font-size: 12px;
      line-height: 1.45;
    }}
    a {{ color: #1d4ed8; }}
    .error-box {{
      padding: 12px 14px;
      border-radius: 8px;
      border: 1px solid #fecaca;
      background: #fef2f2;
      color: #991b1b;
      font-weight: 700;
    }}
    @media (max-width: 840px) {{
      .split {{ grid-template-columns: 1fr; }}
      .panel-head {{ flex-direction: column; }}
      main {{ width: min(100vw - 18px, 1280px); }}
      svg {{ min-width: 680px; }}
    }}
  </style>
</head>
<body>
  <header>
    <h1>Pickle Preview</h1>
    <p>{count} pickle file(s) found under {esc(root.as_posix())}. Generated at {esc(output.as_posix())}.</p>
  </header>
  <main>
    <section class="panel">
      <div class="panel-head">
        <div>
          <p class="eyebrow">Index</p>
          <h2>All .pkl files</h2>
        </div>
      </div>
      {summary}
    </section>
    {sections}
  </main>
</body>
</html>
"""


def cvss_color(value: float) -> str:
    if value >= 8.5:
        return "#dc2626"
    if value >= 7.0:
        return "#f97316"
    if value >= 4.0:
        return "#ca8a04"
    return "#15803d"


def node_color(role: str, os_name: str) -> str:
    if "attacker" in role:
        return "#15803d"
    if "goal" in role or "crown" in role or "domain" in role:
        return "#dc2626"
    if "windows" in os_name:
        return "#d97706"
    if "linux" in os_name or "ubuntu" in os_name or "kali" in os_name:
        return "#2563eb"
    return "#7c3aed"


def value_color(value: float, min_v: float, max_v: float) -> str:
    if max_v == min_v:
        t = 0.7
    else:
        t = max(0.0, min(1.0, (value - min_v) / (max_v - min_v)))
    stops = [
        (37, 99, 235),
        (20, 184, 166),
        (245, 158, 11),
        (220, 38, 38),
    ]
    scaled = t * (len(stops) - 1)
    idx = min(int(scaled), len(stops) - 2)
    local_t = scaled - idx
    a = stops[idx]
    b = stops[idx + 1]
    rgb = tuple(round(a[i] + (b[i] - a[i]) * local_t) for i in range(3))
    return f"rgb({rgb[0]}, {rgb[1]}, {rgb[2]})"


def as_float(value: Any) -> float | None:
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def as_builtin(value: Any) -> Any:
    try:
        return value.item()
    except AttributeError:
        return value


def short_repr(value: Any, limit: int) -> str:
    if is_dataclass(value):
        try:
            text = repr(asdict(value))
        except Exception:
            text = repr(value)
    else:
        text = repr(value)
    text = re.sub(r"\s+", " ", text)
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return text


def human_bytes(size: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{size} B"


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


if __name__ == "__main__":
    raise SystemExit(main())
