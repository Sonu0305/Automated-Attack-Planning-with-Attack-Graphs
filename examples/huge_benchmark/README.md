# Huge 600-Device Benchmark

Synthetic, local-only benchmark for comparing planner behavior on a large attack graph.

## Scale

- Devices: `600`
- Attack edges: `1597`
- Zones: `12`
- Start: `10.60.0.1`
- Goal: `10.60.11.50`
- Timing repeats per planner: `25`

## Planner Results

| Planner/view | Steps | Exploit cost | Detection cost | Combined cost | Mean planning time |
|---|---:|---:|---:|---:|---:|
| `astar` | 6 | 1.2 | 5.7 | 29.1 | 0.0662 ms |
| `detection_combined` | 11 | 14.3 | 1.54 | 14.85 | 0.4248 ms |
| `rl_seeded` | 11 | 14.3 | 1.54 | 14.85 | 0.1671 ms |
| `llm_offline` | 6 | 1.2 | 5.7 | 29.1 | 3.253 ms |
| `detection_fastest` | 6 | 1.2 | 5.7 | 29.1 | 86.2081 ms |
| `detection_stealthiest` | 13 | 32.5 | 0.26 | 17.55 | 86.2081 ms |
| `detection_pareto_balanced` | 11 | 14.3 | 1.54 | 14.85 | 86.2081 ms |

## Visuals

![Topology overview](visuals/topology_overview.svg)

![Planner path length](visuals/path_lengths.svg)

![Planning runtime](visuals/planning_runtime.svg)

![Detection cost](visuals/detection_cost.svg)

## Files

- `huge_graph.pkl`: generated graph
- `qtable.pkl`: deterministic learned-policy table for the RL planner
- `benchmark_summary.json`: complete metrics
- `commands.md`: reproducible commands
- `paths/*.json`: selected paths per planner/view
- `dashboard.html`: self-contained static report
