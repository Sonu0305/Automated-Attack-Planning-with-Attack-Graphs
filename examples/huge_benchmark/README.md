# Huge 6,000-Device Benchmark

Synthetic, local-only benchmark for comparing planner behavior on a large attack graph.

## Scale

- Devices: `6000`
- Attack edges: `16005`
- Zones: `12`
- Start: `10.60.0.1`
- Goal: `10.60.11.500`
- Timing repeats per planner: `25`
- LLM backend used in this run: `groq`

## Planner Results

| Planner/view | Steps | Exploit cost | Detection cost | Combined cost | Mean planning time |
|---|---:|---:|---:|---:|---:|
| `astar` | 6 | 1.2 | 5.7 | 29.1 | 0.1164 ms |
| `detection_combined` | 11 | 14.3 | 1.54 | 14.85 | 0.6496 ms |
| `rl_seeded` | 11 | 14.3 | 1.54 | 14.85 | 0.0955 ms |
| `llm_groq` | 11 | 14.3 | 1.54 | 14.85 | 2804.9586 ms |
| `detection_fastest` | 6 | 1.2 | 5.7 | 29.1 | 222.2075 ms |
| `detection_stealthiest` | 18 | 45.0 | 0.36 | 24.3 | 222.2075 ms |
| `detection_pareto_balanced` | 11 | 14.3 | 1.54 | 14.85 | 222.2075 ms |

Live Groq timing is intentionally sampled once even when the other planners use repeated local timing runs.
Live Groq path selection is also nondeterministic, so a fresh rerun may choose a different valid route through the same reduced prompt subgraph.

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
