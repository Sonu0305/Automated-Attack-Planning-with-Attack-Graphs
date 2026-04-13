# AutoAttack — Evaluation Report
Generated: 2026-04-13 13:48:36

## Executive Summary
- Total runs: 16 (4 planners × 4 runs)
- Best planner: **astar** (100.0% success rate)
- Stealthiest planner: **astar** (avg 0.0 IDS alerts/run)
- Fastest planner: **astar** (avg 1.0 steps, 4.5s)

## Planner Comparison Table

| Planner | success_rate | avg_steps | avg_alerts | avg_duration | runs |
|---|---|---|---|---|---|
| astar | 100.0% | 1.0 | 0.0 | 4.5s | 4 |
| detection | 100.0% | 2.0 | 0.0 | 9.3s | 4 |
| llm | 100.0% | 1.0 | 0.0 | 5.2s | 4 |
| rl | 100.0% | 1.0 | 0.0 | 5.1s | 4 |

## ASCII Bar Charts

Success Rate by Planner (%)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
astar     ████████████████████████████████████████  100.0
detection ████████████████████████████████████████  100.0
llm       ████████████████████████████████████████  100.0
rl        ████████████████████████████████████████  100.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Avg IDS Alerts per Run
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
astar                                                 0.0
detection                                             0.0
llm                                                   0.0
rl                                                    0.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

## Raw Data

Machine-readable results: [report.json](report.json)

Interactive dashboard: [dashboard.html](dashboard.html)