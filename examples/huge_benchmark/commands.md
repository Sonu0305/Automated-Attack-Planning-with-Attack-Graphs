# Huge benchmark commands

Regenerate the full benchmark:

```bash
export GROQ_API_KEY="your-groq-api-key"  # optional; enables live Groq instead of offline fallback
python3 scripts/huge_benchmark.py --devices 6000 --repeats 25 --output examples/huge_benchmark
```

Run individual planners against the generated graph:

```bash
python3 main.py --config examples/huge_benchmark/config.yaml plan --graph examples/huge_benchmark/huge_graph.pkl --planner astar --start 10.60.0.1 --goal 10.60.11.500
python3 main.py --config examples/huge_benchmark/config.yaml plan --graph examples/huge_benchmark/huge_graph.pkl --planner detection --start 10.60.0.1 --goal 10.60.11.500 --select stealthiest
python3 main.py --config examples/huge_benchmark/config.yaml plan --graph examples/huge_benchmark/huge_graph.pkl --planner rl --start 10.60.0.1 --goal 10.60.11.500
python3 main.py --config examples/huge_benchmark/config.yaml plan --graph examples/huge_benchmark/huge_graph.pkl --planner llm --start 10.60.0.1 --goal 10.60.11.500
```

The bundled config reads `GROQ_API_KEY` from the environment. Without it,
the benchmark automatically falls back to the local graph-constrained mode.
When Groq is active, the script times the live LLM planner once per benchmark
run to avoid unnecessary API spend.
