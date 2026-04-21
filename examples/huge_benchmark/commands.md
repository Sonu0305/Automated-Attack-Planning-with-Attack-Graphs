# Huge benchmark commands

Regenerate the full benchmark:

```bash
python3 scripts/huge_benchmark.py --devices 600 --repeats 25 --output examples/huge_benchmark
```

Run individual planners against the generated graph:

```bash
python3 main.py --config examples/huge_benchmark/config.yaml plan --graph examples/huge_benchmark/huge_graph.pkl --planner astar --start 10.60.0.1 --goal 10.60.11.50
python3 main.py --config examples/huge_benchmark/config.yaml plan --graph examples/huge_benchmark/huge_graph.pkl --planner detection --start 10.60.0.1 --goal 10.60.11.50 --select stealthiest
python3 main.py --config examples/huge_benchmark/config.yaml plan --graph examples/huge_benchmark/huge_graph.pkl --planner rl --start 10.60.0.1 --goal 10.60.11.50
python3 main.py --config examples/huge_benchmark/config.yaml plan --graph examples/huge_benchmark/huge_graph.pkl --planner llm --start 10.60.0.1 --goal 10.60.11.50
```

The bundled config intentionally uses offline LLM fallback. Add a Groq API key
to that config only if you explicitly want to test live LLM latency on the
large serialized graph.
