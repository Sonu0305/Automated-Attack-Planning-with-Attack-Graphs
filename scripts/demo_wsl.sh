#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p results/demo results/demo_eval logs/snort

python3 main.py --help
python3 main.py scan --help
python3 main.py plan --help
python3 main.py execute --help
python3 main.py evaluate --help
python3 main.py train-rl --help
python3 main.py dashboard --help

python3 main.py --config config.yaml scan \
  --nmap-xml tests/fixtures/scan_fixture.xml \
  --save results/demo/lab_graph.pkl

python3 main.py --config config.yaml plan \
  --graph results/demo/lab_graph.pkl \
  --planner astar \
  --start 192.168.56.10 \
  --goal 192.168.56.30 \
  --save-path results/demo/astar_path.json

python3 main.py --config config.yaml plan \
  --graph results/demo/lab_graph.pkl \
  --planner detection \
  --start 192.168.56.10 \
  --goal 192.168.56.30 \
  --select fastest \
  --save-path results/demo/detection_fastest_path.json

python3 main.py --config config.yaml plan \
  --graph results/demo/lab_graph.pkl \
  --planner detection \
  --start 192.168.56.10 \
  --goal 192.168.56.30 \
  --select stealthiest \
  --save-path results/demo/detection_stealthiest_path.json

python3 main.py --config config.yaml plan \
  --graph results/demo/lab_graph.pkl \
  --planner detection \
  --start 192.168.56.10 \
  --goal 192.168.56.30 \
  --select balanced \
  --save-path results/demo/detection_balanced_path.json

python3 main.py --config config.yaml train-rl \
  --graph results/demo/lab_graph.pkl \
  --episodes 300 \
  --output qtable.pkl

python3 main.py --config config.yaml plan \
  --graph results/demo/lab_graph.pkl \
  --planner rl \
  --start 192.168.56.10 \
  --goal 192.168.56.30 \
  --save-path results/demo/rl_path.json

python3 main.py --config config.yaml plan \
  --graph results/demo/lab_graph.pkl \
  --planner llm \
  --start 192.168.56.10 \
  --goal 192.168.56.30 \
  --save-path results/demo/llm_path.json

python3 main.py --config config.yaml execute \
  --graph results/demo/lab_graph.pkl \
  --planner astar \
  --start 192.168.56.10 \
  --goal 192.168.56.30 \
  --yes

python3 main.py --config config.yaml execute \
  --graph results/demo/lab_graph.pkl \
  --planner detection \
  --start 192.168.56.10 \
  --goal 192.168.56.30 \
  --yes

python3 main.py --config config.yaml execute \
  --graph results/demo/lab_graph.pkl \
  --planner rl \
  --start 192.168.56.10 \
  --goal 192.168.56.30 \
  --yes

python3 main.py --config config.yaml execute \
  --graph results/demo/lab_graph.pkl \
  --planner llm \
  --start 192.168.56.10 \
  --goal 192.168.56.30 \
  --yes

python3 main.py --config config.yaml evaluate \
  --graph results/demo/lab_graph.pkl \
  --runs 2 \
  --output results/demo_eval

python3 main.py --config config.yaml dashboard --output results/demo_eval
