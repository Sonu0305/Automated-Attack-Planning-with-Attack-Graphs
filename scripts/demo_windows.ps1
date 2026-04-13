$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $PSScriptRoot
Set-Location $RootDir

New-Item -ItemType Directory -Force -Path "results\demo" | Out-Null
New-Item -ItemType Directory -Force -Path "results\demo_eval" | Out-Null
New-Item -ItemType Directory -Force -Path "logs\snort" | Out-Null

py -3 .\main.py --help
py -3 .\main.py scan --help
py -3 .\main.py plan --help
py -3 .\main.py execute --help
py -3 .\main.py evaluate --help
py -3 .\main.py train-rl --help
py -3 .\main.py dashboard --help

py -3 .\main.py --config config.yaml scan `
  --nmap-xml tests/fixtures/scan_fixture.xml `
  --save results/demo/lab_graph.pkl

py -3 .\main.py --config config.yaml plan `
  --graph results/demo/lab_graph.pkl `
  --planner astar `
  --start 192.168.56.10 `
  --goal 192.168.56.30 `
  --save-path results/demo/astar_path.json

py -3 .\main.py --config config.yaml plan `
  --graph results/demo/lab_graph.pkl `
  --planner detection `
  --start 192.168.56.10 `
  --goal 192.168.56.30 `
  --select fastest `
  --save-path results/demo/detection_fastest_path.json

py -3 .\main.py --config config.yaml plan `
  --graph results/demo/lab_graph.pkl `
  --planner detection `
  --start 192.168.56.10 `
  --goal 192.168.56.30 `
  --select stealthiest `
  --save-path results/demo/detection_stealthiest_path.json

py -3 .\main.py --config config.yaml plan `
  --graph results/demo/lab_graph.pkl `
  --planner detection `
  --start 192.168.56.10 `
  --goal 192.168.56.30 `
  --select balanced `
  --save-path results/demo/detection_balanced_path.json

py -3 .\main.py --config config.yaml train-rl `
  --graph results/demo/lab_graph.pkl `
  --episodes 300 `
  --output qtable.pkl

py -3 .\main.py --config config.yaml plan `
  --graph results/demo/lab_graph.pkl `
  --planner rl `
  --start 192.168.56.10 `
  --goal 192.168.56.30 `
  --save-path results/demo/rl_path.json

py -3 .\main.py --config config.yaml plan `
  --graph results/demo/lab_graph.pkl `
  --planner llm `
  --start 192.168.56.10 `
  --goal 192.168.56.30 `
  --save-path results/demo/llm_path.json

py -3 .\main.py --config config.yaml execute `
  --graph results/demo/lab_graph.pkl `
  --planner astar `
  --start 192.168.56.10 `
  --goal 192.168.56.30 `
  --yes

py -3 .\main.py --config config.yaml execute `
  --graph results/demo/lab_graph.pkl `
  --planner detection `
  --start 192.168.56.10 `
  --goal 192.168.56.30 `
  --yes

py -3 .\main.py --config config.yaml execute `
  --graph results/demo/lab_graph.pkl `
  --planner rl `
  --start 192.168.56.10 `
  --goal 192.168.56.30 `
  --yes

py -3 .\main.py --config config.yaml execute `
  --graph results/demo/lab_graph.pkl `
  --planner llm `
  --start 192.168.56.10 `
  --goal 192.168.56.30 `
  --yes

py -3 .\main.py --config config.yaml evaluate `
  --graph results/demo/lab_graph.pkl `
  --runs 2 `
  --output results/demo_eval

py -3 .\main.py --config config.yaml dashboard --output results/demo_eval
