#!/bin/bash
# AutoAttack — Attacker node (Kali Linux) provisioning script
# ─────────────────────────────────────────────────────────────────────────────
# Installs: Metasploit Framework, Nmap, Snort, Neo4j, Python 3, AutoAttack
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

echo "[*] AutoAttack: Provisioning attacker (Kali Linux)..."

# ── System update ─────────────────────────────────────────────────────────────
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq

# ── Core tools ────────────────────────────────────────────────────────────────
apt-get install -y -qq \
    metasploit-framework \
    nmap \
    snort \
    python3-pip \
    python3-venv \
    git \
    curl \
    wget \
    jq \
    tmux \
    postgresql \
    postgresql-contrib

# ── Neo4j ─────────────────────────────────────────────────────────────────────
wget -q -O - https://debian.neo4j.com/neotechnology.gpg.key | apt-key add -
echo 'deb https://debian.neo4j.com stable latest' > /etc/apt/sources.list.d/neo4j.list
apt-get update -qq
apt-get install -y -qq neo4j

# Configure Neo4j — disable auth for lab use.
sed -i 's/#dbms.security.auth_enabled=false/dbms.security.auth_enabled=false/' \
    /etc/neo4j/neo4j.conf
sed -i 's/#server.default_listen_address=0.0.0.0/server.default_listen_address=0.0.0.0/' \
    /etc/neo4j/neo4j.conf

systemctl enable neo4j
systemctl start neo4j

# ── PostgreSQL for Metasploit ──────────────────────────────────────────────────
systemctl enable postgresql
systemctl start postgresql

sudo -u postgres psql -c "CREATE USER msf WITH PASSWORD 'msfrpc_password';" 2>/dev/null || true
sudo -u postgres psql -c "CREATE DATABASE msf OWNER msf;" 2>/dev/null || true

msfdb init 2>/dev/null || true

# ── Snort configuration ───────────────────────────────────────────────────────
mkdir -p /var/log/snort
touch /var/log/snort/fast.log
chmod 666 /var/log/snort/fast.log

# Create a minimal Snort config for the lab network.
cat > /etc/snort/snort_lab.conf <<'EOF'
# AutoAttack lab Snort config
var HOME_NET 192.168.56.0/24
var EXTERNAL_NET any
var RULE_PATH /etc/snort/rules

include $RULE_PATH/local.rules
include $RULE_PATH/community.rules
EOF

# ── Python environment ────────────────────────────────────────────────────────
python3 -m pip install --upgrade pip -q

# Install AutoAttack requirements if available.
if [ -f /vagrant/requirements.txt ]; then
    pip3 install -r /vagrant/requirements.txt -q
    echo "[+] AutoAttack Python dependencies installed."
fi

# ── Start Metasploit RPC daemon ───────────────────────────────────────────────
# Uses password from environment or default.
MSF_PASSWORD="${MSF_RPC_PASSWORD:-msfrpc_password}"

# Kill any existing msfrpcd.
pkill msfrpcd 2>/dev/null || true
sleep 2

nohup msfrpcd -P "${MSF_PASSWORD}" -S -f -a 0.0.0.0 \
    > /var/log/msfrpcd.log 2>&1 &

echo "[+] Metasploit RPC daemon started on port 55553 (password: ${MSF_PASSWORD})"

# ── Clone/link AutoAttack repo ────────────────────────────────────────────────
if [ -d /vagrant ]; then
    ln -sfn /vagrant /opt/autoattack
    echo "[+] AutoAttack linked at /opt/autoattack"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║     AutoAttack Attacker Node — Provisioning Complete     ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  Metasploit RPC : 127.0.0.1:55553                        ║"
echo "║  Neo4j Bolt     : bolt://localhost:7687                   ║"
echo "║  Snort log      : /var/log/snort/fast.log                 ║"
echo "║  AutoAttack     : /opt/autoattack                         ║"
echo "╚══════════════════════════════════════════════════════════╝"
