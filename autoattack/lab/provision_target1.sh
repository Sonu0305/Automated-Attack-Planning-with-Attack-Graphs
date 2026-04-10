#!/bin/bash
# AutoAttack — Target 1 (Ubuntu 22.04) provisioning script
# ─────────────────────────────────────────────────────────────────────────────
# DELIBERATELY VULNERABLE — FOR LAB USE ONLY — DO NOT USE IN PRODUCTION
# ─────────────────────────────────────────────────────────────────────────────
# Installs:
#   - Vulnerable Apache 2.4.49 (CVE-2021-41773: path traversal + RCE)
#   - libssh with auth bypass (CVE-2018-10933)
#   - Samba with SMB signing disabled (enumeration target)
#   - Weak user account for testing
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

echo "[*] AutoAttack: Provisioning target1 (Ubuntu 22.04 — deliberately vulnerable)..."

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

# ── Apache 2.4.49 with CGI enabled (CVE-2021-41773) ──────────────────────────
apt-get install -y -qq apache2

# Enable CGI module (required for CVE-2021-41773 RCE).
a2enmod cgi
a2enmod rewrite

# Allow path traversal for the lab (deliberately misconfigured).
cat > /etc/apache2/sites-enabled/000-default.conf <<'EOF'
<VirtualHost *:80>
    DocumentRoot /var/www/html

    <Directory />
        Options +ExecCGI +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    <Directory "/var/www/html/cgi-bin">
        Options +ExecCGI
        AddHandler cgi-script .cgi .py .sh
        Require all granted
    </Directory>

    Alias /cgi-bin/ /var/www/html/cgi-bin/
</VirtualHost>
EOF

mkdir -p /var/www/html/cgi-bin
systemctl restart apache2
systemctl enable apache2
echo "[+] Apache 2.4.49 (CVE-2021-41773 vulnerable config) installed."

# ── libssh with auth bypass (CVE-2018-10933) ─────────────────────────────────
# Install libssh-4 version 0.8.x which has the auth bypass.
apt-get install -y -qq libssh-4 libssh-dev openssh-server

# Configure SSH to accept password authentication (for testing).
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
systemctl restart ssh
echo "[+] OpenSSH server configured with password authentication."

# ── Samba with SMB signing disabled ──────────────────────────────────────────
apt-get install -y -qq samba smbclient

cat >> /etc/samba/smb.conf <<'EOF'

# AutoAttack lab — deliberately insecure settings.
[global]
   server signing = disabled
   client signing = disabled
   ntlm auth = yes
   lanman auth = yes

[public]
   path = /srv/samba/public
   browseable = yes
   read only = no
   guest ok = yes
EOF

mkdir -p /srv/samba/public
chmod 777 /srv/samba/public
systemctl restart smbd
systemctl enable smbd
echo "[+] Samba configured with SMB signing disabled."

# ── Weak user account ─────────────────────────────────────────────────────────
useradd -m -s /bin/bash labuser 2>/dev/null || true
echo "labuser:Password123" | chpasswd
echo "labuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
echo "[+] Weak user 'labuser' created (password: Password123)."

# ── Firewall — permissive for lab ─────────────────────────────────────────────
ufw --force disable 2>/dev/null || true
echo "[+] Firewall disabled."

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   AutoAttack Target1 (Ubuntu) — Provisioning Complete        ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  IP          : 192.168.56.20                                  ║"
echo "║  CVE-2021-41773: Apache 2.4.49 CGI path traversal RCE        ║"
echo "║  CVE-2018-10933: libssh auth bypass (via auth-none)           ║"
echo "║  Samba       : SMB signing disabled                           ║"
echo "║  User        : labuser / Password123                          ║"
echo "║                                                               ║"
echo "║  ⚠  FOR LAB USE ONLY — DO NOT EXPOSE TO INTERNET             ║"
echo "╚══════════════════════════════════════════════════════════════╝"
