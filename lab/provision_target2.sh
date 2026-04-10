# AutoAttack — Target 2 (Windows Server 2019) provisioning script
# ─────────────────────────────────────────────────────────────────────────────
# DELIBERATELY VULNERABLE — FOR LAB USE ONLY — DO NOT USE IN PRODUCTION
# ─────────────────────────────────────────────────────────────────────────────
# Configures:
#   - SMBv1 enabled (CVE-2017-0144 — EternalBlue / MS17-010)
#   - WinRM enabled for remote management
#   - RDP enabled (CVE-2019-0708 — BlueKeep target)
#   - Windows Firewall disabled
#   - Windows Update disabled
#   - Weak lab admin account
# ─────────────────────────────────────────────────────────────────────────────

#Requires -RunAsAdministrator

Write-Host "[*] AutoAttack: Provisioning target2 (Windows Server 2019 - deliberately vulnerable)..."

# ── Enable SMBv1 (MS17-010 / EternalBlue target) ─────────────────────────────
Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force
Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
Set-SmbServerConfiguration -RequireSecuritySignature $false -Force
Set-SmbServerConfiguration -EnableSecuritySignature $false -Force

Write-Host "[+] SMBv1 enabled (CVE-2017-0144 EternalBlue target)."

# ── Enable WinRM for remote management ───────────────────────────────────────
Enable-PSRemoting -Force -SkipNetworkProfileCheck
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true
winrm set winrm/config/client '@{TrustedHosts="*"}'

# Allow WinRM through firewall.
New-NetFirewallRule -DisplayName "WinRM HTTP" -Direction Inbound `
    -Protocol TCP -LocalPort 5985 -Action Allow -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "WinRM HTTPS" -Direction Inbound `
    -Protocol TCP -LocalPort 5986 -Action Allow -ErrorAction SilentlyContinue

Write-Host "[+] WinRM enabled and configured."

# ── Enable RDP (BlueKeep target) ──────────────────────────────────────────────
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
    -Name "fDenyTSConnections" -Value 0
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "UserAuthentication" -Value 0

Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

Write-Host "[+] RDP enabled (CVE-2019-0708 BlueKeep target)."

# ── Disable Windows Firewall (lab only) ───────────────────────────────────────
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

Write-Host "[+] Windows Firewall disabled."

# ── Disable automatic updates (prevent patching during lab) ──────────────────
Set-Service -Name wuauserv -StartupType Disabled -ErrorAction SilentlyContinue
Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue

# Disable via registry as well.
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
    -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
    -Name "NoAutoUpdate" -Value 1 -ErrorAction SilentlyContinue

Write-Host "[+] Windows Update disabled."

# ── Create lab admin user ────────────────────────────────────────────────────
$password = ConvertTo-SecureString "Password123!" -AsPlainText -Force
New-LocalUser -Name "labadmin" -Password $password `
    -FullName "Lab Administrator" `
    -Description "AutoAttack test account" `
    -ErrorAction SilentlyContinue
Add-LocalGroupMember -Group "Administrators" -Member "labadmin" `
    -ErrorAction SilentlyContinue

Write-Host "[+] Lab admin user 'labadmin' created (password: Password123!)."

# ── Open common attacker-facing ports in firewall ────────────────────────────
$ports = @(445, 3389, 135, 139, 5985, 5986, 1433)
foreach ($port in $ports) {
    New-NetFirewallRule -DisplayName "AutoAttack allow $port" `
        -Direction Inbound -Protocol TCP -LocalPort $port `
        -Action Allow -ErrorAction SilentlyContinue
}
Write-Host "[+] Inbound firewall rules added for ports: $($ports -join ', ')."

# ── Disable DEP and ASLR mitigations for lab exploitability ──────────────────
# Note: This is deliberately insecure for lab research purposes.
bcdedit /set nx AlwaysOff 2>&1 | Out-Null
Set-ProcessMitigation -System -Disable ASLR -ErrorAction SilentlyContinue

Write-Host "[+] DEP/ASLR mitigations reduced."

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗"
Write-Host "║  AutoAttack Target2 (Windows) — Provisioning Complete        ║"
Write-Host "╠══════════════════════════════════════════════════════════════╣"
Write-Host "║  IP          : 192.168.56.30                                  ║"
Write-Host "║  CVE-2017-0144: SMBv1 enabled (EternalBlue)                  ║"
Write-Host "║  CVE-2019-0708: RDP enabled without NLA (BlueKeep)           ║"
Write-Host "║  WinRM       : Enabled on ports 5985/5986                     ║"
Write-Host "║  Firewall    : Disabled                                       ║"
Write-Host "║  User        : labadmin / Password123!                        ║"
Write-Host "║                                                               ║"
Write-Host "║  ⚠  FOR LAB USE ONLY — DO NOT EXPOSE TO INTERNET             ║"
Write-Host "╚══════════════════════════════════════════════════════════════╝"
