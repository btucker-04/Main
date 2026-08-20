<#
.SYNOPSIS
    Fix orphaned Nessus Agent Installer-database registrations and reinstall.
    For machines where the normal upgrade AND the ARP-based CleanReinstall
    both fail with 1603 (CustomAction error 1612 in the MSI log).

.DESCRIPTION
    Broken state this targets:
      - HKLM:\SOFTWARE\Classes\Installer\Products has a Nessus Agent entry
      - No matching ARP (Uninstall) entry exists
      - The cached MSI in C:\Windows\Installer is missing
      => RemoveExistingProducts cannot find an uninstall source -> 1612 -> 1603

    Per registration found, the script classifies it:
      ORPHANED (no ARP entry OR cached MSI missing) -> delete registration keys
      HEALTHY  (ARP entry + cached MSI both present) -> normal msiexec /x uninstall

    Then purges leftover Tenable dirs, installs the staged MSI, starts the
    service, and reports link status.

.NOTES
    Deploy via Endpoint Central as SYSTEM. Stage NessusAgent-11.2.0-x64.msi
    beside the script, or set $MsiPath below / pass -MsiPath.
    Exit codes: 0 success / 1 failure.
    After success, verify agent link; relink if your MSI does not embed a key.
#>

[CmdletBinding()]
param([string]$MsiPath = '')

$ErrorActionPreference = 'Stop'
$LogDir  = 'C:\Logs\CompoSecure'
$LogFile = Join-Path $LogDir ('NessusAgent_OrphanFix_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

# Convert compressed Installer-DB product code to standard {GUID} format.
# Compressed form reverses: 8-4-4 segments whole, then byte-pair swaps.
function Convert-CompressedGuid {
    param([string]$Compressed)
    if ($Compressed.Length -ne 32) { return $null }
    $s = $Compressed.ToUpper()
    $p1 = -join ($s.Substring(0,8).ToCharArray()[7..0])
    $p2 = -join ($s.Substring(8,4).ToCharArray()[3..0])
    $p3 = -join ($s.Substring(12,4).ToCharArray()[3..0])
    $p4 = ''
    foreach ($i in 0..1) { $pair = $s.Substring(16 + $i*2, 2); $p4 += $pair[1] + $pair[0] }
    $p5 = ''
    foreach ($i in 0..5) { $pair = $s.Substring(20 + $i*2, 2); $p5 += $pair[1] + $pair[0] }
    return '{' + $p1 + '-' + $p2 + '-' + $p3 + '-' + $p4 + '-' + $p5 + '}'
}

Write-Log '=============================================='
Write-Log ' Nessus Agent Orphan Fix + Reinstall'
Write-Log (' Host : ' + $env:COMPUTERNAME)
Write-Log '=============================================='

# ---- 0. Resolve MSI ---------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($MsiPath)) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $cand = Get-ChildItem -Path $scriptDir -Filter 'NessusAgent-*.msi' -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending | Select-Object -First 1
    if ($cand) { $MsiPath = $cand.FullName }
}
if ([string]::IsNullOrWhiteSpace($MsiPath) -or -not (Test-Path $MsiPath)) {
    if (Test-Path 'C:\NessusAgent-11.2.0-x64.msi') { $MsiPath = 'C:\NessusAgent-11.2.0-x64.msi' }
}
if ([string]::IsNullOrWhiteSpace($MsiPath) -or -not (Test-Path $MsiPath)) {
    Write-Log 'MSI not found. Stage it beside the script or pass -MsiPath.' -Level ERROR
    exit 1
}
Write-Log ('Target MSI: ' + $MsiPath)

# ---- 1. Kill lingering processes / stop service -----------------------------
# Service name is 'Nessus Agent' on older builds, 'Tenable Nessus Agent' on newer.
Write-Log '[1/5] Stopping service and killing lingering processes...'
foreach ($sn in @('Nessus Agent', 'Tenable Nessus Agent')) {
    Stop-Service $sn -Force -ErrorAction SilentlyContinue
}
Get-Process -Name 'nessusd','nessus-service','nessusagent' -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 3

# ---- 2. Classify and clear every Nessus registration ------------------------
Write-Log '[2/5] Scanning Installer database for Nessus registrations...'

$arpGuids = @()
$arpEntries = Get-ItemProperty `
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' `
    -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like '*Nessus*' }
foreach ($e in $arpEntries) { $arpGuids += $e.PSChildName.ToUpper() }
Write-Log ('  ARP Nessus entries: ' + $arpGuids.Count)

$found = 0
Get-ChildItem 'HKLM:\SOFTWARE\Classes\Installer\Products' -ErrorAction SilentlyContinue | ForEach-Object {
    $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    if ($props.ProductName -notlike '*Nessus*') { return }
    $found++

    $compressed = $_.PSChildName
    $guid = Convert-CompressedGuid $compressed
    $cachedMsi = $null
    $srcProps = Get-ItemProperty ($_.PSPath + '\SourceList') -ErrorAction SilentlyContinue
    if ($srcProps) { $cachedMsi = $srcProps.PackageName }
    $localPkg = (Get-ItemProperty ('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\' + $compressed + '\InstallProperties') -ErrorAction SilentlyContinue).LocalPackage

    $hasArp    = $guid -and ($arpGuids -contains $guid.ToUpper())
    $hasCache  = $localPkg -and (Test-Path $localPkg)

    Write-Log ('  Found: ' + $props.ProductName + '  compressed=' + $compressed)
    Write-Log ('    ProductCode : ' + $guid)
    Write-Log ('    ARP entry   : ' + $hasArp)
    Write-Log ('    Cached MSI  : ' + $hasCache + '  (' + $localPkg + ')')

    if ($hasArp -and $hasCache) {
        Write-Log '    HEALTHY registration -> normal uninstall via msiexec /x'
        $u = Start-Process msiexec.exe -ArgumentList ('/x ' + $guid + ' /qn /norestart') -Wait -PassThru
        Write-Log ('    Uninstall exit: ' + $u.ExitCode)
        if ($u.ExitCode -ne 0 -and $u.ExitCode -ne 3010) {
            Write-Log '    Uninstall failed -> treating as orphaned, deleting registration.' -Level WARN
            Remove-Item $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    } else {
        Write-Log '    ORPHANED registration -> deleting Installer DB keys'
        Remove-Item $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Clear the matching UserData entry either way (stale after uninstall/orphan)
    $udPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\' + $compressed
    if (Test-Path $udPath) {
        Remove-Item $udPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log '    Cleared UserData entry.'
    }
}
if ($found -eq 0) { Write-Log '  No Nessus registrations in Installer DB (already clean).' }

# Also clear any surviving ARP entries whose product is now gone
foreach ($e in $arpEntries) {
    if (Test-Path $e.PSPath) {
        Remove-Item $e.PSPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log ('  Cleared stale ARP entry: ' + $e.DisplayName + ' ' + $e.DisplayVersion)
    }
}

# ---- 3. Purge leftover directories ------------------------------------------
Write-Log '[3/5] Purging leftover Tenable directories...'
foreach ($d in @('C:\Program Files\Tenable\Nessus Agent', 'C:\ProgramData\Tenable\Nessus Agent')) {
    if (Test-Path $d) {
        Remove-Item $d -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log ('  Removed: ' + $d)
    }
}

# ---- 4. Fresh install --------------------------------------------------------
Write-Log '[4/5] Installing fresh agent...'
$msiLog = Join-Path $LogDir 'msi_nessus_orphanfix_install.log'
$p = Start-Process msiexec.exe -ArgumentList ('/i "' + $MsiPath + '" /qn /norestart /l*v "' + $msiLog + '"') -Wait -PassThru
Write-Log ('  msiexec exit code: ' + $p.ExitCode)
if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) {
    Write-Log ('  Install FAILED. See ' + $msiLog) -Level ERROR
    exit 1
}

# ---- 5. Start service + report link state -----------------------------------
Write-Log '[5/5] Starting service and checking link status...'
Start-Sleep -Seconds 5
$svc = Get-Service | Where-Object { $_.Name -like '*Nessus Agent*' } | Select-Object -First 1
if (-not $svc) { Write-Log '  No Nessus Agent service found after install!' -Level ERROR; exit 1 }
Write-Log ('  Service name: ' + $svc.Name + '  Status: ' + $svc.Status)
if ($svc.Status -ne 'Running') { Start-Service $svc.Name -ErrorAction SilentlyContinue; Start-Sleep -Seconds 3 }
Write-Log ('  Service: ' + (Get-Service $svc.Name).Status)

$cli = 'C:\Program Files\Tenable\Nessus Agent\nessuscli.exe'
if (Test-Path $cli) {
    $status = & $cli agent status 2>&1
    foreach ($line in $status) { Write-Log ('  ' + $line) }
    if ($status -match 'Not linked' -or $status -notmatch 'Linked') {
        Write-Log '  AGENT NOT LINKED -- run nessuscli agent link with your group key.' -Level WARN
    }
}

Write-Log 'DONE. Re-check EC/Tenable for this host.'
exit 0
