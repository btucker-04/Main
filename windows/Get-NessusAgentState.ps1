<#
.SYNOPSIS
    Read-only triage check for orphaned / broken Nessus Agent installs.
    Returns ONE machine-readable verdict so a fleet run can be sorted into
    "plain upgrade" vs "needs CleanReinstall" without reading full diagnostics.

.DESCRIPTION
    Checks, in order:
      1. Service registration (both 'Nessus Agent' and 'Tenable Nessus Agent')
      2. Running nessusd / nessus-service / nessusagent processes
      3. ARP entries (count + versions -- catches dual product codes)
      4. Installer-database registrations cross-checked against the cached
         MSI in C:\Windows\Installer (the 1612/1603 orphan detector)
      5. Program Files / ProgramData / nessuscli.exe presence
      6. TAG UUID (HKLM\SOFTWARE\Tenable\TAG) -- a surviving UUID across a
         reinstall causes 409 duplicate-UUID errors on link
      7. Link status via 'nessuscli agent status'

    Changes nothing. Safe to run fleet-wide at any time.

.OUTPUTS
    A single line of the form:
        VERDICT: <TOKEN> -- <human summary>
    plus a one-line CSV appended to C:\Logs\CompoSecure\NessusAgentState.csv
    for aggregation across machines.

    Tokens:
      HEALTHY_LINKED        service running, one product, cache intact, linked
      HEALTHY_UNLINKED      install is fine but the agent is not linked
                            (check Zscaler SSL inspection of the manager host)
      ORPHANED_REGISTRATION Installer-DB registration with no ARP entry and/or
                            no cached MSI -> upgrades WILL fail 1612/1603
      ORPHANED_PROCESSES    nessusd/nessus-service running with NO service
                            registration -> holds DB locks, causes 1603
      DUAL_PRODUCTS         more than one Nessus Agent product code in ARP
      LEFTOVER_FILES        no registration at all but directories remain
      NOT_INSTALLED         nothing present
    Multiple problems report the most severe token; all findings are logged.

.NOTES
    Deploy via Endpoint Central (SYSTEM) as:
        powershell -ExecutionPolicy Bypass -File <path>\Get-NessusAgentState.ps1
    Exit codes: 0 = healthy+linked / 2 = attention (unlinked, leftovers)
                1 = orphaned/broken -> run NessusAgent_CleanReinstall.ps1
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'SilentlyContinue'

$LogDir  = 'C:\Logs\CompoSecure'
$LogFile = Join-Path $LogDir ('NessusAgentState_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')
$CsvFile = Join-Path $LogDir 'NessusAgentState.csv'
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

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

$ProgramDir = 'C:\Program Files\Tenable\Nessus Agent'
$DataDir    = 'C:\ProgramData\Tenable\Nessus Agent'
$Cli        = Join-Path $ProgramDir 'nessuscli.exe'

Write-Log '=============================================='
Write-Log ' Nessus Agent State Check (read-only)'
Write-Log (' Host : ' + $env:COMPUTERNAME)
Write-Log '=============================================='

# --------------------------------------------------------------
# 1. Service
# --------------------------------------------------------------
Write-Log ''
Write-Log '[1] Service registration'
$svcs = Get-Service | Where-Object { $_.Name -like '*Nessus Agent*' -or $_.DisplayName -like '*Nessus Agent*' }
$svcName   = ''
$svcStatus = 'none'
if ($svcs) {
    foreach ($s in $svcs) {
        Write-Log ('  ' + $s.Name + ' | ' + $s.DisplayName + ' | ' + $s.Status + ' | ' + $s.StartType)
    }
    $svcName   = ($svcs | Select-Object -First 1).Name
    $svcStatus = ($svcs | Select-Object -First 1).Status.ToString()
} else {
    Write-Log '  No Nessus Agent service registered.' -Level WARN
}

# --------------------------------------------------------------
# 2. Processes
# --------------------------------------------------------------
Write-Log ''
Write-Log '[2] Running processes'
$procs = Get-Process -Name 'nessusd','nessus-service','nessusagent' -ErrorAction SilentlyContinue
$procCount = 0
if ($procs) {
    foreach ($p in $procs) {
        $procCount++
        Write-Log ('  PID ' + $p.Id + '  ' + $p.Name + '  ' + $p.Path)
    }
} else {
    Write-Log '  None running.'
}
$orphanProcs = ($procCount -gt 0 -and -not $svcs)
if ($orphanProcs) {
    Write-Log '  ORPHANED PROCESSES: running with no service registration --' -Level WARN
    Write-Log '  these hold DB locks and cause file-in-use 1603 on install.' -Level WARN
}

# --------------------------------------------------------------
# 3. ARP entries
# --------------------------------------------------------------
Write-Log ''
Write-Log '[3] Add/Remove Programs entries'
$arpPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$arp = Get-ItemProperty -Path $arpPaths -ErrorAction SilentlyContinue |
       Where-Object { $_.DisplayName -like '*Nessus Agent*' }
$arpGuids = @()
$arpVersions = @()
foreach ($e in $arp) {
    $arpGuids += $e.PSChildName.ToUpper()
    $arpVersions += ('' + $e.DisplayVersion)
    Write-Log ('  ' + $e.DisplayName + '  ' + $e.DisplayVersion + '  ' + $e.PSChildName)
}
if (-not $arp) { Write-Log '  No Nessus Agent entries in ARP.' -Level WARN }
$dualProducts = ($arpGuids.Count -gt 1)
if ($dualProducts) { Write-Log '  DUAL PRODUCTS: more than one product code registered.' -Level WARN }

# --------------------------------------------------------------
# 4. Installer-database orphan check
# --------------------------------------------------------------
Write-Log ''
Write-Log '[4] Installer database vs cached MSI'
$regCount     = 0
$orphanedReg  = $false
Get-ChildItem 'HKLM:\SOFTWARE\Classes\Installer\Products' -ErrorAction SilentlyContinue | ForEach-Object {
    $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    if ($props.ProductName -notlike '*Nessus*') { return }
    $regCount++
    $compressed = $_.PSChildName
    $guid = Convert-CompressedGuid $compressed
    $udPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\' + $compressed
    $localPkg = (Get-ItemProperty ($udPath + '\InstallProperties') -ErrorAction SilentlyContinue).LocalPackage
    $hasArp   = $guid -and ($arpGuids -contains $guid.ToUpper())
    $hasCache = $localPkg -and (Test-Path $localPkg)
    Write-Log ('  ' + $props.ProductName + '  ' + $guid)
    Write-Log ('    ARP entry  : ' + $hasArp)
    Write-Log ('    Cached MSI : ' + $hasCache + '  (' + $localPkg + ')')
    if ($hasArp -and $hasCache) {
        Write-Log '    VERDICT: HEALTHY registration'
    } else {
        Write-Log '    VERDICT: ORPHANED -- upgrades will fail 1612/1603.' -Level WARN
        $script:orphanedReg = $true
    }
}
if ($regCount -eq 0) { Write-Log '  No Nessus registrations in the Installer database.' }

# --------------------------------------------------------------
# 5. Files on disk
# --------------------------------------------------------------
Write-Log ''
Write-Log '[5] Files on disk'
$hasProgramDir = Test-Path $ProgramDir
$hasDataDir    = Test-Path $DataDir
$hasCli        = Test-Path $Cli
Write-Log ('  Program dir : ' + $hasProgramDir + '  (' + $ProgramDir + ')')
Write-Log ('  Data dir    : ' + $hasDataDir + '  (' + $DataDir + ')')
Write-Log ('  nessuscli   : ' + $hasCli)
$installedVer = ''
foreach ($rp in @('HKLM:\SOFTWARE\Tenable\Nessus Agent', 'HKLM:\SOFTWARE\WOW6432Node\Tenable\Nessus Agent')) {
    if (Test-Path $rp) {
        $v = (Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue).VERSION
        if ($v) { $installedVer = $v; Write-Log ('  Registry version: ' + $v) }
    }
}

# --------------------------------------------------------------
# 6. TAG UUID
# --------------------------------------------------------------
Write-Log ''
Write-Log '[6] TAG UUID'
$tag = (Get-ItemProperty 'HKLM:\SOFTWARE\Tenable\TAG' -ErrorAction SilentlyContinue)
if ($tag) {
    Write-Log '  TAG key present. A UUID surviving a reinstall causes 409 duplicate-UUID'
    Write-Log '  errors on link -- CleanReinstall deletes it as part of teardown.'
} else {
    Write-Log '  No TAG key.'
}

# --------------------------------------------------------------
# 7. Link status
# --------------------------------------------------------------
Write-Log ''
Write-Log '[7] Link status'
$linked = $false
$linkChecked = $false
if ($hasCli) {
    $status = (& $Cli agent status 2>&1) -join "`n"
    foreach ($line in ($status -split "`n")) { Write-Log ('  ' + $line) }
    $linkChecked = $true
    if (($status -match 'Linked to:\s*\S') -and ($status -notmatch 'Linked to:\s*None')) { $linked = $true }
    if ($status -match 'empty response') {
        Write-Log '  Empty response from controller -- check Zscaler SSL inspection of' -Level WARN
        Write-Log '  sensor.cloud.tenable.com.' -Level WARN
    }
} else {
    Write-Log '  nessuscli.exe not present -- cannot check link state.'
}

# --------------------------------------------------------------
# Verdict (most severe first)
# --------------------------------------------------------------
$token   = ''
$summary = ''
$exit    = 0

if ($orphanedReg) {
    $token = 'ORPHANED_REGISTRATION'
    $summary = 'Installer-DB registration without ARP and/or cached MSI. Run CleanReinstall.'
    $exit = 1
} elseif ($orphanProcs) {
    $token = 'ORPHANED_PROCESSES'
    $summary = 'Nessus processes running with no service registration. Run CleanReinstall.'
    $exit = 1
} elseif ($dualProducts) {
    $token = 'DUAL_PRODUCTS'
    $summary = 'Multiple Nessus Agent product codes in ARP. Run CleanReinstall.'
    $exit = 1
} elseif (-not $arp -and $regCount -eq 0 -and ($hasProgramDir -or $hasDataDir)) {
    $token = 'LEFTOVER_FILES'
    $summary = 'No registration but directories remain. CleanReinstall will purge and install.'
    $exit = 2
} elseif (-not $arp -and $regCount -eq 0 -and -not $hasProgramDir -and -not $hasDataDir) {
    $token = 'NOT_INSTALLED'
    $summary = 'Agent not present. Plain install is fine.'
    $exit = 2
} elseif ($linkChecked -and -not $linked) {
    $token = 'HEALTHY_UNLINKED'
    $summary = 'Install looks healthy but agent is NOT linked. Relink (check Zscaler bypass).'
    $exit = 2
} elseif (-not $svcs) {
    $token = 'BROKEN_NO_SERVICE'
    $summary = 'Registered product but no service. Run CleanReinstall.'
    $exit = 1
} else {
    $token = 'HEALTHY_LINKED'
    $summary = 'Service registered, single product, cache intact, agent linked.'
    $exit = 0
}

Write-Log ''
Write-Log '=============================================='
Write-Log ('VERDICT: ' + $token + ' -- ' + $summary)
Write-Log ('  version=' + $installedVer + '  service=' + $svcName + '/' + $svcStatus + '  arp=' + $arpGuids.Count + '  reg=' + $regCount + '  procs=' + $procCount + '  linked=' + $linked)
Write-Log '=============================================='

# One-line CSV for fleet aggregation
if (-not (Test-Path $CsvFile)) {
    Add-Content -Path $CsvFile -Value 'Timestamp,Host,Verdict,Version,Service,ServiceStatus,ArpCount,RegCount,ProcCount,Linked' -ErrorAction SilentlyContinue
}
$csvLine = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ',' + $env:COMPUTERNAME + ',' + $token + ',' + $installedVer + ',' + $svcName + ',' + $svcStatus + ',' + $arpGuids.Count + ',' + $regCount + ',' + $procCount + ',' + $linked
Add-Content -Path $CsvFile -Value $csvLine -ErrorAction SilentlyContinue
Write-Host ('CSV: ' + $CsvFile)

exit $exit
