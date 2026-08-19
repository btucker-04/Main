<#
.SYNOPSIS
    Clean teardown + reinstall of a broken Nessus Agent install (v4.1).
    Handles every broken state catalogued so far: dual product codes,
    orphaned Installer-DB registrations (1612), orphaned processes
    holding DB locks, and stale ARP entries.

.DESCRIPTION
    Sequence:
      1. Kill orphaned nessusd / nessus-service / nessusagent processes
      2. Stop + delete the service (both old and new service names)
      3. Classify EVERY Nessus registration in the Installer database:
           HEALTHY  (ARP entry + cached MSI present) -> msiexec /x by GUID
           ORPHANED (either missing)                 -> delete Products +
                     UserData registration keys directly (msiexec would 1612)
         Then clear any leftover ARP entries.
      4. Purge leftover Program Files + ProgramData directories
      5. Install the target MSI fresh (with install-time verification that
         files actually landed -- a 3-second exit 0 is treated as suspect)
      6. Start service (either name), optionally relink, report link status

    v3.3: linking with NO agent group now exits 2 (attention), not 0. An agent
    that belongs to no group is never targeted by any agent scan, so it never
    receives a scan policy, never downloads plugins, never scans, and never
    reports -- Tenable keeps showing the OLD agent version indefinitely and the
    finding never clears. Observed on CSLT-173/-178/-205/-210 and CSPC-079: all
    five installed 11.2.2 and linked successfully, EC reported Succeeded, and
    Tenable still showed 11.1.0 days later. Exit 0 must mean "installed, linked,
    and able to report".

    v4.1 (from the 2026-08-07 CSLT-215 runs):
      * PRE-FLIGHT MUTEX CHECK. The teardown is destructive -- it purges both
        directories and deletes the Installer-DB registrations. If the install
        then fails, the host is left with NO AGENT AT ALL, which is what happened
        on CSLT-215 when SentinelOne held the Windows Installer mutex. The script
        now checks for a concurrent MSI operation BEFORE touching anything and
        exits 2 to be retried, rather than dismantling an agent it cannot
        reinstall.
      * msiexec is invoked by FULL PATH with -NoNewWindow. A bare 'msiexec.exe'
        went through ShellExecute and failed in the EC SYSTEM context with
        "No application is associated with the specified file for this operation".
      * 1618 (another install in progress) and 1601 (installer service
        unavailable) are retried with backoff instead of treated as fatal.
      * A final install failure states explicitly that the agent is ABSENT, so
        the host's state is never ambiguous.

.PARAMETER MsiPath
    Path to the Nessus Agent MSI. If omitted, the script searches (in order)
    the script's own directory then C:\ for NessusAgent-*.msi, preferring the
    file whose architecture matches this machine (arm64 / x64 / win32) and
    then the highest version by filename.

    v3.2: the C:\ fallback used to be a HARDCODED filename
    (C:\NessusAgent-11.2.0-x64.msi), so a staged MSI of any other version or
    architecture was not found -- e.g. NessusAgent-11.2.1-arm64.msi on the
    ARM64 laptop CSLT-173. It is now a wildcard search, and architecture-aware
    so an x64 package is never chosen for an ARM64 host (or vice versa).

.PARAMETER LinkKey
    Optional Tenable linking key. If provided, the script relinks the agent
    after install (the ProgramData purge always drops link state).

.PARAMETER LinkGroups
    Agent group(s) for relink, e.g. 'Workstations'.

.PARAMETER LinkHost
    Manager host. Default sensor.cloud.tenable.com (Tenable VM cloud).

.PARAMETER DryRun
    Log every action without changing anything.

.NOTES
    Deploy via Endpoint Central (SYSTEM). EC-safe concatenated strings.
    Exit codes: 0 = success / 3010 = success, reboot recommended / 1 = failure
    Zscaler note: if relink fails with 'empty response from controller',
    check SSL inspection on sensor.cloud.tenable.com.
#>

[CmdletBinding()]
param(
    [string]$MsiPath    = '',
    # Linking key defaults to the CompoSecure group key. The agent is linked
    # automatically after the fresh install (the ProgramData purge always
    # drops link state). Pass -NoLink to install without linking.
    [string]$LinkKey    = '4f858e2b28a33a5927c7805eab8b8533ecb35c983417b392c5b570b5a6a96fba',
    # Groups: if empty, resolved per-host from the embedded map below. A value
    # here overrides the map (useful for a host not in the map).
    [string]$LinkGroups = '',
    [string]$LinkHost   = 'sensor.cloud.tenable.com',
    [switch]$NoLink,
    [switch]$DryRun
)

# ==============================================================
# Tenable agent-group resolution -- PREFIX RULES + EXACT OVERRIDES
# Derived from the cleaned agents export 2026-08-04 (593 hosts).
# Verified: 592/593 hosts resolve exactly; the only unresolved host is
# SYS76-01, which genuinely has no group in Tenable and must be
# assigned one by a human.
#
# Why prefix rules instead of a per-host map: a 496-line hostname map
# went stale the moment a machine was imaged, and any host missing from
# it linked with NO GROUP -- which means no scan policy, no plugins, no
# results, and a finding that never clears (cost us CSLT-173/-178/-205/
# -210 and CSPC-079). Prefix rules cover new machines automatically.
#
# MAINTENANCE: add a prefix rule when a new naming convention appears;
# add an override only when a single host legitimately differs from its
# prefix. Note 'nessuscli agent link --groups' REPLACES membership, so
# multi-group hosts must list every group.
# ==============================================================

# Exact-hostname overrides -- checked FIRST, win over any prefix rule.
$GroupOverride = @{
    'CS-MCALPHA-01' = 'CIS Windows Server 2019'
    'CS-VCID01' = 'Critical Assets,Windows Servers'
    'CSPRLT-13' = 'CIS Windows 10 Benchmark,Laptops'
    'CV-MBPC02' = 'MacBook'
    'CX-DCPR01' = 'CIS Windows Server 2019'
}

# Prefix rules. LONGEST matching prefix wins, so more specific entries
# (CS-MEM-JUMP) correctly beat broader ones (CS-).
$GroupPrefix = @(
    @{ P = 'C02V'; G = 'Securitas Physical Security' }
    @{ P = 'ACCESS-CLIENT'; G = 'Securitas Physical Security' }
    @{ P = 'MIMAKI'; G = 'Shop Floor Equip' }
    @{ P = 'SWISSQ'; G = 'Shop Floor Equip' }
    @{ P = 'SHRB'; G = 'Shop Floor Equip' }
    @{ P = 'SHOPPR'; G = 'Shop Floor Equip' }
    @{ P = 'LCELO'; G = 'Shop Floor Equip' }
    @{ P = 'CSMB'; G = 'MacBook' }
    @{ P = 'CSPRMB'; G = 'MacBook' }
    @{ P = 'CSPRIM'; G = 'MacBook' }
    @{ P = 'CSIM'; G = 'MacBook' }
    @{ P = 'CSMS'; G = 'MacBook' }
    @{ P = 'ARMB'; G = 'MacBook' }
    @{ P = 'JRIEGEL-MAC'; G = 'MacBook' }
    @{ P = 'CSPC'; G = 'Desktop PC' }
    @{ P = 'CSMEPC'; G = 'Desktop PC' }
    @{ P = 'CSDVPC'; G = 'Desktop PC' }
    @{ P = 'CSPSPC'; G = 'Desktop PC' }
    @{ P = 'CSPRPC'; G = 'Desktop PC' }
    @{ P = 'CSLD'; G = 'Desktop PC' }
    @{ P = 'CSLT'; G = 'Laptops' }
    @{ P = 'CSPRLT'; G = 'Laptops' }
    @{ P = 'CSMELT'; G = 'Laptops' }
    @{ P = 'CSDVLT'; G = 'Laptops' }
    @{ P = 'CSXPS'; G = 'Laptops' }
    @{ P = 'CSPRXPS'; G = 'Laptops' }
    @{ P = 'CSRZ'; G = 'Laptops' }
    @{ P = 'CSPRRZ'; G = 'Laptops' }
    @{ P = 'CSSB'; G = 'Laptops' }
    @{ P = 'CSLV'; G = 'Laptops' }
    @{ P = 'CS-APG-JUMP'; G = 'DMZ Servers' }
    @{ P = 'CS-DVN-JUMP'; G = 'DMZ Servers' }
    @{ P = 'CS-MEM-JUMP'; G = 'DMZ Servers' }
    @{ P = 'CS-PRC-JUMP'; G = 'DMZ Servers' }
    @{ P = 'CS-RSV-JUMP'; G = 'DMZ Servers' }
    @{ P = 'CS-EA'; G = 'DMZ Servers' }
    @{ P = 'CS-'; G = 'Windows Servers' }
    @{ P = 'CX-'; G = 'Windows Servers' }
    @{ P = 'CV-'; G = 'Windows Servers' }
    @{ P = 'TENABLE-'; G = 'Windows Servers' }
)

function Resolve-AgentGroups {
    param([string]$HostName)
    $h = $HostName.ToUpper()
    if ($GroupOverride.ContainsKey($h)) { return $GroupOverride[$h] }
    $bestPrefix = ''
    $bestGroups = ''
    foreach ($rule in $GroupPrefix) {
        if ($h.StartsWith($rule.P) -and ($rule.P.Length -gt $bestPrefix.Length)) {
            $bestPrefix = $rule.P
            $bestGroups = $rule.G
        }
    }
    return $bestGroups
}



$ErrorActionPreference = 'Stop'

$LogDir  = 'C:\Logs\CompoSecure'
$LogFile = Join-Path $LogDir ('NessusAgent_CleanReinstall_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}
function Test-MsiInProgress {
    # Canonical check: Windows Installer holds Global\_MSIExecute for the
    # duration of an install or uninstall. If it can be opened, something is busy.
    try {
        $m = [System.Threading.Mutex]::OpenExisting('Global\_MSIExecute')
        $m.Dispose()
        return $true
    } catch [System.Threading.WaitHandleCannotBeOpenedException] {
        return $false
    } catch {
        return $false
    }
}

function Get-OtherInstallerProcesses {
    $out = @()
    Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match '^(msiexec|setup|install.*|SentinelInstaller|TrustedInstaller)$'
    } | ForEach-Object { $out += ($_.Name + ' (PID ' + $_.Id + ')') }
    return $out
}

function Invoke-Msi {
    # Full path + -NoNewWindow: a bare filename goes through ShellExecute and
    # fails under EC's SYSTEM context. 1618/1601 are transient contention
    # errors, so retry with backoff rather than failing the run.
    param([string]$Arguments, [int]$Retries = 4)
    $msiexec = Join-Path $env:SystemRoot 'System32\msiexec.exe'
    if (-not (Test-Path $msiexec)) { $msiexec = 'msiexec.exe' }
    $attempt = 0
    while ($true) {
        $attempt++
        $p = Start-Process -FilePath $msiexec -ArgumentList $Arguments -Wait -PassThru -NoNewWindow
        $code = $p.ExitCode
        if ($code -ne 1618 -and $code -ne 1601) { return $code }
        if ($attempt -ge $Retries) {
            Write-Log ('    Still ' + $code + ' after ' + $attempt + ' attempts.') -Level ERROR
            return $code
        }
        $wait = 30 * $attempt
        Write-Log ('    ' + $code + ' = installer busy. Waiting ' + $wait + 's, retry ' + $attempt + '/' + $Retries + '...') -Level WARN
        Start-Sleep -Seconds $wait
    }
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

$ServiceNames = @('Nessus Agent', 'Tenable Nessus Agent')
$ProcNames    = @('nessusd', 'nessus-service', 'nessusagent')
$ProgramDir   = 'C:\Program Files\Tenable\Nessus Agent'
$DataDir      = 'C:\ProgramData\Tenable\Nessus Agent'
$RebootNeeded = $false
$NoGroup      = $false

Write-Log '=============================================='
Write-Log ' Nessus Agent Clean Reinstall (v4.1)'
Write-Log (' Host   : ' + $env:COMPUTERNAME)
Write-Log (' DryRun : ' + $DryRun)
Write-Log (' Relink : ' + ((-not $NoLink) -and ($LinkKey -ne '')))
Write-Log '=============================================='

# ==============================================================
# 0. Resolve the MSI path
# ==============================================================
Write-Log ''
Write-Log '[0/6] Resolving target MSI...'
if ([string]::IsNullOrWhiteSpace($MsiPath)) {
    # OS architecture (PROCESSOR_ARCHITEW6432 is set when PS itself is emulated)
    $osArch = $env:PROCESSOR_ARCHITEW6432
    if ([string]::IsNullOrWhiteSpace($osArch)) { $osArch = $env:PROCESSOR_ARCHITECTURE }
    switch ($osArch) {
        'ARM64' { $archToken = 'arm64' }
        'AMD64' { $archToken = 'x64' }
        'x86'   { $archToken = 'win32' }
        default { $archToken = '' }
    }
    Write-Log ('  OS architecture : ' + $osArch + '  (expecting MSI token: ' + $archToken + ')')

    $searchDirs = @()
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    if (-not [string]::IsNullOrWhiteSpace($scriptDir)) { $searchDirs += $scriptDir }
    $searchDirs += 'C:\'

    $candidates = @()
    foreach ($dir in $searchDirs) {
        $found = Get-ChildItem -Path $dir -Filter 'NessusAgent-*.msi' -File -ErrorAction SilentlyContinue
        foreach ($f in $found) {
            $candidates += $f
            Write-Log ('  Found staged MSI : ' + $f.FullName + '  (' + [math]::Round($f.Length/1MB,1) + ' MB)')
        }
    }

    if ($candidates.Count -gt 0) {
        $archMatch = @($candidates | Where-Object { $archToken -and ($_.Name -like ('*' + $archToken + '*')) })
        if ($archMatch.Count -gt 0) {
            $pick = ($archMatch | Sort-Object Name -Descending | Select-Object -First 1)
            Write-Log ('  Architecture match: ' + $pick.Name)
        } else {
            $pick = ($candidates | Sort-Object Name -Descending | Select-Object -First 1)
            Write-Log ('  WARNING: no MSI matching architecture ' + $archToken + '.') -Level WARN
            Write-Log ('  Falling back to ' + $pick.Name + ' -- verify this is correct for this host.') -Level WARN
        }
        $MsiPath = $pick.FullName
    }
}
if ([string]::IsNullOrWhiteSpace($MsiPath) -or -not (Test-Path $MsiPath)) {
    Write-Log '  MSI not found. Stage NessusAgent-*.msi beside this script or in C:\,' -Level ERROR
    Write-Log '  or pass -MsiPath explicitly. Searched the script directory and C:\.' -Level ERROR
    exit 1
}
Write-Log ('  Target MSI : ' + $MsiPath)

# ==============================================================
# 0b. PRE-FLIGHT: do not tear down if another install is running
# ==============================================================
Write-Log ''
Write-Log '[0b] Pre-flight: checking for a concurrent MSI operation...'
if (Test-MsiInProgress) {
    Write-Log '  Another Windows Installer operation is IN PROGRESS (Global\_MSIExecute held).' -Level WARN
    foreach ($o in (Get-OtherInstallerProcesses)) { Write-Log ('    installer process: ' + $o) -Level WARN }
    Write-Log '  This script purges the agent directories and registrations BEFORE it' -Level WARN
    Write-Log '  installs. If that install then fails with 1618, the host is left with no' -Level WARN
    Write-Log '  agent. Refusing to start; re-run once the other install finishes.' -Level WARN
    Write-Log '  (CSLT-215, 2026-08-07: SentinelOne was mid-install and held the mutex.)' -Level WARN
    Write-Log '=============================================='
    exit 2
}
Write-Log '  No concurrent MSI operation detected.'

# ==============================================================
# 1. Kill orphaned Nessus processes
# ==============================================================
Write-Log ''
Write-Log '[1/6] Killing Nessus processes...'
$killed = 0
foreach ($pn in $ProcNames) {
    foreach ($p in (Get-Process -Name $pn -ErrorAction SilentlyContinue)) {
        Write-Log ('  Found ' + $p.Name + ' (PID ' + $p.Id + ')') -Level WARN
        if ($DryRun) { Write-Log '    [DRYRUN] Would kill.'; continue }
        try { Stop-Process -Id $p.Id -Force -ErrorAction Stop; $killed++; Write-Log '    Killed.' }
        catch { Write-Log ('    Failed to kill PID ' + $p.Id + ': ' + $_) -Level ERROR }
    }
}
if ($killed -eq 0) { Write-Log '  No Nessus processes running.' }
Start-Sleep -Seconds 3

# ==============================================================
# 2. Stop + delete service (both possible names)
# ==============================================================
Write-Log ''
Write-Log '[2/6] Handling service registration(s)...'
$anySvc = $false
foreach ($sn in $ServiceNames) {
    $svc = Get-Service -Name $sn -ErrorAction SilentlyContinue
    if (-not $svc) { continue }
    $anySvc = $true
    Write-Log ('  Service "' + $sn + '" present, status: ' + $svc.Status)
    if ($DryRun) { Write-Log '    [DRYRUN] Would stop and delete.'; continue }
    if ($svc.Status -ne 'Stopped') {
        Stop-Service -Name $sn -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
    }
    $scResult = & sc.exe delete $sn 2>&1
    Write-Log ('    sc delete: ' + ($scResult -join ' '))
}
if (-not $anySvc) { Write-Log '  No Nessus service registered (already gone).' }

# ==============================================================
# 3. Classify + clear every Nessus registration
# ==============================================================
Write-Log ''
Write-Log '[3/6] Classifying Installer-DB registrations...'

$uninstallPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$arpEntries = Get-ItemProperty -Path $uninstallPaths -ErrorAction SilentlyContinue |
              Where-Object { $_.DisplayName -like '*Nessus*' }
$arpGuids = @()
foreach ($e in $arpEntries) { $arpGuids += $e.PSChildName.ToUpper() }
Write-Log ('  ARP Nessus entries: ' + $arpGuids.Count)

$foundReg = 0
Get-ChildItem 'HKLM:\SOFTWARE\Classes\Installer\Products' -ErrorAction SilentlyContinue | ForEach-Object {
    $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    if ($props.ProductName -notlike '*Nessus*') { return }
    $foundReg++

    $compressed = $_.PSChildName
    $guid = Convert-CompressedGuid $compressed
    $udPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\' + $compressed
    $localPkg = (Get-ItemProperty ($udPath + '\InstallProperties') -ErrorAction SilentlyContinue).LocalPackage

    $hasArp   = $guid -and ($arpGuids -contains $guid.ToUpper())
    $hasCache = $localPkg -and (Test-Path $localPkg)

    Write-Log ('  ' + $props.ProductName + '  ' + $guid + '  ARP=' + $hasArp + '  Cache=' + $hasCache)

    if ($DryRun) {
        if ($hasArp -and $hasCache) { Write-Log '    [DRYRUN] HEALTHY -> would msiexec /x.' }
        else { Write-Log '    [DRYRUN] ORPHANED -> would delete registration keys.' }
        return
    }

    if ($hasArp -and $hasCache) {
        Write-Log '    HEALTHY -> normal uninstall via msiexec /x'
        $uCode = Invoke-Msi ('/x ' + $guid + ' /qn /norestart /l*v "' + $LogDir + '\msi_uninstall_' + $compressed + '.log"')
        $u = [pscustomobject]@{ ExitCode = $uCode }
        Write-Log ('    Uninstall exit: ' + $u.ExitCode)
        if ($u.ExitCode -eq 3010) { $script:RebootNeeded = $true }
        if ($u.ExitCode -ne 0 -and $u.ExitCode -ne 3010) {
            Write-Log '    Uninstall failed -> falling back to registration deletion.' -Level WARN
            Remove-Item $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    } else {
        Write-Log '    ORPHANED -> deleting Installer-DB registration (msiexec would 1612)'
        Remove-Item $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $udPath) {
        Remove-Item $udPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log '    Cleared UserData entry.'
    }
}
if ($foundReg -eq 0) { Write-Log '  No Nessus registrations in the Installer database.' }

# Clear any ARP entries that survived (stale after orphan deletion)
if (-not $DryRun) {
    foreach ($e in $arpEntries) {
        if (Test-Path $e.PSPath) {
            Remove-Item $e.PSPath -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log ('  Cleared stale ARP entry: ' + $e.DisplayName + ' ' + $e.DisplayVersion)
        }
    }
}
Start-Sleep -Seconds 3

# ==============================================================
# 4. Purge leftover directories
# ==============================================================
Write-Log ''
Write-Log '[4/6] Purging leftover directories...'
foreach ($dir in @($ProgramDir, $DataDir)) {
    if (-not (Test-Path $dir)) { Write-Log ('  Clean: ' + $dir); continue }
    Write-Log ('  Found leftover: ' + $dir) -Level WARN
    if ($DryRun) { Write-Log '    [DRYRUN] Would remove.'; continue }
    try {
        Remove-Item -Path $dir -Recurse -Force -ErrorAction Stop
        Write-Log '    Removed.'
    } catch {
        Write-Log ('    Could not fully remove: ' + $_) -Level WARN
        Write-Log '    Reboot required before reinstall.' -Level WARN
        $RebootNeeded = $true
    }
}

# ==============================================================
# 5. Fresh install (with sanity verification)
# ==============================================================
Write-Log ''
Write-Log '[5/6] Installing fresh Nessus Agent...'

if ($RebootNeeded -and -not $DryRun) {
    Write-Log '  Locked leftovers detected. Skipping install; re-run after reboot.' -Level WARN
    exit 3010
}

if ($DryRun) {
    Write-Log ('  [DRYRUN] Would run: msiexec /i "' + $MsiPath + '" /qn /norestart')
} else {
    $installLog = $LogDir + '\msi_install_nessusagent.log'
    $installStart = Get-Date
    $msiArgs = '/i "' + $MsiPath + '" /qn /norestart /l*v "' + $installLog + '"'
    $installCode = Invoke-Msi $msiArgs
    $proc = [pscustomobject]@{ ExitCode = $installCode }
    $elapsed = [math]::Round(((Get-Date) - $installStart).TotalSeconds)
    Write-Log ('  msiexec exit code: ' + $proc.ExitCode + '  (took ' + $elapsed + 's)')

    if ($proc.ExitCode -eq 3010) { $RebootNeeded = $true }
    elseif ($proc.ExitCode -ne 0) {
        Write-Log ('  Install FAILED. See ' + $installLog) -Level ERROR
        Write-Log '  *** THIS HOST NOW HAS NO NESSUS AGENT. ***' -Level ERROR
        Write-Log '  The teardown completed but the install did not. Re-run this script once' -Level ERROR
        Write-Log '  the blocking condition clears; nothing else will restore the agent.' -Level ERROR
        if ($proc.ExitCode -eq 1618) {
            Write-Log '  1618 = another installation in progress. The MSI log names the other' -Level ERROR
            Write-Log '  installer under "Post-install cleanup". Wait for it, then re-run.' -Level ERROR
        }
        exit 1
    }

    # Sanity: exit 0 in seconds with no files on disk = short-circuited install
    if (-not (Test-Path (Join-Path $ProgramDir 'nessuscli.exe'))) {
        Write-Log '  Exit 0 but nessuscli.exe missing from install dir -- install did NOT land.' -Level ERROR
        Write-Log ('  Review ' + $installLog) -Level ERROR
        exit 1
    }
}

# ==============================================================
# 6. Start service, relink if key provided, report status
# ==============================================================
Write-Log ''
Write-Log '[6/6] Service + link status...'

if ($DryRun) {
    Write-Log '  [DRYRUN] Skipping verification.'
    Write-Log '=============================================='
    exit 0
}

Start-Sleep -Seconds 5
$svcFinal = Get-Service | Where-Object { $_.Name -like '*Nessus Agent*' } | Select-Object -First 1
if (-not $svcFinal) {
    Write-Log '  No Nessus Agent service found after install (checked both names)!' -Level ERROR
    exit 1
}
Write-Log ('  Service: ' + $svcFinal.Name + '  Status: ' + $svcFinal.Status)
if ($svcFinal.Status -ne 'Running') {
    Start-Service $svcFinal.Name -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    Write-Log ('  Post-start status: ' + (Get-Service $svcFinal.Name).Status)
}

$cli = Join-Path $ProgramDir 'nessuscli.exe'
if ((Test-Path $cli) -and $LinkKey -and -not $NoLink) {
    # Resolve groups: explicit -LinkGroups wins; else look up this host in the map.
    $hostKey = $env:COMPUTERNAME.ToUpper()
    $groups  = $LinkGroups
    if (-not $groups) {
        $groups = Resolve-AgentGroups $hostKey
        if ($groups) {
            Write-Log ('  Mapped groups for ' + $hostKey + ': ' + $groups)
        } else {
            Write-Log ('  ' + $hostKey + ' NOT IN GROUP MAP -- would link with NO group.') -Level WARN
            Write-Log '  An agent in no group is never targeted by any agent scan: no scan' -Level WARN
            Write-Log '  policy, no plugins, no results. Tenable would keep reporting the OLD' -Level WARN
            Write-Log '  version indefinitely and the finding would never clear.' -Level WARN
            Write-Log '  FIX: pass -LinkGroups, add the host to the map, or assign the group' -Level WARN
            Write-Log '  in Tenable (Sensors > Agents) after this run.' -Level WARN
            $script:NoGroup = $true
        }
    } else {
        Write-Log ('  Using -LinkGroups override: ' + $groups)
    }
    Write-Log ('  Linking agent to ' + $LinkHost + '...')
    $linkArgs = @('agent', 'link', ('--key=' + $LinkKey), ('--host=' + $LinkHost), '--port=443')
    if ($groups) { $linkArgs += ('--groups=' + $groups) }
    $linkOut = & $cli $linkArgs 2>&1
    foreach ($line in $linkOut) { Write-Log ('    ' + $line) }
    if ($linkOut -match 'empty response') {
        Write-Log '  Link failed with empty response -- check Zscaler SSL inspection of ' -Level WARN
        Write-Log ('  ' + $LinkHost + ' (add bypass) and retry.') -Level WARN
    }
} elseif ($NoLink) {
    Write-Log '  -NoLink set: skipping link step.'
}
if (Test-Path $cli) {
    $status = & $cli agent status 2>&1
    foreach ($line in $status) { Write-Log ('  ' + $line) }
    if (($status -join ' ') -match 'Not linked') {
        Write-Log '  AGENT NOT LINKED -- run nessuscli agent link with your key.' -Level WARN
    }
}

Write-Log ''
Write-Log '=============================================='
Write-Log ' Clean reinstall complete.'
Write-Log (' Log : ' + $LogFile)
if ($NoGroup) {
    Write-Log ' ATTENTION: agent linked with NO GROUP -- it will NOT scan or report' -Level WARN
    Write-Log ' until a group is assigned. Assign it in Tenable (Sensors > Agents)' -Level WARN
    Write-Log ' or re-run with -LinkGroups. Exiting 2 so this is not read as done.' -Level WARN
}
Write-Log '=============================================='
if ($RebootNeeded) { exit 3010 }
if ($NoGroup) { exit 2 }
exit 0
