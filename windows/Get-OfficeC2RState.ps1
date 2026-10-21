<#
.SYNOPSIS
    Read-only check of why an Office Click-to-Run finding is still open after
    Update-OfficeC2R.ps1 ran. Reports what Tenable actually reads (the file
    version of each Office binary on disk) next to what C2R says it is.

.DESCRIPTION
    Written for cslt-226 / cslt-062 / csdvlt-07 / csmelt-10 (2026-10-21):
    plugin 335115 (Access C2R, August 2026) stayed ACTIVE the day after
    Update-OfficeC2R.ps1 ran. That script only LAUNCHES OfficeC2RClient
    /update and exits 0; it never confirms the build changed. Tenable's C2R
    plugins compare the file version of e.g.
    C:\Program Files\Microsoft Office\root\Office16\MsAccess.exe with the
    fixed build (16.0.20228.20190 for the August 2026 round), so a host
    stays flagged when:
      - the update never ran or never finished (C2R version unchanged),
      - a policy pins the build or points updates at a stale share,
      - updates are disabled by policy (the C2R script's registry override
        does not beat a GPO),
      - the update staged but the binaries were not swapped yet,
      - an old copy of the app lives somewhere else on disk: a leftover
        32-bit C2R folder after a move to 64-bit, or an MSI Office/Access.

    Checks (all reads; nothing is changed):
      1. C2R Configuration and Updates keys (64-bit view, so the 32-bit EC
         agent sees the real values): VersionToReport, Platform, channel,
         UpdatesEnabled, UpdateToVersion, UpdateUrl / UpdatePath.
      2. Office update policies (GPO and cloud policy): enableautomaticupdates,
         updatetargetversion, updatepath, updatebranch, updatedeadline.
      3. File versions of the Office binaries in BOTH Program Files roots, for
         C2R (root\Office16) and MSI (Office16 / Office15) layouts.
      4. Office apps running now, and error lines from the newest C2R logs in
         C:\Windows\Temp (where C2R logs when run as SYSTEM).

.PARAMETER ExpectVersion
    Optional fixed build from the Tenable finding (e.g. 16.0.20228.20190).
    When given, any Office binary below it is reported. Without it the
    script still reports every inconsistency it can see on its own.

.OUTPUTS
    One line:  VERDICT: <TOKEN> -- <summary>
    plus one CSV row appended to C:\Logs\CompoSecure\OfficeC2RState.csv.

    Tokens (most severe first; every finding is logged):
      NOT_C2R            no Click-to-Run configuration on this machine
      LEFTOVER_FILES     an Office binary outside the active C2R install
                         (other Program Files root, or an MSI Office folder)
      PINNED_TARGET      a policy or UpdateToVersion holds the build
      UPDATES_DISABLED   Office update policy is off (GPO / cloud policy)
      CUSTOM_SOURCE      updates come from a share or URL, not the Office CDN
      NOT_FINALIZED      a binary is older than C2R's VersionToReport
                         (staged, not applied: an app was open, or a reboot)
      BELOW_EXPECTED     the build is below -ExpectVersion (update did not land)
      CONSISTENT         nothing above; if Tenable still flags the host, the
                         scan predates the update or the channel has no fix yet

.NOTES
    Deploy via Endpoint Central (SYSTEM). Changes nothing; safe fleet-wide.
    Exit: 0 = report written, 1 = could not run.
#>

[CmdletBinding()]
param(
    [string]$ExpectVersion = ''
)

$ChannelMap = @{
    '492350f6-3a01-4f97-b9c0-c7c6ddf67d60' = 'Current Channel'
    '55336b82-a18d-4dd6-b5f6-9e5095c314a6' = 'Monthly Enterprise Channel'
    '7ffbc6bf-bc32-4f92-8982-f9dd17fd3114' = 'Semi-Annual Enterprise Channel'
    'b8f9b850-328d-4355-9145-c59439a0c4cf' = 'Semi-Annual Enterprise Channel (Preview)'
    '64256afe-f5d9-4f86-8936-8840a6a4f5be' = 'Current Channel (Preview)'
    '5440fd1f-7ecb-4221-8110-145efaa6372f' = 'Beta Channel'
    'f2e724c1-748f-4b47-8fb8-8e0d210e9208' = 'Office 2019 Perpetual (PerpetualVL2019)'
    '5030841d-c919-4594-8d2d-84ae4f96e58e' = 'Office LTSC 2021 (PerpetualVL2021)'
    '7983bac0-e531-40cf-be00-fd24fe66619c' = 'Office LTSC 2024 (PerpetualVL2024)'
}

$OfficeBinaries = @('MSACCESS.EXE', 'WINWORD.EXE', 'EXCEL.EXE', 'OUTLOOK.EXE', 'POWERPNT.EXE',
                    'PPCORE.DLL', 'GRAPH.EXE', 'MSPUB.EXE', 'VISIO.EXE', 'WINPROJ.EXE', 'ONENOTE.EXE')

# CDNBaseUrl / UpdateChannel URL -> channel name.
function Get-C2RChannelName {
    param([string]$Url)
    $guid = (('' + $Url).TrimEnd('/') -split '/')[-1].ToLowerInvariant()
    if (-not $guid) { return '' }
    if ($ChannelMap.ContainsKey($guid)) { return $ChannelMap[$guid] }
    return ('Unknown (' + $guid + ')')
}

# Office folders that may hold binaries Tenable reads. The active C2R
# install is root\Office16 under the Program Files matching its Platform.
function Get-OfficeFolders {
    param([string]$Platform)
    $pf64 = 'C:\Program Files\Microsoft Office'
    $pf86 = 'C:\Program Files (x86)\Microsoft Office'
    $active = $(if ($Platform -eq 'x86') { $pf86 + '\root\Office16' } else { $pf64 + '\root\Office16' })
    $all = @(($pf64 + '\root\Office16'), ($pf86 + '\root\Office16'),
             ($pf64 + '\Office16'), ($pf86 + '\Office16'), ($pf64 + '\Office15'), ($pf86 + '\Office15'))
    $out = @()
    foreach ($f in $all) {
        $out += [pscustomobject]@{ Path = $f; Active = ($f -eq $active) }
    }
    return $out
}

# First update source that is not the Office CDN; '' when all are CDN or unset.
function Get-CustomUpdateSource {
    param([string[]]$Sources)
    foreach ($s in $Sources) {
        $t = ('' + $s).Trim()
        if (-not $t) { continue }
        if ($t -match '^https?://officecdn\.microsoft\.com/') { continue }
        return $t
    }
    return ''
}

# Inputs gathered from the machine -> @(token, summary, all findings).
function Get-StateVerdict {
    param(
        [bool]$HasC2R,
        [object[]]$Files,            # Path, Version ([version] or $null), Active (bool)
        [string]$ReportVersion,
        [string]$PolicyTargetVersion,
        [string]$UpdateToVersion,
        [string]$PolicyAutoUpdates,  # '0' = disabled by policy
        [string]$UpdatesEnabled,
        [string]$CustomSource,
        [string]$ExpectVersion
    )
    $findings = New-Object System.Collections.ArrayList
    $tokens = New-Object System.Collections.ArrayList
    if (-not $HasC2R) {
        $msi = @($Files | Where-Object { $_.Version })
        if ($msi.Count -gt 0) {
            [void]$findings.Add('no Click-to-Run install, but Office binaries exist: ' + (($msi | ForEach-Object { $_.Path + ' ' + $_.Version }) -join '; '))
        }
        return @('NOT_C2R', 'Office Click-to-Run is not installed; Update-OfficeC2R.ps1 cannot patch this machine', $findings)
    }
    $report = $null
    try { $report = [version]$ReportVersion } catch { }
    $expect = $null
    if ($ExpectVersion) { try { $expect = [version]$ExpectVersion } catch { } }

    $leftover = @($Files | Where-Object { $_.Version -and -not $_.Active })
    foreach ($f in $leftover) { [void]$findings.Add('outside the active install: ' + $f.Path + ' ' + $f.Version) }
    if ($leftover.Count -gt 0) { [void]$tokens.Add('LEFTOVER_FILES') }

    if ($PolicyTargetVersion -or $UpdateToVersion) {
        if ($PolicyTargetVersion) { [void]$findings.Add('policy updatetargetversion = ' + $PolicyTargetVersion) }
        if ($UpdateToVersion) { [void]$findings.Add('C2R UpdateToVersion = ' + $UpdateToVersion) }
        [void]$tokens.Add('PINNED_TARGET')
    }
    if ($PolicyAutoUpdates -eq '0') {
        [void]$findings.Add('policy enableautomaticupdates = 0 (Office updates disabled by GPO / cloud policy)')
        [void]$tokens.Add('UPDATES_DISABLED')
    } elseif (('' + $UpdatesEnabled) -eq 'False') {
        [void]$findings.Add('C2R UpdatesEnabled = False')
        [void]$tokens.Add('UPDATES_DISABLED')
    }
    if ($CustomSource) {
        [void]$findings.Add('updates come from ' + $CustomSource + ' (not the Office CDN); that source may hold an old build')
        [void]$tokens.Add('CUSTOM_SOURCE')
    }
    $active = @($Files | Where-Object { $_.Version -and $_.Active })
    if ($report) {
        $stale = @($active | Where-Object { $_.Version -lt $report })
        foreach ($f in $stale) { [void]$findings.Add('older than VersionToReport ' + $report + ': ' + $f.Path + ' ' + $f.Version) }
        if ($stale.Count -gt 0) { [void]$tokens.Add('NOT_FINALIZED') }
    }
    if ($expect) {
        $below = @($active | Where-Object { $_.Version -lt $expect })
        foreach ($f in $below) { [void]$findings.Add('below the fixed build ' + $expect + ': ' + $f.Path + ' ' + $f.Version) }
        if ($below.Count -gt 0 -or ($report -and $report -lt $expect)) { [void]$tokens.Add('BELOW_EXPECTED') }
    }

    $order = @('LEFTOVER_FILES', 'PINNED_TARGET', 'UPDATES_DISABLED', 'CUSTOM_SOURCE', 'NOT_FINALIZED', 'BELOW_EXPECTED')
    foreach ($t in $order) {
        if ($tokens -contains $t) {
            $summary = switch ($t) {
                'LEFTOVER_FILES'   { 'an old Office copy outside the C2R install is what Tenable reads; remove it (C2R updates never touch it)' }
                'PINNED_TARGET'    { 'the build is held by a target-version setting; clear it, then update' }
                'UPDATES_DISABLED' { 'Office updates are disabled by policy; the C2R script cannot override a GPO' }
                'CUSTOM_SOURCE'    { 'updates come from a custom share/URL; check it holds the fixed build' }
                'NOT_FINALIZED'    { 'the update staged but binaries were not replaced; close Office (or reboot) and re-run' }
                'BELOW_EXPECTED'   { 'the installed build is below the fixed build; the update did not land' }
            }
            return @($t, $summary, $findings)
        }
    }
    return @('CONSISTENT', 'install is consistent; if Tenable still flags it, rescan (the scan may predate the update)', $findings)
}

if ($env:OFFICE_C2R_STATE_DOTSOURCE -eq '1') { return }

# -----------------------------------------------------------------------------
$ErrorActionPreference = 'Stop'
$LogDir  = 'C:\Logs\CompoSecure'
$LogFile = Join-Path $LogDir ('OfficeC2RState_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')
$CsvFile = Join-Path $LogDir 'OfficeC2RState.csv'
try {
    if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
} catch {
    Write-Host ('Cannot create ' + $LogDir + ': ' + $_)
    exit 1
}

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

# All values of an HKLM key in the 64-bit view (the 32-bit EC agent would
# otherwise read WOW6432Node). Empty hashtable when the key is absent.
function Get-HklmValues {
    param([string]$SubKey)
    $h = @{}
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
        $k = $base.OpenSubKey($SubKey)
        if ($k) {
            foreach ($n in $k.GetValueNames()) { $h[$n] = $k.GetValue($n) }
            $k.Close()
        }
        $base.Close()
    } catch {
        Write-Log ('  Could not read HKLM\' + $SubKey + ': ' + $_) -Level WARN
    }
    return $h
}

function Get-FileVersion4 {
    param([string]$Path)
    try {
        $vi = (Get-Item -LiteralPath $Path).VersionInfo
        return New-Object System.Version($vi.FileMajorPart, $vi.FileMinorPart, $vi.FileBuildPart, $vi.FilePrivatePart)
    } catch { return $null }
}

function Get-Val {
    param([hashtable]$H, [string]$Name)
    foreach ($k in $H.Keys) { if ($k -ieq $Name) { return ('' + $H[$k]).Trim() } }
    return ''
}

Write-Log '=============================================='
Write-Log ' Office C2R state (read-only)'
Write-Log (' Host : ' + $env:COMPUTERNAME)
if ($ExpectVersion) { Write-Log (' Expected fixed build : ' + $ExpectVersion) }
Write-Log '=============================================='

# 1. C2R configuration
Write-Log ''
Write-Log '[1/4] Click-to-Run configuration'
$cfg = Get-HklmValues 'SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
$upd = Get-HklmValues 'SOFTWARE\Microsoft\Office\ClickToRun\Updates'
$hasC2R = ($cfg.Count -gt 0)
$platform = Get-Val $cfg 'Platform'
$reportVer = Get-Val $cfg 'VersionToReport'
$channel = Get-C2RChannelName (Get-Val $cfg 'CDNBaseUrl')
$updChannel = Get-Val $cfg 'UpdateChannel'
if ($hasC2R) {
    Write-Log ('  Products        : ' + (Get-Val $cfg 'ProductReleaseIds'))
    Write-Log ('  VersionToReport : ' + $reportVer)
    Write-Log ('  Platform        : ' + $platform)
    Write-Log ('  Channel (CDN)   : ' + $channel)
    if ($updChannel) { Write-Log ('  UpdateChannel   : ' + (Get-C2RChannelName $updChannel) + '  (overrides CDNBaseUrl at the next update)') }
    foreach ($n in @('UpdatesEnabled', 'UpdateToVersion', 'UpdateUrl', 'UpdatePath', 'UpdateDeadline', 'UpdateChannelChanged')) {
        $v = Get-Val $cfg $n
        if ($v) { Write-Log ('  ' + $n.PadRight(15) + ' : ' + $v) }
    }
    foreach ($n in ($upd.Keys | Sort-Object)) { Write-Log ('  Updates\' + $n + ' = ' + $upd[$n]) }
} else {
    Write-Log '  No Click-to-Run configuration key.' -Level WARN
}

# 2. Policies
Write-Log ''
Write-Log '[2/4] Office update policies'
$pol = Get-HklmValues 'SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate'
$cloud = Get-HklmValues 'SOFTWARE\Policies\Microsoft\cloud\office\16.0\common\officeupdate'
foreach ($set in @(@('GPO', $pol), @('Cloud policy', $cloud))) {
    $h = $set[1]
    if ($h.Count -eq 0) { Write-Log ('  ' + $set[0] + ': none') ; continue }
    foreach ($n in ($h.Keys | Sort-Object)) { Write-Log ('  ' + $set[0] + ': ' + $n + ' = ' + $h[$n]) }
}
$policyTarget = Get-Val $pol 'updatetargetversion'
if (-not $policyTarget) { $policyTarget = Get-Val $cloud 'updatetargetversion' }
$policyAuto = Get-Val $pol 'enableautomaticupdates'
if (-not $policyAuto) { $policyAuto = Get-Val $cloud 'enableautomaticupdates' }
$customSource = Get-CustomUpdateSource @((Get-Val $pol 'updatepath'), (Get-Val $cloud 'updatepath'), (Get-Val $cfg 'UpdateUrl'), (Get-Val $cfg 'UpdatePath'))

# 3. Binaries on disk (what Tenable reads)
Write-Log ''
Write-Log '[3/4] Office binaries on disk'
$files = @()
foreach ($folder in (Get-OfficeFolders -Platform $platform)) {
    if (-not (Test-Path -LiteralPath $folder.Path)) { continue }
    $tag = $(if ($folder.Active -and $hasC2R) { 'active C2R' } else { 'NOT the active install' })
    Write-Log ('  ' + $folder.Path + '  (' + $tag + ')')
    foreach ($b in $OfficeBinaries) {
        $p = Join-Path $folder.Path $b
        if (-not (Test-Path -LiteralPath $p)) { continue }
        $v = Get-FileVersion4 $p
        Write-Log ('    ' + $b.PadRight(13) + ' ' + $v)
        $files += [pscustomobject]@{ Path = $p; Version = $v; Active = ($folder.Active -and $hasC2R) }
    }
}
if ($files.Count -eq 0) { Write-Log '  No Office binaries found in the standard folders.' -Level WARN }

# 4. Running apps and C2R logs
Write-Log ''
Write-Log '[4/4] Running Office apps and recent C2R logs'
$names = @('MSACCESS', 'WINWORD', 'EXCEL', 'OUTLOOK', 'POWERPNT', 'ONENOTE', 'MSPUB', 'VISIO', 'WINPROJ', 'lync', 'Teams')
$running = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $names -contains $_.ProcessName })
if ($running.Count -eq 0) { Write-Log '  No Office apps running.' }
foreach ($p in $running) { Write-Log ('  RUNNING: ' + $p.ProcessName + ' (PID ' + $p.Id + ', session ' + $p.SessionId + ')') }
$logs = @(Get-ChildItem -LiteralPath (Join-Path $env:WINDIR 'Temp') -Filter ($env:COMPUTERNAME + '-*.log') -ErrorAction SilentlyContinue |
          Sort-Object LastWriteTime -Descending | Select-Object -First 3)
if ($logs.Count -eq 0) { Write-Log '  No C2R logs in C:\Windows\Temp.' }
foreach ($l in $logs) {
    Write-Log ('  ' + $l.Name + '  (' + $l.LastWriteTime.ToString('yyyy-MM-dd HH:mm') + ', ' + [math]::Round($l.Length / 1KB) + ' KB)')
    $hits = @(Select-String -LiteralPath $l.FullName -Pattern 'error|fail|blocked|UpdatesEnabled|UpdateToVersion|ApplyUpdates' -ErrorAction SilentlyContinue |
              Where-Object { $_.Line -notmatch 'ErrorCode[:=]\s*0\b' } | Select-Object -Last 8)
    foreach ($h in $hits) {
        $t = $h.Line.Trim()
        if ($t.Length -gt 220) { $t = $t.Substring(0, 220) + '...' }
        Write-Log ('    ' + $t)
    }
}

# Verdict
$r = Get-StateVerdict -HasC2R $hasC2R -Files $files -ReportVersion $reportVer -PolicyTargetVersion $policyTarget `
    -UpdateToVersion (Get-Val $cfg 'UpdateToVersion') -PolicyAutoUpdates $policyAuto -UpdatesEnabled (Get-Val $cfg 'UpdatesEnabled') `
    -CustomSource $customSource -ExpectVersion $ExpectVersion
$token = $r[0]; $summary = $r[1]; $findings = @($r[2])
Write-Log ''
if ($findings.Count -gt 0) {
    Write-Log 'Findings:'
    foreach ($f in $findings) { Write-Log ('  - ' + $f) }
}
$access = ($files | Where-Object { $_.Active -and $_.Path -like '*\MSACCESS.EXE' } | Select-Object -First 1)
$accessVer = $(if ($access) { '' + $access.Version } else { '' })
Write-Log ('VERDICT: ' + $token + ' -- ' + $summary)
Write-Log '=============================================='

try {
    if (-not (Test-Path $CsvFile)) {
        Add-Content -Path $CsvFile -Value 'Timestamp,Host,Verdict,Platform,Channel,VersionToReport,MsAccessVersion,PolicyTarget,PolicyAutoUpdates,CustomSource,Findings'
    }
    $cells = @((Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $env:COMPUTERNAME, $token, $platform, $channel, $reportVer, $accessVer,
               $policyTarget, $policyAuto, $customSource, ($findings -join ' | '))
    Add-Content -Path $CsvFile -Value (($cells | ForEach-Object { ('' + $_) -replace ',', ';' }) -join ',')
} catch {
    Write-Log ('  Could not append to ' + $CsvFile + ': ' + $_) -Level WARN
}
exit 0
