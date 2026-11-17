<#
.SYNOPSIS
    Removes classic Microsoft Teams (Teams 1.x, the Electron client) from
    every user profile and removes the Teams Machine-Wide Installer that puts
    it back. Nessus plugins 175408, 179635 (Microsoft Teams < 1.6.x). (v1)

.DESCRIPTION
    Written for CSPRLT-46 (2026-11-17 export):
      Path              : C:\Users\vdasilva\AppData\Local\Microsoft\Teams\current\
      Installed version : 1.5.0.28361
      Fixed version     : 1.6.0.18681

    Classic Teams reached end of availability on 2025-07-01 and no longer
    signs in, so there is no newer 1.x to install: the finding clears by
    removing it. New Teams (the MSTeams MSIX package, ms-teams.exe) is a
    separate product and is never touched; the log says whether it is
    present.

    Classic Teams installs per user with Squirrel, so SYSTEM cannot uninstall
    it the normal way. For each profile (signed in or not) the script:
      * stops Teams.exe / Update.exe running from that profile's classic
        Teams folder;
      * deletes %LOCALAPPDATA%\Microsoft\Teams (what Tenable reads) and the
        ProgramData\<user>\Microsoft\Teams variant;
      * deletes Desktop and Start Menu shortcuts whose target is the classic
        Update.exe or current\Teams.exe;
      * removes the user's Uninstall\Teams entry and the
        com.squirrel.Teams.Teams Run value (loading NTUSER.DAT if signed out).
    %APPDATA%\Microsoft\Teams (settings, custom backgrounds) is left alone;
    Tenable does not read it.

    The Teams Machine-Wide Installer MSI reinstalls classic Teams into every
    profile at sign-in. It is uninstalled with msiexec /x and its
    TeamsMachineInstaller Run value and Teams Installer folder are removed.

    Every removal is verified by re-reading the folder or registry entry.

.PARAMETER DryRun
    Report what would be removed; change nothing.

.NOTES
    Deploy via Endpoint Central (SYSTEM). No arguments needed; -DryRun is the
    only switch. Configure EC 'Specify exit code(s)' as 0,3010.
    Logs: C:\Logs\CompoSecure\RemoveTeamsClassic_*.log; msiexec log beside it.
    Exit: 0 = no classic Teams left anywhere (verified)
          3010 = as 0, and msiexec asked for a reboot
          2 = a profile hive could not be loaded to clean its registry entries
              (files are gone; Tenable reads files)
          1 = something could not be removed (see FAILED in the SUMMARY)
#>

[CmdletBinding()]
param(
    [switch]$DryRun
)

$MachineWideName = 'Teams Machine-Wide Installer'
$SquirrelRunValue = 'com.squirrel.Teams.Teams'
$MachineRunValue = 'TeamsMachineInstaller'

# Only domain/local accounts (S-1-5-21-) and Entra ID accounts (S-1-12-1-)
# are people; SYSTEM, LOCAL SERVICE and NETWORK SERVICE are skipped.
function Test-SkipProfileSid {
    param([string]$Sid)
    return -not (($Sid -match '^S-1-5-21-') -or ($Sid -match '^S-1-12-1-'))
}

# Classic Teams folders a profile can hold. Tenable's path is the first.
function Get-ClassicTeamsDirs {
    param([string]$ProfilePath, [string]$ProgramData)
    $user = Split-Path -Leaf $ProfilePath.TrimEnd('\')
    return @(
        ($ProfilePath.TrimEnd('\') + '\AppData\Local\Microsoft\Teams'),
        ($ProgramData.TrimEnd('\') + '\' + $user + '\Microsoft\Teams')
    )
}

# A shortcut belongs to classic Teams when it starts the Squirrel Update.exe
# or current\Teams.exe in a Microsoft\Teams folder. New Teams shortcuts point
# at ms-teams.exe under WindowsApps and never match.
function Test-ClassicTeamsShortcut {
    param([string]$Target)
    if (-not $Target) { return $false }
    return ($Target -match '\\Microsoft\\Teams\\(Update\.exe|current\\Teams\.exe)$')
}

function Test-TeamsMachineWideEntry {
    param([string]$DisplayName)
    return (('' + $DisplayName).Trim() -eq $MachineWideName)
}

# {GUID} from an ARP UninstallString such as MsiExec.exe /X{731F6BAA-...}, or
# from the subkey name when that is the product code.
function Get-MsiProductCode {
    param([string]$UninstallString, [string]$KeyName)
    foreach ($s in @($KeyName, $UninstallString)) {
        $m = [regex]::Match(('' + $s), '\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}')
        if ($m.Success) { return $m.Value.ToUpperInvariant() }
    }
    return ''
}

function Get-MsiExitMeaning {
    param([int]$Code)
    switch ($Code) {
        0       { return 'success' }
        1605    { return 'product not installed (already gone)' }
        1612    { return 'installation source unavailable (cached MSI missing)' }
        1618    { return 'another installation is in progress' }
        1641    { return 'success, reboot started' }
        3010    { return 'success, reboot required' }
        -1      { return 'timed out' }
        default { return 'failed (code ' + $Code + ')' }
    }
}

function Get-FinalExitCode {
    param([bool]$Failed, [bool]$NeedsHuman, [bool]$Reboot)
    if ($Failed) { return 1 }
    if ($NeedsHuman) { return 2 }
    if ($Reboot) { return 3010 }
    return 0
}

# Deletes a folder or file, retrying once (Squirrel leaves files locked for
# a moment after Teams exits). Returns '' when it is gone, else the error.
function Remove-PathVerified {
    param([string]$Path)
    $err = ''
    for ($i = 1; $i -le 2; $i++) {
        try { Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop } catch { $err = '' + $_ }
        if (-not (Test-Path -LiteralPath $Path)) { return '' }
        if ($i -eq 1) { Start-Sleep -Seconds 3 }
    }
    if (-not $err) { $err = 'still present after delete' }
    return $err
}

if ($env:REMOVE_TEAMS_DOTSOURCE -eq '1') { return }

$ErrorActionPreference = 'Stop'
$LogDir  = 'C:\Logs\CompoSecure'
$Stamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
$LogFile = $LogDir + '\RemoveTeamsClassic_' + $Stamp + '.log'
$MsiTimeoutMinutes = 15
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

function Invoke-Reg {
    param([string[]]$Arguments)
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & ($env:WINDIR + '\System32\reg.exe') @Arguments 2>&1
        $text = @($out | ForEach-Object { if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { '' + $_ } }) -join ' '
        return [pscustomobject]@{ Code = $LASTEXITCODE; Output = $text.Trim() }
    } finally { $ErrorActionPreference = $old }
}

function Get-UserProfiles {
    $out = @()
    $base = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    foreach ($k in (Get-ChildItem $base -ErrorAction SilentlyContinue)) {
        $sid = $k.PSChildName
        if (Test-SkipProfileSid $sid) { continue }
        $p = '' + (Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
        if (-not $p -or -not (Test-Path -LiteralPath $p)) { continue }
        $out += [pscustomobject]@{ Sid = $sid; Path = $p.TrimEnd('\') }
    }
    return $out
}

function Get-TeamsVersionIn {
    param([string]$Dir)
    $exe = $Dir + '\current\Teams.exe'
    if (-not (Test-Path -LiteralPath $exe)) { return '' }
    return ('' + (Get-Item -LiteralPath $exe).VersionInfo.FileVersion).Trim()
}

function Get-MachineWideEntries {
    $out = @()
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
            $un = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
            if (-not $un) { continue }
            foreach ($n in $un.GetSubKeyNames()) {
                $k = $un.OpenSubKey($n)
                if (-not $k) { continue }
                if (-not (Test-TeamsMachineWideEntry ('' + $k.GetValue('DisplayName')))) { continue }
                $code = Get-MsiProductCode -UninstallString ('' + $k.GetValue('UninstallString')) -KeyName $n
                $out += [pscustomobject]@{ Code = $code; Version = ('' + $k.GetValue('DisplayVersion')); View = ('' + $view) }
            }
        } catch { }
    }
    return @($out | Sort-Object Code -Unique)
}

function Remove-MachineRunValue {
    $removed = @()
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
            $run = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Run', $true)
            if ($run -and ($run.GetValueNames() -contains $MachineRunValue)) {
                if (-not $DryRun) { $run.DeleteValue($MachineRunValue) }
                $removed += ('' + $view)
            }
        } catch { Write-Log ('    Could not clear the ' + $MachineRunValue + ' Run value (' + $view + '): ' + $_) -Level WARN }
    }
    return $removed
}

function Invoke-MsiUninstall {
    param([string]$ProductCode, [string]$MsiLog)
    $q = [char]34
    $exe = $env:WINDIR + '\System32\msiexec.exe'
    $msiArgs = '/x ' + $ProductCode + ' /qn /norestart /l*v ' + $q + $MsiLog + $q
    Write-Log ('    Running: ' + $exe + ' ' + $msiArgs)
    $p = Start-Process -FilePath $exe -ArgumentList $msiArgs -NoNewWindow -PassThru
    $null = $p.Handle
    if (-not $p.WaitForExit($MsiTimeoutMinutes * 60 * 1000)) {
        try { $p.Kill() } catch { }
        return -1
    }
    $p.WaitForExit()
    if ($null -eq $p.ExitCode) { return -2 }
    return [int]$p.ExitCode
}

function Get-ProcessesIn {
    param([string]$Dir)
    $prefix = $Dir.TrimEnd('\') + '\'
    return @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) })
}

function Get-ClassicShortcuts {
    param([string]$ProfilePath)
    $dirs = @(
        ($ProfilePath + '\Desktop'),
        ($ProfilePath + '\OneDrive*\Desktop'),
        ($ProfilePath + '\AppData\Roaming\Microsoft\Windows\Start Menu\Programs')
    )
    $shell = New-Object -ComObject WScript.Shell
    $out = @()
    foreach ($d in $dirs) {
        foreach ($lnk in @(Get-ChildItem -Path $d -Filter '*.lnk' -Recurse -File -ErrorAction SilentlyContinue)) {
            try { $t = $shell.CreateShortcut($lnk.FullName).TargetPath } catch { continue }
            if (Test-ClassicTeamsShortcut $t) { $out += $lnk.FullName }
        }
    }
    return $out
}

# Removes the user's Uninstall\Teams key and Squirrel Run value. Returns ''
# on success (or nothing to do), else the reason.
function Clear-UserRegistry {
    param([string]$Sid, [string]$ProfilePath)
    $loaded = $false
    $hive = 'HKU\' + $Sid
    try {
        if (-not (Test-Path ('Registry::HKEY_USERS\' + $Sid))) {
            $ntuser = $ProfilePath + '\NTUSER.DAT'
            if (-not (Test-Path -LiteralPath $ntuser)) { return 'hive not loaded and ' + $ntuser + ' missing' }
            if ($DryRun) { return '' }
            $r = Invoke-Reg @('load', $hive, $ntuser)
            if ($r.Code -ne 0) { return 'reg load failed: ' + $r.Output }
            $loaded = $true
        }
        $root = 'Registry::HKEY_USERS\' + $Sid + '\Software\Microsoft\Windows\CurrentVersion'
        $un = $root + '\Uninstall\Teams'
        if (Test-Path $un) {
            Write-Log ('    ' + $(if ($DryRun) { '[DRYRUN] Would remove ' } else { 'Removing ' }) + 'HKU\' + $Sid + '\...\Uninstall\Teams')
            if (-not $DryRun) { Remove-Item -Path $un -Recurse -Force -ErrorAction Stop }
        }
        $run = $root + '\Run'
        if ((Test-Path $run) -and ((Get-Item $run).GetValueNames() -contains $SquirrelRunValue)) {
            Write-Log ('    ' + $(if ($DryRun) { '[DRYRUN] Would remove ' } else { 'Removing ' }) + 'Run\' + $SquirrelRunValue)
            if (-not $DryRun) { Remove-ItemProperty -Path $run -Name $SquirrelRunValue -Force -ErrorAction Stop }
        }
        if (-not $DryRun -and ((Test-Path $un) -or ((Test-Path $run) -and ((Get-Item $run).GetValueNames() -contains $SquirrelRunValue)))) {
            return 'registry entries still present after delete'
        }
        return ''
    } catch {
        return 'registry cleanup failed: ' + $_
    } finally {
        if ($loaded) {
            [gc]::Collect()
            $u = Invoke-Reg @('unload', $hive)
            if ($u.Code -ne 0) { Write-Log ('    WARNING: reg unload ' + $hive + ' failed: ' + $u.Output) -Level WARN }
        }
    }
}

Write-Log '=============================================='
Write-Log ' Remove classic Microsoft Teams (v1)'
Write-Log (' Host   : ' + $env:COMPUTERNAME)
Write-Log (' DryRun : ' + $DryRun)
Write-Log '=============================================='

$failed = $false
$needsHuman = $false
$reboot = $false
$results = @()

$newTeams = @(Get-ChildItem -Path ($env:ProgramFiles + '\WindowsApps') -Directory -Filter 'MSTeams_*' -ErrorAction SilentlyContinue)
if ($env:ProgramW6432) { $newTeams += @(Get-ChildItem -Path ($env:ProgramW6432 + '\WindowsApps') -Directory -Filter 'MSTeams_*' -ErrorAction SilentlyContinue) }
if ($newTeams.Count -gt 0) { Write-Log ('New Teams is installed (' + (($newTeams | Select-Object -ExpandProperty Name -Unique) -join ', ') + ') -- not touched.') }
else { Write-Log 'New Teams (MSTeams) is not installed. Deploy it separately if this user still needs Teams.' -Level WARN }

Write-Log ''
Write-Log '[1/2] Teams Machine-Wide Installer'
$mwi = @(Get-MachineWideEntries)
if ($mwi.Count -eq 0) { Write-Log '  Not installed.' }
foreach ($e in $mwi) {
    Write-Log ('  Found ' + $MachineWideName + ' ' + $e.Version + ' ' + $e.Code + ' (' + $e.View + ')')
    if (-not $e.Code) {
        $results += 'FAILED   ' + $MachineWideName + ' ' + $e.Version + ' -- no product code in its uninstall entry'
        $failed = $true
        continue
    }
    if ($DryRun) { $results += 'DRYRUN   would uninstall ' + $MachineWideName + ' ' + $e.Version; continue }
    $msiLog = $LogDir + '\RemoveTeamsClassic_msi_' + $Stamp + '.log'
    $code = Invoke-MsiUninstall -ProductCode $e.Code -MsiLog $msiLog
    if ($code -eq 1618) {
        Write-Log '    Another installation is in progress; retrying in 60s.' -Level WARN
        Start-Sleep -Seconds 60
        $code = Invoke-MsiUninstall -ProductCode $e.Code -MsiLog $msiLog
    }
    $meaning = $(if ($code -eq -2) { 'UNKNOWN (no exit code)' } else { Get-MsiExitMeaning $code })
    Write-Log ('    msiexec exit: ' + $code + ' -- ' + $meaning + '  (log ' + $msiLog + ')')
    $still = @(Get-MachineWideEntries | Where-Object { $_.Code -eq $e.Code })
    if ($still.Count -eq 0) {
        $results += 'REMOVED  ' + $MachineWideName + ' ' + $e.Version
        if ($code -eq 3010 -or $code -eq 1641) { $reboot = $true }
    } else {
        $results += 'FAILED   ' + $MachineWideName + ' ' + $e.Version + ' -- still registered, msiexec ' + $meaning
        $failed = $true
    }
}
foreach ($v in (Remove-MachineRunValue)) { Write-Log ('  ' + $(if ($DryRun) { '[DRYRUN] Would remove' } else { 'Removed' }) + ' HKLM Run\' + $MachineRunValue + ' (' + $v + ')') }
foreach ($pf in @(${env:ProgramFiles(x86)}, $env:ProgramFiles, $env:ProgramW6432)) {
    if (-not $pf) { continue }
    $dir = $pf + '\Teams Installer'
    if (-not (Test-Path -LiteralPath $dir)) { continue }
    if ($DryRun) { $results += 'DRYRUN   would delete ' + $dir; continue }
    $err = Remove-PathVerified -Path $dir
    if ($err) { $results += 'FAILED   ' + $dir + ' -- ' + $err; $failed = $true }
    else { $results += 'REMOVED  ' + $dir }
}

Write-Log ''
Write-Log '[2/2] Per-user classic Teams'
$profiles = @(Get-UserProfiles)
Write-Log ('  ' + $profiles.Count + ' user profile(s).')
$foundAny = $false
foreach ($pr in $profiles) {
    $dirs = @(Get-ClassicTeamsDirs -ProfilePath $pr.Path -ProgramData $env:ProgramData | Where-Object { Test-Path -LiteralPath $_ })
    $links = @(Get-ClassicShortcuts -ProfilePath $pr.Path)
    # A signed-out profile with no Teams files is not loaded just to look
    # for leftover registry entries: Tenable reads files.
    $hasReg = Test-Path ('Registry::HKEY_USERS\' + $pr.Sid + '\Software\Microsoft\Windows\CurrentVersion\Uninstall\Teams')
    if ($dirs.Count -eq 0 -and $links.Count -eq 0 -and -not $hasReg) { continue }
    $foundAny = $true
    Write-Log ('  ' + $pr.Path + ' (' + $pr.Sid + ')')
    foreach ($d in $dirs) {
        $ver = Get-TeamsVersionIn -Dir $d
        Write-Log ('    ' + $d + $(if ($ver) { '  Teams ' + $ver } else { '' }))
        if ($DryRun) { $results += 'DRYRUN   would delete ' + $d + $(if ($ver) { ' (' + $ver + ')' } else { '' }); continue }
        foreach ($p in (Get-ProcessesIn -Dir $d)) {
            Write-Log ('    Stopping ' + $p.Name + ' (PID ' + $p.ProcessId + ')')
            Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
        }
        $err = Remove-PathVerified -Path $d
        if ($err) {
            Write-Log ('    Could not delete: ' + $err) -Level ERROR
            $results += 'FAILED   ' + $d + ' -- ' + $err
            $failed = $true
        } else {
            $results += 'REMOVED  ' + $d + $(if ($ver) { ' (' + $ver + ')' } else { '' })
        }
    }
    foreach ($l in $links) {
        if ($DryRun) { Write-Log ('    [DRYRUN] Would delete shortcut ' + $l); continue }
        $err = Remove-PathVerified -Path $l
        if ($err) { Write-Log ('    Could not delete shortcut ' + $l + ': ' + $err) -Level WARN }
        else { Write-Log ('    Deleted shortcut ' + $l) }
    }
    $regErr = Clear-UserRegistry -Sid $pr.Sid -ProfilePath $pr.Path
    if ($regErr) {
        Write-Log ('    ' + $regErr) -Level WARN
        $results += 'HELD     ' + $pr.Path + ' registry -- ' + $regErr
        $needsHuman = $true
    }
}
if (-not $foundAny) { Write-Log '  No classic Teams in any profile.' }

if (-not $DryRun) {
    Write-Log ''
    Write-Log 'Verifying...'
    foreach ($pr in $profiles) {
        foreach ($d in (Get-ClassicTeamsDirs -ProfilePath $pr.Path -ProgramData $env:ProgramData)) {
            if (Test-Path -LiteralPath ($d + '\current\Teams.exe')) {
                Write-Log ('  STILL PRESENT: ' + $d + '\current\Teams.exe') -Level ERROR
                $failed = $true
            }
        }
    }
    if (@(Get-MachineWideEntries).Count -gt 0) {
        Write-Log ('  STILL PRESENT: ' + $MachineWideName) -Level ERROR
        $failed = $true
    }
}

Write-Log ''
Write-Log '================ SUMMARY ================'
if ($results.Count -eq 0) { Write-Log '  Nothing to remove.' }
foreach ($r in $results) { Write-Log ('  ' + $r) }
if ($DryRun) {
    Write-Log 'RESULT: DRYRUN -- nothing was changed.'
    exit 0
}
$exitCode = Get-FinalExitCode -Failed $failed -NeedsHuman $needsHuman -Reboot $reboot
switch ($exitCode) {
    0       { Write-Log 'RESULT: no classic Teams left on this machine (verified).' }
    3010    { Write-Log 'RESULT: classic Teams removed; reboot required to finish the MSI uninstall.' }
    2       { Write-Log 'RESULT: classic Teams files removed; a profile hive could not be cleaned (see HELD).' }
    default { Write-Log 'RESULT: something could not be removed (see FAILED).' }
}
exit $exitCode
