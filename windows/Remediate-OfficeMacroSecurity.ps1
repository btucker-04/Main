<#
.SYNOPSIS
    Remediation: Office macro security settings
    Nessus Plugin IDs: 123459 (Untrusted Microsoft Office Macro Execution Enabled)
                       123461 (Microsoft Office Trust Access to VBA Project Model Object Enabled)

.DESCRIPTION
    Fixes the Trust Center > Macro Settings values Tenable flags, for every
    Office app and version that has them, in every place they can be set:

      Value        App       Flagged when           Set to
      AccessVBOM   any       nonzero                0   (123461: VBA project access off)
      VBAWarnings  any       1 (enable all macros)  2   (123459: disable with notification,
                                                         the Office default)
      Level        Outlook   1 (no security check)  2   (123459: Outlook's equivalent)

    VBAWarnings 3 (signed macros only) and 4 (disable all) are stricter than
    the default and are left alone.

    The values live under
        <hive>\SOFTWARE\Microsoft\Office\<ver>\<App>\Security            (user/app setting)
        <hive>\SOFTWARE\Policies\Microsoft\Office\<ver>\<App>\Security   (Group Policy / Intune)
    in HKLM (both registry views) and in every user hive. EC runs as SYSTEM, so
    the script walks every local profile from ProfileList, plus the Default
    profile that new accounts are copied from.

    IN-USE HIVES. reg load fails with a being-used-by-another-process error whenever
    a user's NTUSER.DAT is already loaded: the user is signed in, a previous
    script mounted it and never unloaded it, or the profile is loaded under a
    different key than its ProfileList SID. Windows records every loaded hive
    file and the key it is mounted at in
    HKLM\SYSTEM\CurrentControlSet\Control\hivelist, so the script looks the
    file up there and writes through whatever key already holds it. reg load is
    only used for hives that are not loaded anywhere.

    Setting values are fixed. Policy values are REPORTED and left alone by
    default: Group Policy or Intune re-applies them, so the fix belongs in that
    policy. -EnforcePolicy instead writes the safe value as a per-user policy
    for Office 16.0, which also greys out the options so users cannot change
    them back; a real GPO/Intune policy still overwrites it at its next refresh.

    Something usually turned these on deliberately -- an add-in that needs VBA
    project access, or a user told to enable all macros for a workbook. Fixing
    them can break that workflow; confirm with the user first.

.PARAMETER EnforcePolicy
    Also write per-user policy values (AccessVBOM 0, VBAWarnings 2, Outlook
    Level 2) for Office 16.0, overwriting any local policy value.

.PARAMETER DryRun
    Report what would change without writing anything.

.NOTES
    Deploy via Endpoint Central (SYSTEM), -File invocation, bare switches only.
    Log: C:\Logs\CompoSecure\OfficeMacroSecurity_<timestamp>.log
    Exit codes: 0 = nothing flagged remains
                2 = still flagged only where this script deliberately does not
                    write (a policy value, without -EnforcePolicy), or a profile
                    hive could not be opened -- fix the policy / reboot and retry
                1 = a write failed
#>
[CmdletBinding()]
param(
    [switch]$EnforcePolicy,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

$PolicyApps = @('Excel', 'Word', 'PowerPoint', 'Access', 'Outlook', 'Visio', 'Project', 'Publisher')
$EnforceVersion = '16.0'

function Get-MacroSettingNames {
    param([string]$App)
    $names = @('AccessVBOM', 'VBAWarnings')
    if ($App -eq 'Outlook') { $names += 'Level' }
    return $names
}

function Get-MacroSettingFixValue {
    param([string]$Name)
    switch ($Name) {
        'AccessVBOM'  { return 0 }
        'VBAWarnings' { return 2 }
        'Level'       { return 2 }
        default       { throw ('Unknown macro setting ' + $Name) }
    }
}

function Get-MacroSettingAction {
    # 'OK' (safe or absent), 'FIX' (write the safe value) or 'REPORT' (policy; needs a human).
    param([string]$Name, $Value, [bool]$IsPolicy, [bool]$EnforcePolicy)
    if ($null -eq $Value) { return 'OK' }
    $n = 0
    $parsed = [int]::TryParse(('' + $Value), [ref]$n)
    $flagged = $false
    switch ($Name) {
        'AccessVBOM'  { $flagged = (-not $parsed) -or ($n -ne 0) }
        'VBAWarnings' { $flagged = $parsed -and ($n -eq 1) }
        'Level'       { $flagged = $parsed -and ($n -eq 1) }
        default       { throw ('Unknown macro setting ' + $Name) }
    }
    if (-not $flagged) { return 'OK' }
    if ($IsPolicy -and -not $EnforcePolicy) { return 'REPORT' }
    return 'FIX'
}

function Get-OfficeBaseKeys {
    # Registry subtrees (relative to a hive root) that can hold Office macro settings.
    param([bool]$IsMachine)
    $bases = @(
        [pscustomobject]@{ Path = 'SOFTWARE\Microsoft\Office'; IsPolicy = $false },
        [pscustomobject]@{ Path = 'SOFTWARE\Policies\Microsoft\Office'; IsPolicy = $true }
    )
    if ($IsMachine) {
        $bases += [pscustomobject]@{ Path = 'SOFTWARE\WOW6432Node\Microsoft\Office'; IsPolicy = $false }
        $bases += [pscustomobject]@{ Path = 'SOFTWARE\WOW6432Node\Policies\Microsoft\Office'; IsPolicy = $true }
    }
    return $bases
}

function Select-UserProfiles {
    # ProfileList rows -> real local/domain user profiles (S-1-5-21-*), skipping
    # service accounts and profiles whose folder no longer exists.
    param([object[]]$Entries, [scriptblock]$PathExists)
    $out = @()
    foreach ($e in $Entries) {
        if ($e.Sid -notmatch '^S-1-5-21-[\d-]+$') { continue }
        if (-not $e.ProfilePath) { continue }
        if (-not (& $PathExists $e.ProfilePath)) { continue }
        $out += $e
    }
    return $out
}

function Find-LoadedHiveKey {
    # hivelist value name -> file, e.g.
    #   \REGISTRY\USER\TempHive = \Device\HarddiskVolume3\Users\asmith\NTUSER.DAT
    # Returns 'HKEY_USERS\<name>' for the key holding NtUserPath, or $null.
    param([hashtable]$HiveList, [string]$NtUserPath)
    $tail = ($NtUserPath -replace '^[A-Za-z]:', '')
    if (-not $tail.StartsWith('\')) { $tail = '\' + $tail }
    foreach ($name in ($HiveList.Keys | Sort-Object)) {
        $file = '' + $HiveList[$name]
        if (-not $file) { continue }
        if ($name -notmatch '^\\REGISTRY\\USER\\(.+)$') { continue }
        $sub = $matches[1]
        if ($file.EndsWith($tail, [StringComparison]::OrdinalIgnoreCase)) { return ('HKEY_USERS\' + $sub) }
    }
    return $null
}

if ($env:OFFICE_MACRO_DOTSOURCE -eq '1') { return }

$LogDir  = 'C:\Logs\CompoSecure'
$LogFile = $LogDir + '\OfficeMacroSecurity_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log'
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

$script:Fixed    = 0
$script:Reported = 0
$script:Failed   = 0
$script:Skipped  = 0

function Get-HiveList {
    $map = @{}
    $p = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\hivelist' -ErrorAction SilentlyContinue
    if ($p) {
        foreach ($prop in $p.PSObject.Properties) {
            if ($prop.Name -like '\REGISTRY\*') { $map[$prop.Name] = '' + $prop.Value }
        }
    }
    return $map
}

function Invoke-HiveRemediation {
    param([string]$HiveRoot, [string]$Label, [bool]$IsMachine)
    $found = 0
    foreach ($base in (Get-OfficeBaseKeys -IsMachine $IsMachine)) {
        $officeKey = $HiveRoot + '\' + $base.Path
        if (-not (Test-Path $officeKey)) { continue }
        $versions = @(Get-ChildItem $officeKey -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\d+\.0$' })
        foreach ($ver in $versions) {
            foreach ($app in (Get-ChildItem $ver.PSPath -ErrorAction SilentlyContinue)) {
                $sec = $app.PSPath + '\Security'
                if (-not (Test-Path $sec)) { continue }
                $props = Get-ItemProperty $sec -ErrorAction SilentlyContinue
                foreach ($name in (Get-MacroSettingNames -App $app.PSChildName)) {
                    $val = $null
                    if ($props -and ($props.PSObject.Properties.Name -contains $name)) { $val = $props.$name }
                    if ($null -eq $val) { continue }
                    $found++
                    $where = $base.Path + '\' + $ver.PSChildName + '\' + $app.PSChildName + '\Security\' + $name
                    $action = Get-MacroSettingAction -Name $name -Value $val -IsPolicy $base.IsPolicy -EnforcePolicy $EnforcePolicy
                    $fix = Get-MacroSettingFixValue -Name $name
                    switch ($action) {
                        'OK' { Write-Log ('  OK       ' + $where + ' = ' + $val) }
                        'REPORT' {
                            Write-Log ('  POLICY   ' + $where + ' = ' + $val) -Level WARN
                            Write-Log '           Set by Group Policy / Intune. Change that policy' -Level WARN
                            Write-Log '           (or re-run with -EnforcePolicy for a local override).' -Level WARN
                            $script:Reported++
                        }
                        'FIX' {
                            if ($DryRun) {
                                Write-Log ('  [DRYRUN] would set ' + $where + ' ' + $val + ' -> ' + $fix)
                                $script:Fixed++
                            } else {
                                try {
                                    Set-ItemProperty -Path $sec -Name $name -Value $fix -Type DWord -ErrorAction Stop
                                    Write-Log ('  FIXED    ' + $where + ' ' + $val + ' -> ' + $fix)
                                    $script:Fixed++
                                } catch {
                                    Write-Log ('  FAILED   ' + $where + ': ' + $_) -Level ERROR
                                    $script:Failed++
                                }
                            }
                        }
                        default { throw ('Unhandled action ' + $action) }
                    }
                }
            }
        }
    }

    if ($EnforcePolicy -and -not $IsMachine) {
        foreach ($app in $PolicyApps) {
            $sec = $HiveRoot + '\SOFTWARE\Policies\Microsoft\Office\' + $EnforceVersion + '\' + $app + '\Security'
            foreach ($name in (Get-MacroSettingNames -App $app)) {
                $fix = Get-MacroSettingFixValue -Name $name
                $cur = (Get-ItemProperty $sec -Name $name -ErrorAction SilentlyContinue).$name
                if ($null -ne $cur -and ('' + $cur) -eq ('' + $fix)) { continue }
                if ($DryRun) { Write-Log ('  [DRYRUN] would enforce policy ' + $app + ' ' + $EnforceVersion + ' ' + $name + '=' + $fix); continue }
                try {
                    if (-not (Test-Path $sec)) { New-Item -Path $sec -Force | Out-Null }
                    Set-ItemProperty -Path $sec -Name $name -Value $fix -Type DWord -ErrorAction Stop
                } catch {
                    Write-Log ('  FAILED   policy ' + $app + ' ' + $name + ': ' + $_) -Level ERROR
                    $script:Failed++
                }
            }
        }
        Write-Log ('  Policy values enforced for ' + ($PolicyApps -join ', ') + ' (' + $EnforceVersion + ').')
    }
    if ($found -eq 0) { Write-Log ('  No Office macro settings in ' + $Label + '.') }
}

function Invoke-UserHive {
    param([string]$Sid, [string]$ProfilePath, [string]$Label)
    Write-Log ''
    Write-Log ('--- ' + $Label + ' ---')
    if ($Sid -and (Test-Path ('Registry::HKEY_USERS\' + $Sid))) {
        Write-Log '  Hive loaded (user signed in) -- writing to it directly.'
        Invoke-HiveRemediation -HiveRoot ('Registry::HKEY_USERS\' + $Sid) -Label $Label -IsMachine $false
        return
    }
    $ntuser = $ProfilePath + '\NTUSER.DAT'
    if (-not (Test-Path -LiteralPath $ntuser)) {
        Write-Log ('  No NTUSER.DAT at ' + $ntuser + ' -- skipped.') -Level WARN
        return
    }
    $held = Find-LoadedHiveKey -HiveList (Get-HiveList) -NtUserPath $ntuser
    if ($held) {
        Write-Log ('  NTUSER.DAT is already loaded at ' + $held + ' -- writing through that key instead of reg load.')
        Invoke-HiveRemediation -HiveRoot ('Registry::' + $held) -Label $Label -IsMachine $false
        return
    }
    # A private mount name, not the SID: if the user signs in while it is
    # mounted, Windows must not find its own HKU\<SID> slot taken.
    $mount = 'CompoSecure_Macro_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    $out = & reg.exe load ('HKU\' + $mount) $ntuser 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log ('  Could not load ' + $ntuser + ': ' + ($out -join ' ')) -Level WARN
        Write-Log '  The file is locked but not listed in hivelist (an app or backup tool has it' -Level WARN
        Write-Log '  open). The next run after a reboot, or while the user is signed in, will reach it.' -Level WARN
        $script:Skipped++
        return
    }
    try {
        Invoke-HiveRemediation -HiveRoot ('Registry::HKEY_USERS\' + $mount) -Label $Label -IsMachine $false
    } finally {
        $unloaded = $false
        for ($i = 0; $i -lt 5 -and -not $unloaded; $i++) {
            [gc]::Collect()
            [gc]::WaitForPendingFinalizers()
            $null = & reg.exe unload ('HKU\' + $mount) 2>&1
            $unloaded = ($LASTEXITCODE -eq 0)
            if (-not $unloaded) { Start-Sleep -Seconds 1 }
        }
        if (-not $unloaded) { Write-Log ('  WARNING: could not unload HKU\' + $mount + '; it unloads at reboot.') -Level WARN }
    }
}

# --- main ---------------------------------------------------------------------
Write-Log '=============================================='
Write-Log ' Office macro security -- Plugins 123459 / 123461'
Write-Log (' Host          : ' + $env:COMPUTERNAME)
Write-Log (' Running as    : ' + [Security.Principal.WindowsIdentity]::GetCurrent().Name)
Write-Log (' -EnforcePolicy: ' + $EnforcePolicy)
Write-Log (' -DryRun       : ' + $DryRun)
Write-Log '=============================================='

$running = @(Get-Process -Name EXCEL, WINWORD, POWERPNT, MSACCESS, OUTLOOK -ErrorAction SilentlyContinue | ForEach-Object { $_.ProcessName } | Sort-Object -Unique)
if ($running.Count -gt 0) { Write-Log ('  Office running: ' + ($running -join ', ') + ' (registry change still applies; nothing is closed).') }

Write-Log ''
Write-Log '--- Machine (HKLM) ---'
Invoke-HiveRemediation -HiveRoot 'Registry::HKEY_LOCAL_MACHINE' -Label 'HKLM' -IsMachine $true

$plBase = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
$entries = @(Get-ChildItem $plBase -ErrorAction SilentlyContinue | ForEach-Object {
    [pscustomobject]@{
        Sid = $_.PSChildName
        ProfilePath = [Environment]::ExpandEnvironmentVariables(('' + (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ProfileImagePath))
    }
})
$profiles = @(Select-UserProfiles -Entries $entries -PathExists { param($p) Test-Path -LiteralPath $p })
foreach ($p in $profiles) {
    Invoke-UserHive -Sid $p.Sid -ProfilePath $p.ProfilePath -Label ('User ' + (Split-Path -Leaf $p.ProfilePath) + ' (' + $p.Sid + ')')
}

$defaultProfile = (Get-ItemProperty $plBase -ErrorAction SilentlyContinue).Default
if (-not $defaultProfile) { $defaultProfile = $env:SystemDrive + '\Users\Default' }
$defaultProfile = [Environment]::ExpandEnvironmentVariables($defaultProfile)
if (Test-Path -LiteralPath $defaultProfile) {
    Invoke-UserHive -Sid '' -ProfilePath $defaultProfile -Label 'Default profile (new accounts)'
}

Write-Log ''
Write-Log '=============================================='
Write-Log (' Fixed: ' + $script:Fixed + '   Policy (left): ' + $script:Reported + '   Hives skipped: ' + $script:Skipped + '   Failed: ' + $script:Failed)
if ($DryRun) { Write-Log ' DRY RUN -- nothing was changed.' }
Write-Log '=============================================='
if ($script:Failed -gt 0) { exit 1 }
if ($script:Reported -gt 0 -or $script:Skipped -gt 0) { exit 2 }
exit 0
