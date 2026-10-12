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
    only used for hives that are not loaded anywhere, and its failures are
    logged (with the hivelist contents) instead of stopping the run.

    LOCKED BY SOMETHING ELSE. If reg load still fails, the file is held open
    by a process outside the registry (CSPRLT-68, 2026-10-12: danielmora's
    NTUSER.DAT was locked but in no hivelist entry). The script then registers
    an Active Setup component (HKLM\SOFTWARE\Microsoft\Active Setup\Installed
    Components\CompoSecure-OfficeMacroSecurity). At each user's next sign-in,
    Windows runs the same fix once, as that user, against their own HKCU, before
    the desktop loads. The run still exits 2, because that user is not fixed yet.
    hivelist is checked again after a failed reg load, because another process
    can mount the hive in between (CSPRLT-68: HKU\{GUID}); if it has, the fix
    is written through that key instead.

    64-BIT. The EC agent runs scripts in 32-bit PowerShell, which sees
    HKLM\SOFTWARE redirected to WOW6432Node. The script relaunches itself in
    64-bit PowerShell so it reads 64-bit Office settings and writes Active Setup
    to the view Windows processes.

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

function Invoke-NativeCommand {
    # Windows PowerShell 5.1 turns a native command's stderr into a terminating
    # error under ErrorActionPreference Stop when 2>&1 is used, so run it under
    # Continue and hand the result back as data.
    param([string]$FilePath, [string[]]$Arguments)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = @(& $FilePath @Arguments 2>&1 | ForEach-Object { '' + $_ })
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prev
    }
    return [pscustomobject]@{ ExitCode = $code; Output = (Format-NativeOutput -Lines $out) }
}

function Format-NativeOutput {
    # 5.1 wraps each stderr line in an ErrorRecord and can add a bare
    # RemoteException record whose text is just the type name.
    param([string[]]$Lines)
    $keep = @($Lines | Where-Object { $_ -and $_.Trim() -and ($_.Trim() -ne 'System.Management.Automation.RemoteException') } | ForEach-Object { $_.Trim() })
    return ($keep -join ' ')
}

function Test-Needs64BitRelaunch {
    # A 32-bit process (the EC agent is 32-bit) sees HKLM\SOFTWARE redirected to
    # WOW6432Node, so it misses 64-bit Office settings and writes Active Setup
    # entries to the wrong view.
    param([bool]$Is64BitOS, [bool]$Is64BitProcess)
    return ($Is64BitOS -and -not $Is64BitProcess)
}

function Get-RelaunchArguments {
    param([string]$ScriptPath, [bool]$EnforcePolicy, [bool]$DryRun)
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $ScriptPath)
    if ($EnforcePolicy) { $a += '-EnforcePolicy' }
    if ($DryRun) { $a += '-DryRun' }
    return $a
}

function Get-LogonFixScript {
    # Runs as the user at sign-in (Active Setup), against their own HKCU. Same
    # rules as Get-MacroSettingAction for setting values; policy keys are not
    # user-writable and are left to the SYSTEM run.
    return @'
$ErrorActionPreference = 'SilentlyContinue'
$base = 'HKCU:\Software\Microsoft\Office'
foreach ($ver in @(Get-ChildItem $base | Where-Object { $_.PSChildName -match '^\d+\.0$' })) {
    foreach ($app in @(Get-ChildItem $ver.PSPath)) {
        $sec = $app.PSPath + '\Security'
        if (-not (Test-Path $sec)) { continue }
        $p = Get-ItemProperty $sec
        if ($null -ne $p.AccessVBOM -and ('' + $p.AccessVBOM) -ne '0') { Set-ItemProperty $sec -Name AccessVBOM -Value 0 -Type DWord }
        if (('' + $p.VBAWarnings) -eq '1') { Set-ItemProperty $sec -Name VBAWarnings -Value 2 -Type DWord }
        if ($app.PSChildName -eq 'Outlook' -and ('' + $p.Level) -eq '1') { Set-ItemProperty $sec -Name Level -Value 2 -Type DWord }
    }
}
'@
}

function Get-ActiveSetupStubPath {
    param([string]$Script)
    $b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Script))
    return ('powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand ' + $b64)
}

function Get-ActiveSetupVersion {
    # Active Setup re-runs a component for a user when HKLM's Version is higher
    # than the one recorded in their HKCU, so each staging gets a newer one.
    param([datetime]$Now)
    return ('' + $Now.Year + ',' + ($Now.Month * 100 + $Now.Day) + ',' + ($Now.Hour * 100 + $Now.Minute) + ',0')
}

if ($env:OFFICE_MACRO_DOTSOURCE -eq '1') { return }

if (Test-Needs64BitRelaunch -Is64BitOS ([Environment]::Is64BitOperatingSystem) -Is64BitProcess ([Environment]::Is64BitProcess)) {
    $ps64 = $env:WINDIR + '\Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $ps64) {
        $relaunchArgs = Get-RelaunchArguments -ScriptPath $PSCommandPath -EnforcePolicy $EnforcePolicy -DryRun $DryRun
        & $ps64 @relaunchArgs
        exit $LASTEXITCODE
    }
}

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
$script:SkippedUsers = @()
$ActiveSetupKey = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\CompoSecure-OfficeMacroSecurity'

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
    $load = Invoke-NativeCommand -FilePath 'reg.exe' -Arguments @('load', ('HKU\' + $mount), $ntuser)
    if ($load.ExitCode -ne 0) {
        Write-Log ('  Could not load ' + $ntuser + ': ' + $load.Output) -Level WARN
        # Another process can mount the hive between the first hivelist check and
        # reg load (CSPRLT-68: HKU\{GUID}, loaded by something else). Look again.
        $hl = Get-HiveList
        $held = Find-LoadedHiveKey -HiveList $hl -NtUserPath $ntuser
        if ($held) {
            Write-Log ('  Another process has it loaded at ' + $held + ' -- writing through that key.')
            Invoke-HiveRemediation -HiveRoot ('Registry::' + $held) -Label $Label -IsMachine $false
            return
        }
        Write-Log '  The file is locked, but not by the registry: no hivelist entry holds it.' -Level WARN
        Write-Log '  Loaded user hives right now:' -Level WARN
        foreach ($k in ($hl.Keys | Where-Object { $_ -like '\REGISTRY\USER\*' } | Sort-Object)) {
            Write-Log ('    ' + $k + ' = ' + $hl[$k]) -Level WARN
        }
        $script:Skipped++
        $script:SkippedUsers += $Label
        return
    }
    try {
        Invoke-HiveRemediation -HiveRoot ('Registry::HKEY_USERS\' + $mount) -Label $Label -IsMachine $false
    } finally {
        $unloaded = $false
        for ($i = 0; $i -lt 5 -and -not $unloaded; $i++) {
            [gc]::Collect()
            [gc]::WaitForPendingFinalizers()
            $unloaded = ((Invoke-NativeCommand -FilePath 'reg.exe' -Arguments @('unload', ('HKU\' + $mount))).ExitCode -eq 0)
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
Write-Log (' PowerShell    : ' + $(if ([Environment]::Is64BitProcess) { '64-bit' } else { '32-bit' }))
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

if ($script:SkippedUsers.Count -gt 0) {
    Write-Log ''
    Write-Log '--- Sign-in fallback for hives that could not be opened ---'
    foreach ($u in $script:SkippedUsers) { Write-Log ('  ' + $u) }
    $stub = Get-ActiveSetupStubPath -Script (Get-LogonFixScript)
    $asVer = Get-ActiveSetupVersion -Now (Get-Date)
    if ($DryRun) {
        Write-Log ('  [DRYRUN] would register Active Setup ' + $ActiveSetupKey + ' (Version ' + $asVer + ')')
    } else {
        try {
            if (-not (Test-Path $ActiveSetupKey)) { New-Item -Path $ActiveSetupKey -Force | Out-Null }
            Set-ItemProperty -Path $ActiveSetupKey -Name '(default)' -Value 'CompoSecure Office macro security' -ErrorAction Stop
            Set-ItemProperty -Path $ActiveSetupKey -Name StubPath -Value $stub -ErrorAction Stop
            Set-ItemProperty -Path $ActiveSetupKey -Name Version -Value $asVer -ErrorAction Stop
            Set-ItemProperty -Path $ActiveSetupKey -Name IsInstalled -Value 1 -Type DWord -ErrorAction Stop
            Write-Log ('  Registered Active Setup (Version ' + $asVer + '). At each user''s next sign-in,')
            Write-Log '  Windows runs the fix once as that user against their own registry, before'
            Write-Log '  the desktop loads. Re-run this script afterwards to confirm.'
        } catch {
            Write-Log ('  FAILED to register Active Setup: ' + $_) -Level ERROR
            $script:Failed++
        }
    }
}

Write-Log ''
Write-Log '=============================================='
Write-Log (' Fixed: ' + $script:Fixed + '   Policy (left): ' + $script:Reported + '   Hives skipped: ' + $script:Skipped + '   Failed: ' + $script:Failed)
if ($DryRun) { Write-Log ' DRY RUN -- nothing was changed.' }
Write-Log '=============================================='
if ($script:Failed -gt 0) { exit 1 }
if ($script:Reported -gt 0 -or $script:Skipped -gt 0) { exit 2 }
exit 0
