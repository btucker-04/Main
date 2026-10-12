<#
.SYNOPSIS
    Remediation: Microsoft Office Trust Access to VBA Project Model Object Enabled
    Nessus Plugin ID: 123461

.DESCRIPTION
    Turns off Trust Center > Macro Settings > Trust access to the VBA project
    object model (registry value AccessVBOM) for every Office app and version
    that has it on. With it on, any macro or add-in can read and rewrite the
    VBA code in documents, which is how macro malware spreads between files.

    AccessVBOM (DWORD, nonzero = on) lives under
        <hive>\SOFTWARE\Microsoft\Office\<ver>\<App>\Security            (user/app setting)
        <hive>\SOFTWARE\Policies\Microsoft\Office\<ver>\<App>\Security   (Group Policy / Intune)
    in HKLM (both registry views) and in every user hive. EC runs as SYSTEM, so
    the script walks every local profile from ProfileList, mounting NTUSER.DAT
    for users who are not signed in, plus the Default profile that new accounts
    are copied from.

    Setting values are set to 0. Policy values are REPORTED and left alone by
    default: Group Policy or Intune re-applies them, so the fix belongs in that
    policy. -EnforcePolicy instead writes a policy value of 0 for every user,
    which also greys out the checkbox so it cannot be ticked again; a real
    GPO/Intune policy will still overwrite it at the next refresh.

    Usually an add-in turned this on deliberately (reporting/ERP connectors,
    VBA-generating tools, document automation). Turning it off can break that
    add-in for the user -- confirm with them first.

    Office reads the setting when an add-in touches the VBA project, so a
    running Office app picks up the change without a restart in most cases;
    Tenable reads the registry, so the finding clears at the next scan either way.

.PARAMETER EnforcePolicy
    Also write SOFTWARE\Policies\...\<App>\Security\AccessVBOM = 0 in every user
    hive for Office 16.0, overwriting any local policy value of 1.

.PARAMETER DryRun
    Report what would change without writing anything.

.NOTES
    Deploy via Endpoint Central (SYSTEM), -File invocation, bare switches only.
    Log: C:\Logs\CompoSecure\OfficeVbomAccess_<timestamp>.log
    Exit codes: 0 = AccessVBOM is off everywhere
                2 = still on only where this script deliberately does not write
                    (a policy value, without -EnforcePolicy), or a profile hive
                    could not be loaded -- fix the policy / retry when signed out
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

function Get-VbomAction {
    # 'OK' (off or absent), 'DISABLE' (set it to 0) or 'REPORT' (leave it, needs a human).
    param($Value, [bool]$IsPolicy, [bool]$EnforcePolicy)
    if ($null -eq $Value) { return 'OK' }
    $n = 0
    if (-not [int]::TryParse(('' + $Value), [ref]$n)) { $n = 1 }
    if ($n -eq 0) { return 'OK' }
    if ($IsPolicy -and -not $EnforcePolicy) { return 'REPORT' }
    return 'DISABLE'
}

function Get-OfficeBaseKeys {
    # Registry subtrees (relative to a hive root) that can hold Office AccessVBOM values.
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

if ($env:OFFICE_VBOM_DOTSOURCE -eq '1') { return }

$LogDir  = 'C:\Logs\CompoSecure'
$LogFile = $LogDir + '\OfficeVbomAccess_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log'
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

$script:Disabled = 0
$script:Reported = 0
$script:Failed   = 0
$script:Skipped  = 0

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
                $val = (Get-ItemProperty $sec -Name AccessVBOM -ErrorAction SilentlyContinue).AccessVBOM
                $action = Get-VbomAction -Value $val -IsPolicy $base.IsPolicy -EnforcePolicy $EnforcePolicy
                if ($null -eq $val) { continue }
                $found++
                $where = $base.Path + '\' + $ver.PSChildName + '\' + $app.PSChildName + '\Security'
                switch ($action) {
                    'OK' { Write-Log ('  OK       ' + $where + '  AccessVBOM=' + $val) }
                    'REPORT' {
                        Write-Log ('  POLICY   ' + $where + '  AccessVBOM=' + $val) -Level WARN
                        Write-Log '           Set by Group Policy / Intune. Change that policy to Disabled' -Level WARN
                        Write-Log '           (or re-run with -EnforcePolicy for a local override).' -Level WARN
                        $script:Reported++
                    }
                    'DISABLE' {
                        if ($DryRun) {
                            Write-Log ('  [DRYRUN] would set ' + $where + '  AccessVBOM ' + $val + ' -> 0')
                            $script:Disabled++
                            continue
                        }
                        try {
                            Set-ItemProperty -Path $sec -Name AccessVBOM -Value 0 -Type DWord -ErrorAction Stop
                            Write-Log ('  DISABLED ' + $where + '  AccessVBOM ' + $val + ' -> 0')
                            $script:Disabled++
                        } catch {
                            Write-Log ('  FAILED   ' + $where + ': ' + $_) -Level ERROR
                            $script:Failed++
                        }
                    }
                    default { throw ('Unhandled action ' + $action) }
                }
            }
        }
    }

    if ($EnforcePolicy -and -not $IsMachine) {
        foreach ($app in $PolicyApps) {
            $sec = $HiveRoot + '\SOFTWARE\Policies\Microsoft\Office\' + $EnforceVersion + '\' + $app + '\Security'
            $cur = (Get-ItemProperty $sec -Name AccessVBOM -ErrorAction SilentlyContinue).AccessVBOM
            if ($null -ne $cur -and ('' + $cur) -eq '0') { continue }
            if ($DryRun) { Write-Log ('  [DRYRUN] would enforce policy ' + $app + ' ' + $EnforceVersion + ' AccessVBOM=0'); continue }
            try {
                if (-not (Test-Path $sec)) { New-Item -Path $sec -Force | Out-Null }
                Set-ItemProperty -Path $sec -Name AccessVBOM -Value 0 -Type DWord -ErrorAction Stop
            } catch {
                Write-Log ('  FAILED   policy ' + $app + ': ' + $_) -Level ERROR
                $script:Failed++
            }
        }
        Write-Log ('  Policy AccessVBOM=0 enforced for ' + ($PolicyApps -join ', ') + ' (' + $EnforceVersion + ').')
    }
    if ($found -eq 0) { Write-Log ('  No AccessVBOM values in ' + $Label + '.') }
}

function Invoke-UserHive {
    param([string]$Sid, [string]$ProfilePath, [string]$Label)
    Write-Log ''
    Write-Log ('--- ' + $Label + ' ---')
    $loadedRoot = 'Registry::HKEY_USERS\' + $Sid
    if ($Sid -and (Test-Path $loadedRoot)) {
        Invoke-HiveRemediation -HiveRoot $loadedRoot -Label $Label -IsMachine $false
        return
    }
    $ntuser = $ProfilePath + '\NTUSER.DAT'
    if (-not (Test-Path -LiteralPath $ntuser)) {
        Write-Log ('  No NTUSER.DAT at ' + $ntuser + ' -- skipped.') -Level WARN
        return
    }
    # A private mount name, not the SID: if the user signs in while it is
    # mounted, Windows must not find its own HKU\<SID> slot taken.
    $mount = 'CompoSecure_VBOM_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    $out = & reg.exe load ('HKU\' + $mount) $ntuser 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log ('  Could not load ' + $ntuser + ': ' + ($out -join ' ')) -Level WARN
        Write-Log '  (Usually the hive is in use by a process running as that user.)' -Level WARN
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
Write-Log ' Office VBA project object model access -- Plugin 123461'
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
Write-Log (' Disabled: ' + $script:Disabled + '   Policy (left): ' + $script:Reported + '   Hives skipped: ' + $script:Skipped + '   Failed: ' + $script:Failed)
if ($DryRun) { Write-Log ' DRY RUN -- nothing was changed.' }
Write-Log '=============================================='
if ($script:Failed -gt 0) { exit 1 }
if ($script:Reported -gt 0 -or $script:Skipped -gt 0) { exit 2 }
exit 0
