<#
.SYNOPSIS
    Updates the Microsoft Visual C++ 2015-2022 (v14) runtimes to Microsoft's
    latest, clears broken registrations that block the upgrade, and can
    remove the unsupported 2005-2013 runtimes.

.DESCRIPTION
    CSPRLT-94 (2026-10-26): Citrix Workspace exited 101603 because its VC++
    prerequisite could not upgrade 'Microsoft Visual C++ 2022 X86 Minimum
    Runtime - 14.42.34433': MSI Error 1714 (the older version cannot be
    removed) with System Error 1612 (the old version's cached .msi is gone).
    Every vc_redist upgrade, repair or uninstall fails the same way until
    that registration is cleared.

    Steps:
      1. Inventory every Visual C++ entry in Add/Remove Programs (64- and
         32-bit views), and every VC++ Windows Installer registration: is
         its cached .msi (LocalPackage) still on disk? For v14 bundles: is
         the Package Cache exe (BundleCachePath) still there?
      2. Broken v14 registrations are removed from the registry, after a
         reg export backup of every key touched, so the new installer runs
         as a fresh install. Only Windows Installer's bookkeeping goes: the
         runtime DLLs stay on disk and apps keep working. -SkipBrokenCleanup
         only reports them.
      3. Target: vc_redist.<arch>.exe staged beside this script or in C:\,
         else downloaded from https://aka.ms/vc14 (Microsoft's permalink
         for the latest v14; aka.ms/vs/17 stopped at the VS 2022 build
         14.44). No pinned version: the target is
         the file's own version. The file must have an MZ header and a Valid
         Authenticode signature from Microsoft Corporation.
      4. Installs for each architecture whose v14 runtime is below the
         target or whose broken registration was cleared. -InstallMissing
         also installs architectures that have no v14 runtime. Waits for
         Windows Installer to be idle first, and retries on 1618 (another
         install in progress), naming the installer processes holding it.
      5. Unsupported runtimes (2005, 2008, 2010, 2012, 2013) are listed.
         -RemoveUnsupported uninstalls them; any app built against them
         stops working, so use it only where Tenable flags them.
      6. Verify by re-reading Add/Remove Programs and the registrations,
         never by an installer's exit code. The version that counts is the
         Minimum Runtime MSI: a bundle entry can outlive a failed install.

.PARAMETER SkipBrokenCleanup
    Report broken registrations; do not remove them (the update for that
    architecture will then fail the same way).

.PARAMETER InstallMissing
    Also install the v14 runtime for architectures that have none
    (x86 and x64 on x64 Windows; plus arm64 on ARM64).

.PARAMETER RemoveUnsupported
    Uninstall Visual C++ 2005-2013 runtimes. One whose cached installer is
    missing has its registration cleared instead (its DLLs stay on disk).

.PARAMETER DryRun
    Report what would be done; change nothing (exit 2 when work is due).

.NOTES
    Deploy via Endpoint Central (SYSTEM; relaunches itself as 64-bit).
    Script Arguments: bare switches only, e.g. -RemoveUnsupported
    Specify exit code(s): 0,3010
    Dependency Files (optional, for offline or Zscaler-blocked hosts):
      vc_redist.x86.exe, vc_redist.x64.exe, vc_redist.arm64.exe
    Log: C:\Logs\CompoSecure\VCRedist_<timestamp>.log, installer logs beside it
    Backups: C:\Logs\CompoSecure\VCRedist_backup_<timestamp>\*.reg
             (undo a cleanup with: reg import <file>)
    Exit: 0    = every v14 runtime current, nothing broken left
          3010 = done, reboot needed
          2    = needs a human: dry run with work due, another install
                 was in progress (1618), or an unsupported removal failed
          1    = failed: no verified installer, an install or a cleanup failed
#>
[CmdletBinding()]
param(
    [switch]$SkipBrokenCleanup,
    [switch]$InstallMissing,
    [switch]$RemoveUnsupported,
    [switch]$DryRun
)

$VcRedistBaseUrl = 'https://aka.ms/vc14/vc_redist.'
$InstallTimeoutMinutes = 20
$IdleWaitMinutes = 10
$BusyAttempts = 3

# '14.42.34433', 'v14.42.34433.00' -> [version] with four parts; $null otherwise.
function ConvertTo-VcVersion {
    param([string]$Text)
    $t = ('' + $Text).Trim() -replace '^[vV]', ''
    if ($t -notmatch '^\d+(\.\d+){1,3}$') { return $null }
    $parts = @($t.Split('.') | ForEach-Object { [int]$_ })
    while ($parts.Count -lt 4) { $parts += 0 }
    return New-Object System.Version($parts[0], $parts[1], $parts[2], $parts[3])
}

# Add/Remove Programs name + version -> Year, Arch, Kind, Version, Major,
# Supported; $null when it is not a VC++ runtime (Debug Runtime is part of
# Visual Studio, not a redistributable).
#   'Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.42.34433'
#   'Microsoft Visual C++ 2022 X86 Minimum Runtime - 14.42.34433'
#   'Microsoft Visual C++ 2010  x64 Redistributable - 10.0.40219'
#   'Microsoft Visual C++ 2008 Redistributable - x86 9.0.30729.6161'
#   'Microsoft Visual C++ 2005 Redistributable'  (x86, version only in DisplayVersion)
function ConvertTo-VcEntry {
    param([string]$DisplayName, [string]$DisplayVersion)
    $n = ('' + $DisplayName).Trim()
    if ($n -notmatch '^Microsoft Visual C\+\+ (\d{4})(?:-(\d{4}))?\s') { return $null }
    $y1 = $Matches[1]; $y2 = $Matches[2]
    $year = [int]$(if ($y2) { $y2 } else { $y1 })
    if ($n -match '(?i)Debug Runtime') { return $null }
    $kind = ''
    if ($n -match '(?i)Minimum Runtime') { $kind = 'Minimum' }
    elseif ($n -match '(?i)Additional Runtime') { $kind = 'Additional' }
    elseif ($n -match '(?i)Redistributable') { $kind = 'Redistributable' }
    else { return $null }
    $arch = 'x86'
    if ($n -match '(?i)\b(x86|x64|arm64|ia64)\b') { $arch = $Matches[1].ToLowerInvariant() }
    $ver = ConvertTo-VcVersion $DisplayVersion
    if ($null -eq $ver -and $n -match '(\d+(?:\.\d+){1,3})\s*$') { $tail = $Matches[1]; $ver = ConvertTo-VcVersion $tail }
    $byYear = @{ 2005 = 8; 2008 = 9; 2010 = 10; 2012 = 11; 2013 = 12 }
    $major = $(if ($null -ne $ver) { $ver.Major } elseif ($byYear.ContainsKey($year)) { $byYear[$year] } else { 14 })
    return [pscustomobject]@{
        DisplayName = $n; Year = $year; Arch = $arch; Kind = $kind
        Version = $ver; Major = $major; Supported = ($major -ge 14)
    }
}

# Windows Installer packs GUIDs: each of the first three groups reversed,
# then every byte of the last two groups nibble-swapped. The transform is
# its own inverse.
function Convert-GuidHex {
    param([string]$Hex)
    $h = ('' + $Hex) -replace '[{}\-]', ''
    if ($h -notmatch '^[0-9A-Fa-f]{32}$') { return '' }
    $h = $h.ToUpperInvariant()
    $r = (-join ($h.Substring(0, 8).ToCharArray()[7..0])) + (-join ($h.Substring(8, 4).ToCharArray()[3..0])) + (-join ($h.Substring(12, 4).ToCharArray()[3..0]))
    for ($i = 16; $i -lt 32; $i += 2) { $r += $h[$i + 1]; $r += $h[$i] }
    return $r
}

function ConvertTo-PackedGuid {
    param([string]$Guid)
    if ($Guid -notmatch '^\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?$') { return '' }
    return Convert-GuidHex $Guid
}

function ConvertFrom-PackedGuid {
    param([string]$Packed)
    if ($Packed -notmatch '^[0-9A-Fa-f]{32}$') { return '' }
    $h = Convert-GuidHex $Packed
    return '{' + $h.Substring(0, 8) + '-' + $h.Substring(8, 4) + '-' + $h.Substring(12, 4) + '-' + $h.Substring(16, 4) + '-' + $h.Substring(20, 12) + '}'
}

function Get-VcInstallOutcome {
    # UNKNOWN: no exit code; the re-read decides.
    param($ExitCode)
    if ($null -eq $ExitCode -or ('' + $ExitCode) -eq '') { return 'UNKNOWN' }
    switch ([int]$ExitCode) {
        0       { return 'OK' }
        3010    { return 'REBOOT' }
        1641    { return 'REBOOT' }
        1638    { return 'NEWER' }
        1618    { return 'BUSY' }
        default { return 'FAIL' }
    }
}

function Get-VcExitMeaning {
    param($ExitCode)
    if ($null -eq $ExitCode -or ('' + $ExitCode) -eq '') { return '' }
    $t = @{
        1602 = 'cancelled'
        1603 = 'fatal error during installation'
        1612 = 'the installation source (cached installer) is not available'
        1618 = 'another installation is already in progress'
        1638 = 'another version of this product is already installed'
        1641 = 'success, a restart was started'
        1714 = 'the older version cannot be removed'
        3010 = 'success, restart required'
    }
    $c = [int]$ExitCode
    if ($t.ContainsKey($c)) { return ('' + $c + ': ' + $t[$c]) }
    return ''
}

# Error lines from a vc_redist (Burn + MSI) log, de-duplicated, at most $Max.
function Get-VcLogErrorLines {
    param([string]$Text, [int]$Max)
    if (-not $Text) { return @() }
    $out = @()
    foreach ($line in ($Text -split '\r?\n')) {
        $t = $line.Trim()
        if ($t -match '(?i)(\bError \d{4}\b|Return value 3\b|Installation (failed|operation failed)|error 0x8[0-9a-f]{7}|Failed to (install|execute|uninstall)|System Error \d+|Applied (execute|rollback) package: [^,]+, result: 0x0*[1-9a-f])') {
            if ($t.Length -gt 300) { $t = $t.Substring(0, 300) }
            if ($out -notcontains $t) { $out += $t }
            if ($out.Count -ge $Max) { break }
        }
    }
    return $out
}

# A cause in plain words from the log text, or ''.
function Get-VcLogHint {
    param([string]$Text)
    $t = '' + $Text
    if ($t -match '(?i)Error 1714' -and $t -match '(?i)System Error 1612') {
        return 'an older VC++ runtime cannot be removed because its cached installer is missing (1714 / 1612); run without -SkipBrokenCleanup'
    }
    if ($t -match '(?i)0x80070666') { return 'a newer version of this runtime is already installed (0x80070666)' }
    if ($t -match '(?i)0x80070652') { return 'another installation was in progress (0x80070652 / 1618)' }
    return ''
}

function Test-MicrosoftSigner {
    param([string]$Subject)
    return (('' + $Subject) -match '(^|,\s*)O=Microsoft Corporation\s*(,|$)')
}

function Get-VcArchsForOs {
    # PROCESSOR_ARCHITEW6432 is set only in a 32-bit process on 64-bit Windows.
    param([string]$ProcessorArchitecture, [string]$ProcessorArchitectureW6432)
    $p = $(if ($ProcessorArchitectureW6432) { $ProcessorArchitectureW6432 } else { $ProcessorArchitecture })
    switch (('' + $p).ToUpperInvariant()) {
        'AMD64' { return @('x86', 'x64') }
        'ARM64' { return @('x86', 'x64', 'arm64') }
        default { return @('x86') }
    }
}

# Newest installed v14 runtime per architecture: the Minimum Runtime MSI is
# the runtime itself; the bundle entry is the fallback unless -RuntimeOnly
# (a bundle stays registered when its MSIs failed, CSPRLT-94).
function Get-InstalledV14 {
    param([object[]]$Entries, [string]$Arch, [switch]$RuntimeOnly)
    $best = $null
    $kinds = $(if ($RuntimeOnly) { @('Minimum') } else { @('Minimum', 'Redistributable') })
    foreach ($kind in $kinds) {
        foreach ($e in $Entries) {
            if ($e.Arch -ne $Arch -or $e.Major -ne 14 -or $e.Kind -ne $kind -or $null -eq $e.Version) { continue }
            if ($null -eq $best -or $e.Version -gt $best) { $best = $e.Version }
        }
        if ($null -ne $best) { return $best }
    }
    return $null
}

# v14 bundle entries for an architecture with no Minimum Runtime MSI.
function Select-OrphanV14Bundles {
    param([object[]]$Entries)
    $withRuntime = @($Entries | Where-Object { $_.Major -eq 14 -and $_.Kind -eq 'Minimum' } | ForEach-Object { $_.Arch })
    return @($Entries | Where-Object { $_.Major -eq 14 -and $_.Kind -eq 'Redistributable' -and $withRuntime -notcontains $_.Arch })
}

# Running installers that can hold the Windows Installer lock (1618):
# msiexec clients and custom-action hosts (not the idle service, /V),
# and setup bootstrappers. Objects need Name, ProcessId, CommandLine.
function Select-InstallerProcesses {
    param([object[]]$Processes, [int]$ExcludePid)
    $out = @()
    foreach ($p in $Processes) {
        if ($p.ProcessId -eq $ExcludePid) { continue }
        $n = '' + $p.Name
        $c = '' + $p.CommandLine
        if ($n -ieq 'msiexec.exe') {
            if ($c -match '(?i)\s[/-]V\s*$') { continue }
            $out += $p
        } elseif ($n -match '(?i)(vc_?redist|setup|install|TrolleyExpress|CitrixWorkspaceApp)') {
            $out += $p
        }
    }
    return $out
}

# Registrations to clear: VC++ runtime MSIs whose cached .msi is gone, and
# v14 bundles whose cached exe is gone. Pre-v14 only with -RemoveUnsupported.
function Select-BrokenVcRegistrations {
    param([object[]]$Products, [object[]]$Bundles, [bool]$IncludeUnsupported)
    $out = @()
    foreach ($p in $Products) {
        if ($p.CacheOk) { continue }
        if ($p.Major -ge 14 -or $IncludeUnsupported) { $out += [pscustomobject]@{ Type = 'msi'; Item = $p } }
    }
    foreach ($b in $Bundles) {
        if ($b.Kind -ne 'Redistributable' -or $b.Major -ne 14 -or -not $b.BundleCachePath -or $b.CacheOk) { continue }
        $out += [pscustomobject]@{ Type = 'bundle'; Item = $b }
    }
    return $out
}

# Which architectures get an install: registration cleared, bundle without
# its runtime MSI, below target, or (with -InstallMissing) absent.
# Objects: Arch, From, To, Reason.
function Get-VcInstallPlan {
    param([string[]]$Archs, [hashtable]$Installed, [hashtable]$Target, [string[]]$Cleared, [bool]$InstallMissing, [string[]]$Orphaned = @())
    $plan = @()
    foreach ($a in $Archs) {
        if (-not $Target.ContainsKey($a) -or $null -eq $Target[$a]) { continue }
        $have = $Installed[$a]
        $reason = ''
        if ($Cleared -contains $a) { $reason = 'broken registration cleared' }
        elseif ($Orphaned -contains $a) { $reason = 'bundle registered without its runtime' }
        elseif ($null -ne $have -and $have -lt $Target[$a]) { $reason = 'below target' }
        elseif ($null -eq $have -and $InstallMissing) { $reason = 'not installed (-InstallMissing)' }
        if ($reason) { $plan += [pscustomobject]@{ Arch = $a; From = $have; To = $Target[$a]; Reason = $reason } }
    }
    return $plan
}

function Get-FinalExitCode {
    param([bool]$Failed, [bool]$NeedsHuman, [bool]$Reboot)
    if ($Failed) { return 1 }
    if ($NeedsHuman) { return 2 }
    if ($Reboot) { return 3010 }
    return 0
}

function Test-Needs64BitRelaunch {
    param([bool]$Is64BitOS, [bool]$Is64BitProcess)
    return ($Is64BitOS -and -not $Is64BitProcess)
}

function Get-RelaunchArguments {
    param([string]$ScriptPath, [hashtable]$Bound)
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $ScriptPath)
    foreach ($k in ($Bound.Keys | Sort-Object)) {
        $v = $Bound[$k]
        if ($v -is [System.Management.Automation.SwitchParameter]) {
            if ($v.IsPresent) { $a += ('-' + $k) }
        } elseif ($null -ne $v -and ('' + $v) -ne '') {
            $a += @(('-' + $k), ('' + $v))
        }
    }
    return $a
}

if ($env:VCREDIST_UPDATE_DOTSOURCE -eq '1') { return }

# -----------------------------------------------------------------------------
$ErrorActionPreference = 'Stop'

if (Test-Needs64BitRelaunch -Is64BitOS ([Environment]::Is64BitOperatingSystem) -Is64BitProcess ([Environment]::Is64BitProcess)) {
    $ps64 = $env:WINDIR + '\Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $ps64) {
        $relaunchArgs = Get-RelaunchArguments -ScriptPath $PSCommandPath -Bound $PSBoundParameters
        & $ps64 @relaunchArgs
        exit $LASTEXITCODE
    }
}

$Stamp     = Get-Date -Format 'yyyyMMdd_HHmmss'
$LogDir    = 'C:\Logs\CompoSecure'
$LogFile   = Join-Path $LogDir ('VCRedist_' + $Stamp + '.log')
$BackupDir = Join-Path $LogDir ('VCRedist_backup_' + $Stamp)
$TempDir   = Join-Path $env:WINDIR 'Temp\VCRedist_Update'
$Q = [string][char]34
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}
$Issues = New-Object System.Collections.ArrayList
function Add-Issue {
    param([string]$Msg, [switch]$Fail)
    [void]$Issues.Add($Msg)
    if ($Fail) { $script:Failed = $true; Write-Log ('  PROBLEM: ' + $Msg) -Level ERROR }
    else { $script:NeedsHuman = $true; Write-Log ('  PROBLEM: ' + $Msg) -Level WARN }
}
$Failed = $false
$NeedsHuman = $false
$Reboot = $false

$UninstallPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
$UserDataPath  = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18'

function Open-Hklm {
    param([Microsoft.Win32.RegistryView]$View)
    return [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $View)
}

function Get-VcArpEntries {
    $out = @()
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
        $base = Open-Hklm $view
        $un = $base.OpenSubKey($UninstallPath)
        if ($null -eq $un) { $base.Close(); continue }
        foreach ($name in $un.GetSubKeyNames()) {
            $k = $un.OpenSubKey($name)
            if ($null -eq $k) { continue }
            $e = ConvertTo-VcEntry -DisplayName ('' + $k.GetValue('DisplayName')) -DisplayVersion ('' + $k.GetValue('DisplayVersion'))
            if ($e) {
                $cache = '' + $k.GetValue('BundleCachePath')
                $e | Add-Member -NotePropertyName Key -NotePropertyValue $name
                $e | Add-Member -NotePropertyName View -NotePropertyValue $view
                $e | Add-Member -NotePropertyName SystemComponent -NotePropertyValue (('' + $k.GetValue('SystemComponent')) -eq '1')
                $e | Add-Member -NotePropertyName IsMsi -NotePropertyValue (('' + $k.GetValue('WindowsInstaller')) -eq '1')
                $e | Add-Member -NotePropertyName BundleCachePath -NotePropertyValue $cache
                $e | Add-Member -NotePropertyName CacheOk -NotePropertyValue ($cache -and (Test-Path -LiteralPath $cache))
                $out += $e
            }
            $k.Close()
        }
        $un.Close(); $base.Close()
    }
    return $out
}

function Get-VcMsiRegistrations {
    $out = @()
    $base = Open-Hklm ([Microsoft.Win32.RegistryView]::Registry64)
    $prods = $base.OpenSubKey($UserDataPath + '\Products')
    if ($null -ne $prods) {
        foreach ($packed in $prods.GetSubKeyNames()) {
            $ip = $prods.OpenSubKey($packed + '\InstallProperties')
            if ($null -eq $ip) { continue }
            $e = ConvertTo-VcEntry -DisplayName ('' + $ip.GetValue('DisplayName')) -DisplayVersion ('' + $ip.GetValue('DisplayVersion'))
            if ($e) {
                $lp = '' + $ip.GetValue('LocalPackage')
                $e | Add-Member -NotePropertyName Packed -NotePropertyValue $packed
                $e | Add-Member -NotePropertyName ProductCode -NotePropertyValue (ConvertFrom-PackedGuid $packed)
                $e | Add-Member -NotePropertyName LocalPackage -NotePropertyValue $lp
                $e | Add-Member -NotePropertyName CacheOk -NotePropertyValue ($lp -and (Test-Path -LiteralPath $lp))
                $out += $e
            }
            $ip.Close()
        }
        $prods.Close()
    }
    $base.Close()
    return $out
}

function Format-VcVersion {
    param($Version)
    if ($null -eq $Version) { return 'none' }
    return ('' + $Version)
}

function Invoke-Native {
    # Exit code and output as data: native stderr must not become a
    # terminating error under Stop in Windows PowerShell 5.1.
    param([string]$Path, [string[]]$Arguments)
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $o = & $Path @Arguments 2>&1 | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] -or $_.Exception.Message } | ForEach-Object { '' + $_ }
        return [pscustomobject]@{ Code = $LASTEXITCODE; Output = (@($o) -join ' ') }
    } finally { $ErrorActionPreference = $old }
}

$BackupCount = 0
function Backup-RegKey {
    param([string]$Path, [Microsoft.Win32.RegistryView]$View)
    if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null }
    $script:BackupCount++
    $file = Join-Path $BackupDir (('{0:D3}' -f $script:BackupCount) + '_' + (($Path -split '\\')[-1]) + '.reg')
    $flag = $(if ($View -eq [Microsoft.Win32.RegistryView]::Registry32) { '/reg:32' } else { '/reg:64' })
    $r = Invoke-Native -Path ($env:WINDIR + '\System32\reg.exe') -Arguments @('export', ('HKLM\' + $Path), $file, '/y', $flag)
    if ($r.Code -ne 0 -or -not (Test-Path -LiteralPath $file)) {
        Write-Log ('  Backup of HKLM\' + $Path + ' failed: ' + $r.Output) -Level ERROR
        return $false
    }
    return $true
}

function Test-RegKey {
    param([string]$Path, [Microsoft.Win32.RegistryView]$View)
    $base = Open-Hklm $View
    $k = $base.OpenSubKey($Path)
    $found = ($null -ne $k)
    if ($found) { $k.Close() }
    $base.Close()
    return $found
}

# Keys under $Parent holding a value named $Name (UpgradeCodes, Components).
function Find-KeysWithValue {
    param([string]$Parent, [string[]]$Names)
    $hits = @()
    $base = Open-Hklm ([Microsoft.Win32.RegistryView]::Registry64)
    $p = $base.OpenSubKey($Parent)
    if ($null -ne $p) {
        foreach ($sub in $p.GetSubKeyNames()) {
            $k = $p.OpenSubKey($sub)
            if ($null -eq $k) { continue }
            $vals = $k.GetValueNames()
            foreach ($n in $Names) { if ($vals -contains $n) { $hits += [pscustomobject]@{ Path = ($Parent + '\' + $sub); Name = $n } } }
            $k.Close()
        }
        $p.Close()
    }
    $base.Close()
    return $hits
}

# Clear one product's Windows Installer registration. Every key is exported
# first; nothing is deleted unless all backups succeeded.
function Remove-MsiRegistration {
    param($Product, [object[]]$UpgradeHits, [object[]]$ComponentHits)
    $v64 = [Microsoft.Win32.RegistryView]::Registry64
    $v32 = [Microsoft.Win32.RegistryView]::Registry32
    $keys = @()
    foreach ($p in @(('SOFTWARE\Classes\Installer\Products\' + $Product.Packed), ('SOFTWARE\Classes\Installer\Features\' + $Product.Packed), ($UserDataPath + '\Products\' + $Product.Packed))) {
        if (Test-RegKey -Path $p -View $v64) { $keys += [pscustomobject]@{ Path = $p; View = $v64 } }
    }
    foreach ($v in @($v64, $v32)) {
        $p = $UninstallPath + '\' + $Product.ProductCode
        if (Test-RegKey -Path $p -View $v) { $keys += [pscustomobject]@{ Path = $p; View = $v } }
    }
    $values = @($UpgradeHits + $ComponentHits | Where-Object { $_.Name -eq $Product.Packed })
    foreach ($k in $keys) { if (-not (Backup-RegKey -Path $k.Path -View $k.View)) { return $false } }
    foreach ($p in @($values | ForEach-Object { $_.Path } | Select-Object -Unique)) { if (-not (Backup-RegKey -Path $p -View $v64)) { return $false } }
    try {
        foreach ($k in $keys) {
            $base = Open-Hklm $k.View
            $base.DeleteSubKeyTree($k.Path, $false)
            $base.Close()
        }
        $base = Open-Hklm $v64
        foreach ($val in $values) {
            $key = $base.OpenSubKey($val.Path, $true)
            if ($null -eq $key) { continue }
            $key.DeleteValue($val.Name, $false)
            $left = $key.ValueCount + $key.SubKeyCount
            $key.Close()
            if ($val.Path -like 'SOFTWARE\Classes\Installer\UpgradeCodes\*' -and $left -eq 0) { $base.DeleteSubKeyTree($val.Path, $false) }
        }
        $base.Close()
    } catch {
        Write-Log ('  Registry delete failed: ' + $_) -Level ERROR
        return $false
    }
    Write-Log ('  Cleared: ' + $keys.Count + ' key(s), ' + $values.Count + ' value(s)')
    return $true
}

function Remove-BundleRegistration {
    param($Bundle)
    $p = $UninstallPath + '\' + $Bundle.Key
    if (-not (Backup-RegKey -Path $p -View $Bundle.View)) { return $false }
    try {
        $base = Open-Hklm $Bundle.View
        $base.DeleteSubKeyTree($p, $false)
        $base.Close()
    } catch {
        Write-Log ('  Registry delete failed: ' + $_) -Level ERROR
        return $false
    }
    return $true
}

function Find-StagedVcRedist {
    param([string]$Arch)
    $dirs = @()
    if ($PSScriptRoot) { $dirs += $PSScriptRoot }
    $dirs += 'C:\'
    foreach ($d in $dirs) {
        $f = Join-Path $d ('vc_redist.' + $Arch + '.exe')
        if (Test-Path -LiteralPath $f) { return $f }
    }
    return ''
}

function Invoke-Download {
    param([string]$Url, [string]$Dest)
    foreach ($attempt in 1..3) {
        try {
            Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing -TimeoutSec 300
            return $true
        } catch {
            Write-Log ('  Download attempt ' + $attempt + ' of 3 failed: ' + $_) -Level WARN
            Start-Sleep -Seconds 10
        }
    }
    return $false
}

# Path to a verified vc_redist for $Arch and its version, or $null.
function Get-VerifiedVcRedist {
    param([string]$Arch)
    $path = Find-StagedVcRedist -Arch $Arch
    $downloaded = $false
    if ($path) {
        Write-Log ('  ' + $Arch + ': staged ' + $path)
    } else {
        if (-not (Test-Path $TempDir)) { New-Item -ItemType Directory -Path $TempDir -Force | Out-Null }
        $path = Join-Path $TempDir ('vc_redist.' + $Arch + '.exe')
        $url = $VcRedistBaseUrl + $Arch + '.exe'
        Write-Log ('  ' + $Arch + ': downloading ' + $url)
        if (-not (Invoke-Download -Url $url -Dest $path)) {
            Write-Log ('  ' + $Arch + ': download failed. Stage vc_redist.' + $Arch + '.exe beside this script if aka.ms is blocked.') -Level ERROR
            return $null
        }
        $downloaded = $true
    }
    $ok = $false
    try {
        $fs = [System.IO.File]::OpenRead($path)
        $b0 = $fs.ReadByte(); $b1 = $fs.ReadByte(); $len = $fs.Length
        $fs.Close()
        $ok = ($b0 -eq 0x4D -and $b1 -eq 0x5A -and $len -gt 5MB)
    } catch { }
    if (-not $ok) {
        Write-Log ('  ' + $Arch + ': ' + $path + ' is not an installer (block page?). Not running it.') -Level ERROR
        if ($downloaded) { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
        return $null
    }
    $status = 'Error'; $subject = ''
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $path
        $status = '' + $sig.Status
        if ($sig.SignerCertificate) { $subject = $sig.SignerCertificate.Subject }
    } catch { Write-Log ('  Signature check failed to run: ' + $_) -Level ERROR }
    if ($status -ne 'Valid' -or -not (Test-MicrosoftSigner $subject)) {
        Write-Log ('  ' + $Arch + ': signature ' + $status + ' ' + $subject + ' -- not Microsoft. Not running it.') -Level ERROR
        if ($downloaded) { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
        return $null
    }
    $ver = ConvertTo-VcVersion ((Get-Item -LiteralPath $path).VersionInfo.ProductVersion)
    if ($null -eq $ver -or $ver.Major -ne 14) {
        Write-Log ('  ' + $Arch + ': unexpected version ' + (Get-Item -LiteralPath $path).VersionInfo.ProductVersion + '. Not running it.') -Level ERROR
        return $null
    }
    Write-Log ('  ' + $Arch + ': ' + $ver + '  (signed by Microsoft Corporation)')
    return [pscustomobject]@{ Path = $path; Version = $ver; Downloaded = $downloaded }
}

function Invoke-Bounded {
    param([string]$Path, [string]$Arguments, [int]$TimeoutMinutes)
    Write-Log ('  Running: ' + $Path + ' ' + $Arguments)
    $p = Start-Process -FilePath $Path -ArgumentList $Arguments -NoNewWindow -PassThru
    $null = $p.Handle
    if (-not $p.WaitForExit($TimeoutMinutes * 60 * 1000)) {
        Write-Log ('  Still running after ' + $TimeoutMinutes + ' minutes; killing the installer tree.') -Level ERROR
        & ($env:WINDIR + '\System32\taskkill.exe') '/PID' $p.Id '/T' '/F' 2>&1 | Out-Null
        return $null
    }
    $p.WaitForExit()
    return $p.ExitCode
}

function Write-InstallLogErrors {
    param([string]$LogBase)
    $text = ''
    foreach ($f in @(Get-ChildItem -LiteralPath $LogDir -File -Filter ((Split-Path $LogBase -Leaf) -replace '\.log$', '*.log') -ErrorAction SilentlyContinue | Sort-Object LastWriteTime)) {
        $t = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction SilentlyContinue
        $lines = @(Get-VcLogErrorLines -Text $t -Max 6)
        if ($lines.Count -gt 0) {
            Write-Log ('  ' + $f.Name + ':') -Level ERROR
            foreach ($l in $lines) { Write-Log ('    ' + $l) -Level ERROR }
        }
        $text += $t
    }
    return (Get-VcLogHint -Text $text)
}

# Windows Installer holds Global\_MSIExecute while any install runs.
function Test-MsiBusy {
    $m = $null
    try {
        if ([System.Threading.Mutex]::TryOpenExisting('Global\_MSIExecute', [ref]$m)) { $m.Dispose(); return $true }
        return $false
    } catch [System.UnauthorizedAccessException] {
        return $true
    } catch {
        return $false
    }
}

function Get-InstallerProcessText {
    $procs = @()
    try { $procs = @(Get-CimInstance Win32_Process -ErrorAction Stop | Select-Object Name, ProcessId, CommandLine) } catch { return '(process list unavailable)' }
    $hits = @(Select-InstallerProcesses -Processes $procs -ExcludePid $PID)
    if ($hits.Count -eq 0) { return 'none found' }
    return (($hits | ForEach-Object {
        $c = '' + $_.CommandLine
        if ($c.Length -gt 160) { $c = $c.Substring(0, 160) + '...' }
        $_.Name + ' (' + $_.ProcessId + ')' + $(if ($c) { ' ' + $c } else { '' })
    }) -join '; ')
}

# $true once Windows Installer is idle; $false after $Minutes.
function Wait-InstallerIdle {
    param([int]$Minutes)
    if (-not (Test-MsiBusy)) { return $true }
    Write-Log ('  Windows Installer is busy: ' + (Get-InstallerProcessText)) -Level WARN
    Write-Log ('  Waiting up to ' + $Minutes + ' minutes for it to finish...')
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalMinutes -lt $Minutes) {
        Start-Sleep -Seconds 15
        if (-not (Test-MsiBusy)) { Write-Log ('  Windows Installer idle after ' + [int]$sw.Elapsed.TotalSeconds + 's.'); return $true }
    }
    Write-Log ('  Still busy after ' + $Minutes + ' minutes: ' + (Get-InstallerProcessText)) -Level WARN
    return $false
}

function Get-DllVersion {
    param([string]$Path)
    try {
        $vi = (Get-Item -LiteralPath $Path -ErrorAction Stop).VersionInfo
        return ('' + $vi.FileMajorPart + '.' + $vi.FileMinorPart + '.' + $vi.FileBuildPart + '.' + $vi.FilePrivatePart)
    } catch { return 'missing' }
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Archs = @(Get-VcArchsForOs -ProcessorArchitecture $env:PROCESSOR_ARCHITECTURE -ProcessorArchitectureW6432 $env:PROCESSOR_ARCHITEW6432)

Write-Log '=============================================='
Write-Log ' Visual C++ runtimes: update v14, clear broken registrations'
Write-Log (' Host    : ' + $env:COMPUTERNAME + '   architectures: ' + ($Archs -join ', '))
Write-Log (' Options : SkipBrokenCleanup=' + $SkipBrokenCleanup + ' InstallMissing=' + $InstallMissing + ' RemoveUnsupported=' + $RemoveUnsupported + ' DryRun=' + $DryRun)
Write-Log '=============================================='

# ---- 1. Inventory -----------------------------------------------------------
Write-Log '[1] Installed Visual C++ runtimes'
$arp = @(Get-VcArpEntries)
$msi = @(Get-VcMsiRegistrations)
foreach ($e in ($arp | Sort-Object Year, Arch, DisplayName)) {
    $flags = @()
    if ($e.SystemComponent) { $flags += 'component' }
    if (-not $e.Supported) { $flags += 'UNSUPPORTED' }
    if ($e.BundleCachePath -and -not $e.CacheOk) { $flags += 'CACHED EXE MISSING' }
    Write-Log ('  ' + $e.DisplayName + '  [' + (Format-VcVersion $e.Version) + ']' + $(if ($flags.Count) { '  (' + ($flags -join ', ') + ')' } else { '' }))
}
if ($arp.Count -eq 0) { Write-Log '  None in Add/Remove Programs.' }
foreach ($p in ($msi | Where-Object { -not $_.CacheOk })) {
    Write-Log ('  Windows Installer: ' + $p.DisplayName + '  ' + $p.ProductCode + '  cached .msi MISSING (' + $(if ($p.LocalPackage) { $p.LocalPackage } else { 'none recorded' }) + ')') -Level WARN
}
$installed = @{}
foreach ($a in $Archs) { $installed[$a] = Get-InstalledV14 -Entries $arp -Arch $a }
foreach ($a in $Archs) { Write-Log ('  v14 runtime ' + $a + ' : ' + (Format-VcVersion $installed[$a])) }
foreach ($o in (Select-OrphanV14Bundles -Entries $arp)) {
    Write-Log ('  ' + $o.DisplayName + ' is registered, but no ' + $o.Arch + ' Minimum Runtime MSI is installed (a failed earlier install)') -Level WARN
}
$sysDll = $env:WINDIR + '\System32\vcruntime140.dll'
$wowDll = $env:WINDIR + '\SysWOW64\vcruntime140.dll'
function Write-DllVersions {
    if ([Environment]::Is64BitOperatingSystem) {
        Write-Log ('  vcruntime140.dll  x64: ' + (Get-DllVersion $sysDll) + '   x86: ' + (Get-DllVersion $wowDll))
    } else {
        Write-Log ('  vcruntime140.dll  x86: ' + (Get-DllVersion $sysDll))
    }
}
Write-DllVersions

# ---- 2. Broken registrations -----------------------------------------------
Write-Log '[2] Broken registrations'
$broken = @(Select-BrokenVcRegistrations -Products $msi -Bundles $arp -IncludeUnsupported ([bool]$RemoveUnsupported))
$cleared = @()
if ($broken.Count -eq 0) {
    Write-Log '  None.'
} else {
    foreach ($b in $broken) { Write-Log ('  ' + $b.Type + ': ' + $b.Item.DisplayName + $(if ($b.Type -eq 'msi') { '  ' + $b.Item.ProductCode } else { '  ' + $b.Item.BundleCachePath })) -Level WARN }
    if ($SkipBrokenCleanup) {
        Add-Issue ('' + $broken.Count + ' broken VC++ registration(s) left in place (-SkipBrokenCleanup); upgrades of those runtimes fail with 1714 / 1612')
    } elseif ($DryRun) {
        Write-Log '  [DRYRUN] Would back up and clear them.'
        $NeedsHuman = $true
        foreach ($b in $broken) { if ($b.Item.Major -eq 14 -and $cleared -notcontains $b.Item.Arch) { $cleared += $b.Item.Arch } }
    } else {
        $packedNames = @($broken | Where-Object { $_.Type -eq 'msi' } | ForEach-Object { $_.Item.Packed })
        $upHits = @(); $compHits = @()
        if ($packedNames.Count -gt 0) {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $upHits = @(Find-KeysWithValue -Parent 'SOFTWARE\Classes\Installer\UpgradeCodes' -Names $packedNames)
            $compHits = @(Find-KeysWithValue -Parent ($UserDataPath + '\Components') -Names $packedNames)
            Write-Log ('  Found ' + $upHits.Count + ' upgrade-code and ' + $compHits.Count + ' component reference(s) in ' + [int]$sw.Elapsed.TotalSeconds + 's.')
        }
        foreach ($b in $broken) {
            Write-Log ('  Clearing ' + $b.Item.DisplayName)
            $ok = $(if ($b.Type -eq 'msi') { Remove-MsiRegistration -Product $b.Item -UpgradeHits $upHits -ComponentHits $compHits } else { Remove-BundleRegistration -Bundle $b.Item })
            if (-not $ok) { Add-Issue ('could not clear the registration of ' + $b.Item.DisplayName + ' (nothing deleted without a backup)') -Fail; continue }
            if ($b.Item.Major -eq 14 -and $cleared -notcontains $b.Item.Arch) { $cleared += $b.Item.Arch }
        }
        if (Test-Path $BackupDir) { Write-Log ('  Backups: ' + $BackupDir + '  (undo: reg import <file>)') }
        $arp = @(Get-VcArpEntries)
        $msi = @(Get-VcMsiRegistrations)
        foreach ($a in $Archs) { $installed[$a] = Get-InstalledV14 -Entries $arp -Arch $a }
    }
}

# ---- 3. Target versions ----------------------------------------------------
Write-Log '[3] Latest Microsoft Visual C++ v14 redistributable'
$wanted = @($Archs | Where-Object { $null -ne $installed[$_] -or $cleared -contains $_ -or $InstallMissing })
$target = @{}
$installers = @{}
if ($wanted.Count -eq 0) {
    Write-Log '  No v14 runtime installed; nothing to update (-InstallMissing installs it).'
}
foreach ($a in $wanted) {
    $r = Get-VerifiedVcRedist -Arch $a
    if ($null -eq $r) { Add-Issue ('no verified vc_redist.' + $a + '.exe; ' + $a + ' not updated') -Fail; continue }
    $target[$a] = $r.Version
    $installers[$a] = $r
}

# ---- 4. Install ------------------------------------------------------------
Write-Log '[4] Install'
$orphaned = @(Select-OrphanV14Bundles -Entries $arp | ForEach-Object { $_.Arch } | Select-Object -Unique)
$plan = @(Get-VcInstallPlan -Archs $Archs -Installed $installed -Target $target -Cleared $cleared -InstallMissing ([bool]$InstallMissing) -Orphaned $orphaned)
if ($plan.Count -eq 0) { Write-Log '  Every v14 runtime is current.' }
$failHints = @{}
foreach ($step in $plan) {
    Write-Log ('  ' + $step.Arch + ': ' + (Format-VcVersion $step.From) + ' -> ' + $step.To + '  (' + $step.Reason + ')')
    if ($DryRun) { $NeedsHuman = $true; continue }
    $outcome = 'UNKNOWN'
    foreach ($attempt in 1..$BusyAttempts) {
        $null = Wait-InstallerIdle -Minutes $IdleWaitMinutes
        $logBase = Join-Path $LogDir ('VCRedist_' + $Stamp + '_' + $step.Arch + '_install' + $(if ($attempt -gt 1) { '_try' + $attempt } else { '' }) + '.log')
        $code = Invoke-Bounded -Path $installers[$step.Arch].Path -Arguments ('/install /quiet /norestart /log ' + $Q + $logBase + $Q) -TimeoutMinutes $InstallTimeoutMinutes
        $meaning = Get-VcExitMeaning -ExitCode $code
        Write-Log ('  Exit code: ' + $(if ($null -eq $code) { '(not reported)' } else { $code }) + $(if ($meaning) { '  (' + $meaning + ')' } else { '' }))
        $outcome = Get-VcInstallOutcome -ExitCode $code
        if ($outcome -ne 'BUSY') { break }
        Write-Log ('  Installers running now: ' + (Get-InstallerProcessText)) -Level WARN
        $null = Write-InstallLogErrors -LogBase $logBase
        if ($attempt -lt $BusyAttempts) { Write-Log ('  Retrying (' + ($attempt + 1) + ' of ' + $BusyAttempts + ').') }
    }
    switch ($outcome) {
        'OK'      { }
        'NEWER'   { }
        'UNKNOWN' { }
        'REBOOT'  { $Reboot = $true }
        'BUSY'    { Add-Issue ($step.Arch + ': another installation was still in progress after ' + $BusyAttempts + ' attempts; re-run later') }
        'FAIL'    {
            $hint = Write-InstallLogErrors -LogBase $logBase
            if ($hint) { Write-Log ('  Cause: ' + $hint) -Level ERROR; $failHints[$step.Arch] = $hint }
        }
        default   { throw 'Unknown install outcome' }
    }
    if ($installers[$step.Arch].Downloaded) { Remove-Item -LiteralPath $installers[$step.Arch].Path -Force -ErrorAction SilentlyContinue }
}

# ---- 5. Unsupported runtimes -------------------------------------------------
Write-Log '[5] Unsupported runtimes (2005-2013)'
$unsupported = @($arp | Where-Object { -not $_.Supported -and -not $_.SystemComponent })
if ($unsupported.Count -eq 0) {
    Write-Log '  None.'
} elseif (-not $RemoveUnsupported) {
    foreach ($u in $unsupported) { Write-Log ('  ' + $u.DisplayName + '  (kept; -RemoveUnsupported removes it)') -Level WARN }
} else {
    foreach ($u in $unsupported) {
        if ($DryRun) { Write-Log ('  [DRYRUN] Would remove ' + $u.DisplayName); $NeedsHuman = $true; continue }
        Write-Log ('  Removing ' + $u.DisplayName)
        $log = Join-Path $LogDir ('VCRedist_' + $Stamp + '_remove_' + $u.Year + '_' + $u.Arch + '.log')
        $null = Wait-InstallerIdle -Minutes $IdleWaitMinutes
        if ($u.BundleCachePath -and $u.CacheOk) {
            $code = Invoke-Bounded -Path $u.BundleCachePath -Arguments ('/uninstall /quiet /norestart /log ' + $Q + $log + $Q) -TimeoutMinutes $InstallTimeoutMinutes
        } elseif ($u.IsMsi -and (ConvertTo-PackedGuid $u.Key)) {
            $code = Invoke-Bounded -Path ($env:WINDIR + '\System32\msiexec.exe') -Arguments ('/x ' + $u.Key + ' /qn /norestart /l*v ' + $Q + $log + $Q) -TimeoutMinutes $InstallTimeoutMinutes
        } else {
            Write-Log '  No usable uninstaller (cached exe missing and not an MSI entry).' -Level WARN
            $code = $null
        }
        $meaning = Get-VcExitMeaning -ExitCode $code
        Write-Log ('  Exit code: ' + $(if ($null -eq $code) { '(none)' } else { $code }) + $(if ($meaning) { '  (' + $meaning + ')' } else { '' }))
        if ((Get-VcInstallOutcome -ExitCode $code) -eq 'REBOOT') { $Reboot = $true }
    }
}

# ---- 6. Verify ---------------------------------------------------------------
Write-Log '[6] Verify'
if ($DryRun) {
    Write-Log '  [DRYRUN] Nothing changed.'
} else {
    $arp = @(Get-VcArpEntries)
    $msi = @(Get-VcMsiRegistrations)
    foreach ($step in $plan) {
        $now = Get-InstalledV14 -Entries $arp -Arch $step.Arch -RuntimeOnly
        if ($null -ne $now -and $now -ge $step.To) {
            Write-Log ('  ' + $step.Arch + ' v14 runtime ' + $now + '  OK')
        } elseif ($Reboot) {
            Write-Log ('  ' + $step.Arch + ' v14 runtime ' + (Format-VcVersion $now) + '; expected after the reboot') -Level WARN
        } else {
            Add-Issue ($step.Arch + ' v14 runtime is ' + (Format-VcVersion $now) + ' after the install, not ' + $step.To + $(if ($failHints.ContainsKey($step.Arch)) { ': ' + $failHints[$step.Arch] } else { '' })) -Fail
        }
    }
    foreach ($a in $Archs) {
        if (($plan | Where-Object { $_.Arch -eq $a }) -or $null -eq $installed[$a]) { continue }
        Write-Log ('  ' + $a + ' v14 runtime ' + (Format-VcVersion (Get-InstalledV14 -Entries $arp -Arch $a)) + '  (no change needed)')
    }
    if (-not $SkipBrokenCleanup) {
        foreach ($b in @(Select-BrokenVcRegistrations -Products $msi -Bundles $arp -IncludeUnsupported ([bool]$RemoveUnsupported))) {
            Add-Issue ('still broken: ' + $b.Item.DisplayName) -Fail
        }
    }
    if ($RemoveUnsupported) {
        foreach ($u in @($arp | Where-Object { -not $_.Supported -and -not $_.SystemComponent })) {
            Add-Issue ('still installed: ' + $u.DisplayName)
        }
    }
    foreach ($o in (Select-OrphanV14Bundles -Entries $arp)) {
        Write-Log ('  ' + $o.DisplayName + ' is registered without a Minimum Runtime MSI') -Level WARN
    }
    Write-DllVersions
}

# ---- Summary -----------------------------------------------------------------
$final = Get-FinalExitCode -Failed $Failed -NeedsHuman $NeedsHuman -Reboot $Reboot
Write-Log ''
if ($Issues.Count -gt 0) {
    Write-Log 'Problems:'
    foreach ($m in $Issues) { Write-Log ('  - ' + $m) }
}
if ($unsupported.Count -gt 0 -and -not $RemoveUnsupported) {
    Write-Log ('Note: ' + $unsupported.Count + ' unsupported VC++ runtime(s) kept; re-run with -RemoveUnsupported if Tenable flags them and nothing needs them.')
}
switch ($final) {
    0       { Write-Log 'RESULT: Visual C++ v14 runtimes current; no broken registrations.' }
    3010    { Write-Log 'RESULT: done; reboot to finish.' }
    2       { Write-Log $(if ($DryRun) { 'RESULT: dry run; work is due (see above).' } else { 'RESULT: needs attention (see Problems).' }) -Level WARN }
    1       { Write-Log 'RESULT: FAILED (see Problems).' -Level ERROR }
    default { throw ('Unknown exit code ' + $final) }
}
Write-Log ('Log: ' + $LogFile)
exit $final
