<#
.SYNOPSIS
    Upgrades Citrix Workspace app (CWA) for Windows from a staged installer
    (target: 2607 LTSR) and moves the machine from .NET 8 to .NET 10.

.DESCRIPTION
    WHY THIS EXISTS. .NET 8 reaches end of support on 2026-11-10. CWA 2409
    through 2507.1 LTSR CU2 require the x86 .NET Desktop Runtime 8.x, so a
    machine running them cannot drop .NET 8. CWA 2507.1 LTSR CU3, 2607 LTSR
    and later Current Releases require the x86 .NET Desktop Runtime 10.0.9 or
    later instead (x86 even on 64-bit Windows). Upgrading CWA is what lets
    .NET 8 go.

    Steps:
      1. Inventory: installed CWA (Add/Remove Programs), .NET Desktop Runtime
         x86 versions, and every .NET 8 runtime on the machine.
      2. Skip if CWA is already at or above the staged installer's version.
         CWA is not installed where it is missing unless -InstallIfMissing.
      3. Defer (exit 2) while a Citrix session is open (wfica32 / CDViewer),
         unless -ForceClose.
      4. Install the x86 .NET Desktop Runtime 10 first if it is missing
         (Citrix's documented Method 3). CWA would otherwise download it from
         downloadplugins.citrix.com during setup, which Zscaler can block.
         Uses a staged windowsdesktop-runtime-10.*-win-x86.exe beside the
         script if present, else https://aka.ms/dotnet/10.0/.
      5. Run the CWA installer silently, with Citrix auto-update off (EC
         manages the version) and telemetry opted out.
      6. Verify the new version in Add/Remove Programs, and that .NET 10 x86
         Desktop Runtime is present.
      7. .NET 8 readiness. Reports what still needs .NET 8: an older CWA, or
         any framework-dependent app whose *.runtimeconfig.json targets an
         8.x shared framework without rollForward LatestMajor. With
         -RemoveDotNet8 and no blockers, runs Remove-DotNetEolChannel.ps1
         -DotNet8 -RemoveStaleFolders (stage it beside this script). That
         also removes the swidtag and Package Cache leftovers Tenable reads
         (CSPC-004, 2026-10).

    The .NET 10 runtime CWA depends on must never be uninstalled; this
    script only ever adds it.

    CWA version numbers: 2607 LTSR reports 26.7.x in Add/Remove Programs.
    $DotNet10MinCwaVersion (26.7) is the lowest version this script treats as
    confirmed on .NET 10. 2507.1 CU3 also uses .NET 10, but its version
    string is not pinned here, so it counts as unconfirmed and .NET 8
    removal is blocked on it.

    64-BIT. The EC agent runs scripts in 32-bit PowerShell, which sees
    HKLM\SOFTWARE redirected to WOW6432Node and would miss a 64-bit CWA's
    uninstall entry, so the script relaunches itself as 64-bit.

    32-BIT OR 64-BIT INSTALLER. Stage both; the script picks one per machine:
      * 32-bit Windows                -> 32-bit.
      * CWA already 64-bit (or ARM64) -> the same architecture. Citrix does
        not support going from 64-bit back to 32-bit.
      * CWA already 32-bit            -> 32-bit, so the upgrade does not also
        change architecture. -MigrateTo64Bit uses the native build instead
        (x64, or ARM64 on ARM devices); 2607 is the last LTSR with a 32-bit
        build.
      * CWA not installed             -> the native build, or 32-bit when
        only that is staged.
    The installed architecture comes from where CWA registers in
    Add/Remove Programs: a 32-bit install registers under WOW6432Node.
    A staged installer's architecture comes from its file name (ARM64, then
    x64 / amd64 / 64bit), else the executable's PE header, else 32-bit.
    Rename a file if the log shows the wrong architecture for it.
    Citrix will not change architecture within the same version (the
    installer reports it is already installed); that case is reported
    (exit 2) for a manual uninstall of the 32-bit build first.

.PARAMETER InstallerPath
    Full path to one CWA installer, used as-is. Default: pick from the
    CitrixWorkspace*.exe files beside the script (EC extracts dependency
    files there), then C:\. Local/terminal use; in EC, stage the files.

.PARAMETER MigrateTo64Bit
    Replace a 32-bit CWA with the native 64-bit (or ARM64) build during the
    upgrade. Check for 32-bit third-party virtual channel add-ons first, and
    add -SkipThirdPartyVCCheck if the silent install stops on that check.

.PARAMETER InstallIfMissing
    Install CWA on machines that do not have it. Default is upgrade only.

.PARAMETER ForceClose
    Close open Citrix sessions and CWA processes instead of deferring.
    Disconnects the user from any running virtual app or desktop.

.PARAMETER AutoUpdate
    Leave Citrix auto-update on, limited to LTSR cumulative updates
    (AutoUpdateCheck=auto AutoUpdateStream=LTSR). Default turns it off.

.PARAMETER SkipThirdPartyVCCheck
    Pass /SkipThirdPartyVCCheck. Only matters when a 64-bit installer
    replaces a 32-bit CWA: the silent install otherwise pauses or fails on
    32-bit third-party virtual channel add-ons. Confirm none are in use first.

.PARAMETER ForceInstall
    Pass /forceinstall: Citrix's cleanup-and-reinstall for a failed upgrade
    or an unsupported old version. Use for a retry, not the first run.

.PARAMETER SkipDotNetPrestage
    Do not install .NET 10 x86 first; let the CWA installer fetch it.

.PARAMETER RemoveDotNet8
    After a verified upgrade, remove .NET 8 via Remove-DotNetEolChannel.ps1
    when nothing on the machine still needs it.

.PARAMETER DryRun
    Report what would happen; change nothing.

.NOTES
    Deploy via Endpoint Central (SYSTEM), -File invocation.
    Dependency files: the CWA 2607 LTSR installer(s), 32-bit and 64-bit; optionally
    windowsdesktop-runtime-10.*-win-x86.exe and Remove-DotNetEolChannel.ps1.
    Script Arguments: bare switches only, e.g. -RemoveDotNet8
    Specify exit code(s): 0,3010
    Log: C:\Logs\CompoSecure\CitrixWorkspace_<timestamp>.log
    CWA's own install logs: <Program Files>\Citrix\Logs\CTXWorkspaceInstallLogs-*
    (or a SYSTEM temp folder). On a failed install the script also logs the
    exit code's meaning, MsiInstaller failures from the Application event log,
    and whether NetworkProvider\Order ProviderOrder exists (CTX697148).
    Exit: 0 = done / 3010 = done, reboot needed /
          2 = deferred or needs a human (session open, .NET 8 still needed) /
          1 = failed
#>
[CmdletBinding()]
param(
    [string]$InstallerPath = '',
    [switch]$MigrateTo64Bit,
    [switch]$InstallIfMissing,
    [switch]$ForceClose,
    [switch]$AutoUpdate,
    [switch]$SkipThirdPartyVCCheck,
    [switch]$ForceInstall,
    [switch]$SkipDotNetPrestage,
    [switch]$RemoveDotNet8,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

$DotNet10MinCwaVersion = [version]'26.7'
$DotNet10MinDesktop    = [version]'10.0.9'
$SessionProcesses = @('wfica32', 'wfica', 'CDViewer')
$CwaProcesses     = @('wfica32', 'wfica', 'CDViewer', 'SelfService', 'SelfServicePlugin', 'Receiver', 'concentr', 'redirector', 'AuthManSvr', 'WebHelper')
$InstallTimeoutMinutes = 60

function ConvertTo-SafeVersion {
    param([string]$Text)
    if (-not $Text) { return $null }
    if ($Text -notmatch '(\d+(\.\d+){1,3})') { return $null }
    $v = $null
    if ([version]::TryParse($matches[1], [ref]$v)) { return $v }
    return $null
}

function Select-CwaArpEntry {
    # Main product entry only ('Citrix Workspace 2607'); CWA also registers
    # component entries such as 'Citrix Workspace(DV)' and 'Citrix Workspace Inside'.
    param([object[]]$Entries)
    $best = $null
    foreach ($e in $Entries) {
        if (('' + $e.DisplayName) -notmatch '^Citrix Workspace \d{4}') { continue }
        $v = ConvertTo-SafeVersion ('' + $e.DisplayVersion)
        if (-not $v) { continue }
        if (-not $best -or $v -gt $best.Version) {
            $best = [pscustomobject]@{ DisplayName = $e.DisplayName; Version = $v; IsWow = [bool]$e.IsWow; InstallLocation = ('' + $e.InstallLocation) }
        }
    }
    return $best
}

function ConvertTo-OsArch {
    # PROCESSOR_ARCHITEW6432 is set only in a 32-bit process on 64-bit Windows.
    param([string]$ProcessorArchitecture, [string]$ProcessorArchitectureW6432)
    $a = $ProcessorArchitectureW6432
    if (-not $a) { $a = $ProcessorArchitecture }
    switch (('' + $a).ToUpperInvariant()) {
        'AMD64' { return 'x64' }
        'ARM64' { return 'arm64' }
        'X86'   { return 'x86' }
        default { return '' }
    }
}

function Get-CwaInstalledArch {
    # The 64-bit builds name themselves ('Citrix Workspace 2607 (x64)',
    # CSLT-057); otherwise the install folder (32-bit CWA lives in Program
    # Files (x86)), then the registry view its uninstall entry is in.
    param([string]$DisplayName, [bool]$IsWow, [string]$InstallLocation, [string]$OsArch)
    if ($OsArch -eq 'x86') { return 'x86' }
    if ($DisplayName -match '(?i)\(ARM64\)') { return 'arm64' }
    if ($DisplayName -match '(?i)\(x64\)') { return 'x64' }
    if ($InstallLocation -match '(?i)\\Program Files \(x86\)\\') { return 'x86' }
    if ($InstallLocation -match '(?i)\\Program Files\\') { return $OsArch }
    if ($IsWow) { return 'x86' }
    return $OsArch
}

function Get-InstallerArch {
    # PeMachine: IMAGE_FILE_HEADER.Machine of the exe, or 0 if unreadable.
    param([string]$Name, [int]$PeMachine)
    if ($Name -match '(?i)arm64') { return 'arm64' }
    if ($Name -match '(?i)(x64|amd64|64bit|64-bit)') { return 'x64' }
    switch ($PeMachine) {
        0xAA64  { return 'arm64' }
        0x8664  { return 'x64' }
        default { return 'x86' }
    }
}

function Resolve-TargetArch {
    # Returns Arch (installer architecture to use), Reason, and Error ('' when ok).
    param([string]$OsArch, [string]$InstalledArch, [bool]$MigrateTo64Bit, [string[]]$Available)
    $native = $OsArch
    if (-not $native) { $native = 'x86' }
    if ($InstalledArch) {
        if ($InstalledArch -eq 'x86' -and $native -ne 'x86' -and $MigrateTo64Bit) {
            $want = $native; $why = 'migrating 32-bit CWA to ' + $native
        } else {
            $want = $InstalledArch; $why = 'matches the installed ' + $InstalledArch + ' CWA'
        }
    } elseif ($Available -contains $native) {
        $want = $native; $why = 'not installed; native ' + $native + ' build'
    } else {
        $want = 'x86'; $why = 'not installed; no ' + $native + ' installer staged, using 32-bit'
    }
    $err = ''
    if ($Available -notcontains $want) {
        $err = 'no ' + $want + ' installer staged (' + $why + ')'
        if ($InstalledArch -eq 'x86' -and $want -eq 'x86') { $err += '; stage the 32-bit installer or use -MigrateTo64Bit' }
    }
    return [pscustomobject]@{ Arch = $want; Reason = $why; Error = $err }
}

function Test-SameVersionArchSwitch {
    # Citrix's installer refuses to change architecture without a version
    # change ('already installed'); the 32-bit build must be uninstalled first.
    param([string]$InstalledArch, [version]$InstalledVersion, [string]$TargetArch, [version]$InstallerVersion)
    if (-not $InstalledArch -or $InstalledArch -eq $TargetArch) { return $false }
    if (-not $InstalledVersion -or -not $InstallerVersion) { return $false }
    return ($InstalledVersion -ge $InstallerVersion)
}

function Test-CwaUsesDotNet10 {
    param([version]$Version)
    if (-not $Version) { return $false }
    return ($Version -ge $DotNet10MinCwaVersion)
}

function Select-StagedInstaller {
    # Files: objects with FullName and Version ([version] or $null). Newest version wins.
    param([object[]]$Files)
    $pick = $null
    foreach ($f in $Files) {
        if (-not $pick) { $pick = $f; continue }
        $a = $f.Version; $b = $pick.Version
        if ($a -and (-not $b -or $a -gt $b)) { $pick = $f }
    }
    return $pick
}

function Get-CwaInstallArguments {
    param([bool]$AutoUpdate, [bool]$SkipThirdPartyVCCheck, [bool]$ForceInstall)
    $a = @('/silent')
    if ($ForceInstall) { $a += '/forceinstall' }
    if ($SkipThirdPartyVCCheck) { $a += '/SkipThirdPartyVCCheck' }
    if ($AutoUpdate) { $a += @('AutoUpdateCheck=auto', 'AutoUpdateStream=LTSR') }
    else { $a += 'AutoUpdateCheck=disabled' }
    $a += 'EnableCEIP=False'
    return $a
}

function Get-InstallOutcome {
    # UNKNOWN: no exit code was reported; the version check decides.
    param($ExitCode)
    if ($null -eq $ExitCode -or ('' + $ExitCode) -eq '') { return 'UNKNOWN' }
    switch ([int]$ExitCode) {
        0       { return 'OK' }
        3010    { return 'REBOOT' }
        1641    { return 'REBOOT' }
        default { return 'FAIL' }
    }
}

function Get-RuntimeConfigNet8Need {
    # Returns the 8.x shared framework a *.runtimeconfig.json binds to, or $null
    # when the app does not need the .NET 8 runtime: self-contained
    # (includedFrameworks), a different major, or rollForward LatestMajor
    # (runs on 10 once 8 is gone).
    param([string]$Json)
    try { $cfg = $Json | ConvertFrom-Json } catch { return $null }
    $ro = $cfg.runtimeOptions
    if (-not $ro) { return $null }
    if ($ro.includedFrameworks) { return $null }
    if (('' + $ro.rollForward) -eq 'LatestMajor') { return $null }
    $fws = @()
    if ($ro.framework) { $fws += $ro.framework }
    if ($ro.frameworks) { $fws += @($ro.frameworks) }
    foreach ($fw in $fws) {
        if (('' + $fw.version) -match '^8\.') { return ('' + $fw.name + ' ' + $fw.version) }
    }
    return $null
}

function ConvertTo-PeArch {
    param([int]$Machine)
    switch ($Machine) {
        0x014C  { return 'x86' }
        0x8664  { return 'x64' }
        0xAA64  { return 'arm64' }
        default { return '' }
    }
}

function Test-Net8AppUsesInstalled {
    # True when a .NET 8 folder this app can load is installed: same shared
    # framework, and the same architecture as its apphost (any architecture
    # when the app has no apphost). An x64 app cannot load the x86 runtime,
    # so removing x86 .NET 8 does not affect it (CSLT-057: Dell DTP
    # diagnostics, x64, on a machine with only x86 .NET 8).
    param([string]$Framework, [string]$Arch, [object[]]$Installed)
    foreach ($i in $Installed) {
        if ($i.Framework -ne $Framework) { continue }
        if (-not $Arch -or $i.Arch -eq $Arch) { return $true }
    }
    return $false
}

function Get-DotNet8Blockers {
    # Cwa: $null when CWA is not installed. Net8Apps: paths of apps that need .NET 8.
    param($CwaVersion, [bool]$CwaInstalled, [bool]$HasDotNet10Desktop, [string[]]$Net8Apps)
    $b = @()
    if ($CwaInstalled -and -not (Test-CwaUsesDotNet10 -Version $CwaVersion)) {
        $b += ('Citrix Workspace ' + $CwaVersion + ' is not confirmed on .NET 10 (needs ' + $DotNet10MinCwaVersion + '+)')
    }
    if ($CwaInstalled -and -not $HasDotNet10Desktop) {
        $b += ('.NET Desktop Runtime ' + $DotNet10MinDesktop + '+ (x86) is not installed, and Citrix Workspace needs it')
    }
    foreach ($p in $Net8Apps) { $b += ('needs .NET 8: ' + $p) }
    return $b
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

function Get-PeMachine {
    # IMAGE_FILE_HEADER.Machine: e_lfanew at 0x3C points at 'PE\0\0', Machine follows.
    param([string]$Path)
    try {
        $fs = [System.IO.File]::OpenRead($Path)
        try {
            $br = New-Object System.IO.BinaryReader($fs)
            if ($fs.Length -lt 0x40) { return 0 }
            $fs.Position = 0x3C
            $pe = $br.ReadInt32()
            if ($pe -lt 0 -or ($pe + 6) -gt $fs.Length) { return 0 }
            $fs.Position = $pe
            if ($br.ReadUInt32() -ne 0x00004550) { return 0 }
            return [int]$br.ReadUInt16()
        } finally { $fs.Close() }
    } catch { return 0 }
}

function Get-InstallLogErrorLines {
    # MSI / TrolleyExpress failure lines, de-duplicated, at most $Max.
    param([string]$Text, [int]$Max)
    if (-not $Text) { return @() }
    $out = @()
    foreach ($line in ($Text -split '\r?\n')) {
        $t = $line.Trim()
        # CWAInstaller (2311+, CTX695461): InstallSuccess = False names the component.
        if ($t -match '(?i)(\bError \d{4}\b|Return value 3\b|Installation (failed|operation failed)|\bfailed with (error|exit) code\b|Product: .+ -- Error|InstallSuccess = False|Exiting Application with error Code : [1-9])') {
            if ($t.Length -gt 300) { $t = $t.Substring(0, 300) }
            if ($out -notcontains $t) { $out += $t }
            if ($out.Count -ge $Max) { break }
        }
    }
    return $out
}

function Get-CwaExitCodeMeaning {
    # Citrix CTX695019 for 4xxxx/5xxxx. 1xxxxx is not in that table; CWA
    # 2603+ returned 101603 on CSPRLT-94 (2026-10-15 and 2026-10-26), which
    # reads as 100000 + the MSI error of a component install.
    param($ExitCode)
    if ($null -eq $ExitCode -or ('' + $ExitCode) -eq '') { return '' }
    $c = [int]$ExitCode
    $msi = @{
        1602 = 'user cancelled'
        1603 = 'fatal error during installation'
        1618 = 'another installation is already in progress'
        1625 = 'blocked by system policy'
        1638 = 'another version of this product is already installed'
    }
    $cwa = @{
        40002 = 'a previous installation exists; uninstall it and retry'
        40008 = 'a more recent version is available'
        40026 = 'could not stop processes or drivers; reboot and retry'
        40027 = 'a Citrix update is already in progress'
        40028 = 'administrator rights required'
        40032 = 'already up to date'
        40034 = 'a component MSI install failed'
        40035 = 'a component MSI uninstall failed'
        40037 = 'partial success: mandatory components installed'
        50001 = 'a client exists that only an administrator can modify'
        50002 = 'upgrade path is unsupported'
    }
    if ($cwa.ContainsKey($c)) { return ('CWA ' + $c + ': ' + $cwa[$c]) }
    if ($msi.ContainsKey($c)) { return ('MSI ' + $c + ': ' + $msi[$c]) }
    if ($c -ge 100000 -and $c -le 199999) {
        $inner = $c - 100000
        $m = 'not in Citrix''s exit-code table; likely MSI error ' + $inner + ' from a component install'
        if ($msi.ContainsKey($inner)) { $m += ' (' + $msi[$inner] + ')' }
        return $m
    }
    return ''
}

function Get-CwaLogRoots {
    # Folders CWA's installer may log to when run as SYSTEM. Windows 11's
    # GetTempPath2 gives SYSTEM C:\Windows\SystemTemp rather than %TEMP%.
    param([string]$ProgramFilesX86, [string]$ProgramW6432, [string]$ProgramFiles, [string]$Temp, [string]$WinDir)
    $r = @()
    foreach ($pf in @($ProgramFilesX86, $ProgramW6432, $ProgramFiles)) { if ($pf) { $r += ($pf + '\Citrix\Logs') } }
    if ($Temp) { $r += $Temp }
    if ($WinDir) {
        $r += @(($WinDir + '\Temp'), ($WinDir + '\SystemTemp'), ($WinDir + '\System32\config\systemprofile\AppData\Local\Temp'))
    }
    $out = @()
    foreach ($p in $r) { if ($out -notcontains $p.TrimEnd('\')) { $out += $p.TrimEnd('\') } }
    return $out
}

function Select-MsiFailureMessages {
    # MsiInstaller event messages that report a failure, de-duplicated, at most $Max.
    param([string[]]$Messages, [int]$Max)
    $out = @()
    foreach ($m in $Messages) {
        if (-not $m) { continue }
        $t = ($m -replace '\s+', ' ').Trim()
        $fail = ($t -match '(?i)error status: (\d+)' -and $Matches[1] -ne '0') -or
                ($t -match '(?i)Installation (operation )?failed') -or
                ($t -match '(?i) -- Error \d+')
        if (-not $fail) { continue }
        if ($t.Length -gt 300) { $t = $t.Substring(0, 300) }
        if ($out -notcontains $t) { $out += $t }
        if ($out.Count -ge $Max) { break }
    }
    return $out
}

function Get-MsiFailureHint {
    # MsiInstaller failure messages -> the cause in plain words, or ''.
    # CSPRLT-94 (2026-10-26): CWA's VC++ prerequisite hit 1714 + System
    # Error 1612, so CWA itself exited 101603.
    param([string[]]$Messages)
    foreach ($m in $Messages) {
        if ($m -match '(?i)Product: (.+?) -- Error 1714\..*System Error 1612') {
            return ('The installed ' + $Matches[1] + ' cannot be upgraded: Windows Installer''s cached copy of the old version is missing (MSI 1714 / 1612). Remove that broken registration, then retry.')
        }
    }
    return ''
}

function Format-DotNet8Folders {
    param([object[]]$Folders)
    if (-not $Folders -or $Folders.Count -eq 0) { return 'none' }
    return (($Folders | ForEach-Object { $_.Framework + ' ' + $_.Version + ' (' + $_.Arch + ')' }) -join '; ')
}

if ($env:CITRIX_WORKSPACE_DOTSOURCE -eq '1') { return }

if (Test-Needs64BitRelaunch -Is64BitOS ([Environment]::Is64BitOperatingSystem) -Is64BitProcess ([Environment]::Is64BitProcess)) {
    $ps64 = $env:WINDIR + '\Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $ps64) {
        $relaunchArgs = Get-RelaunchArguments -ScriptPath $PSCommandPath -Bound $PSBoundParameters
        & $ps64 @relaunchArgs
        exit $LASTEXITCODE
    }
}

$LogDir  = 'C:\Logs\CompoSecure'
$LogFile = $LogDir + '\CitrixWorkspace_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log'
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$TempDir = $env:WINDIR + '\Temp'

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

function Get-ArpEntries {
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    $out = @()
    foreach ($r in $roots) {
        $isWow = ($r -match 'WOW6432Node')
        foreach ($k in @(Get-ChildItem $r -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue
            if ($p -and $p.DisplayName) {
                $p | Add-Member -NotePropertyName IsWow -NotePropertyValue $isWow -Force
                $out += $p
            }
        }
    }
    return $out
}

function Get-DotNetRoots {
    $roots = @()
    if (${env:ProgramFiles(x86)}) {
        $roots += [pscustomobject]@{ Arch = 'x86'; Path = (${env:ProgramFiles(x86)} + '\dotnet') }
        $roots += [pscustomobject]@{ Arch = 'x64'; Path = ($env:ProgramFiles + '\dotnet') }
    } else {
        $roots += [pscustomobject]@{ Arch = 'x86'; Path = ($env:ProgramFiles + '\dotnet') }
    }
    return $roots
}

function Get-X86DesktopVersions {
    $root = (Get-DotNetRoots | Where-Object { $_.Arch -eq 'x86' } | Select-Object -First 1).Path
    $dir = $root + '\shared\Microsoft.WindowsDesktop.App'
    $out = @()
    foreach ($d in @(Get-ChildItem $dir -Directory -ErrorAction SilentlyContinue)) {
        $v = ConvertTo-SafeVersion $d.Name
        if ($v) { $out += $v }
    }
    return ($out | Sort-Object)
}

function Get-DotNet8Folders {
    # Objects: Framework, Version, Arch.
    $out = @()
    foreach ($r in Get-DotNetRoots) {
        foreach ($fw in @(Get-ChildItem ($r.Path + '\shared') -Directory -ErrorAction SilentlyContinue)) {
            foreach ($d in @(Get-ChildItem $fw.FullName -Directory -Filter '8.*' -ErrorAction SilentlyContinue)) {
                $out += [pscustomobject]@{ Framework = $fw.Name; Version = $d.Name; Arch = $r.Arch }
            }
        }
    }
    return $out
}

function Find-Net8Apps {
    # Framework-dependent apps bound to an 8.x shared framework, as objects:
    # Path, Framework, Arch (from the apphost .exe beside the runtimeconfig;
    # '' when there is none). The dotnet folders themselves (SDK tools) are
    # left to Remove-DotNetEolChannel.ps1.
    $dirs = @($env:ProgramFiles)
    if (${env:ProgramFiles(x86)}) { $dirs += ${env:ProgramFiles(x86)} }
    foreach ($u in @(Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
        $p = $u.FullName + '\AppData\Local\Programs'
        if (Test-Path $p) { $dirs += $p }
    }
    $hits = @()
    foreach ($d in $dirs) {
        foreach ($f in @(Get-ChildItem $d -Recurse -File -Filter '*.runtimeconfig.json' -ErrorAction SilentlyContinue)) {
            if ($f.FullName -match '\\dotnet\\') { continue }
            $json = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction SilentlyContinue
            $need = Get-RuntimeConfigNet8Need -Json $json
            if (-not $need) { continue }
            $exe = $f.FullName -replace '\.runtimeconfig\.json$', '.exe'
            $arch = ''
            if (Test-Path -LiteralPath $exe) { $arch = ConvertTo-PeArch -Machine (Get-PeMachine -Path $exe) }
            $hits += [pscustomobject]@{ Path = $f.FullName; Framework = ($need -split ' ')[0]; Need = $need; Arch = $arch }
        }
    }
    return $hits
}

function Find-StagedFile {
    param([string]$Filter)
    return (Select-StagedInstaller -Files @(Get-StagedFiles -Filter $Filter))
}

function Get-StagedFiles {
    param([string]$Filter)
    $dirs = @()
    if ($PSScriptRoot) { $dirs += $PSScriptRoot }
    $dirs += 'C:\'
    $files = @()
    foreach ($d in $dirs) {
        if (-not (Test-Path -LiteralPath $d -PathType Container)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $d -Filter $Filter -File -ErrorAction SilentlyContinue)) {
            $v = ConvertTo-SafeVersion ('' + $f.VersionInfo.ProductVersion)
            if (-not $v) { $v = ConvertTo-SafeVersion ('' + $f.VersionInfo.FileVersion) }
            if (-not $v) { $v = ConvertTo-SafeVersion $f.Name }
            $arch = Get-InstallerArch -Name $f.Name -PeMachine (Get-PeMachine -Path $f.FullName)
            $files += [pscustomobject]@{ FullName = $f.FullName; Version = $v; Arch = $arch }
        }
    }
    return $files
}

function Test-ExeHeader {
    param([string]$Path, [long]$MinBytes)
    $item = Get-Item -LiteralPath $Path
    $fs = [System.IO.File]::OpenRead($Path)
    try { $b1 = $fs.ReadByte(); $b2 = $fs.ReadByte() } finally { $fs.Close() }
    return ($b1 -eq 0x4D -and $b2 -eq 0x5A -and $item.Length -ge $MinBytes)
}

function Invoke-Installer {
    # Full path + -NoNewWindow: a bare filename goes through ShellExecute and
    # can fail under EC's SYSTEM context. Returns the exit code, -1 on timeout,
    # or $null if Windows did not report one.
    param([string]$Path, [string[]]$Arguments, [int]$TimeoutMinutes)
    Write-Log ('  Running: ' + $Path + ' ' + ($Arguments -join ' '))
    $p = Start-Process -FilePath $Path -ArgumentList $Arguments -NoNewWindow -PassThru
    # Without an open handle, ExitCode is empty after WaitForExit(timeout)
    # (CSLT-057: both installers logged 'Exit code: ' blank).
    $null = $p.Handle
    if (-not $p.WaitForExit($TimeoutMinutes * 60 * 1000)) {
        Write-Log ('  Still running after ' + $TimeoutMinutes + ' minutes; leaving it to finish.') -Level ERROR
        return -1
    }
    $p.WaitForExit()
    return $p.ExitCode
}

function Install-DotNet10Desktop {
    $staged = Find-StagedFile -Filter 'windowsdesktop-runtime-10.*-win-x86.exe'
    if ($staged) {
        $exe = $staged.FullName
        Write-Log ('  Staged installer: ' + $exe)
    } else {
        $url = 'https://aka.ms/dotnet/10.0/windowsdesktop-runtime-win-x86.exe'
        $exe = $TempDir + '\windowsdesktop-runtime-10-win-x86.exe'
        Write-Log ('  Downloading ' + $url)
        if ($DryRun) { Write-Log '  [DRYRUN] Would download and install.'; return 'OK' }
        $ok = $false
        foreach ($attempt in 1..3) {
            try {
                Invoke-WebRequest -Uri $url -OutFile $exe -UseBasicParsing -TimeoutSec 300
                $ok = $true
                break
            } catch {
                Write-Log ('  Download attempt ' + $attempt + ' of 3 failed: ' + $_) -Level WARN
                Start-Sleep -Seconds 10
            }
        }
        if (-not $ok -or -not (Test-ExeHeader -Path $exe -MinBytes 5MB)) {
            Write-Log '  Download failed or is not an installer (proxy block page?). Stage' -Level ERROR
            Write-Log '  windowsdesktop-runtime-10.*-win-x86.exe beside this script.' -Level ERROR
            Remove-Item $exe -Force -ErrorAction SilentlyContinue
            return 'FAIL'
        }
    }
    if ($DryRun) { Write-Log '  [DRYRUN] Would install.'; return 'OK' }
    $bundleLog = $LogDir + '\CitrixWorkspace_dotnet10_x86_bundle.log'
    $dq = [string][char]34
    $code = Invoke-Installer -Path $exe -Arguments @('/install', '/quiet', '/norestart', '/log', ($dq + $bundleLog + $dq)) -TimeoutMinutes 20
    Write-Log ('  Exit code: ' + $(if ($null -eq $code) { '(not reported)' } else { $code }))
    if (-not $staged) { Remove-Item $exe -Force -ErrorAction SilentlyContinue }
    $outcome = Get-InstallOutcome -ExitCode $code
    if ($outcome -eq 'UNKNOWN') {
        $now = @(Get-X86DesktopVersions | Where-Object { $_ -ge $DotNet10MinDesktop })
        if ($now.Count -gt 0) { $outcome = 'OK' } else { $outcome = 'FAIL' }
        Write-Log ('  No exit code; .NET 10 x86 now present: ' + ($now.Count -gt 0))
    }
    if ($outcome -eq 'FAIL') { Write-Log ('  Bundle log: ' + $bundleLog) -Level ERROR }
    return $outcome
}

function Write-CwaInstallLogHint {
    # CWA logs to <Program Files>\Citrix\Logs, but a run under SYSTEM can log
    # to a SYSTEM temp folder instead. CSPRLT-94 (exit 101603) twice left no
    # log folder from the run in Program Files, %TEMP% or C:\Windows\Temp, so
    # loose installer logs written since the install started count too. The
    # VC++ prerequisite step logs to its own CTXPreRequisiteInstallLogs-*
    # folder (CSPRLT-94 2026-10-26: that was where the failure was).
    param([bool]$Failed, [datetime]$Since)
    $bases = @(Get-CwaLogRoots -ProgramFilesX86 ${env:ProgramFiles(x86)} -ProgramW6432 $env:ProgramW6432 -ProgramFiles $env:ProgramFiles -Temp $env:TEMP -WinDir $env:WINDIR)
    $cutoff = $Since.AddMinutes(-1)
    $all = @()
    $loose = @()
    foreach ($b in $bases) {
        foreach ($f in @('CTXWorkspaceInstallLogs*', 'CTXReceiverInstallLogs*', 'CTXPreRequisiteInstallLogs*')) {
            $all += @(Get-ChildItem -LiteralPath $b -Directory -Filter $f -ErrorAction SilentlyContinue)
        }
        foreach ($f in @('CWAInstaller*.log', 'TrolleyExpress*.log', 'CtxInstall-*.log', 'PreRequisiteInstaller*.log')) {
            $loose += @(Get-ChildItem -LiteralPath $b -File -Filter $f -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $cutoff })
        }
    }
    $thisRun = @($all | Where-Object { $_.LastWriteTime -ge $cutoff } | Sort-Object LastWriteTime)
    $logs = @()
    if ($thisRun.Count -gt 0) {
        foreach ($d in $thisRun) {
            Write-Log ('  Citrix install logs: ' + $d.FullName + '  (' + $d.LastWriteTime + ')')
            $logs += @(Get-ChildItem -LiteralPath $d.FullName -Recurse -File -Filter '*.log' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime)
        }
    } else {
        $latest = $all | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($latest) { Write-Log ('  Citrix install logs: ' + $latest.FullName + '  (' + $latest.LastWriteTime + ')  -- older than this run') }
    }
    if ($thisRun.Count -eq 0 -and $loose.Count -gt 0) {
        $logs = @($loose | Sort-Object LastWriteTime)
        foreach ($d in @($logs | ForEach-Object { $_.DirectoryName } | Select-Object -Unique)) { Write-Log ('  Citrix installer logs from this run in: ' + $d) }
    } elseif ($thisRun.Count -eq 0) {
        Write-Log ('  No Citrix installer log from this run in: ' + ($bases -join ', ') + '.')
    }
    if (-not $Failed -or $logs.Count -eq 0) { return }
    $shown = 0
    foreach ($log in $logs) {
        $lines = @(Get-InstallLogErrorLines -Text (Get-Content -LiteralPath $log.FullName -Raw -ErrorAction SilentlyContinue) -Max 5)
        if ($lines.Count -eq 0) { continue }
        Write-Log ('  ' + $log.Name + ':') -Level ERROR
        foreach ($l in $lines) { Write-Log ('    ' + $l) -Level ERROR }
        $shown += $lines.Count
        if ($shown -ge 20) { break }
    }
    if ($shown -eq 0) { Write-Log '  No error lines found in those logs.' }
}

function Write-CwaFailureDiagnostics {
    # Evidence that does not depend on where CWA put its own logs.
    param([datetime]$Since)
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'MsiInstaller'; StartTime = $Since.AddMinutes(-1) } -ErrorAction SilentlyContinue | Sort-Object TimeCreated)
    $fails = @(Select-MsiFailureMessages -Messages @($events | ForEach-Object { $_.Message }) -Max 10)
    if ($fails.Count -gt 0) {
        Write-Log '  Windows Installer failures since the install started (Application log, MsiInstaller):' -Level ERROR
        foreach ($f in $fails) { Write-Log ('    ' + $f) -Level ERROR }
        $hint = Get-MsiFailureHint -Messages $fails
        if ($hint) { Write-Log ('  Cause: ' + $hint) -Level ERROR }
    } else {
        Write-Log ('  Windows Installer logged ' + $events.Count + ' event(s) since the install started, none a failure.')
    }
    # CTX697148: CWA 2607's SSON custom action fails with 1603 when this is missing.
    $po = $null
    try { $po = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order' -Name ProviderOrder -ErrorAction Stop).ProviderOrder } catch { }
    if (-not $po) {
        Write-Log '  HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order ProviderOrder is missing or empty.' -Level ERROR
        Write-Log '  CWA single sign-on setup fails with 1603 without it (Citrix CTX697148); default value: RDPNP,LanmanWorkstation,webclient' -Level ERROR
    } else {
        Write-Log ('  NetworkProvider\Order ProviderOrder: ' + $po)
    }
}

$Failed = $false
$NeedsHuman = $false
$Reboot = $false

Write-Log '=============================================='
Write-Log ' Citrix Workspace app update + .NET 8 -> 10'
Write-Log (' Host    : ' + $env:COMPUTERNAME)
Write-Log (' 64-bit  : ' + [Environment]::Is64BitProcess)
Write-Log (' Options : MigrateTo64Bit=' + $MigrateTo64Bit + ' InstallIfMissing=' + $InstallIfMissing + ' ForceClose=' + $ForceClose + ' AutoUpdate=' + $AutoUpdate + ' SkipThirdPartyVCCheck=' + $SkipThirdPartyVCCheck + ' ForceInstall=' + $ForceInstall + ' SkipDotNetPrestage=' + $SkipDotNetPrestage + ' RemoveDotNet8=' + $RemoveDotNet8 + ' DryRun=' + $DryRun)
Write-Log '=============================================='

# ---- 1. Inventory -----------------------------------------------------------
Write-Log '[1] Current state'
$osArch = ConvertTo-OsArch -ProcessorArchitecture $env:PROCESSOR_ARCHITECTURE -ProcessorArchitectureW6432 $env:PROCESSOR_ARCHITEW6432
Write-Log ('  Windows architecture : ' + $osArch)
$cwa = Select-CwaArpEntry -Entries (Get-ArpEntries)
$cwaArch = ''
if ($cwa) {
    $cwaArch = Get-CwaInstalledArch -DisplayName $cwa.DisplayName -IsWow $cwa.IsWow -InstallLocation $cwa.InstallLocation -OsArch $osArch
    Write-Log ('  Citrix Workspace : ' + $cwa.DisplayName + '  ' + $cwa.Version + '  (' + $cwaArch + ')')
} else {
    Write-Log '  Citrix Workspace : not installed (machine-wide)'
    # CSPRLT-94: Tenable still reported an old CWA from a per-user install
    # or leftover ICA Client files, neither of which has a machine entry.
    $outside = @()
    foreach ($pf in @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ } | Select-Object -Unique) {
        $outside += @(Get-Item -LiteralPath ($pf + '\Citrix\ICA Client\wfica32.exe'), ($pf + '\Citrix\ICA Client\wfica.exe') -ErrorAction SilentlyContinue)
    }
    foreach ($u in @(Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
        $outside += @(Get-Item -LiteralPath ($u.FullName + '\AppData\Local\Citrix\ICA Client\wfica32.exe'), ($u.FullName + '\AppData\Local\Citrix\ICA Client\wfica.exe') -ErrorAction SilentlyContinue)
    }
    foreach ($f in @($outside | Sort-Object FullName -Unique)) {
        Write-Log ('  Old copy outside Add/Remove Programs: ' + $f.FullName + '  ' + $f.VersionInfo.ProductVersion) -Level WARN
    }
    if ($outside.Count -gt 0) {
        Write-Log '  Remove it with Remove-CitrixWorkspaceLegacy.ps1 (add -ReinstallMachineWide to install 2607).' -Level WARN
    }
}
$desktopX86 = @(Get-X86DesktopVersions)
Write-Log ('  .NET Desktop Runtime x86 : ' + $(if ($desktopX86.Count) { ($desktopX86 -join ', ') } else { 'none' }))
$net8 = @(Get-DotNet8Folders)
Write-Log ('  .NET 8 runtimes : ' + (Format-DotNet8Folders -Folders $net8))

# ---- 2. Installer + decision ------------------------------------------------
Write-Log '[2] Installer'
$installer = $null
$staged = @()
if ($InstallerPath) {
    if (-not (Test-Path -LiteralPath $InstallerPath)) {
        Write-Log ('  -InstallerPath not found: ' + $InstallerPath) -Level ERROR
        exit 1
    }
    $item = Get-Item -LiteralPath $InstallerPath
    $staged = @([pscustomobject]@{
        FullName = $item.FullName
        Version  = (ConvertTo-SafeVersion ('' + $item.VersionInfo.ProductVersion))
        Arch     = (Get-InstallerArch -Name $item.Name -PeMachine (Get-PeMachine -Path $item.FullName))
    })
} else {
    $staged = @(Get-StagedFiles -Filter 'CitrixWorkspace*.exe')
}
foreach ($s in $staged) {
    Write-Log ('  Staged: ' + $s.FullName + '  version ' + $(if ($s.Version) { $s.Version } else { 'unknown' }) + '  arch ' + $s.Arch)
}
if ($staged.Count -gt 0) {
    $available = @($staged | ForEach-Object { $_.Arch } | Sort-Object -Unique)
    $target = Resolve-TargetArch -OsArch $osArch -InstalledArch $cwaArch -MigrateTo64Bit $MigrateTo64Bit -Available $available
    Write-Log ('  Target architecture: ' + $target.Arch + ' (' + $target.Reason + ')')
    if ($target.Error) {
        $newest = Select-StagedInstaller -Files $staged
        $current = $cwa -and $newest.Version -and $cwa.Version -ge $newest.Version
        if ($current) {
            Write-Log ('  ' + $target.Error + '. CWA is already at the staged version, so nothing to install.') -Level WARN
        } else {
            Write-Log ('  ' + $target.Error + '.') -Level ERROR
            $Failed = $true
        }
    } else {
        $installer = Select-StagedInstaller -Files @($staged | Where-Object { $_.Arch -eq $target.Arch })
    }
}

$needInstall = $false
if ($staged.Count -eq 0) {
    Write-Log '  No CitrixWorkspace*.exe staged beside the script or in C:\.' -Level WARN
    if (-not $cwa -or -not (Test-CwaUsesDotNet10 -Version $cwa.Version)) {
        Write-Log '  Add the 2607 LTSR installer(s) to the EC package as dependency files.' -Level ERROR
        $Failed = $true
    }
} elseif ($installer) {
    Write-Log ('  Using: ' + $installer.FullName)
    if ($cwa -and (Test-SameVersionArchSwitch -InstalledArch $cwaArch -InstalledVersion $cwa.Version -TargetArch $target.Arch -InstallerVersion $installer.Version)) {
        Write-Log ('  CWA ' + $cwa.Version + ' (' + $cwaArch + ') is already at this version. Citrix will not switch') -Level WARN
        Write-Log ('  to ' + $target.Arch + ' without a version change: uninstall the ' + $cwaArch + ' CWA first, then re-run.') -Level WARN
        $NeedsHuman = $true
    } elseif (-not $cwa) {
        if ($InstallIfMissing) { $needInstall = $true; Write-Log '  Not installed; -InstallIfMissing set, installing.' }
        else { Write-Log '  Not installed; upgrade-only run, skipping (use -InstallIfMissing to install).' }
    } elseif ($installer.Version -and $cwa.Version -ge $installer.Version) {
        Write-Log '  Installed version is already at or above the installer. No upgrade needed.'
    } else {
        $needInstall = $true
        if ($cwaArch -and $cwaArch -ne $target.Arch) {
            Write-Log ('  Upgrade needed, ' + $cwaArch + ' -> ' + $target.Arch + '.')
            if (-not $SkipThirdPartyVCCheck) {
                Write-Log '  If the install stops on the 32-bit add-on check, re-run with -SkipThirdPartyVCCheck' -Level WARN
                Write-Log '  after confirming no 32-bit third-party virtual channels are in use.' -Level WARN
            }
        } else {
            Write-Log '  Upgrade needed.'
        }
    }
}

# ---- 3. Open sessions -------------------------------------------------------
if ($needInstall -and -not $Failed) {
    Write-Log '[3] Open Citrix sessions'
    $open = @(Get-Process -Name $SessionProcesses -ErrorAction SilentlyContinue)
    if ($open.Count -gt 0) {
        Write-Log ('  Open: ' + (($open | ForEach-Object { $_.Name + ' (PID ' + $_.Id + ')' }) -join ', '))
        if (-not $ForceClose) {
            Write-Log '  A user is in a Citrix session. Deferring; re-run later or use -ForceClose.' -Level WARN
            Write-Log '===== END (deferred) ====='
            exit 2
        }
    } else {
        Write-Log '  None.'
    }
    $running = @(Get-Process -Name $CwaProcesses -ErrorAction SilentlyContinue)
    if ($running.Count -gt 0 -and ($ForceClose -or $open.Count -eq 0)) {
        $names = @($running | ForEach-Object { $_.Name } | Sort-Object -Unique)
        Write-Log ('  Closing CWA processes: ' + ($names -join ', '))
        if (-not $DryRun) { $running | Stop-Process -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 3 }
    }

    # ---- 4. .NET 10 x86 Desktop Runtime first ------------------------------
    Write-Log '[4] .NET 10 x86 Desktop Runtime'
    $has10 = @($desktopX86 | Where-Object { $_ -ge $DotNet10MinDesktop }).Count -gt 0
    if ($has10) {
        Write-Log '  Already installed.'
    } elseif ($SkipDotNetPrestage) {
        Write-Log '  Missing; -SkipDotNetPrestage set, the CWA installer will download it'
        Write-Log '  from downloadplugins.citrix.com.'
    } else {
        $r = Install-DotNet10Desktop
        if ($r -eq 'REBOOT') { $Reboot = $true }
        if ($r -eq 'FAIL') {
            Write-Log '  Continuing: the CWA installer will try to download it itself.' -Level WARN
        }
    }

    # ---- 5. Install CWA ----------------------------------------------------
    Write-Log '[5] Installing Citrix Workspace'
    $cwaArgs = Get-CwaInstallArguments -AutoUpdate $AutoUpdate -SkipThirdPartyVCCheck $SkipThirdPartyVCCheck -ForceInstall $ForceInstall
    if ($DryRun) {
        Write-Log ('  [DRYRUN] Would run: ' + $installer.FullName + ' ' + ($cwaArgs -join ' '))
    } else {
        $installStart = Get-Date
        $code = Invoke-Installer -Path $installer.FullName -Arguments $cwaArgs -TimeoutMinutes $InstallTimeoutMinutes
        Write-Log ('  Exit code: ' + $(if ($null -eq $code) { '(not reported)' } else { $code }))
        switch (Get-InstallOutcome -ExitCode $code) {
            'OK'     { }
            'UNKNOWN' { Write-Log '  No exit code reported; the version check below decides.' -Level WARN }
            'REBOOT' { $Reboot = $true; Write-Log '  Reboot required to finish.' }
            'FAIL'   {
                $Failed = $true
                $meaning = Get-CwaExitCodeMeaning -ExitCode $code
                if ($meaning) { Write-Log ('  Exit code meaning: ' + $meaning) -Level ERROR }
                Write-Log '  Install failed. Reboot and retry first (an uninstall just before can leave' -Level ERROR
                Write-Log '  files pending deletion), then -ForceInstall. If a 32-bit CWA is being' -Level ERROR
                Write-Log '  replaced by 64-bit, also consider -SkipThirdPartyVCCheck.' -Level ERROR
            }
            default  { throw 'Unknown install outcome' }
        }
        Write-CwaInstallLogHint -Failed $Failed -Since $installStart
        if ($Failed) { Write-CwaFailureDiagnostics -Since $installStart }
    }

    # ---- 6. Verify ---------------------------------------------------------
    if (-not $DryRun) {
        Write-Log '[6] Verify'
        $cwa = Select-CwaArpEntry -Entries (Get-ArpEntries)
        $desktopX86 = @(Get-X86DesktopVersions)
        if ($cwa) { Write-Log ('  Citrix Workspace : ' + $cwa.DisplayName + '  ' + $cwa.Version + '  (' + (Get-CwaInstalledArch -DisplayName $cwa.DisplayName -IsWow $cwa.IsWow -InstallLocation $cwa.InstallLocation -OsArch $osArch) + ')') }
        else { Write-Log '  Citrix Workspace : not found in Add/Remove Programs' -Level ERROR }
        Write-Log ('  .NET Desktop Runtime x86 : ' + $(if ($desktopX86.Count) { ($desktopX86 -join ', ') } else { 'none' }))
        if (-not $Failed -and $installer.Version -and (-not $cwa -or $cwa.Version -lt $installer.Version)) {
            if ($Reboot) {
                Write-Log '  New version not registered yet; expected until the reboot.' -Level WARN
            } else {
                Write-Log ('  Installer exited cleanly but the version is not ' + $installer.Version + '.') -Level ERROR
                $Failed = $true
            }
        }
        if (-not $Failed -and $cwa -and -not $Reboot) {
            $nowArch = Get-CwaInstalledArch -DisplayName $cwa.DisplayName -IsWow $cwa.IsWow -InstallLocation $cwa.InstallLocation -OsArch $osArch
            if ($nowArch -ne $target.Arch) {
                Write-Log ('  Installed architecture reads as ' + $nowArch + ', expected ' + $target.Arch + '. Check') -Level WARN
                Write-Log '  Program Files vs Program Files (x86)\Citrix\ICA Client.' -Level WARN
            }
        }
    }
}

# ---- 7. .NET 8 readiness ----------------------------------------------------
Write-Log '[7] .NET 8 removal readiness'
$net8 = @(Get-DotNet8Folders)
if ($net8.Count -eq 0) {
    Write-Log '  No .NET 8 runtime on this machine.'
} elseif ($DryRun -and $needInstall) {
    Write-Log '  [DRYRUN] Readiness depends on the upgrade above; skipped.'
} else {
    Write-Log '  Scanning installed apps for .NET 8 runtimeconfig.json files...'
    $apps = @()
    foreach ($a in @(Find-Net8Apps)) {
        $archText = $(if ($a.Arch) { $a.Arch } else { 'no apphost' })
        if (Test-Net8AppUsesInstalled -Framework $a.Framework -Arch $a.Arch -Installed $net8) {
            $apps += ($a.Path + '  [' + $a.Need + ', ' + $archText + ']')
        } else {
            Write-Log ('  Not a blocker: ' + $a.Path + '  [' + $a.Need + ', ' + $archText + ']')
            Write-Log ('    No ' + $archText + ' ' + $a.Framework + ' 8.x is installed, so removing .NET 8 does not change this app.')
        }
    }
    $has10 = @($desktopX86 | Where-Object { $_ -ge $DotNet10MinDesktop }).Count -gt 0
    $cwaVer = $null
    if ($cwa) { $cwaVer = $cwa.Version }
    $blockers = @(Get-DotNet8Blockers -CwaVersion $cwaVer -CwaInstalled ([bool]$cwa) -HasDotNet10Desktop $has10 -Net8Apps $apps)
    if ($blockers.Count -gt 0) {
        Write-Log '  .NET 8 is still needed:' -Level WARN
        foreach ($b in $blockers) { Write-Log ('    ' + $b) -Level WARN }
        if ($RemoveDotNet8) { $NeedsHuman = $true; Write-Log '  Not removing .NET 8.' -Level WARN }
    } elseif (-not $RemoveDotNet8) {
        Write-Log '  Nothing found that needs .NET 8. Re-run with -RemoveDotNet8 to remove it.'
    } elseif ($Failed) {
        Write-Log '  Not removing .NET 8 after a failed upgrade.' -Level WARN
    } else {
        $remover = $null
        foreach ($d in @($PSScriptRoot, 'C:\')) {
            if ($d -and (Test-Path ($d + '\Remove-DotNetEolChannel.ps1'))) { $remover = $d + '\Remove-DotNetEolChannel.ps1'; break }
        }
        if (-not $remover) {
            Write-Log '  Remove-DotNetEolChannel.ps1 is not staged beside this script; add it to' -Level ERROR
            Write-Log '  the EC package to remove .NET 8.' -Level ERROR
            $NeedsHuman = $true
        } else {
            $rmArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $remover, '-DotNet8', '-RemoveStaleFolders')
            if ($DryRun) { $rmArgs += '-DryRun' }
            Write-Log ('  Running ' + $remover + ' -DotNet8 -RemoveStaleFolders' + $(if ($DryRun) { ' -DryRun' } else { '' }))
            $prev = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            try { & ($PSHOME + '\powershell.exe') @rmArgs; $rmCode = $LASTEXITCODE } finally { $ErrorActionPreference = $prev }
            Write-Log ('  Remove-DotNetEolChannel exit: ' + $rmCode)
            switch ($rmCode) {
                0       { Write-Log '  .NET 8 removed.' }
                3010    { $Reboot = $true; Write-Log '  .NET 8 removed; reboot needed.' }
                2       { $NeedsHuman = $true; Write-Log '  Remover needs a human decision; see its log.' -Level WARN }
                default { $Failed = $true; Write-Log '  .NET 8 removal failed; see its log.' -Level ERROR }
            }
        }
    }
}

$final = Get-FinalExitCode -Failed $Failed -NeedsHuman $NeedsHuman -Reboot $Reboot
Write-Log ('===== END (exit ' + $final + ') =====')
Write-Log ('Log: ' + $LogFile)
exit $final
