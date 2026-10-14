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

.PARAMETER InstallerPath
    Full path to the CWA installer. Default: the newest CitrixWorkspace*.exe
    beside the script (EC extracts dependency files there), then C:\.
    Local/terminal use; in EC, stage the file instead.

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
    Dependency files: the CWA 2607 LTSR installer; optionally
    windowsdesktop-runtime-10.*-win-x86.exe and Remove-DotNetEolChannel.ps1.
    Script Arguments: bare switches only, e.g. -RemoveDotNet8
    Specify exit code(s): 0,3010
    Log: C:\Logs\CompoSecure\CitrixWorkspace_<timestamp>.log
    CWA's own install logs: <Program Files>\Citrix\Logs\CTXWorkspaceInstallLogs-*
    Exit: 0 = done / 3010 = done, reboot needed /
          2 = deferred or needs a human (session open, .NET 8 still needed) /
          1 = failed
#>
[CmdletBinding()]
param(
    [string]$InstallerPath = '',
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
$InstallTimeoutMinutes = 30

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
            $best = [pscustomobject]@{ DisplayName = $e.DisplayName; Version = $v }
        }
    }
    return $best
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
    param([int]$ExitCode)
    switch ($ExitCode) {
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
        foreach ($k in @(Get-ChildItem $r -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue
            if ($p -and $p.DisplayName) { $out += $p }
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
    $out = @()
    foreach ($r in Get-DotNetRoots) {
        foreach ($fw in @(Get-ChildItem ($r.Path + '\shared') -Directory -ErrorAction SilentlyContinue)) {
            foreach ($d in @(Get-ChildItem $fw.FullName -Directory -Filter '8.*' -ErrorAction SilentlyContinue)) {
                $out += ($fw.Name + ' ' + $d.Name + ' (' + $r.Arch + ')')
            }
        }
    }
    return $out
}

function Find-Net8Apps {
    # Framework-dependent apps bound to an 8.x shared framework. The dotnet
    # folders themselves (SDK tools) are left to Remove-DotNetEolChannel.ps1.
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
            if ($need) { $hits += ($f.FullName + '  [' + $need + ']') }
        }
    }
    return $hits
}

function Find-StagedFile {
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
            $files += [pscustomobject]@{ FullName = $f.FullName; Version = $v }
        }
    }
    return (Select-StagedInstaller -Files $files)
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
    # can fail under EC's SYSTEM context. Returns the exit code, or -1 on timeout.
    param([string]$Path, [string[]]$Arguments, [int]$TimeoutMinutes)
    Write-Log ('  Running: ' + $Path + ' ' + ($Arguments -join ' '))
    $p = Start-Process -FilePath $Path -ArgumentList $Arguments -NoNewWindow -PassThru
    if (-not $p.WaitForExit($TimeoutMinutes * 60 * 1000)) {
        Write-Log ('  Still running after ' + $TimeoutMinutes + ' minutes; leaving it to finish.') -Level ERROR
        return -1
    }
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
    Write-Log ('  Exit code: ' + $code)
    if (-not $staged) { Remove-Item $exe -Force -ErrorAction SilentlyContinue }
    $outcome = Get-InstallOutcome -ExitCode $code
    if ($outcome -eq 'FAIL') { Write-Log ('  Bundle log: ' + $bundleLog) -Level ERROR }
    return $outcome
}

function Write-CwaInstallLogHint {
    foreach ($base in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
        if (-not $base) { continue }
        $latest = Get-ChildItem ($base + '\Citrix\Logs') -Filter 'CTXWorkspaceInstallLogs*' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($latest) {
            Write-Log ('  Citrix install logs: ' + $latest.FullName)
            return
        }
    }
    Write-Log '  No CTXWorkspaceInstallLogs folder found under Program Files\Citrix\Logs.'
}

$Failed = $false
$NeedsHuman = $false
$Reboot = $false

Write-Log '=============================================='
Write-Log ' Citrix Workspace app update + .NET 8 -> 10'
Write-Log (' Host    : ' + $env:COMPUTERNAME)
Write-Log (' 64-bit  : ' + [Environment]::Is64BitProcess)
Write-Log (' Options : InstallIfMissing=' + $InstallIfMissing + ' ForceClose=' + $ForceClose + ' AutoUpdate=' + $AutoUpdate + ' SkipThirdPartyVCCheck=' + $SkipThirdPartyVCCheck + ' ForceInstall=' + $ForceInstall + ' SkipDotNetPrestage=' + $SkipDotNetPrestage + ' RemoveDotNet8=' + $RemoveDotNet8 + ' DryRun=' + $DryRun)
Write-Log '=============================================='

# ---- 1. Inventory -----------------------------------------------------------
Write-Log '[1] Current state'
$cwa = Select-CwaArpEntry -Entries (Get-ArpEntries)
if ($cwa) { Write-Log ('  Citrix Workspace : ' + $cwa.DisplayName + '  ' + $cwa.Version) }
else { Write-Log '  Citrix Workspace : not installed' }
$desktopX86 = @(Get-X86DesktopVersions)
Write-Log ('  .NET Desktop Runtime x86 : ' + $(if ($desktopX86.Count) { ($desktopX86 -join ', ') } else { 'none' }))
$net8 = @(Get-DotNet8Folders)
Write-Log ('  .NET 8 runtimes : ' + $(if ($net8.Count) { ($net8 -join '; ') } else { 'none' }))

# ---- 2. Installer + decision ------------------------------------------------
Write-Log '[2] Installer'
$installer = $null
if ($InstallerPath) {
    if (-not (Test-Path -LiteralPath $InstallerPath)) {
        Write-Log ('  -InstallerPath not found: ' + $InstallerPath) -Level ERROR
        exit 1
    }
    $item = Get-Item -LiteralPath $InstallerPath
    $installer = [pscustomobject]@{ FullName = $item.FullName; Version = (ConvertTo-SafeVersion ('' + $item.VersionInfo.ProductVersion)) }
} else {
    $installer = Find-StagedFile -Filter 'CitrixWorkspace*.exe'
}

$needInstall = $false
if (-not $installer) {
    Write-Log '  No CitrixWorkspace*.exe staged beside the script or in C:\.' -Level WARN
    if (-not $cwa -or -not (Test-CwaUsesDotNet10 -Version $cwa.Version)) {
        Write-Log '  Add the 2607 LTSR installer to the EC package as a dependency file.' -Level ERROR
        $Failed = $true
    }
} else {
    Write-Log ('  ' + $installer.FullName + '  version ' + $(if ($installer.Version) { $installer.Version } else { 'unknown' }))
    if (-not $cwa) {
        if ($InstallIfMissing) { $needInstall = $true; Write-Log '  Not installed; -InstallIfMissing set, installing.' }
        else { Write-Log '  Not installed; upgrade-only run, skipping (use -InstallIfMissing to install).' }
    } elseif ($installer.Version -and $cwa.Version -ge $installer.Version) {
        Write-Log '  Installed version is already at or above the installer. No upgrade needed.'
    } else {
        $needInstall = $true
        Write-Log '  Upgrade needed.'
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
        $code = Invoke-Installer -Path $installer.FullName -Arguments $cwaArgs -TimeoutMinutes $InstallTimeoutMinutes
        Write-Log ('  Exit code: ' + $code)
        switch (Get-InstallOutcome -ExitCode $code) {
            'OK'     { }
            'REBOOT' { $Reboot = $true; Write-Log '  Reboot required to finish.' }
            'FAIL'   {
                $Failed = $true
                Write-Log '  Install failed. Retry with -ForceInstall; if a 32-bit CWA is being' -Level ERROR
                Write-Log '  replaced by 64-bit, also consider -SkipThirdPartyVCCheck.' -Level ERROR
            }
            default  { throw 'Unknown install outcome' }
        }
        Write-CwaInstallLogHint
    }

    # ---- 6. Verify ---------------------------------------------------------
    if (-not $DryRun) {
        Write-Log '[6] Verify'
        $cwa = Select-CwaArpEntry -Entries (Get-ArpEntries)
        $desktopX86 = @(Get-X86DesktopVersions)
        if ($cwa) { Write-Log ('  Citrix Workspace : ' + $cwa.DisplayName + '  ' + $cwa.Version) }
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
    $apps = @(Find-Net8Apps)
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
