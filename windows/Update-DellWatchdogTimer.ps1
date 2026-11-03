<#
.SYNOPSIS
    Updates the Dell Watchdog Timer kernel driver (WDTKernel.sys) to 2.0.0.1
    or later from a staged Dell Update Package. Nessus plugin 339708
    (DSA-2026-248, CVE-2026-61407).

.DESCRIPTION
    Tenable reads the FileVersion of C:\Windows\System32\drivers\WDTKernel.sys.
    csprpc-134 had 1.2.1.0 (2026-11-03).

    The Dell Update Package (DUP) .exe must be staged beside this script (EC
    Dependency Files) or in C:\. The first *Watchdog*.exe or *WDT*.exe found is
    used. Before anything is installed, the DUP is extracted (/s /e=) and the
    WDTKernel.sys inside it is read: a package whose driver is below the fixed
    version is refused. The DUP then runs silently (/s /l=), and the driver
    file on disk is re-read; the DUP exit code alone never decides the result.

    The EC agent is 32-bit and System32\drivers is redirected to SysWOW64
    for 32-bit processes, so the script relaunches itself in 64-bit
    PowerShell.

.PARAMETER InstallerPath
    Full path to the Dell Watchdog Timer DUP .exe, for terminal use. Leave
    empty under EC; the staged file beside the script is found automatically.

.PARAMETER DryRun
    Inventory, find and inspect the staged DUP, but do not install.

.NOTES
    Deploy via Endpoint Central (SYSTEM) as the package's Installation Command,
    no arguments. Logs: C:\Logs\CompoSecure. No reboot is issued.
    Exit: 0 = driver at or above the fixed version (or not present)
          3010 = installed, reboot required to finish
          2 = a human must look (package not applicable to this model, or
              the DUP says up to date while the file is still old)
          1 = failure
#>

[CmdletBinding()]
param(
    [string]$InstallerPath = '',
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$LogDir  = 'C:\Logs\CompoSecure'
$Stamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
$LogFile = $LogDir + '\DellWatchdogTimer_' + $Stamp + '.log'
$DupLog  = $LogDir + '\DellWatchdogTimer_dup_' + $Stamp + '.log'

# Minimum from DSA-2026-248. A newer DUP is accepted; only an older one is refused.
$FixedVersion = [version]'2.0.0.1'
$DriverName   = 'WDTKernel.sys'
$InstallTimeoutMinutes = 15
$ExtractTimeoutMinutes = 5

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

function ConvertTo-DriverVersion {
    # '1.2.1.0' or '2.0.0.1 (WinBuild.160101.0800)' -> [version]; $null if none.
    param([string]$Text)
    if ($Text -notmatch '(\d+(\.\d+){1,3})') { return $null }
    $v = $matches[1]
    try { return [version]$v } catch { return $null }
}

function Get-DupExitMeaning {
    # Dell Update Package return codes (Dell DUP CLI reference).
    param($Code)
    if ($null -eq $Code) { return 'UNKNOWN (no exit code: timed out or killed)' }
    switch ([int]$Code) {
        0 { return 'SUCCESS' }
        1 { return 'UNSUCCESSFUL (see the DUP log)' }
        2 { return 'REBOOT_REQUIRED' }
        3 { return 'SOFT_DEPENDENCY_ERROR (same or newer version already installed, or a downgrade without /f)' }
        4 { return 'HARD_DEPENDENCY_ERROR (a prerequisite is missing)' }
        5 { return 'QUALIFICATION_ERROR (this package does not apply to this system)' }
        6 { return 'REBOOTING_SYSTEM' }
        default { return ('code ' + $Code + ' (not in the DUP table; see the DUP log)') }
    }
}

function Test-PendingDriverRename {
    # True when PendingFileRenameOperations replaces the driver at next boot.
    param([string[]]$Operations, [string]$Name)
    foreach ($op in @($Operations)) {
        if ($op -and $op.ToLowerInvariant().EndsWith('\' + $Name.ToLowerInvariant())) { return $true }
    }
    return $false
}

function Get-WdtResult {
    # Decides the exit code from the re-read driver version, not the DUP code alone.
    param($After, [version]$Fixed, $DupCode, [bool]$PendingRename)
    $meaning = Get-DupExitMeaning $DupCode
    if ($null -ne $After -and $After -ge $Fixed) {
        if ($DupCode -eq 2 -or $DupCode -eq 6 -or $PendingRename) {
            return [pscustomobject]@{ Exit = 3010; Message = ('Driver file is ' + $After + '. Reboot to load it (DUP: ' + $meaning + ').') }
        }
        return [pscustomobject]@{ Exit = 0; Message = ('Driver file is ' + $After + ', at or above ' + $Fixed + '.') }
    }
    if ($DupCode -eq 2 -or $DupCode -eq 6 -or $PendingRename) {
        return [pscustomobject]@{ Exit = 3010; Message = ('DUP staged the update (' + $meaning + '); the file is replaced at the next restart. Rescan after rebooting.') }
    }
    if ($DupCode -eq 5) {
        return [pscustomobject]@{ Exit = 2; Message = ('DUP: ' + $meaning + '. Download the Watchdog Timer package listed for this model on dell.com/support.') }
    }
    if ($DupCode -eq 0 -or $DupCode -eq 3) {
        return [pscustomobject]@{ Exit = 2; Message = ('DUP: ' + $meaning + ', but the driver file is still ' + $After + '. Check the DUP log and Device Manager.') }
    }
    return [pscustomobject]@{ Exit = 1; Message = ('DUP: ' + $meaning + '. Driver file is still ' + $After + '.') }
}

function Find-PayloadDriver {
    param([string]$Dir, [string]$Name)
    return @(Get-ChildItem -LiteralPath $Dir -Recurse -File -Filter $Name -ErrorAction SilentlyContinue)
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
        } elseif ('' + $v) {
            $a += @(('-' + $k), ('' + $v))
        }
    }
    return $a
}

if ($env:DELLWDT_DOTSOURCE -eq '1') { return }

# ==============================================================
# Live run (Windows / Endpoint Central)
# ==============================================================
if (Test-Needs64BitRelaunch -Is64BitOS ([Environment]::Is64BitOperatingSystem) -Is64BitProcess ([Environment]::Is64BitProcess)) {
    $ps64 = $env:WINDIR + '\Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $ps64) {
        $relaunchArgs = Get-RelaunchArguments -ScriptPath $PSCommandPath -Bound $PSBoundParameters
        & $ps64 @relaunchArgs
        exit $LASTEXITCODE
    }
}

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$DriverPath = $env:WINDIR + '\System32\drivers\' + $DriverName

function Get-DriverVersion {
    if (-not (Test-Path -LiteralPath $DriverPath)) { return $null }
    $vi = (Get-Item -LiteralPath $DriverPath).VersionInfo
    $v = ConvertTo-DriverVersion -Text ('' + $vi.FileVersion)
    if ($null -eq $v) {
        $v = ConvertTo-DriverVersion -Text ('' + $vi.FileMajorPart + '.' + $vi.FileMinorPart + '.' + $vi.FileBuildPart + '.' + $vi.FilePrivatePart)
    }
    return $v
}

function Invoke-Bounded {
    param([string]$Path, [string]$Arguments, [int]$TimeoutMinutes)
    Write-Log ('  Running: ' + $Path + ' ' + $Arguments)
    $p = Start-Process -FilePath $Path -ArgumentList $Arguments -NoNewWindow -PassThru
    # Without an open handle, ExitCode is empty after WaitForExit(timeout).
    $null = $p.Handle
    if (-not $p.WaitForExit($TimeoutMinutes * 60 * 1000)) {
        Write-Log ('  Still running after ' + $TimeoutMinutes + ' minutes; killing the process tree.') -Level ERROR
        & ($env:WINDIR + '\System32\taskkill.exe') '/PID' $p.Id '/T' '/F' 2>&1 | Out-Null
        return $null
    }
    $p.WaitForExit()
    if ($null -eq $p.ExitCode -or ('' + $p.ExitCode) -eq '') { return $null }
    return [int]$p.ExitCode
}

Write-Log '=============================================='
Write-Log ' Dell Watchdog Timer driver -- Plugin 339708 (DSA-2026-248)'
Write-Log (' Host   : ' + $env:COMPUTERNAME)
Write-Log (' Target : ' + $DriverName + ' ' + $FixedVersion + ' or later')
Write-Log (' DryRun : ' + $DryRun)
Write-Log '=============================================='

# ==============================================================
# 1. Inventory
# ==============================================================
Write-Log ''
Write-Log '[1/4] Inventory...'
$cs = Get-CimInstance Win32_ComputerSystem
Write-Log ('  Model   : ' + $cs.Manufacturer + ' ' + $cs.Model)
$before = Get-DriverVersion
if (-not (Test-Path -LiteralPath $DriverPath)) {
    Write-Log ('  ' + $DriverPath + ' not present. Nothing to do.')
    exit 0
}
Write-Log ('  Driver  : ' + $DriverPath + '  ' + $before)
$svc = Get-CimInstance Win32_SystemDriver -Filter ('PathName LIKE ' + [char]39 + '%' + $DriverName + [char]39) -ErrorAction SilentlyContinue
foreach ($s in @($svc)) { if ($s) { Write-Log ('  Service : ' + $s.Name + '  State=' + $s.State + '  Start=' + $s.StartMode) } }
if ($null -ne $before -and $before -ge $FixedVersion) {
    Write-Log ('  Already ' + $before + ', at or above ' + $FixedVersion + '. Nothing to do.')
    exit 0
}
if ($null -eq $before) { Write-Log '  Driver version unreadable; treating it as vulnerable.' -Level WARN }

# ==============================================================
# 2. Find and inspect the staged DUP
# ==============================================================
Write-Log ''
Write-Log '[2/4] Locating the staged Dell Update Package...'
if ([string]::IsNullOrWhiteSpace($InstallerPath)) {
    $dirs = @()
    if ($PSScriptRoot) { $dirs += $PSScriptRoot }
    $dirs += 'C:\'
    foreach ($d in $dirs) {
        $cands = @(Get-ChildItem -Path $d -File -ErrorAction SilentlyContinue |
                   Where-Object { $_.Name -match '(?i)(watchdog|wdt).*\.exe$' } | Sort-Object Name -Descending)
        if ($cands.Count -gt 0) {
            if ($cands.Count -gt 1) { Write-Log ('  ' + $cands.Count + ' candidates in ' + $d + '; using ' + $cands[0].Name) -Level WARN }
            $InstallerPath = $cands[0].FullName
            break
        }
    }
}
if ([string]::IsNullOrWhiteSpace($InstallerPath) -or -not (Test-Path -LiteralPath $InstallerPath)) {
    Write-Log '  No Dell Watchdog Timer DUP found (*Watchdog*.exe or *WDT*.exe beside this script or in C:\).' -Level ERROR
    Write-Log '  Add the .exe to the EC package as a Dependency File and re-run.' -Level ERROR
    exit 1
}
Write-Log ('  Installer: ' + $InstallerPath)

$extractDir = $env:WINDIR + '\Temp\DellWDT_' + $Stamp
$exCode = Invoke-Bounded -Path $InstallerPath -Arguments ('/s /e=' + $extractDir) -TimeoutMinutes $ExtractTimeoutMinutes
$payload = @()
if (Test-Path -LiteralPath $extractDir) { $payload = Find-PayloadDriver -Dir $extractDir -Name $DriverName }
if ($payload.Count -eq 0) {
    Write-Log ('  Could not read ' + $DriverName + ' from the package (extract exit ' + $exCode + '). The re-read after install decides.') -Level WARN
} else {
    $best = $null
    foreach ($f in $payload) {
        $pv = ConvertTo-DriverVersion -Text ('' + $f.VersionInfo.FileVersion)
        Write-Log ('  Package driver: ' + $f.FullName.Substring($extractDir.Length) + '  ' + $pv)
        if ($null -ne $pv -and ($null -eq $best -or $pv -gt $best)) { $best = $pv }
    }
    if ($null -ne $best -and $best -lt $FixedVersion) {
        Write-Log ('  The staged package contains ' + $DriverName + ' ' + $best + ', below ' + $FixedVersion + '.') -Level ERROR
        Write-Log '  Installing it would leave plugin 339708 open. Stage the DSA-2026-248 package. Nothing was changed.' -Level ERROR
        Remove-Item -LiteralPath $extractDir -Recurse -Force -ErrorAction SilentlyContinue
        exit 1
    }
}
Remove-Item -LiteralPath $extractDir -Recurse -Force -ErrorAction SilentlyContinue

if ($DryRun) {
    Write-Log ''
    Write-Log ('  [DRYRUN] Would run ' + $InstallerPath + ' /s /l=' + $DupLog)
    Write-Log '=============================================='
    exit 0
}

# ==============================================================
# 3. Install
# ==============================================================
Write-Log ''
Write-Log '[3/4] Installing...'
$code = Invoke-Bounded -Path $InstallerPath -Arguments ('/s /l=' + $DupLog) -TimeoutMinutes $InstallTimeoutMinutes
Write-Log ('  DUP exit: ' + (Get-DupExitMeaning $code) + '  (log: ' + $DupLog + ')')
if (Test-Path -LiteralPath $DupLog) {
    Get-Content -LiteralPath $DupLog -Tail 15 -ErrorAction SilentlyContinue | ForEach-Object { Write-Log ('    | ' + $_) }
}

# ==============================================================
# 4. Verify
# ==============================================================
Write-Log ''
Write-Log '[4/4] Verifying the driver on disk...'
Start-Sleep -Seconds 3
$after = Get-DriverVersion
Write-Log ('  ' + $DriverPath + '  before ' + $before + '  after ' + $after)
$pfro = @((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations)
$pending = Test-PendingDriverRename -Operations $pfro -Name $DriverName
if ($pending) { Write-Log ('  A pending file rename replaces ' + $DriverName + ' at the next restart.') }

$r = Get-WdtResult -After $after -Fixed $FixedVersion -DupCode $code -PendingRename $pending
$level = if ($r.Exit -eq 0 -or $r.Exit -eq 3010) { 'INFO' } elseif ($r.Exit -eq 2) { 'WARN' } else { 'ERROR' }
Write-Log ('  RESULT: ' + $r.Message) -Level $level
if ($r.Exit -eq 0 -or $r.Exit -eq 3010) { Write-Log '  Re-run a Nessus scan (after the restart, if one is required) to confirm plugin 339708 clears.' }
Write-Log '=============================================='
exit $r.Exit
