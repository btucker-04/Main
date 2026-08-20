<#
.SYNOPSIS
    Updates Microsoft Visual Studio instances to the latest build of their
    channel (Nessus plugins 307350/307351/307352/314647 for VS 2022 ->
    17.14.31+, and 298992 for VS 18 -> 18.3.0+).

.DESCRIPTION
    Uses the Visual Studio installer's own update mechanism (vs_installer.exe
    / setup.exe update), which is SKU- and channel-agnostic -- this is why
    it works where EC's channel/SKU-specific VS patch reports Not Applicable
    (e.g. VS 2022 Community), and where EC has no catalog entry at all
    (VS 18 / 2026 line).

    Enumerates every installed VS instance via vswhere, updates each to the
    latest of its channel, and verifies the resulting catalog version.

    Developer-workstation safe:
      - If devenv.exe is running for an instance, that instance is SKIPPED
        (exit 2) unless -ForceCloseVS -- a developer mid-build should not be
        interrupted. Mosyle/EC re-run picks it up later.

.PARAMETER ForceCloseVS
    Close running devenv.exe before updating. WARNING: can lose unsaved work.

.PARAMETER DryRun
    Report instances and intended actions without changing anything.

.NOTES
    Deploy via Endpoint Central (SYSTEM). Logs: C:\Logs\CompoSecure.
    Requires network to Microsoft VS update CDN (aka.ms / visualstudio.com /
    download.visualstudio.microsoft.com). Exit: 0 ok / 2 skipped / 1 failure.
#>

[CmdletBinding()]
param(
    [switch]$ForceCloseVS,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$LogDir  = 'C:\Logs\CompoSecure'
$LogFile = Join-Path $LogDir ('VSUpdate_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

$Skipped = 0
$Failed  = 0
$Updated = 0

Write-Log '=============================================='
Write-Log ' Visual Studio Update (v2) -- 307350/307351/307352/314647/298992'
Write-Log (' Host   : ' + $env:COMPUTERNAME)
Write-Log (' DryRun : ' + $DryRun)
Write-Log '=============================================='

# --------------------------------------------------------------
# Locate the VS installer + vswhere
# --------------------------------------------------------------
$vsInstallerDir = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer'
$vswhere    = Join-Path $vsInstallerDir 'vswhere.exe'
$vsInstaller = Join-Path $vsInstallerDir 'vs_installer.exe'
$setupExe   = Join-Path $vsInstallerDir 'setup.exe'
$updater    = if (Test-Path $vsInstaller) { $vsInstaller } elseif (Test-Path $setupExe) { $setupExe } else { '' }

if (-not (Test-Path $vswhere) -or [string]::IsNullOrWhiteSpace($updater)) {
    Write-Log '  VS Installer/vswhere not found. Is Visual Studio installed here?' -Level ERROR
    exit 1
}
Write-Log ('  Updater : ' + $updater)

# --------------------------------------------------------------
# Enumerate all instances (including prerelease / non-default)
# --------------------------------------------------------------
$json = & $vswhere -all -prerelease -format json 2>$null | Out-String
try {
    $instances = $json | ConvertFrom-Json
} catch {
    Write-Log ('  Failed to parse vswhere output: ' + $_) -Level ERROR
    exit 1
}
if (-not $instances) {
    Write-Log '  No VS instances reported by vswhere.'
    exit 0
}

foreach ($inst in $instances) {
    $instId   = $inst.instanceId
    $instPath = $inst.installationPath
    $instVer  = $inst.installationVersion
    $instName = $inst.displayName
    Write-Log ''
    Write-Log ('--- ' + $instName + ' (' + $instVer + ') ---')
    Write-Log ('  Path: ' + $instPath)

    # Is this instance's devenv running?
    $devenv = Join-Path $instPath 'Common7\IDE\devenv.exe'
    $running = Get-Process -Name 'devenv' -ErrorAction SilentlyContinue |
               Where-Object { $_.Path -eq $devenv }
    if ($running) {
        if (-not $ForceCloseVS) {
            Write-Log '  devenv.exe RUNNING for this instance -- skipping (use -ForceCloseVS' -Level WARN
            Write-Log '  to override). Will be picked up on a later run. Exit 2 at end.' -Level WARN
            $Skipped++
            continue
        }
        if (-not $DryRun) {
            Write-Log '  -ForceCloseVS: closing devenv.exe...' -Level WARN
            $running | Stop-Process -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
        }
    }

    if ($DryRun) {
        Write-Log ('  [DRYRUN] Would run: update --installPath "' + $instPath + '" --passive --norestart')
        continue
    }

    # Update this instance. --wait makes vs_installer block on the SETUP
    # ENGINE and return ITS exit code -- without it, vs_installer.exe hands
    # off to a background process and the launcher's own quick exit (often 1)
    # is meaningless. --quiet avoids UI in SYSTEM context.
    $updArgs = @('update', '--installPath', $instPath, '--quiet', '--norestart', '--force', '--wait')
    Write-Log '  Updating (quiet, --wait on setup engine, no restart)...'
    $started = Get-Date
    $p = Start-Process -FilePath $updater -ArgumentList $updArgs -Wait -PassThru
    $elapsed = [math]::Round(((Get-Date) - $started).TotalSeconds)
    $code = $p.ExitCode
    Write-Log ('  Setup engine exit code: ' + $code + '  (took ' + $elapsed + 's)')

    # VS installer exit codes:
    #   0    = success
    #   3010 = success, reboot required
    #   1    = generic failure (see VS installer logs: %TEMP%\dd_*.log)
    #   1618 = another install already running -- retry later
    #   5007 = blocked (e.g. pending reboot from a prior operation)
    if ($code -eq 0) {
        # ok
    } elseif ($code -eq 3010) {
        Write-Log '  Update applied; reboot recommended.' -Level WARN
    } elseif ($code -eq 1618) {
        Write-Log '  1618: another VS/MSI install is in progress. Retry after it finishes.' -Level ERROR
        $Failed++; continue
    } elseif ($code -eq 5007) {
        Write-Log '  5007: update blocked -- usually a PENDING REBOOT from a prior op.' -Level ERROR
        Write-Log '  Reboot this machine, then re-run.' -Level ERROR
        $Failed++; continue
    } else {
        Write-Log ('  Update FAILED (' + $code + '). Check VS installer logs on the host:') -Level ERROR
        Write-Log '    Get-ChildItem $env:TEMP\dd_*.log | Sort LastWriteTime -Desc | Select -First 3' -Level ERROR
        # If it died in seconds, nothing downloaded -- likely network/proxy (Zscaler)
        if ($elapsed -lt 30) {
            Write-Log '  Failed in <30s = nothing downloaded; suspect Zscaler blocking the VS CDN' -Level ERROR
            Write-Log '  (download.visualstudio.microsoft.com / aka.ms). Verify egress, then retry.' -Level ERROR
        }
        $Failed++; continue
    }

    # Verify new version via vswhere for this instance id
    Start-Sleep -Seconds 3
    $recheck = & $vswhere -all -prerelease -format json 2>$null | Out-String | ConvertFrom-Json
    $now = $recheck | Where-Object { $_.instanceId -eq $instId }
    if ($now) {
        Write-Log ('  Post-update version: ' + $now.installationVersion)
        if ([version]$now.installationVersion -gt [version]$instVer) {
            Write-Log '  Version advanced.'
            $Updated++
        } else {
            Write-Log '  Version did not change -- may already be current, or update deferred.' -Level WARN
        }
    }
}

Write-Log ''
Write-Log '=============================================='
Write-Log (' Updated: ' + $Updated + '  Skipped(running): ' + $Skipped + '  Failed: ' + $Failed)
Write-Log ' Re-run a Nessus scan to confirm the VS plugins clear.'
Write-Log '=============================================='
if ($Failed -gt 0)  { exit 1 }
if ($Skipped -gt 0) { exit 2 }
exit 0
