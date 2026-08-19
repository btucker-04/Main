<#
.SYNOPSIS
    Third-party remediation for cspc-100 (Cognex vision workstation):
      1. Notepad++ 8.9.3 -> 8.9.6.1+  (plugins 318684 / 311263 / 306546)
      2. Cursor < 3.0                 (plugin 324969, Sev 4)
      3. Office C2R -> 16.0.20026.20168 (plugins 320864 / 320865 / 320866)

.DESCRIPTION
    PRODUCTION-SAFE DEFAULTS for a shop-floor-adjacent vision machine:
      - Never reboots.
      - Never force-closes running apps unless -ForceCloseApps is passed;
        a component whose app is running is skipped (exit 2) for retry later.
      - Office C2R update runs with forceappshutdown=false, so it waits
        for Office apps to close on their own.

    Cursor note: it is a per-user install (found under Users\*\AppData).
    Running as SYSTEM cannot cleanly upgrade another user's per-user app.
      - Default        : notify the logged-in user to open Cursor (it
                         self-updates on launch) and log the finding.
      - -RemoveCursor  : delete the per-user install(s) entirely -- use if
                         Cursor is not sanctioned on this machine.

.PARAMETER RemoveCursor
    Remove per-user Cursor installs instead of notifying.

.PARAMETER ForceCloseApps
    Kill notepad++.exe / Cursor.exe if running instead of skipping.

.PARAMETER SkipNotepadPP / SkipCursor / SkipOffice
    Skip individual components.

.PARAMETER DryRun
    Log every action without changing anything.

.NOTES
    Deploy via Endpoint Central (SYSTEM). Logs: C:\Logs\CompoSecure.
    Exit codes: 0 = all done / 3010 n/a / 1 = failure / 2 = partial (skips)
    .NET Core 10.0.9 and Nessus Agent 11.2.0 on this machine are covered by
    Update-DotNetRuntimes_302122_307353.ps1 and NessusAgent_CleanReinstall.ps1.
#>

[CmdletBinding()]
param(
    [switch]$RemoveCursor,
    [switch]$ForceCloseApps,
    [switch]$SkipNotepadPP,
    [switch]$SkipCursor,
    [switch]$SkipOffice,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$LogDir  = 'C:\Logs\CompoSecure'
$LogFile = Join-Path $LogDir ('Remediate_ThirdParty_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}
function Notify-User {
    param([string]$Msg)
    try { & msg.exe * /TIME:60 $Msg 2>$null } catch { }
}

$NppTargetVersion    = [version]'8.9.6.1'
$NppUrl              = 'https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.9.6.1/npp.8.9.6.1.Installer.x64.exe'
$OfficeTargetVersion = [version]'16.0.20026.20168'

$Skipped = 0
$Failed  = 0

Write-Log '=============================================='
Write-Log ' Third-Party Remediation (cspc-100 profile)'
Write-Log (' Host   : ' + $env:COMPUTERNAME)
Write-Log (' DryRun : ' + $DryRun)
Write-Log '=============================================='
Write-Log 'NOTE: production vision workstation profile -- no reboots, no'
Write-Log 'forced app closures unless -ForceCloseApps.'

# ==============================================================
# 1. Notepad++  ->  8.9.6.1
# ==============================================================
Write-Log ''
Write-Log '[1/3] Notepad++ ...'
if ($SkipNotepadPP) {
    Write-Log '  Skipped by parameter.'
} else {
    $nppExe = 'C:\Program Files\Notepad++\notepad++.exe'
    if (-not (Test-Path $nppExe)) {
        Write-Log '  Notepad++ not installed. Nothing to do.'
    } else {
        $nppVer = [version](Get-Item $nppExe).VersionInfo.FileVersion
        Write-Log ('  Installed: ' + $nppVer + '  Target: ' + $NppTargetVersion)
        if ($nppVer -ge $NppTargetVersion) {
            Write-Log '  Already at or above target.'
        } else {
            $running = Get-Process -Name 'notepad++' -ErrorAction SilentlyContinue
            if ($running -and -not $ForceCloseApps) {
                Write-Log '  Notepad++ is RUNNING. Skipping to avoid losing unsaved work.' -Level WARN
                Notify-User 'IT Security: please close Notepad++ so a security update can install. It will be retried automatically.'
                $Skipped++
            } else {
                if ($running -and $ForceCloseApps -and -not $DryRun) {
                    Write-Log '  ForceCloseApps: killing notepad++.exe' -Level WARN
                    $running | Stop-Process -Force
                    Start-Sleep -Seconds 2
                }
                $installer = Join-Path $env:TEMP 'npp_update.exe'
                if ($DryRun) {
                    Write-Log ('  [DRYRUN] Would download ' + $NppUrl + ' and install /S')
                } else {
                    Write-Log ('  Downloading ' + $NppUrl)
                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                    Invoke-WebRequest -Uri $NppUrl -OutFile $installer -UseBasicParsing
                    $size = (Get-Item $installer).Length
                    Write-Log ('  Downloaded ' + [math]::Round($size/1MB,1) + ' MB')
                    if ($size -lt 3MB) {
                        Write-Log '  Download too small -- likely a block page (Zscaler?). Aborting component.' -Level ERROR
                        Remove-Item $installer -Force -ErrorAction SilentlyContinue
                        $Failed++
                    } else {
                        $p = Start-Process -FilePath $installer -ArgumentList '/S' -Wait -PassThru
                        Write-Log ('  Installer exit: ' + $p.ExitCode)
                        Remove-Item $installer -Force -ErrorAction SilentlyContinue
                        Start-Sleep -Seconds 3
                        $newVer = [version](Get-Item $nppExe).VersionInfo.FileVersion
                        Write-Log ('  Now installed: ' + $newVer)
                        if ($newVer -lt $NppTargetVersion) { Write-Log '  Version still below target!' -Level ERROR; $Failed++ }
                    }
                }
            }
        }
    }
}

# ==============================================================
# 2. Cursor (per-user installs)
# ==============================================================
Write-Log ''
Write-Log '[2/3] Cursor ...'
if ($SkipCursor) {
    Write-Log '  Skipped by parameter.'
} else {
    $cursorDirs = Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
                  ForEach-Object { Join-Path $_.FullName 'AppData\Local\Programs\cursor' } |
                  Where-Object { Test-Path (Join-Path $_ 'Cursor.exe') }
    if (-not $cursorDirs) {
        Write-Log '  No per-user Cursor installs found.'
    } else {
        foreach ($dir in $cursorDirs) {
            $owner = ($dir -split '\\')[2]
            $cVer = (Get-Item (Join-Path $dir 'Cursor.exe')).VersionInfo.ProductVersion
            Write-Log ('  Found: ' + $dir + '  (user: ' + $owner + ', version: ' + $cVer + ')')

            if (-not $RemoveCursor) {
                Write-Log '  Default mode: per-user app cannot be upgraded from SYSTEM context.' -Level WARN
                Write-Log '  Notifying user to launch Cursor (self-updates) or contact IT.' -Level WARN
                Notify-User ('IT Security: your Cursor editor (v' + $cVer + ') has a critical vulnerability. Please open Cursor and let it update to 3.x, or contact IT.')
                $Skipped++
                continue
            }

            # -RemoveCursor: purge the per-user install
            $running = Get-Process -Name 'Cursor' -ErrorAction SilentlyContinue
            if ($running -and -not $ForceCloseApps) {
                Write-Log '  Cursor is RUNNING. Skipping removal (use -ForceCloseApps to override).' -Level WARN
                $Skipped++
                continue
            }
            if ($DryRun) {
                Write-Log ('  [DRYRUN] Would remove ' + $dir + ' plus shortcuts and Updater dir.')
                continue
            }
            if ($running) { $running | Stop-Process -Force; Start-Sleep -Seconds 2 }
            try {
                Remove-Item $dir -Recurse -Force
                Write-Log '  Removed install directory.'
                $updater = 'C:\Users\' + $owner + '\AppData\Local\cursor-updater'
                if (Test-Path $updater) { Remove-Item $updater -Recurse -Force; Write-Log '  Removed updater directory.' }
                foreach ($lnk in @(
                    ('C:\Users\' + $owner + '\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Cursor.lnk'),
                    ('C:\Users\' + $owner + '\Desktop\Cursor.lnk')
                )) {
                    if (Test-Path $lnk) { Remove-Item $lnk -Force; Write-Log ('  Removed shortcut: ' + $lnk) }
                }
                Write-Log ('  Cursor removed for user ' + $owner + '.')
            } catch {
                Write-Log ('  Removal error: ' + $_) -Level ERROR
                $Failed++
            }
        }
    }
}

# ==============================================================
# 3. Office C2R -> June 2026 build
# ==============================================================
Write-Log ''
Write-Log '[3/3] Office Click-to-Run ...'
if ($SkipOffice) {
    Write-Log '  Skipped by parameter.'
} else {
    $c2rKey = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
    $c2rExe = 'C:\Program Files\Common Files\microsoft shared\ClickToRun\OfficeC2RClient.exe'
    if (-not (Test-Path $c2rKey) -or -not (Test-Path $c2rExe)) {
        Write-Log '  Office C2R not detected. Nothing to do.'
    } else {
        $curVer = [version](Get-ItemProperty $c2rKey).VersionToReport
        Write-Log ('  Installed: ' + $curVer + '  Target: ' + $OfficeTargetVersion)
        if ($curVer -ge $OfficeTargetVersion) {
            Write-Log '  Already at or above target.'
        } elseif ($DryRun) {
            Write-Log '  [DRYRUN] Would trigger OfficeC2RClient.exe /update user (no forced app shutdown).'
        } else {
            Write-Log '  Triggering C2R update (waits for Office apps to close on their own)...'
            Start-Process -FilePath $c2rExe -ArgumentList '/update user displaylevel=false forceappshutdown=false updatepromptuser=false'
            Write-Log '  Update launched (runs asynchronously in the background).'
            Write-Log '  Version will advance once download+apply completes and Office apps are closed.'
            Notify-User 'IT Security: an Office security update will apply in the background. Please close Word/Excel/Outlook when convenient.'
        }
    }
}

# ==============================================================
Write-Log ''
Write-Log '=============================================='
Write-Log (' Done. Skipped: ' + $Skipped + '  Failed: ' + $Failed)
Write-Log (' Log: ' + $LogFile)
Write-Log ' Reminder: .NET Core (10.0.9) and Nessus Agent (11.2.0) on this'
Write-Log ' host are handled by the existing dedicated scripts.'
Write-Log '=============================================='
if ($Failed -gt 0) { exit 1 }
if ($Skipped -gt 0) { exit 2 }
exit 0
