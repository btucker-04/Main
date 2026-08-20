<#
.SYNOPSIS
    Universal Office Click-to-Run updater. Channel-agnostic: updates the
    machine to the newest build of ITS OWN channel, so it works where
    EC's channel-specific M365 patches report Not Applicable.

.DESCRIPTION
    1. Reads the C2R configuration: product IDs, current version, channel
       (CDNBaseUrl GUID mapped to a friendly name) -- all logged, so the
       fleet logs double as a channel census.
    2. Triggers OfficeC2RClient.exe /update with forceappshutdown=false:
       the update stages in the background and finalizes when Office apps
       are closed by the user. No interruption.
    3. Optionally polls VersionToReport for up to -WaitMinutes to report
       whether the version advanced before exiting (default 0 = fire and
       exit; EC re-run or rescan verifies later).

.PARAMETER WaitMinutes
    Minutes to poll for the version to advance. 0 (default) = do not wait.
    Note: with apps open, finalization can wait indefinitely on the user,
    so a timeout here is NOT a failure -- exit stays 0 with a note.

.NOTES
    Deploy via Endpoint Central (SYSTEM). Logs: C:\Logs\CompoSecure.
    Exit codes: 0 = triggered (or already current) / 1 = C2R missing or
    trigger failed.
#>

[CmdletBinding()]
param([int]$WaitMinutes = 0)

$ErrorActionPreference = 'Stop'
$LogDir  = 'C:\Logs\CompoSecure'
$LogFile = Join-Path $LogDir ('OfficeC2RUpdate_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

$ChannelMap = @{
    '492350f6-3a01-4f97-b9c0-c7c6ddf67d60' = 'Current Channel'
    '55336b82-a18d-4dd6-b5f6-9e5095c314a6' = 'Monthly Enterprise Channel'
    '7ffbc6bf-bc32-4f92-8982-f9dd17fd3114' = 'Semi-Annual Enterprise Channel'
    'b8f9b850-328d-4355-9145-c59439a0c4cf' = 'Semi-Annual Enterprise Channel (Preview)'
    '64256afe-f5d9-4f86-8936-8840a6a4f5be' = 'Current Channel (Preview)'
    '5440fd1f-7ecb-4221-8110-145efaa6372f' = 'Beta Channel'
    'f2e724c1-748f-4b47-8fb8-8e0d210e9208' = 'Office 2019 Perpetual (PerpetualVL2019)'
    '5030841d-c919-4594-8d2d-84ae4f96e58e' = 'Office LTSC 2021 (PerpetualVL2021)'
    '7983bac0-e531-40cf-be00-fd24fe66619c' = 'Office LTSC 2024 (PerpetualVL2024)'
}

Write-Log '=============================================='
Write-Log ' Office C2R Universal Update'
Write-Log (' Host : ' + $env:COMPUTERNAME)
Write-Log '=============================================='

$c2rKey = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
$c2rExe = 'C:\Program Files\Common Files\microsoft shared\ClickToRun\OfficeC2RClient.exe'

if (-not (Test-Path $c2rKey) -or -not (Test-Path $c2rExe)) {
    Write-Log 'Office Click-to-Run not detected on this machine.' -Level ERROR
    exit 1
}

$cfg = Get-ItemProperty $c2rKey
$curVer = [version]$cfg.VersionToReport
$cdn = '' + $cfg.CDNBaseUrl
$channelGuid = ($cdn -split '/')[-1].ToLower()
$channelName = $ChannelMap[$channelGuid]
if (-not $channelName) { $channelName = 'Unknown (' + $channelGuid + ')' }

Write-Log ('Products : ' + $cfg.ProductReleaseIds)
Write-Log ('Version  : ' + $curVer)
Write-Log ('Channel  : ' + $channelName)
Write-Log ('Platform : ' + $cfg.Platform)

Write-Log ''
Write-Log 'Triggering C2R update (background; waits for Office apps to close)...'
try {
    Start-Process -FilePath $c2rExe -ArgumentList '/update user displaylevel=false forceappshutdown=false updatepromptuser=false'
    Write-Log 'Update launched.'
} catch {
    Write-Log ('Failed to launch OfficeC2RClient: ' + $_) -Level ERROR
    exit 1
}

if ($WaitMinutes -gt 0) {
    Write-Log ('Polling for version change (up to ' + $WaitMinutes + ' min)...')
    $deadline = (Get-Date).AddMinutes($WaitMinutes)
    $advanced = $false
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 60
        $nowVer = [version](Get-ItemProperty $c2rKey).VersionToReport
        if ($nowVer -gt $curVer) {
            Write-Log ('Version advanced: ' + $curVer + ' -> ' + $nowVer)
            $advanced = $true
            break
        }
    }
    if (-not $advanced) {
        Write-Log 'Version has not advanced yet -- update is staged and will finalize' -Level WARN
        Write-Log 'when Office apps are closed. Not a failure; verify at next rescan.' -Level WARN
    }
}

Write-Log ''
Write-Log '=============================================='
Write-Log ' Done. Channel + version above; rescan to confirm findings clear.'
Write-Log '=============================================='
exit 0
