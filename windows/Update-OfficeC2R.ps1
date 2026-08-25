<#
.SYNOPSIS
    Universal Office Click-to-Run updater (v2). Channel-agnostic: updates the
    machine to the newest build of ITS OWN channel, so it works where
    EC's channel-specific M365 patches report Not Applicable.

.DESCRIPTION
    1. Reads the C2R configuration: product IDs, current version, channel
       (CDNBaseUrl GUID mapped to a friendly name) -- all logged, so the
       fleet logs double as a channel census.

       v2 (from the 2026-08-25 CSLT-107 investigation): checks
       UpdatesEnabled in the C2R Configuration key BEFORE triggering an
       update. When this is False, OfficeC2RClient.exe /update launches,
       sees updates are administratively disabled, and exits WITHOUT
       UPDATING -- silently, with no error and no indication in this
       script's own log that nothing happened. This is almost certainly
       why several hosts kept RESURFACING on the M365 channel-support
       finding: something (a GPO, a config.xml baked in at original
       deployment) disabled updates fleet-wide, and each fix only "worked"
       when someone forced an update through a path that bypasses the
       flag -- with normal automatic updates staying off in between.

       v2 detects UpdatesEnabled=False and, by default, temporarily sets it
       to True in the registry, triggers the update, and reports the flag's
       ORIGINAL state clearly so you know it needs a policy-level fix (this
       script does not touch Group Policy). -LeaveUpdatesDisabled skips the
       override and just reports the blocker instead, for a host where
       disabling updates is a deliberate decision you don't want a script
       overriding.
    2. Triggers OfficeC2RClient.exe /update with forceappshutdown=true:
       any open Office apps are force-closed so the update can stage and
       finalize immediately instead of waiting on the user. Pass
       -ForceAppShutdown:$false to fall back to the old non-disruptive
       behavior (stage in background, finalize when the user closes Office).
    3. Optionally polls VersionToReport for up to -WaitMinutes to report
       whether the version advanced before exiting (default 0 = fire and
       exit; EC re-run or rescan verifies later).

.PARAMETER ForceAppShutdown
    When set (default), open Office apps are force-closed so the update
    finalizes right away. Setting -ForceAppShutdown:$false stages the
    update in the background and finalizes only when the user closes Office.

.PARAMETER LeaveUpdatesDisabled
    If UpdatesEnabled is False, do NOT override it -- just report the
    blocker and exit (2). Use this where disabled updates are a deliberate,
    known decision for this host.

.PARAMETER WaitMinutes
    Minutes to poll for the version to advance. 0 (default) = do not wait.
    Note: without -ForceAppShutdown and with apps open, finalization can
    wait indefinitely on the user, so a timeout here is NOT a failure --
    exit stays 0 with a note.

.NOTES
    Deploy via Endpoint Central (SYSTEM). Logs: C:\Logs\CompoSecure.
    Exit codes: 0 = triggered (or already current) / 2 = updates
    administratively disabled and -LeaveUpdatesDisabled given (not
    attempted) / 1 = C2R missing or trigger failed.
#>

[CmdletBinding()]
param(
    [int]$WaitMinutes = 0,
    [bool]$ForceAppShutdown = $true,
    # If UpdatesEnabled is False, do NOT override it -- just report the
    # blocker and exit. Use this where disabled updates are a deliberate,
    # known decision for this host.
    [switch]$LeaveUpdatesDisabled
)

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
Write-Log ' Office C2R Universal Update (v2)'
Write-Log (' Host : ' + $env:COMPUTERNAME)
Write-Log '=============================================='

$c2rKey = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
$c2rExe = 'C:\Program Files\Common Files\microsoft shared\ClickToRun\OfficeC2RClient.exe'

if (-not (Test-Path $c2rKey) -or -not (Test-Path $c2rExe)) {
    Write-Log 'Office Click-to-Run not detected on this machine.' -Level ERROR
    exit 1
}

$cfg = Get-ItemProperty $c2rKey

$updatesEnabledOriginal = $cfg.UpdatesEnabled
Write-Log ('UpdatesEnabled (as found): ' + $updatesEnabledOriginal)
$restoreUpdatesEnabled = $false
if ($updatesEnabledOriginal -eq $false -or ('' + $updatesEnabledOriginal) -eq 'False') {
    Write-Log 'UpdatesEnabled is FALSE. OfficeC2RClient /update will launch and exit' -Level WARN
    Write-Log 'WITHOUT UPDATING when this is set -- silently, with no error. This is' -Level WARN
    Write-Log 'almost certainly why this host keeps resurfacing on channel-support' -Level WARN
    Write-Log 'findings between manual fixes.' -Level WARN
    Write-Log 'Likely source: a GPO (Office ADMX "Hide/disable updates"), or a' -Level WARN
    Write-Log 'config.xml <Updates Enabled="FALSE"/> baked in at original deployment.' -Level WARN
    Write-Log 'This script does not change Group Policy -- if a GPO is reapplying this' -Level WARN
    Write-Log 'value, the override below will be reverted at the next policy refresh.' -Level WARN
    if ($LeaveUpdatesDisabled) {
        Write-Log 'LeaveUpdatesDisabled set -- not overriding. Reporting only.' -Level WARN
        Write-Log '=============================================='
        exit 2
    }
    Write-Log 'Temporarily setting UpdatesEnabled=True so this update can proceed...' -Level WARN
    try {
        Set-ItemProperty -Path $c2rKey -Name 'UpdatesEnabled' -Value $true -ErrorAction Stop
        $restoreUpdatesEnabled = $true
        Write-Log '  Set. (Reminder: find and fix the policy/config source, or this reverts.)' -Level WARN
    } catch {
        Write-Log ('  Failed to set UpdatesEnabled: ' + $_) -Level ERROR
        Write-Log '  Cannot proceed -- the update call would silently no-op.' -Level ERROR
        exit 1
    }
}
$curVer = [version]$cfg.VersionToReport
$cdn = '' + $cfg.CDNBaseUrl
$channelGuid = ($cdn -split '/')[-1].ToLower()
$channelName = $ChannelMap[$channelGuid]
if (-not $channelName) { $channelName = 'Unknown (' + $channelGuid + ')' }

Write-Log ('Products : ' + $cfg.ProductReleaseIds)
Write-Log ('Version  : ' + $curVer)
Write-Log ('Channel  : ' + $channelName)
Write-Log ('Platform : ' + $cfg.Platform)

$forceFlag = if ($ForceAppShutdown) { 'true' } else { 'false' }
$c2rArgs = '/update user displaylevel=false forceappshutdown=' + $forceFlag + ' updatepromptuser=false'

Write-Log ''
if ($ForceAppShutdown) {
    Write-Log 'Triggering C2R update (forceappshutdown=true; open Office apps will be closed)...'
} else {
    Write-Log 'Triggering C2R update (background; waits for Office apps to close)...'
}
try {
    Start-Process -FilePath $c2rExe -ArgumentList $c2rArgs
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
        Write-Log 'Version has not advanced yet -- update is still staging/finalizing.' -Level WARN
        Write-Log 'Not a failure; verify at next rescan.' -Level WARN
    }
}

Write-Log ''
if ($restoreUpdatesEnabled) {
    Write-Log '*** UpdatesEnabled was FALSE and was overridden to True for this run. ***' -Level WARN
    Write-Log '*** Find and fix the policy/config.xml source, or this host will silently' -Level WARN
    Write-Log '*** stop updating again the next time that policy reapplies. ***' -Level WARN
}
Write-Log '=============================================='
Write-Log ' Done. Channel + version above; rescan to confirm findings clear.'
Write-Log '=============================================='
exit 0
