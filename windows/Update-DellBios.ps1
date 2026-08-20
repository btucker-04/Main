<#
.SYNOPSIS
    Updates Dell client BIOS to the model-appropriate fixed version using
    Dell Command | Update CLI. Nessus Plugin 309963 (DSA-2025-153,
    Weak Password Recovery Mechanism).

.DESCRIPTION
    The 31 affected machines span 12 different Dell models, each with its own
    fixed BIOS version, so a per-model payload approach does not scale.
    dcu-cli queries Dell for THIS machine's applicable BIOS and applies it --
    model-agnostic by design.

    ** FIRMWARE SAFETY GUARDS -- all of these run before anything is flashed **
      1. BitLocker: every protected volume is suspended for ONE reboot
         (Suspend-BitLocker -RebootCount 1). A BIOS flash changes TPM
         measurements; without this, users hit a recovery-key prompt.
         Protection auto-resumes after the next restart.
      2. Power: aborts on laptops running on battery, or below
         -MinBatteryPercent. Desktops (no battery) pass automatically.
      3. Pending reboot: aborts if one is already pending -- stacking a BIOS
         flash on top of a pending servicing operation is asking for trouble.
      4. -reboot=disable: DCU stages the update and does NOT restart. You
         control when the flash actually happens (it applies at next boot).

.PARAMETER BiosPassword
    BIOS admin/setup password, if one is set. Without it the flash will fail
    (often silently) on password-protected systems. NOTE: the exact dcu-cli
    switch varies by DCU version (-password vs -encryptedPassword +
    -encryptionKey); if the log shows a password/authentication failure,
    verify the switch for the installed DCU version.

.PARAMETER MinBatteryPercent
    Minimum battery charge required on laptops. Default 30.

.PARAMETER RebootAfter
    Restart immediately after staging so the flash applies and BitLocker
    resumes promptly. Default OFF -- without it, plan a restart soon, since
    BitLocker stays suspended until the next reboot.

.PARAMETER DryRun
    Scan and report only. Does NOT suspend BitLocker and does NOT flash.

.NOTES
    Deploy via Endpoint Central (SYSTEM). Logs: C:\Logs\CompoSecure.
    Requires Dell Command | Update installed. Needs egress to Dell's update
    CDN (downloads.dell.com / dell.com) -- Zscaler may need a bypass.
    Exit: 0 = no update needed / 3010 = staged, reboot required
          2 = skipped by a safety guard / 1 = failure
#>

[CmdletBinding()]
param(
    [string]$BiosPassword     = '',
    [int]   $MinBatteryPercent = 30,
    [switch]$RebootAfter,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$LogDir  = 'C:\Logs\CompoSecure'
$LogFile = Join-Path $LogDir ('DellBIOSUpdate_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')
$DcuLog  = Join-Path $LogDir ('dcu_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

Write-Log '=============================================='
Write-Log ' Dell BIOS Update -- Plugin 309963 (DSA-2025-153)'
Write-Log (' Host   : ' + $env:COMPUTERNAME)
Write-Log (' DryRun : ' + $DryRun)
Write-Log '=============================================='

# ==============================================================
# 1. Inventory: model + current BIOS
# ==============================================================
Write-Log ''
Write-Log '[1/6] System inventory...'
$cs   = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
Write-Log ('  Manufacturer : ' + $cs.Manufacturer)
Write-Log ('  Model        : ' + $cs.Model)
Write-Log ('  BIOS version : ' + $bios.SMBIOSBIOSVersion)
Write-Log ('  BIOS date    : ' + $bios.ReleaseDate)

if ($cs.Manufacturer -notmatch 'Dell') {
    Write-Log '  Not a Dell system. Nothing to do.' -Level WARN
    exit 0
}

# ==============================================================
# 2. Locate dcu-cli
# ==============================================================
Write-Log ''
Write-Log '[2/6] Locating Dell Command | Update CLI...'
$dcu = ''
foreach ($p in @(
    'C:\Program Files\Dell\CommandUpdate\dcu-cli.exe',
    'C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe'
)) {
    if (Test-Path $p) { $dcu = $p; break }
}
if (-not $dcu) {
    Write-Log '  dcu-cli.exe NOT FOUND -- Dell Command | Update is not installed.' -Level ERROR
    Write-Log '  Deploy DCU via EC first (Dell Command | Update for Windows Universal),' -Level ERROR
    Write-Log '  then re-run. DCU is the model-aware path; without it each of the 12' -Level ERROR
    Write-Log '  affected models would need its own BIOS payload.' -Level ERROR
    exit 1
}
Write-Log ('  Found: ' + $dcu)

# ==============================================================
# 3. Safety guard: pending reboot
# ==============================================================
Write-Log ''
Write-Log '[3/6] Safety guard -- pending reboot...'
$pending = $false
foreach ($k in @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
)) {
    if (Test-Path $k) { $pending = $true }
}
$pfro = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
if ($pfro) { $pending = $true }

if ($pending) {
    Write-Log '  A reboot is already PENDING on this machine.' -Level WARN
    Write-Log '  Refusing to stage a BIOS flash on top of pending servicing work.' -Level WARN
    Write-Log '  Reboot first, then re-run. Exit 2.' -Level WARN
    exit 2
}
Write-Log '  No pending reboot.'

# ==============================================================
# 4. Safety guard: power / battery
# ==============================================================
Write-Log ''
Write-Log '[4/6] Safety guard -- power state...'
$batt = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue
if (-not $batt) {
    Write-Log '  No battery detected (desktop/tower) -- on AC by definition.'
} else {
    # BatteryStatus 2 = AC connected. 1 = discharging.
    $onAc    = ($batt | Where-Object { $_.BatteryStatus -eq 2 }) -ne $null
    $charge  = ($batt | Measure-Object -Property EstimatedChargeRemaining -Minimum).Minimum
    Write-Log ('  On AC power : ' + $onAc)
    Write-Log ('  Charge      : ' + $charge + '%')
    if (-not $onAc) {
        Write-Log '  Running on BATTERY. A BIOS flash must not run unplugged.' -Level WARN
        Write-Log '  Exit 2 -- retry when the machine is on AC.' -Level WARN
        exit 2
    }
    if ($charge -lt $MinBatteryPercent) {
        Write-Log ('  Charge below ' + $MinBatteryPercent + '% minimum. Exit 2 -- retry when charged.') -Level WARN
        exit 2
    }
}

# ==============================================================
# 5. Scan for an applicable BIOS update
# ==============================================================
Write-Log ''
Write-Log '[5/6] Scanning for applicable BIOS update...'
$scanArgs = @('/scan', '-updateType=bios', '-silent', ('-outputLog=' + $DcuLog))
$scan = Start-Process -FilePath $dcu -ArgumentList $scanArgs -Wait -PassThru -NoNewWindow
Write-Log ('  dcu-cli /scan exit code: ' + $scan.ExitCode)
# Common dcu-cli codes: 0 = success/updates found, 500 = no updates available,
# 1 = reboot required, 2/3 = error, 4 = invalid args. Codes vary by DCU version.
if ($scan.ExitCode -eq 500) {
    Write-Log '  DCU reports no applicable BIOS update for this model.'
    Write-Log '  If Tenable still flags it, the BIOS may already be at/above the fixed'
    Write-Log '  version, or DCU cannot reach Dell (check Zscaler egress to dell.com).'
    exit 0
}
if ($scan.ExitCode -ne 0) {
    Write-Log ('  Scan returned ' + $scan.ExitCode + ' -- see ' + $DcuLog) -Level ERROR
    exit 1
}

if ($DryRun) {
    Write-Log ''
    Write-Log '  [DRYRUN] A BIOS update IS available for this model.'
    Write-Log '  [DRYRUN] Would suspend BitLocker (1 reboot) and stage the flash.'
    Write-Log ('  [DRYRUN] DCU scan detail: ' + $DcuLog)
    Write-Log '=============================================='
    exit 0
}

# ==============================================================
# 6. Suspend BitLocker, apply, report
# ==============================================================
Write-Log ''
Write-Log '[6/6] Suspending BitLocker and applying BIOS update...'

$suspended = @()
try {
    $vols = Get-BitLockerVolume -ErrorAction Stop | Where-Object { $_.ProtectionStatus -eq 'On' }
    if (-not $vols) {
        Write-Log '  No BitLocker-protected volumes (nothing to suspend).'
    }
    foreach ($v in $vols) {
        Suspend-BitLocker -MountPoint $v.MountPoint -RebootCount 1 -ErrorAction Stop | Out-Null
        $suspended += $v.MountPoint
        Write-Log ('  Suspended BitLocker on ' + $v.MountPoint + ' for 1 reboot.')
    }
} catch {
    Write-Log ('  BitLocker handling failed: ' + $_) -Level ERROR
    Write-Log '  ABORTING before flash -- proceeding could trigger recovery prompts.' -Level ERROR
    exit 1
}

$applyArgs = @('/applyUpdates', '-updateType=bios', '-reboot=disable', '-silent', ('-outputLog=' + $DcuLog))
if ($BiosPassword) {
    $applyArgs += ('-password=' + $BiosPassword)
    Write-Log '  BIOS password supplied.'
}
$apply = Start-Process -FilePath $dcu -ArgumentList $applyArgs -Wait -PassThru -NoNewWindow
$code  = $apply.ExitCode
Write-Log ('  dcu-cli /applyUpdates exit code: ' + $code)

$ok = ($code -eq 0 -or $code -eq 1 -or $code -eq 5)
if (-not $ok) {
    Write-Log ('  Update FAILED (' + $code + '). See ' + $DcuLog) -Level ERROR
    if ($BiosPassword) {
        Write-Log '  If the log shows a password/auth failure, this DCU version may expect' -Level ERROR
        Write-Log '  -encryptedPassword + -encryptionKey instead of -password.' -Level ERROR
    }
    # Resume BitLocker since no flash is pending
    foreach ($mp in $suspended) {
        Resume-BitLocker -MountPoint $mp -ErrorAction SilentlyContinue | Out-Null
        Write-Log ('  Resumed BitLocker on ' + $mp + ' (no flash pending).')
    }
    exit 1
}

Write-Log ''
Write-Log '  BIOS update STAGED. The flash applies during the next restart.'
Write-Log ('  Current BIOS still reports: ' + (Get-CimInstance Win32_BIOS).SMBIOSBIOSVersion)
Write-Log '  Version will change only after the reboot completes.'
if ($suspended.Count -gt 0) {
    Write-Log '  BitLocker is SUSPENDED until the next reboot -- restart promptly.' -Level WARN
}

if ($RebootAfter) {
    Write-Log '  -RebootAfter set: restarting in 60 seconds...'
    & shutdown.exe /r /t 60 /c 'IT Security: applying a BIOS update. Please save your work.'
}

Write-Log '=============================================='
Write-Log ' Re-run a Nessus scan AFTER the reboot to confirm 309963 clears.'
Write-Log '=============================================='
exit 3010
