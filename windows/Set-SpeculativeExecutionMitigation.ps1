<#
.SYNOPSIS
    Remediation: Windows Speculative Execution Configuration Check -
    Intel BHI (CVE-2022-0001). Nessus plugin 302873. (v1)

.DESCRIPTION
    Plugin 302873 reads two DWORDs under
      HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management
        FeatureSettingsOverrideMask
        FeatureSettingsOverride
    and accepts any of its three recommended settings (mask 0x3 in all):
      BHI only                 FeatureSettingsOverride 0x00800000   (default)
      Combined, HT enabled     FeatureSettingsOverride 0x00800048   (-Combined)
      Combined, HT disabled    FeatureSettingsOverride 0x00802048   (-CombinedDisableHT)

    v1 (2026-11-05 group export: swissqp-01..06, shrbpr-lb1/lc1/ld1,
    mimaki-ujf13/14/22 -- all 'FeatureSettingsOverrideMask: Not Set' and
    'FeatureSettingsOverride: Not Set').

    Behaviour:
      * Both values absent -> write the chosen setting.
      * Already one of the three accepted settings -> leave it (exit 0).
      * Something else is set: if adding only the BHI bit (0x00800000)
        produces an accepted setting, merge it in (e.g. 0x48 -> 0x800048).
        Otherwise HOLD with exit 2 -- an existing value may deliberately
        disable a mitigation (0x3 turns off Spectre v2 / Meltdown), and
        overwriting it is a decision for a human. -Force overwrites.
      * The kernel reads these values only at boot. After a change the
        script exits 3010 and records the change time; later runs keep
        returning 3010 until the machine has rebooted since that change.

    The mitigation also needs a Windows build that implements it; on an
    unpatched build the values are ignored at runtime (the scan, which
    reads the registry, still clears).

.PARAMETER Combined
    Write Tenable Recommended Settings 3 (0x00800048, HT enabled): BHI plus
    the combined speculative-execution mitigations.

.PARAMETER CombinedDisableHT
    Write Tenable Recommended Settings 2 (0x00802048): as -Combined but also
    disables Hyper-Threading. Costs CPU throughput; only on request.

.PARAMETER Force
    Overwrite an existing non-accepted FeatureSettingsOverride value.

.PARAMETER DryRun
    Log what would change; write nothing.

.NOTES
    Deploy via Endpoint Central (SYSTEM). Bare switches only.
    Configure EC "Specify exit code(s)" as 0,3010.
    Exit: 0 = compliant and active since last boot / 3010 = compliant, reboot
    required / 2 = existing value held for a human / 1 = could not write or verify.
#>

[CmdletBinding()]
param(
    [switch]$Combined,
    [switch]$CombinedDisableHT,
    [switch]$Force,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

$MmPath     = 'SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
$MarkerPath = 'SOFTWARE\CompoSecure\SpeculativeExecution'
$BhiBit     = 0x00800000
# GetValue returns a DWORD as Int32 (high bit set = negative). The literal
# 0xFFFFFFFF is Int32 -1 in PowerShell, so the unsigned mask must be built as Int64.
$DwordMask  = [int64]4294967295
$MaskValue  = 3
$Accepted   = @(
    @{ Name = 'BHI only';              Override = 0x00800000 },
    @{ Name = 'Combined, HT enabled';  Override = 0x00800048 },
    @{ Name = 'Combined, HT disabled'; Override = 0x00802048 }
)

function Format-Dword {
    param($Value)
    if ($null -eq $Value) { return 'Not Set' }
    return ('0x{0:X8}' -f ([int64]$Value -band $DwordMask))
}

function Get-AcceptedName {
    param($Override, $Mask)
    if ($null -eq $Override -or $null -eq $Mask) { return '' }
    if (([int64]$Mask -band $DwordMask) -ne $MaskValue) { return '' }
    $o = [int64]$Override -band $DwordMask
    foreach ($a in $Accepted) { if ($o -eq $a.Override) { return $a.Name } }
    return ''
}

function Get-MitigationPlan {
    # Returns @{ Action = Compliant | Set | Merge | Conflict; Override = <value to write> }
    param($CurrentOverride, $CurrentMask, [int64]$Target, [bool]$Force)
    $name = Get-AcceptedName $CurrentOverride $CurrentMask
    if ($name) { return @{ Action = 'Compliant'; Override = [int64]$CurrentOverride -band $DwordMask; Name = $name } }
    if ($null -eq $CurrentOverride -and $null -eq $CurrentMask) {
        return @{ Action = 'Set'; Override = $Target }
    }
    if ($null -ne $CurrentOverride) {
        $merged = ([int64]$CurrentOverride -band $DwordMask) -bor $BhiBit
        $mergedName = Get-AcceptedName $merged $MaskValue
        if ($mergedName) { return @{ Action = 'Merge'; Override = $merged; Name = $mergedName } }
    } elseif ($null -ne $CurrentMask -and ([int64]$CurrentMask -band $DwordMask) -eq $MaskValue) {
        return @{ Action = 'Set'; Override = $Target }
    }
    if ($Force) { return @{ Action = 'Set'; Override = $Target } }
    return @{ Action = 'Conflict'; Override = $Target }
}

function Test-RebootPending {
    param([datetime]$ChangedAt, [datetime]$LastBoot)
    return ($ChangedAt -gt $LastBoot)
}

if ($env:SPECEXEC_DOTSOURCE -eq '1') { return }

$LogDir  = 'C:\Logs\CompoSecure'
$LogFile = Join-Path $LogDir ('SpeculativeExecution_302873_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

function Read-MmValues {
    $k = $script:Hklm.OpenSubKey($MmPath, $false)
    try {
        return @{
            Override = $k.GetValue('FeatureSettingsOverride', $null)
            Mask     = $k.GetValue('FeatureSettingsOverrideMask', $null)
        }
    } finally { $k.Close() }
}

Write-Log '=============================================='
Write-Log ' Speculative Execution Mitigation - Intel BHI (plugin 302873) v1'
Write-Log '=============================================='

$target = 0x00800000; $targetName = 'BHI only'
if ($CombinedDisableHT) { $target = 0x00802048; $targetName = 'Combined, HT disabled' }
elseif ($Combined)      { $target = 0x00800048; $targetName = 'Combined, HT enabled' }
Write-Log ('Host     : ' + $env:COMPUTERNAME)
Write-Log ('Target   : ' + $targetName + '  FeatureSettingsOverride ' + (Format-Dword $target) + '  Mask ' + (Format-Dword $MaskValue))
if ($DryRun) { Write-Log 'DryRun   : nothing will be written.' }

try {
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $os  = Get-CimInstance Win32_OperatingSystem
    Write-Log ('CPU      : ' + $cpu.Name + '  (' + $cpu.Manufacturer + ')')
    Write-Log ('OS       : ' + $os.Caption + '  build ' + $os.BuildNumber + '.' + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).UBR)
    $lastBoot = $os.LastBootUpTime
    Write-Log ('LastBoot : ' + $lastBoot.ToString('yyyy-MM-dd HH:mm:ss'))
    if ($cpu.Manufacturer -ne 'GenuineIntel') {
        Write-Log 'Not an Intel CPU: BHI does not apply, but the scan still reads the registry. Setting it is harmless.' 'WARN'
    }
} catch {
    Write-Log ('Could not read CPU/OS info: ' + $_.Exception.Message) 'WARN'
    $lastBoot = [datetime]::MinValue
}

# HKLM\SYSTEM is not WOW64-redirected, but the 32-bit EC agent should never
# depend on that: open the 64-bit view explicitly.
$script:Hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)

$before = Read-MmValues
Write-Log ('Current  : FeatureSettingsOverrideMask ' + (Format-Dword $before.Mask) + '  FeatureSettingsOverride ' + (Format-Dword $before.Override))

$plan = Get-MitigationPlan $before.Override $before.Mask $target ([bool]$Force)
Write-Log ('Plan     : ' + $plan.Action)

switch ($plan.Action) {
    'Compliant' {
        Write-Log ('Already an accepted setting (' + $plan.Name + '). Not changing it.') 'OK'
    }
    'Conflict' {
        Write-Log 'FeatureSettingsOverride is set to a value that is not one of the accepted' 'WARN'
        Write-Log 'settings, and adding the BHI bit alone does not make it one. It may be' 'WARN'
        Write-Log 'deliberately disabling a mitigation (0x1 = Spectre v2 off, 0x2 = Meltdown off).' 'WARN'
        Write-Log ('RESULT: HELD -- not overwritten. Re-run with -Force to write ' + (Format-Dword $target) + ', or pick -Combined.') 'WARN'
        exit 2
    }
    { $_ -in 'Set', 'Merge' } {
        $what = 'FeatureSettingsOverrideMask=' + (Format-Dword $MaskValue) + '  FeatureSettingsOverride=' + (Format-Dword $plan.Override)
        if ($plan.Action -eq 'Merge') { $what = $what + '  (existing value + BHI bit = ' + $plan.Name + ')' }
        if ($DryRun) {
            Write-Log ('[DRYRUN] Would write ' + $what)
            Write-Log 'RESULT: dry run, nothing changed.'
            exit 0
        }
        Write-Log ('Writing  : ' + $what)
        try {
            $k = $script:Hklm.OpenSubKey($MmPath, $true)
            $k.SetValue('FeatureSettingsOverrideMask', [int]$MaskValue, [Microsoft.Win32.RegistryValueKind]::DWord)
            $k.SetValue('FeatureSettingsOverride', [int]$plan.Override, [Microsoft.Win32.RegistryValueKind]::DWord)
            $k.Close()
            $m = $script:Hklm.CreateSubKey($MarkerPath)
            $m.SetValue('ChangedAt', (Get-Date).ToString('o'), [Microsoft.Win32.RegistryValueKind]::String)
            $m.SetValue('Override', (Format-Dword $plan.Override), [Microsoft.Win32.RegistryValueKind]::String)
            $m.Close()
        } catch {
            Write-Log ('Write failed: ' + $_.Exception.Message) 'ERROR'
            Write-Log 'RESULT: FAILED -- registry not changed.' 'ERROR'
            exit 1
        }
    }
    default {
        Write-Log ('Unknown plan action: ' + $plan.Action) 'ERROR'
        exit 1
    }
}

$after = Read-MmValues
Write-Log ('Readback : FeatureSettingsOverrideMask ' + (Format-Dword $after.Mask) + '  FeatureSettingsOverride ' + (Format-Dword $after.Override))
$acceptedNow = Get-AcceptedName $after.Override $after.Mask
if (-not $acceptedNow) {
    Write-Log 'RESULT: FAILED -- readback is not an accepted setting.' 'ERROR'
    exit 1
}

$changedAt = $null
$marker = $script:Hklm.OpenSubKey($MarkerPath, $false)
if ($marker) {
    $raw = $marker.GetValue('ChangedAt', $null)
    $marker.Close()
    if ($raw) { try { $changedAt = [datetime]::Parse($raw, $null, [System.Globalization.DateTimeStyles]::RoundtripKind) } catch { $changedAt = $null } }
}
if ($changedAt -and (Test-RebootPending $changedAt $lastBoot)) {
    Write-Log ('RESULT: ' + $acceptedNow + ' is set (changed ' + $changedAt.ToString('yyyy-MM-dd HH:mm') + '). The kernel applies it at') 'WARN'
    Write-Log '        boot: REBOOT REQUIRED for the mitigation to take effect. Exiting 3010.' 'WARN'
    exit 3010
}
Write-Log ('RESULT: ' + $acceptedNow + ' is set and in effect since the last boot.') 'OK'
exit 0
