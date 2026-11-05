# Unit tests for Set-SpeculativeExecutionMitigation.ps1 (plugin 302873).
# Run: pwsh -NoProfile -File windows/tests/Set-SpeculativeExecutionMitigation.Tests.ps1
#
# 2026-11-05 export (swissqp, shrbpr, mimaki hosts):
#   FeatureSettingsOverrideMask: Not Set
#   FeatureSettingsOverride: Not Set
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path (Split-Path -Parent $here) 'Set-SpeculativeExecutionMitigation.ps1'
$env:SPECEXEC_DOTSOURCE = '1'
. $scriptPath
$failed = 0
function Assert-Equal {
    param($Got, $Want, [string]$Name)
    if ($Got -ne $Want) {
        Write-Host ('FAIL ' + $Name + ': got ' + $Got + ' want ' + $Want)
        $script:failed++
    } else {
        Write-Host ('OK   ' + $Name)
    }
}

# --- The export: both Not Set -------------------------------------------------
$p = Get-MitigationPlan $null $null 0x00800000 $false
Assert-Equal $p.Action 'Set' 'Not Set / Not Set -> Set'
Assert-Equal (Format-Dword $p.Override) '0x00800000' 'default target is Recommended Settings 1 (BHI only)'
$p = Get-MitigationPlan $null $null 0x00800048 $false
Assert-Equal (Format-Dword $p.Override) '0x00800048' '-Combined target is Recommended Settings 3'

# --- Each of Tenable's three recommended settings is left alone ---------------
foreach ($v in 0x00800000, 0x00800048, 0x00802048) {
    $p = Get-MitigationPlan $v 3 0x00800000 $false
    Assert-Equal $p.Action 'Compliant' ('accepted ' + (Format-Dword $v) + ' is compliant')
}
Assert-Equal (Get-AcceptedName 0x00800000 3) 'BHI only' 'names Recommended Settings 1'
Assert-Equal (Get-AcceptedName 0x00800000 1) '' 'wrong mask is not accepted'
Assert-Equal (Get-AcceptedName 0x00800000 $null) '' 'missing mask is not accepted'

# --- Existing combined mitigation without the BHI bit: merge ------------------
$p = Get-MitigationPlan 0x48 3 0x00800000 $false
Assert-Equal $p.Action 'Merge' '0x48 gains the BHI bit'
Assert-Equal (Format-Dword $p.Override) '0x00800048' '0x48 -> 0x00800048'
$p = Get-MitigationPlan 0x2048 3 0x00800000 $false
Assert-Equal (Format-Dword $p.Override) '0x00802048' '0x2048 -> 0x00802048'
$p = Get-MitigationPlan 0x00800000 $null 0x00800000 $false
Assert-Equal $p.Action 'Merge' 'BHI value without a mask gets the mask'

# --- A value that disables mitigations is held, unless -Force -----------------
$p = Get-MitigationPlan 3 3 0x00800000 $false
Assert-Equal $p.Action 'Conflict' '0x3 (Spectre v2 + Meltdown off) is held'
$p = Get-MitigationPlan 3 3 0x00800000 $true
Assert-Equal $p.Action 'Set' '-Force overwrites 0x3'
Assert-Equal (Format-Dword $p.Override) '0x00800000' '-Force writes the target'
$p = Get-MitigationPlan $null 3 0x00800000 $false
Assert-Equal $p.Action 'Set' 'mask 3 with no override -> Set'
$p = Get-MitigationPlan $null 1 0x00800000 $false
Assert-Equal $p.Action 'Conflict' 'odd mask with no override is held'

# --- Reboot tracking -----------------------------------------------------------
$boot = [datetime]'2026-11-05T06:00:00'
Assert-Equal (Test-RebootPending ([datetime]'2026-11-05T09:30:00') $boot) $true 'changed after boot -> reboot pending'
Assert-Equal (Test-RebootPending ([datetime]'2026-11-04T17:00:00') $boot) $false 'changed before boot -> in effect'

Assert-Equal (Format-Dword $null) 'Not Set' 'absent value prints like the scan'
Assert-Equal (Format-Dword -1) '0xFFFFFFFF' 'negative DWORD prints unsigned'
# 0x80800000 comes back from GetValue as a negative Int32; it must not match 0x00800000.
Assert-Equal (Get-AcceptedName ([int]-2139095040) 3) '' 'high-bit DWORD is not the BHI setting'
$p = Get-MitigationPlan ([int]-2139095040) 3 0x00800000 $false
Assert-Equal $p.Action 'Conflict' 'high-bit DWORD is held, not merged'

if ($failed -gt 0) {
    Write-Host ([Environment]::NewLine + $failed + ' test(s) failed')
    exit 1
}
Write-Host ([Environment]::NewLine + 'All tests passed')
exit 0
