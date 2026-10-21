# Unit tests for Get-OfficeC2RState.ps1 verdict logic.
# Run: pwsh -NoProfile -File windows/tests/Get-OfficeC2RState.Tests.ps1
#
# cslt-226 / cslt-062 / csdvlt-07 / csmelt-10 (2026-10-21): plugin 335115
# (Access C2R, August 2026) stayed ACTIVE after Update-OfficeC2R.ps1, which
# only launches the update. Tenable reads MsAccess.exe's file version
# (remote 16.0.20228.20110, fixed 16.0.20228.20190).
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path (Split-Path -Parent $here) 'Get-OfficeC2RState.ps1'
$env:OFFICE_C2R_STATE_DOTSOURCE = '1'
. $scriptPath
$failed = 0
function Assert-Eq {
    param($Actual, $Expected, [string]$Name)
    if ("$Actual" -ne "$Expected") {
        Write-Host "FAIL $Name : got '$Actual' expected '$Expected'"
        $script:failed++
    } else {
        Write-Host "OK   $Name"
    }
}

$c2r = 'C:\Program Files\Microsoft Office\root\Office16\'
$x86 = 'C:\Program Files (x86)\Microsoft Office\root\Office16\'
function F { param([string]$Path, [string]$Ver, [bool]$Active = $true)
    [pscustomobject]@{ Path = $Path; Version = $(if ($Ver) { [version]$Ver } else { $null }); Active = $Active }
}
function V { param([hashtable]$P)
    $base = @{ HasC2R = $true; Files = @(); ReportVersion = ''; PolicyTargetVersion = ''; UpdateToVersion = '';
               PolicyAutoUpdates = ''; UpdatesEnabled = 'True'; CustomSource = ''; ExpectVersion = '' }
    foreach ($k in $P.Keys) { $base[$k] = $P[$k] }
    return Get-StateVerdict @base
}

# Channel names
Assert-Eq (Get-C2RChannelName 'http://officecdn.microsoft.com/pr/55336b82-a18d-4dd6-b5f6-9e5095c314a6') 'Monthly Enterprise Channel' 'MEC from CDNBaseUrl'
Assert-Eq (Get-C2RChannelName 'http://officecdn.microsoft.com/pr/492350F6-3A01-4F97-B9C0-C7C6DDF67D60/') 'Current Channel' 'upper case + trailing slash'
Assert-Eq (Get-C2RChannelName 'http://officecdn.microsoft.com/pr/00000000-0000-0000-0000-000000000000') 'Unknown (00000000-0000-0000-0000-000000000000)' 'unknown guid'
Assert-Eq (Get-C2RChannelName '') '' 'no url'

# Folders
$folders = Get-OfficeFolders -Platform 'x64'
Assert-Eq (@($folders | Where-Object { $_.Active }).Path) 'C:\Program Files\Microsoft Office\root\Office16' 'x64 active root'
Assert-Eq (@($folders | Where-Object { $_.Active }).Count) '1' 'exactly one active folder'
Assert-Eq (@(Get-OfficeFolders -Platform 'x86' | Where-Object { $_.Active }).Path) 'C:\Program Files (x86)\Microsoft Office\root\Office16' 'x86 active root'
Assert-Eq (@($folders | Where-Object { $_.Path -like '*\Office15' }).Count) '2' 'MSI Office 2013 folders checked'

# Update source
Assert-Eq (Get-CustomUpdateSource @('', 'http://officecdn.microsoft.com/pr/55336b82-a18d-4dd6-b5f6-9e5095c314a6')) '' 'CDN is not custom'
Assert-Eq (Get-CustomUpdateSource @('\\fs01\OfficeUpdates', '')) '\\fs01\OfficeUpdates' 'UNC share is custom'
Assert-Eq (Get-CustomUpdateSource @('', '', '')) '' 'unset'

# Verdicts
$r = V @{ Files = @((F ($c2r + 'MSACCESS.EXE') '16.0.20228.20110')); ReportVersion = '16.0.20228.20110'; ExpectVersion = '16.0.20228.20190' }
Assert-Eq $r[0] 'BELOW_EXPECTED' 'cslt-226 shape: update never landed'
Assert-Eq (@($r[2]) -join '|') ('below the fixed build 16.0.20228.20190: ' + $c2r + 'MSACCESS.EXE 16.0.20228.20110') 'finding names the file and build'

$r = V @{ Files = @((F ($c2r + 'MSACCESS.EXE') '16.0.20228.20110'), (F ($c2r + 'WINWORD.EXE') '16.0.20228.20190')); ReportVersion = '16.0.20228.20190'; ExpectVersion = '16.0.20228.20190' }
Assert-Eq $r[0] 'NOT_FINALIZED' 'C2R moved on but MsAccess.exe was not replaced'

$r = V @{ Files = @((F ($c2r + 'MSACCESS.EXE') '16.0.20228.20190'), (F ($x86 + 'MSACCESS.EXE') '16.0.17928.20114' $false)); ReportVersion = '16.0.20228.20190'; ExpectVersion = '16.0.20228.20190' }
Assert-Eq $r[0] 'LEFTOVER_FILES' 'old 32-bit Access left behind after a 64-bit move'

$r = V @{ Files = @((F 'C:\Program Files\Microsoft Office\Office16\MSACCESS.EXE' '16.0.5435.1001' $false), (F ($c2r + 'WINWORD.EXE') '16.0.20228.20190')); ReportVersion = '16.0.20228.20190' }
Assert-Eq $r[0] 'LEFTOVER_FILES' 'MSI Access 2016 beside C2R'

$r = V @{ Files = @((F ($c2r + 'MSACCESS.EXE') '16.0.20228.20110')); ReportVersion = '16.0.20228.20110'; PolicyTargetVersion = '16.0.20228.20110'; ExpectVersion = '16.0.20228.20190' }
Assert-Eq $r[0] 'PINNED_TARGET' 'policy target version outranks below-expected'

$r = V @{ Files = @((F ($c2r + 'MSACCESS.EXE') '16.0.20228.20110')); ReportVersion = '16.0.20228.20110'; PolicyAutoUpdates = '0' }
Assert-Eq $r[0] 'UPDATES_DISABLED' 'GPO enableautomaticupdates=0'

$r = V @{ Files = @((F ($c2r + 'MSACCESS.EXE') '16.0.20228.20110')); ReportVersion = '16.0.20228.20110'; UpdatesEnabled = 'False' }
Assert-Eq $r[0] 'UPDATES_DISABLED' 'C2R UpdatesEnabled=False'

$r = V @{ Files = @((F ($c2r + 'MSACCESS.EXE') '16.0.20228.20110')); ReportVersion = '16.0.20228.20110'; CustomSource = '\\fs01\OfficeUpdates' }
Assert-Eq $r[0] 'CUSTOM_SOURCE' 'update share'

$r = V @{ Files = @((F ($c2r + 'MSACCESS.EXE') '16.0.20228.20190')); ReportVersion = '16.0.20228.20190'; ExpectVersion = '16.0.20228.20190' }
Assert-Eq $r[0] 'CONSISTENT' 'patched host is consistent'
Assert-Eq (@($r[2]).Count) '0' 'no findings on a patched host'

$r = V @{ Files = @((F ($c2r + 'MSACCESS.EXE') '16.0.20228.20110')); ReportVersion = '16.0.20228.20110' }
Assert-Eq $r[0] 'CONSISTENT' 'without -ExpectVersion an old but consistent build is not flagged'

$r = V @{ Files = @((F ($c2r + 'MSACCESS.EXE') '16.0.20228.20190')); ReportVersion = '16.0.20228.20190'; ExpectVersion = '16.0.20228.20190'; UpdatesEnabled = 'False' }
Assert-Eq $r[0] 'UPDATES_DISABLED' 'disabled updates reported even when currently patched'

$r = V @{ HasC2R = $false; Files = @((F 'C:\Program Files\Microsoft Office\Office16\MSACCESS.EXE' '16.0.5435.1001' $false)) }
Assert-Eq $r[0] 'NOT_C2R' 'MSI-only machine'
Assert-Eq ((@($r[2]) -join '') -like '*Office16\MSACCESS.EXE 16.0.5435.1001*') 'True' 'MSI binary listed'

$r = V @{ Files = @((F ($c2r + 'MSACCESS.EXE') '16.0.20228.20190')); ReportVersion = '16.0.20228.20190'; ExpectVersion = '16.0.20300.20000' }
Assert-Eq $r[0] 'BELOW_EXPECTED' 'numeric build comparison'

if ($failed -gt 0) { Write-Host "$failed test(s) failed"; exit 1 }
Write-Host 'All tests passed'
exit 0
