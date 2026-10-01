# Unit tests for Update-OfficeC2R.ps1 user-warning helpers.
# Run: pwsh -NoProfile -File windows/tests/Update-OfficeC2R.Tests.ps1
#
# -NotifyMinutes warns the signed-in user before forceappshutdown closes
# Office. The warning is only sent when an Office app is actually open,
# and msg.exe must be reached through Sysnative from 32-bit PowerShell.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path (Split-Path -Parent $here) 'Update-OfficeC2R.ps1'
$env:OFFICE_C2R_DOTSOURCE = '1'
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
function Assert-True {
    param([bool]$Cond, [string]$Name)
    if (-not $Cond) { Write-Host "FAIL $Name"; $script:failed++ } else { Write-Host "OK   $Name" }
}

$open = Get-OpenOfficeApps -ProcessNames @('explorer', 'OUTLOOK', 'winword', 'chrome', 'WINWORD')
Assert-Eq ($open -join ',') 'Word,Outlook' 'Office processes map to friendly names, de-duplicated, case-insensitive'

$one = Get-OpenOfficeApps -ProcessNames @('EXCEL')
Assert-Eq $one.Count 1 'a single open app still counts as one'

$none = Get-OpenOfficeApps -ProcessNames @('explorer', 'chrome', 'ms-teams')
Assert-Eq $none.Count 0 'no Office processes means nothing to warn about'

$empty = Get-OpenOfficeApps -ProcessNames @()
Assert-Eq $empty.Count 0 'empty process list returns an empty list'

Assert-Eq (Get-MsgExePath -WinDir 'C:\Windows' -Is64BitOS $true -Is64BitProcess $false) 'C:\Windows\Sysnative\msg.exe' '32-bit PowerShell on 64-bit Windows uses Sysnative'
Assert-Eq (Get-MsgExePath -WinDir 'C:\Windows' -Is64BitOS $true -Is64BitProcess $true) 'C:\Windows\System32\msg.exe' '64-bit PowerShell uses System32'
Assert-Eq (Get-MsgExePath -WinDir 'C:\Windows' -Is64BitOS $false -Is64BitProcess $false) 'C:\Windows\System32\msg.exe' '32-bit Windows uses System32'

$text = Get-NotifyText -Apps @('Word', 'Outlook') -Minutes 5
Assert-True ($text -like '*In 5 minutes*') 'default text states the delay'
Assert-True ($text -like '*Word, Outlook*') 'default text lists the open apps'
Assert-True ((Get-NotifyText -Apps @('Excel') -Minutes 1) -like '*In 1 minute,*') 'one minute is singular'
Assert-Eq (Get-NotifyText -Apps @('Word') -Minutes 5 -Custom 'Save now') 'Save now' 'custom message overrides the default'

if ($failed -gt 0) { Write-Host "$failed test(s) failed"; exit 1 }
Write-Host 'All tests passed'
exit 0
