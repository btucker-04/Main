# Unit tests for Disable-OfficeVbaProjectAccess.ps1 decision helpers.
# Run: pwsh -NoProfile -File windows/tests/Disable-OfficeVbaProjectAccess.Tests.ps1
#
# Plugin 123461 (CSLT-201, 2026-10-12): AccessVBOM on for an Office app. User
# and machine settings are turned off; Group Policy / Intune values are only
# reported unless -EnforcePolicy, because the policy would re-apply them.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path (Split-Path -Parent $here) 'Disable-OfficeVbaProjectAccess.ps1'
$env:OFFICE_VBOM_DOTSOURCE = '1'
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

# --- Get-VbomAction ----------------------------------------------------------
Assert-Eq (Get-VbomAction -Value 1 -IsPolicy $false -EnforcePolicy $false) 'DISABLE' 'user setting 1 is disabled'
Assert-Eq (Get-VbomAction -Value 0 -IsPolicy $false -EnforcePolicy $false) 'OK' 'user setting 0 is left'
Assert-Eq (Get-VbomAction -Value $null -IsPolicy $false -EnforcePolicy $false) 'OK' 'absent value is OK'
Assert-Eq (Get-VbomAction -Value 2 -IsPolicy $false -EnforcePolicy $false) 'DISABLE' 'any nonzero value counts as on'
Assert-Eq (Get-VbomAction -Value 'junk' -IsPolicy $false -EnforcePolicy $false) 'DISABLE' 'unparseable value is treated as on'
Assert-Eq (Get-VbomAction -Value 1 -IsPolicy $true -EnforcePolicy $false) 'REPORT' 'policy 1 is reported, not changed'
Assert-Eq (Get-VbomAction -Value 1 -IsPolicy $true -EnforcePolicy $true) 'DISABLE' 'policy 1 is overwritten with -EnforcePolicy'
Assert-Eq (Get-VbomAction -Value 0 -IsPolicy $true -EnforcePolicy $false) 'OK' 'policy 0 is OK'

# --- Get-OfficeBaseKeys --------------------------------------------------------
$user = @(Get-OfficeBaseKeys -IsMachine $false)
Assert-Eq ($user | ForEach-Object { $_.Path }) 'SOFTWARE\Microsoft\Office SOFTWARE\Policies\Microsoft\Office' 'user hive: setting and policy subtrees'
Assert-Eq (($user | Where-Object { $_.IsPolicy }).Path) 'SOFTWARE\Policies\Microsoft\Office' 'policy subtree flagged as policy'
$machine = @(Get-OfficeBaseKeys -IsMachine $true)
Assert-Eq $machine.Count 4 'machine hive adds both WOW6432Node subtrees'
Assert-Eq (($machine | Where-Object { $_.IsPolicy }).Count) 2 'two of the machine subtrees are policy'

# --- Select-UserProfiles -------------------------------------------------------
$entries = @(
    [pscustomobject]@{ Sid = 'S-1-5-18'; ProfilePath = 'C:\Windows\system32\config\systemprofile' },
    [pscustomobject]@{ Sid = 'S-1-5-19'; ProfilePath = 'C:\Windows\ServiceProfiles\LocalService' },
    [pscustomobject]@{ Sid = 'S-1-5-21-111-222-333-1001'; ProfilePath = 'C:\Users\jdoe' },
    [pscustomobject]@{ Sid = 'S-1-5-21-111-222-333-1002'; ProfilePath = 'C:\Users\gone' },
    [pscustomobject]@{ Sid = 'S-1-5-21-111-222-333-1003.bak'; ProfilePath = 'C:\Users\temp' },
    [pscustomobject]@{ Sid = 'S-1-5-21-111-222-333-1004'; ProfilePath = '' }
)
$exists = { param($p) $p -ne 'C:\Users\gone' }
$sel = @(Select-UserProfiles -Entries $entries -PathExists $exists)
Assert-Eq ($sel | ForEach-Object { $_.ProfilePath }) 'C:\Users\jdoe' 'only real user profiles with a folder are kept'

if ($failed -gt 0) {
    Write-Host "`n$failed test(s) failed"
    exit 1
}
Write-Host "`nAll tests passed"
exit 0
