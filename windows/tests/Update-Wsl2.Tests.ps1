# Unit tests for Update-Wsl2.ps1 outcome rules.
# Run: pwsh -NoProfile -File windows/tests/Update-Wsl2.Tests.ps1
#
# A host ran wsl --update, which printed "Updating ... to version: 2.7.14",
# then the script could not read the Appx version, stored 0.0.0, and failed
# because 0.0.0 is below the hardcoded floor 2.6.2. There is no floor.
# A completed update is success; an unreadable version is a warning.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path (Split-Path -Parent $here) 'Update-Wsl2.ps1'
$env:WSL_UPDATE_DOTSOURCE = '1'
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

$log = @'
Checking for updates.
Updating Windows Subsystem for Linux to version: 2.7.14.
Warning 1946.Property 'System.AppUserModel.ID' for shortcut 'WSL.lnk' could not be set.
'@

Assert-Eq (Get-WslVersionFromText -Text $log) '2.7.14' 'version is parsed from the update banner'
Assert-Eq (Get-WslVersionFromText -Text 'The most recent version of Windows Subsystem for Linux is already installed.') '' 'already-installed text has no version'
Assert-Eq (Get-WslVersionFromText -Text '') '' 'empty output has no version'

$updated = Get-WslUpdateOutcome -ExitCode 0 -OutputText $log -ReportedVersion ''
Assert-True $updated.Ok 'exit 0 with a banner version is success'
Assert-Eq $updated.Version '2.7.14' 'banner version is the reported version'

$unreadable = Get-WslUpdateOutcome -ExitCode 0 -OutputText 'Checking for updates.' -ReportedVersion ''
Assert-True $unreadable.Ok 'exit 0 with no readable version is still success'
Assert-Eq $unreadable.Version '' 'missing version stays empty, never 0.0.0'

$failedUpdate = Get-WslUpdateOutcome -ExitCode 1 -OutputText 'The service cannot be started.' -ReportedVersion ''
Assert-True (-not $failedUpdate.Ok) 'non-zero exit with no version banner is a failure'

# Appx can lag the banner. The banner wins when Appx is empty; a real Appx
# version is kept when present.
$appx = Get-WslUpdateOutcome -ExitCode 0 -OutputText $log -ReportedVersion '2.7.14.0'
Assert-Eq $appx.Version '2.7.14.0' 'an Appx version is not discarded'

if ($failed -gt 0) { Write-Host "`n$failed test(s) failed"; exit 1 }
Write-Host "`nAll tests passed"
exit 0
