# Unit tests for Remove-TeamsClassic.ps1 helpers.
# Run: pwsh -NoProfile -File windows/tests/Remove-TeamsClassic.Tests.ps1
#
# Paths are from the 2026-11-17 Tenable export for CSPRLT-46 (plugins
# 175408 / 179635): C:\Users\vdasilva\AppData\Local\Microsoft\Teams\current\
# at 1.5.0.28361.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path (Split-Path -Parent $here) 'Remove-TeamsClassic.ps1'
$env:REMOVE_TEAMS_DOTSOURCE = '1'
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

# --- which profiles are people ---------------------------------------------
Assert-Eq (Test-SkipProfileSid 'S-1-5-18') 'True' 'SYSTEM skipped'
Assert-Eq (Test-SkipProfileSid 'S-1-5-19') 'True' 'LOCAL SERVICE skipped'
Assert-Eq (Test-SkipProfileSid 'S-1-5-20') 'True' 'NETWORK SERVICE skipped'
Assert-Eq (Test-SkipProfileSid 'S-1-5-21-1004336348-1177238915-682003330-1001') 'False' 'domain/local user kept'
Assert-Eq (Test-SkipProfileSid 'S-1-12-1-1234567890-1234567890-1234567890-1234567890') 'False' 'Entra ID user kept'

# --- folders -------------------------------------------------------------------
$d = @(Get-ClassicTeamsDirs -ProfilePath 'C:\Users\vdasilva' -ProgramData 'C:\ProgramData')
Assert-Eq $d[0] 'C:\Users\vdasilva\AppData\Local\Microsoft\Teams' 'Tenable path is the first folder'
Assert-Eq $d[1] 'C:\ProgramData\vdasilva\Microsoft\Teams' 'ProgramData per-user variant'
$d = @(Get-ClassicTeamsDirs -ProfilePath 'C:\Users\vdasilva\' -ProgramData 'C:\ProgramData\')
Assert-Eq $d[0] 'C:\Users\vdasilva\AppData\Local\Microsoft\Teams' 'trailing backslash tolerated'

# --- shortcuts ---------------------------------------------------------------
Assert-Eq (Test-ClassicTeamsShortcut 'C:\Users\vdasilva\AppData\Local\Microsoft\Teams\Update.exe') 'True' 'classic Start Menu shortcut (Update.exe)'
Assert-Eq (Test-ClassicTeamsShortcut 'C:\Users\vdasilva\AppData\Local\Microsoft\Teams\current\Teams.exe') 'True' 'classic shortcut to current\Teams.exe'
Assert-Eq (Test-ClassicTeamsShortcut 'C:\Program Files\WindowsApps\MSTeams_25290.205.4069.4894_x64__8wekyb3d8bbwe\ms-teams.exe') 'False' 'new Teams shortcut kept'
Assert-Eq (Test-ClassicTeamsShortcut 'C:\Users\vdasilva\AppData\Local\Microsoft\TeamsMeetingAddin\1.0\x64\Microsoft.Teams.AddinLoader.dll') 'False' 'meeting add-in is not a Teams shortcut'
Assert-Eq (Test-ClassicTeamsShortcut '') 'False' 'empty target'

# --- Machine-Wide Installer --------------------------------------------------
Assert-Eq (Test-TeamsMachineWideEntry 'Teams Machine-Wide Installer') 'True' 'MWI display name'
Assert-Eq (Test-TeamsMachineWideEntry 'Microsoft Teams Meeting Add-in for Microsoft Office') 'False' 'add-in is not the MWI'
Assert-Eq (Test-TeamsMachineWideEntry 'Microsoft Teams classic') 'False' 'per-user entry is not the MWI'
Assert-Eq (Get-MsiProductCode -UninstallString 'MsiExec.exe /I{731F6BAA-A986-45A4-8936-7C3AAAAA760B}' -KeyName '{731F6BAA-A986-45A4-8936-7C3AAAAA760B}') '{731F6BAA-A986-45A4-8936-7C3AAAAA760B}' 'product code from key name'
Assert-Eq (Get-MsiProductCode -UninstallString 'MsiExec.exe /X{39aff8f1-a2e9-4cd0-a8d7-5b5d0a9c5c4e}' -KeyName 'TeamsMWI') '{39AFF8F1-A2E9-4CD0-A8D7-5B5D0A9C5C4E}' 'product code from UninstallString, upper-cased'
Assert-Eq (Get-MsiProductCode -UninstallString '' -KeyName 'Teams') '' 'no code'

# --- exit codes --------------------------------------------------------------
Assert-Eq (Get-MsiExitMeaning 1605) 'product not installed (already gone)' '1605'
Assert-Eq (Get-MsiExitMeaning 3010) 'success, reboot required' '3010'
Assert-Eq (Get-MsiExitMeaning 1603) 'failed (code 1603)' 'unknown code named'
Assert-Eq (Get-FinalExitCode -Failed $true -NeedsHuman $true -Reboot $true) 1 'failure wins'
Assert-Eq (Get-FinalExitCode -Failed $false -NeedsHuman $true -Reboot $true) 2 'held beats reboot'
Assert-Eq (Get-FinalExitCode -Failed $false -NeedsHuman $false -Reboot $true) 3010 'reboot'
Assert-Eq (Get-FinalExitCode -Failed $false -NeedsHuman $false -Reboot $false) 0 'clean'

# --- deletion is verified ----------------------------------------------------
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('teams_' + [guid]::NewGuid())
$teams = Join-Path $tmp 'Teams'
New-Item -ItemType Directory -Path (Join-Path $teams 'current') -Force | Out-Null
Set-Content -Path (Join-Path $teams 'current/Teams.exe') -Value 'x'
Set-Content -Path (Join-Path $teams 'Update.exe') -Value 'x'
(Get-Item (Join-Path $teams 'Update.exe')).Attributes = 'ReadOnly'
Assert-Eq (Remove-PathVerified -Path $teams) '' 'folder with a read-only file is deleted'
Assert-Eq (Test-Path $teams) 'False' 'folder is gone afterwards'
Assert-Eq (Remove-PathVerified -Path (Join-Path $tmp 'missing')) '' 'missing path counts as removed'
Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ''
if ($failed -gt 0) { Write-Host "$failed test(s) failed"; exit 1 }
Write-Host 'All tests passed'
exit 0
