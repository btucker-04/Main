# Unit tests for Remove-CitrixWorkspaceLegacy.ps1 decision helpers.
# Run: pwsh -NoProfile -File windows/tests/Remove-CitrixWorkspaceLegacy.Tests.ps1
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path (Split-Path -Parent $here) 'Remove-CitrixWorkspaceLegacy.ps1'
$env:CWA_LEGACY_DOTSOURCE = '1'
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

# --- Main entries -------------------------------------------------------------
foreach ($n in @('Citrix Workspace 2309', 'Citrix Workspace 2402', 'Citrix Workspace 2607 (x64)', 'Citrix Workspace 2607 (ARM64)',
        'Citrix Receiver', 'Citrix Receiver 4.12', 'Citrix Receiver 4.9 LTSR')) {
    Assert-Eq (Test-CwaMainEntryName -Name $n) 'True' ('main: ' + $n)
}
foreach ($n in @('Citrix Workspace(DV)', 'Citrix Workspace(USB)', 'Citrix Workspace Inside', 'Citrix Authentication Manager',
        'Citrix Web Helper', 'Citrix Files', 'Citrix Workspace Browser', 'Online Plug-in')) {
    Assert-Eq (Test-CwaMainEntryName -Name $n) 'False' ('component: ' + $n)
}

# --- Old vs current (plugin 207238: older than 2402 LTSR CU1) -----------------
$min = [version]'26.7'
Assert-Eq (Test-CwaVersionOld -Version ([version]'23.9.1.104') -Min $min) 'True' '2309 old'
Assert-Eq (Test-CwaVersionOld -Version ([version]'24.2.1000.1016') -Min $min) 'True' '2402 CU1 below the fleet target'
Assert-Eq (Test-CwaVersionOld -Version ([version]'26.7.0.269') -Min $min) 'False' '2607 current'
Assert-Eq (Test-CwaVersionOld -Version $null -Min $min) 'True' 'unknown version counts as old'

# --- Uninstall string -------------------------------------------------------
$dq = [string][char]34
Assert-Eq (Get-TrolleyExpressPath -UninstallString ($dq + 'C:\ProgramData\Citrix\Citrix Workspace 2309\TrolleyExpress.exe' + $dq + ' /uninstall /cleanup')) 'C:\ProgramData\Citrix\Citrix Workspace 2309\TrolleyExpress.exe' 'machine trolley'
Assert-Eq (Get-TrolleyExpressPath -UninstallString ($dq + 'C:\Users\jdoe\AppData\Local\Citrix\Citrix Workspace 2309\TrolleyExpress.exe' + $dq + ' /uninstall /cleanup')) 'C:\Users\jdoe\AppData\Local\Citrix\Citrix Workspace 2309\TrolleyExpress.exe' 'per-user trolley'
Assert-Eq (Get-TrolleyExpressPath -UninstallString 'C:\ProgramData\Citrix\Citrix Receiver 4.12\TrolleyExpress.exe /uninstall') 'C:\ProgramData\Citrix\Citrix Receiver 4.12\TrolleyExpress.exe' 'unquoted'
Assert-Eq (Get-TrolleyExpressPath -UninstallString 'MsiExec.exe /X{0000}') '' 'not trolley'
Assert-Eq ((Get-TrolleyUninstallArguments) -join ' ') '/uninstall /cleanup /silent' 'trolley arguments'

# --- Run entries ------------------------------------------------------------
$dir = 'C:\Users\jdoe\AppData\Local\Citrix'
Assert-Eq (Test-RunValueInFolder -Data ($dq + 'C:\Users\jdoe\AppData\Local\Citrix\ICA Client\concentr.exe' + $dq + ' /startup') -Folder $dir) 'True' 'connection center startup'
Assert-Eq (Test-RunValueInFolder -Data 'c:\users\JDOE\appdata\local\citrix\ICA Client\redirector.exe' -Folder $dir) 'True' 'case-insensitive'
Assert-Eq (Test-RunValueInFolder -Data 'C:\Program Files (x86)\Citrix\ICA Client\concentr.exe' -Folder $dir) 'False' 'machine install untouched'
Assert-Eq (Test-RunValueInFolder -Data 'C:\Users\jdoe\AppData\Local\CitrixOther\x.exe' -Folder $dir) 'False' 'prefix is not enough'
Assert-Eq (Test-RunValueInFolder -Data '' -Folder $dir) 'False' 'empty'

# --- Outcomes ---------------------------------------------------------------
Assert-Eq (Get-InstallOutcome -ExitCode 0) 'OK' '0'
Assert-Eq (Get-InstallOutcome -ExitCode 3010) 'REBOOT' '3010'
Assert-Eq (Get-InstallOutcome -ExitCode 1) 'FAIL' '1'
Assert-Eq (Get-InstallOutcome -ExitCode $null) 'UNKNOWN' 'no code'
Assert-Eq (Get-FinalExitCode -Failed $false -NeedsHuman $true -Reboot $false) '2' 'deferred'
$r = Get-RelaunchArguments -ScriptPath 'C:\s.ps1' -Bound @{ ReinstallMachineWide = [switch]$true; DryRun = [switch]$false }
Assert-Eq ($r -join ' ') '-NoProfile -ExecutionPolicy Bypass -File C:\s.ps1 -ReinstallMachineWide' 'relaunch arguments'

if ($failed -gt 0) { Write-Host "$failed test(s) failed"; exit 1 }
Write-Host 'All tests passed'
