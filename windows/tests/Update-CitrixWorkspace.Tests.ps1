# Unit tests for Update-CitrixWorkspace.ps1 decision helpers.
# Run: pwsh -NoProfile -File windows/tests/Update-CitrixWorkspace.Tests.ps1
#
# CWA 2409 through 2507.1 LTSR CU2 need the x86 .NET Desktop Runtime 8.x;
# 2607 LTSR needs 10.0.9+. .NET 8 may only go once CWA is on a .NET 10 build
# and no other app still binds to an 8.x shared framework.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path (Split-Path -Parent $here) 'Update-CitrixWorkspace.ps1'
$env:CITRIX_WORKSPACE_DOTSOURCE = '1'
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

# --- ARP selection -----------------------------------------------------------
$arp = @(
    [pscustomobject]@{ DisplayName = 'Citrix Workspace(DV)'; DisplayVersion = '25.7.1.10' },
    [pscustomobject]@{ DisplayName = 'Citrix Workspace Inside'; DisplayVersion = '25.7.1.10' },
    [pscustomobject]@{ DisplayName = 'Citrix Workspace 2507'; DisplayVersion = '25.7.1.10' },
    [pscustomobject]@{ DisplayName = 'Microsoft Edge'; DisplayVersion = '141.0.1' }
)
$sel = Select-CwaArpEntry -Entries $arp
Assert-Eq $sel.DisplayName 'Citrix Workspace 2507' 'main CWA entry picked over component entries'
Assert-Eq $sel.Version '25.7.1.10' 'CWA version parsed'
Assert-Eq (Select-CwaArpEntry -Entries @($arp[0], $arp[3])) '' 'no main entry -> not installed'
$two = @(
    [pscustomobject]@{ DisplayName = 'Citrix Workspace 2409'; DisplayVersion = '24.9.10.28' },
    [pscustomobject]@{ DisplayName = 'Citrix Workspace 2607'; DisplayVersion = '26.7.0.50' }
)
Assert-Eq (Select-CwaArpEntry -Entries $two).Version '26.7.0.50' 'newest of two registrations wins'

# --- .NET 10 confirmation ----------------------------------------------------
Assert-Eq (Test-CwaUsesDotNet10 -Version ([version]'26.7.0.50')) 'True' '2607 is on .NET 10'
Assert-Eq (Test-CwaUsesDotNet10 -Version ([version]'27.1.0.1')) 'True' 'later CWA is on .NET 10'
Assert-Eq (Test-CwaUsesDotNet10 -Version ([version]'25.7.1.10')) 'False' '2507.1 not confirmed'
Assert-Eq (Test-CwaUsesDotNet10 -Version ([version]'24.9.10.28')) 'False' '2409 uses .NET 8'
Assert-Eq (Test-CwaUsesDotNet10 -Version $null) 'False' 'unknown version not confirmed'

# --- staged installer pick ---------------------------------------------------
$files = @(
    [pscustomobject]@{ FullName = 'C:\a\CitrixWorkspaceApp_old.exe'; Version = [version]'25.7.1.10' },
    [pscustomobject]@{ FullName = 'C:\a\CitrixWorkspaceApp.exe'; Version = [version]'26.7.0.50' },
    [pscustomobject]@{ FullName = 'C:\a\CitrixWorkspaceApp_noversion.exe'; Version = $null }
)
Assert-Eq (Select-StagedInstaller -Files $files).FullName 'C:\a\CitrixWorkspaceApp.exe' 'newest staged installer wins'
Assert-Eq (Select-StagedInstaller -Files @()) '' 'no staged installer'

# --- install arguments -------------------------------------------------------
Assert-Eq ((Get-CwaInstallArguments -AutoUpdate $false -SkipThirdPartyVCCheck $false -ForceInstall $false) -join ' ') '/silent AutoUpdateCheck=disabled EnableCEIP=False' 'default arguments'
Assert-Eq ((Get-CwaInstallArguments -AutoUpdate $true -SkipThirdPartyVCCheck $true -ForceInstall $true) -join ' ') '/silent /forceinstall /SkipThirdPartyVCCheck AutoUpdateCheck=auto AutoUpdateStream=LTSR EnableCEIP=False' 'all options'

# --- installer outcome -------------------------------------------------------
Assert-Eq (Get-InstallOutcome -ExitCode 0) 'OK' 'exit 0'
Assert-Eq (Get-InstallOutcome -ExitCode 3010) 'REBOOT' 'exit 3010'
Assert-Eq (Get-InstallOutcome -ExitCode 1641) 'REBOOT' 'exit 1641'
Assert-Eq (Get-InstallOutcome -ExitCode 1603) 'FAIL' 'exit 1603'
Assert-Eq (Get-InstallOutcome -ExitCode -1) 'FAIL' 'timeout'

# --- runtimeconfig.json ------------------------------------------------------
$net8 = '{"runtimeOptions":{"tfm":"net8.0","framework":{"name":"Microsoft.WindowsDesktop.App","version":"8.0.0"}}}'
$net8multi = '{"runtimeOptions":{"tfm":"net8.0","frameworks":[{"name":"Microsoft.NETCore.App","version":"8.0.0"},{"name":"Microsoft.AspNetCore.App","version":"8.0.0"}]}}'
$net8roll = '{"runtimeOptions":{"tfm":"net8.0","rollForward":"LatestMajor","framework":{"name":"Microsoft.NETCore.App","version":"8.0.0"}}}'
$net8self = '{"runtimeOptions":{"tfm":"net8.0","includedFrameworks":[{"name":"Microsoft.NETCore.App","version":"8.0.11"}]}}'
$net10 = '{"runtimeOptions":{"tfm":"net10.0","framework":{"name":"Microsoft.WindowsDesktop.App","version":"10.0.0"}}}'
Assert-Eq (Get-RuntimeConfigNet8Need -Json $net8) 'Microsoft.WindowsDesktop.App 8.0.0' 'net8 desktop app needs 8'
Assert-Eq (Get-RuntimeConfigNet8Need -Json $net8multi) 'Microsoft.NETCore.App 8.0.0' 'net8 multi-framework app needs 8'
Assert-Eq (Get-RuntimeConfigNet8Need -Json $net8roll) '' 'rollForward LatestMajor runs on 10'
Assert-Eq (Get-RuntimeConfigNet8Need -Json $net8self) '' 'self-contained app does not need the shared runtime'
Assert-Eq (Get-RuntimeConfigNet8Need -Json $net10) '' 'net10 app'
Assert-Eq (Get-RuntimeConfigNet8Need -Json 'not json') '' 'unparseable file ignored'
Assert-Eq (Get-RuntimeConfigNet8Need -Json '{}') '' 'no runtimeOptions'

# --- .NET 8 blockers ---------------------------------------------------------
$b = @(Get-DotNet8Blockers -CwaVersion ([version]'26.7.0.50') -CwaInstalled $true -HasDotNet10Desktop $true -Net8Apps @())
Assert-Eq $b.Count 0 'CWA 2607 + .NET 10 + no apps -> ready'
$b = @(Get-DotNet8Blockers -CwaVersion ([version]'24.9.10.28') -CwaInstalled $true -HasDotNet10Desktop $true -Net8Apps @())
Assert-Eq $b.Count 1 'CWA 2409 blocks removal'
$b = @(Get-DotNet8Blockers -CwaVersion ([version]'26.7.0.50') -CwaInstalled $true -HasDotNet10Desktop $false -Net8Apps @())
Assert-Eq $b.Count 1 'CWA 2607 without .NET 10 x86 blocks removal'
$b = @(Get-DotNet8Blockers -CwaVersion $null -CwaInstalled $false -HasDotNet10Desktop $false -Net8Apps @('C:\Program Files\App\App.runtimeconfig.json'))
Assert-Eq $b.Count 1 'no CWA, but a net8 app blocks removal'
$b = @(Get-DotNet8Blockers -CwaVersion $null -CwaInstalled $false -HasDotNet10Desktop $false -Net8Apps @())
Assert-Eq $b.Count 0 'no CWA and no net8 apps -> ready'

# --- exit code ---------------------------------------------------------------
Assert-Eq (Get-FinalExitCode -Failed $true -NeedsHuman $true -Reboot $true) 1 'failure wins'
Assert-Eq (Get-FinalExitCode -Failed $false -NeedsHuman $true -Reboot $true) 2 'needs human over reboot'
Assert-Eq (Get-FinalExitCode -Failed $false -NeedsHuman $false -Reboot $true) 3010 'reboot'
Assert-Eq (Get-FinalExitCode -Failed $false -NeedsHuman $false -Reboot $false) 0 'clean'

# --- 64-bit relaunch ---------------------------------------------------------
Assert-Eq (Test-Needs64BitRelaunch -Is64BitOS $true -Is64BitProcess $false) 'True' '32-bit EC agent on 64-bit OS relaunches'
Assert-Eq (Test-Needs64BitRelaunch -Is64BitOS $true -Is64BitProcess $true) 'False' 'already 64-bit'
$bound = @{ RemoveDotNet8 = [switch]$true; DryRun = [switch]$false; InstallerPath = 'C:\stage\CitrixWorkspaceApp.exe' }
Assert-Eq ((Get-RelaunchArguments -ScriptPath 'C:\s.ps1' -Bound $bound) -join ' ') '-NoProfile -ExecutionPolicy Bypass -File C:\s.ps1 -InstallerPath C:\stage\CitrixWorkspaceApp.exe -RemoveDotNet8' 'relaunch keeps set switches and values'

if ($failed -gt 0) { Write-Host "$failed test(s) failed"; exit 1 }
Write-Host 'All tests passed'
exit 0
