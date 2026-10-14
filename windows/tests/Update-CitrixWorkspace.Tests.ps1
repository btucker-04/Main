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

# --- architecture ------------------------------------------------------------
Assert-Eq (ConvertTo-OsArch -ProcessorArchitecture 'AMD64' -ProcessorArchitectureW6432 '') 'x64' 'x64 OS'
Assert-Eq (ConvertTo-OsArch -ProcessorArchitecture 'x86' -ProcessorArchitectureW6432 'AMD64') 'x64' '32-bit EC agent on x64 OS'
Assert-Eq (ConvertTo-OsArch -ProcessorArchitecture 'ARM64' -ProcessorArchitectureW6432 '') 'arm64' 'ARM64 OS'
Assert-Eq (ConvertTo-OsArch -ProcessorArchitecture 'x86' -ProcessorArchitectureW6432 '') 'x86' '32-bit OS'

Assert-Eq (Get-CwaInstalledArch -IsWow $true -InstallLocation '' -OsArch 'x64') 'x86' 'WOW6432Node entry is 32-bit CWA'
Assert-Eq (Get-CwaInstalledArch -IsWow $false -InstallLocation '' -OsArch 'x64') 'x64' 'native entry is 64-bit CWA'
Assert-Eq (Get-CwaInstalledArch -IsWow $true -InstallLocation 'C:\Program Files\Citrix\ICA Client\' -OsArch 'x64') 'x64' 'Program Files folder wins over a WOW entry'
Assert-Eq (Get-CwaInstalledArch -IsWow $false -InstallLocation 'C:\Program Files (x86)\Citrix\ICA Client\' -OsArch 'x64') 'x86' 'Program Files (x86) folder is 32-bit'
Assert-Eq (Get-CwaInstalledArch -IsWow $false -InstallLocation '' -OsArch 'arm64') 'arm64' 'native entry on ARM is ARM64 CWA'
Assert-Eq (Get-CwaInstalledArch -IsWow $false -InstallLocation '' -OsArch 'x86') 'x86' '32-bit OS is always 32-bit CWA'
$wowArp = @([pscustomobject]@{ DisplayName = 'Citrix Workspace 2507'; DisplayVersion = '25.7.1.10'; IsWow = $true; InstallLocation = 'C:\Program Files (x86)\Citrix\ICA Client\' })
Assert-Eq (Select-CwaArpEntry -Entries $wowArp).IsWow 'True' 'ARP view carried through'
Assert-Eq (Select-CwaArpEntry -Entries $wowArp).InstallLocation 'C:\Program Files (x86)\Citrix\ICA Client\' 'InstallLocation carried through'

Assert-Eq (Get-InstallerArch -Name 'CitrixWorkspaceApp.exe' -PeMachine 0x14c) 'x86' 'plain name, x86 PE -> 32-bit'
Assert-Eq (Get-InstallerArch -Name 'CitrixWorkspaceApp.exe' -PeMachine 0) 'x86' 'plain name, unreadable PE -> 32-bit'
Assert-Eq (Get-InstallerArch -Name 'CitrixWorkspaceAppx64.exe' -PeMachine 0x14c) 'x64' 'x64 in name wins over an x86 bootstrapper'
Assert-Eq (Get-InstallerArch -Name 'CitrixWorkspaceApp_amd64.exe' -PeMachine 0) 'x64' 'amd64 in name'
Assert-Eq (Get-InstallerArch -Name 'CitrixWorkspaceApp64bit.exe' -PeMachine 0) 'x64' '64bit in name'
Assert-Eq (Get-InstallerArch -Name 'CitrixWorkspaceAppARM64.exe' -PeMachine 0x8664) 'arm64' 'ARM64 in name'
Assert-Eq (Get-InstallerArch -Name 'CitrixWorkspaceApp.exe' -PeMachine 0x8664) 'x64' 'x64 PE header'
Assert-Eq (Get-InstallerArch -Name 'CitrixWorkspaceApp.exe' -PeMachine 0xAA64) 'arm64' 'ARM64 PE header'

$both = @('x64', 'x86')
$r = Resolve-TargetArch -OsArch 'x64' -InstalledArch 'x86' -MigrateTo64Bit $false -Available $both
Assert-Eq $r.Arch 'x86' '32-bit CWA stays 32-bit by default'
Assert-Eq $r.Error '' '32-bit installer staged'
$r = Resolve-TargetArch -OsArch 'x64' -InstalledArch 'x86' -MigrateTo64Bit $true -Available $both
Assert-Eq $r.Arch 'x64' '-MigrateTo64Bit moves 32-bit CWA to x64'
$r = Resolve-TargetArch -OsArch 'x64' -InstalledArch 'x64' -MigrateTo64Bit $false -Available $both
Assert-Eq $r.Arch 'x64' '64-bit CWA stays 64-bit'
$r = Resolve-TargetArch -OsArch 'x64' -InstalledArch 'x64' -MigrateTo64Bit $false -Available @('x86')
Assert-Eq $r.Arch 'x64' 'never downgrade 64-bit to 32-bit'
Assert-Eq ($r.Error -ne '') 'True' 'missing x64 installer is an error'
$r = Resolve-TargetArch -OsArch 'x64' -InstalledArch '' -MigrateTo64Bit $false -Available $both
Assert-Eq $r.Arch 'x64' 'fresh install on x64 uses x64'
$r = Resolve-TargetArch -OsArch 'x64' -InstalledArch '' -MigrateTo64Bit $false -Available @('x86')
Assert-Eq $r.Arch 'x86' 'fresh install falls back to 32-bit when only that is staged'
Assert-Eq $r.Error '' 'fallback is not an error'
$r = Resolve-TargetArch -OsArch 'x64' -InstalledArch 'x86' -MigrateTo64Bit $false -Available @('x64')
Assert-Eq $r.Arch 'x86' 'only x64 staged: still wants 32-bit without -MigrateTo64Bit'
Assert-Eq ($r.Error -like '*-MigrateTo64Bit*') 'True' 'error suggests -MigrateTo64Bit'
$r = Resolve-TargetArch -OsArch 'x86' -InstalledArch 'x86' -MigrateTo64Bit $true -Available $both
Assert-Eq $r.Arch 'x86' '32-bit Windows ignores -MigrateTo64Bit'
$r = Resolve-TargetArch -OsArch 'x86' -InstalledArch '' -MigrateTo64Bit $false -Available $both
Assert-Eq $r.Arch 'x86' 'fresh install on 32-bit Windows'
$r = Resolve-TargetArch -OsArch 'arm64' -InstalledArch 'x86' -MigrateTo64Bit $true -Available @('arm64', 'x86', 'x64')
Assert-Eq $r.Arch 'arm64' 'ARM device migrates to ARM64'
$r = Resolve-TargetArch -OsArch 'arm64' -InstalledArch '' -MigrateTo64Bit $false -Available $both
Assert-Eq $r.Arch 'x86' 'ARM fresh install without ARM64 staged uses 32-bit (emulated)'

Assert-Eq (Test-SameVersionArchSwitch -InstalledArch 'x86' -InstalledVersion ([version]'26.7.0.50') -TargetArch 'x64' -InstallerVersion ([version]'26.7.0.50')) 'True' 'same-version 32 -> 64 needs an uninstall'
Assert-Eq (Test-SameVersionArchSwitch -InstalledArch 'x86' -InstalledVersion ([version]'25.7.1.10') -TargetArch 'x64' -InstallerVersion ([version]'26.7.0.50')) 'False' 'upgrade + arch change is allowed'
Assert-Eq (Test-SameVersionArchSwitch -InstalledArch 'x64' -InstalledVersion ([version]'26.7.0.50') -TargetArch 'x64' -InstallerVersion ([version]'26.7.0.50')) 'False' 'same arch'

$staged = @(
    [pscustomobject]@{ FullName = 'C:\a\CitrixWorkspaceApp.exe'; Version = [version]'26.7.0.50'; Arch = 'x86' },
    [pscustomobject]@{ FullName = 'C:\a\CitrixWorkspaceAppx64.exe'; Version = [version]'26.7.0.50'; Arch = 'x64' }
)
Assert-Eq (Select-StagedInstaller -Files @($staged | Where-Object { $_.Arch -eq 'x64' })).FullName 'C:\a\CitrixWorkspaceAppx64.exe' 'pick by arch'

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

# --- PE header ---------------------------------------------------------------
$tmp = [System.IO.Path]::GetTempFileName()
try {
    $bytes = New-Object byte[] 0x90
    $bytes[0] = 0x4D; $bytes[1] = 0x5A
    [BitConverter]::GetBytes([int]0x80).CopyTo($bytes, 0x3C)
    $bytes[0x80] = 0x50; $bytes[0x81] = 0x45
    [BitConverter]::GetBytes([uint16]0x8664).CopyTo($bytes, 0x84)
    [System.IO.File]::WriteAllBytes($tmp, $bytes)
    Assert-Eq (Get-PeMachine -Path $tmp) 0x8664 'PE machine read from header'
    [System.IO.File]::WriteAllBytes($tmp, [byte[]](0x4D, 0x5A, 0x00))
    Assert-Eq (Get-PeMachine -Path $tmp) 0 'truncated file -> 0'
} finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }

if ($failed -gt 0) { Write-Host "$failed test(s) failed"; exit 1 }
Write-Host 'All tests passed'
exit 0
