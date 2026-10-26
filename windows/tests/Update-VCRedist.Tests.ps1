# Unit tests for Update-VCRedist.ps1 decision helpers.
# Run: pwsh -NoProfile -File windows/tests/Update-VCRedist.Tests.ps1
#
# CSPRLT-94 (2026-10-26): 'Microsoft Visual C++ 2022 X86 Minimum Runtime -
# 14.42.34433' had no cached .msi, so every upgrade failed with 1714 / 1612
# and Citrix Workspace's prerequisite step exited 101603.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path (Split-Path -Parent $here) 'Update-VCRedist.ps1'
$env:VCREDIST_UPDATE_DOTSOURCE = '1'
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

# --- versions ------------------------------------------------------------------
Assert-Eq (ConvertTo-VcVersion '14.42.34433') '14.42.34433.0' 'three-part version padded'
Assert-Eq (ConvertTo-VcVersion 'v14.42.34433.00') '14.42.34433.0' 'Runtimes key form'
Assert-Eq (ConvertTo-VcVersion '') '' 'empty -> null'
Assert-Eq ((ConvertTo-VcVersion '14.44.35211.0') -gt (ConvertTo-VcVersion '14.42.34433')) 'True' 'newer build compares greater'

# --- DisplayName parsing -------------------------------------------------------
$e = ConvertTo-VcEntry 'Microsoft Visual C++ 2022 X86 Minimum Runtime - 14.42.34433' '14.42.34433'
Assert-Eq ('' + $e.Kind + '|' + $e.Arch + '|' + $e.Major + '|' + $e.Supported) 'Minimum|x86|14|True' 'CSPRLT-94 runtime parsed'
$e = ConvertTo-VcEntry 'Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.42.34433' '14.42.34433.0'
Assert-Eq ('' + $e.Kind + '|' + $e.Arch + '|' + $e.Year + '|' + $e.Version) 'Redistributable|x64|2022|14.42.34433.0' 'v14 bundle parsed'
$e = ConvertTo-VcEntry 'Microsoft Visual C++ 2022 X64 Additional Runtime - 14.42.34433' '14.42.34433'
Assert-Eq $e.Kind 'Additional' 'additional runtime'
$e = ConvertTo-VcEntry 'Microsoft Visual C++ 2022 ARM64 Minimum Runtime - 14.44.35211' '14.44.35211'
Assert-Eq $e.Arch 'arm64' 'arm64 runtime'
$e = ConvertTo-VcEntry 'Microsoft Visual C++ 2013 Redistributable (x64) - 12.0.40664' '12.0.40664.0'
Assert-Eq ('' + $e.Major + '|' + $e.Supported) '12|False' '2013 unsupported'
$e = ConvertTo-VcEntry 'Microsoft Visual C++ 2010  x64 Redistributable - 10.0.40219' '10.0.40219'
Assert-Eq ('' + $e.Arch + '|' + $e.Major) 'x64|10' '2010 double-space name'
$e = ConvertTo-VcEntry 'Microsoft Visual C++ 2008 Redistributable - x86 9.0.30729.6161' '9.0.30729.6161'
Assert-Eq ('' + $e.Arch + '|' + $e.Version) 'x86|9.0.30729.6161' '2008 name form'
$e = ConvertTo-VcEntry 'Microsoft Visual C++ 2005 Redistributable' '8.0.61001'
Assert-Eq ('' + $e.Arch + '|' + $e.Major + '|' + $e.Supported) 'x86|8|False' '2005 without arch is x86'
$e = ConvertTo-VcEntry 'Microsoft Visual C++ 2012 Redistributable (x86) - 11.0.61030' ''
Assert-Eq $e.Version '11.0.61030.0' 'version from the name when DisplayVersion is blank'
Assert-Eq (ConvertTo-VcEntry 'Microsoft Visual C++ 2022 X64 Debug Runtime - 14.42.34433' '14.42.34433') '' 'debug runtime ignored'
Assert-Eq (ConvertTo-VcEntry 'Microsoft Visual Studio Installer' '3.11') '' 'other products ignored'

# --- packed GUIDs ----------------------------------------------------------------
# VC++ 2008 x86 9.0.30729.6161: product code and its Installer\Products key name.
Assert-Eq (ConvertTo-PackedGuid '{9BE518E6-ECC6-35A9-88E4-87755C07200F}') '6E815EB96CCE9A53884E7857C57002F0' 'GUID packed'
Assert-Eq (ConvertFrom-PackedGuid '6E815EB96CCE9A53884E7857C57002F0') '{9BE518E6-ECC6-35A9-88E4-87755C07200F}' 'packed unpacked'
Assert-Eq (ConvertTo-PackedGuid '{a1b2c3d4-e5f6-0718-293a-4b5c6d7e8f90}') '4D3C2B1A6F5E817092A3B4C5D6E7F809' 'lowercase GUID packed'
Assert-Eq (ConvertFrom-PackedGuid (ConvertTo-PackedGuid '{A1B2C3D4-E5F6-0718-293A-4B5C6D7E8F90}')) '{A1B2C3D4-E5F6-0718-293A-4B5C6D7E8F90}' 'round trip'
Assert-Eq (ConvertTo-PackedGuid 'Microsoft.VS.VC_RuntimeMinimumVSU_x86,v14') '' 'non-GUID key -> empty'
Assert-Eq (ConvertFrom-PackedGuid '{9BE518E6-ECC6-35A9-88E4-87755C07200F}') '' 'unpacking a GUID -> empty'

# --- installed v14 per architecture -------------------------------------------
$arp = @(
    (ConvertTo-VcEntry 'Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.44.35211' '14.44.35211.0'),
    (ConvertTo-VcEntry 'Microsoft Visual C++ 2022 X86 Minimum Runtime - 14.42.34433' '14.42.34433'),
    (ConvertTo-VcEntry 'Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.40.33810' '14.40.33810.0'),
    (ConvertTo-VcEntry 'Microsoft Visual C++ 2013 Redistributable (x64) - 12.0.40664' '12.0.40664.0')
)
Assert-Eq (Get-InstalledV14 -Entries $arp -Arch 'x86') '14.42.34433.0' 'Minimum Runtime is the truth over the bundle'
Assert-Eq (Get-InstalledV14 -Entries $arp -Arch 'x64') '14.40.33810.0' 'bundle used when no Minimum Runtime entry'
Assert-Eq (Get-InstalledV14 -Entries $arp -Arch 'arm64') '' 'absent architecture -> null'
Assert-Eq (Get-InstalledV14 -Entries $arp -Arch 'x64' -RuntimeOnly) '' '-RuntimeOnly ignores the bundle'
Assert-Eq (Get-InstalledV14 -Entries $arp -Arch 'x86' -RuntimeOnly) '14.42.34433.0' '-RuntimeOnly reads the Minimum Runtime'

# CSPRLT-94 after cleanup: the 14.42 x86 bundle stayed registered after its
# MSIs failed; x64 has its runtime.
$after = @(
    (ConvertTo-VcEntry 'Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.42.34433' '14.42.34433.0'),
    (ConvertTo-VcEntry 'Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.50.35719' '14.50.35719'),
    (ConvertTo-VcEntry 'Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.50.35719' '14.50.35719.0'),
    (ConvertTo-VcEntry 'Microsoft Visual C++ 2013 Redistributable (x86) - 12.0.40664' '12.0.40664.0')
)
Assert-Eq ((Select-OrphanV14Bundles -Entries $after | ForEach-Object { $_.Arch }) -join ',') 'x86' 'bundle without runtime found'
Assert-Eq (@(Select-OrphanV14Bundles -Entries $arp | ForEach-Object { $_.Arch }) -join ',') 'x64' 'x64 bundle-only entry is an orphan'
Assert-Eq (Get-InstalledV14 -Entries $after -Arch 'x86' -RuntimeOnly) '' 'CSPRLT-94 verify: no x86 runtime, not 14.42'

# --- installer processes (1618) ---------------------------------------------------
$procs = @(
    [pscustomobject]@{ Name = 'msiexec.exe'; ProcessId = 900; CommandLine = 'C:\WINDOWS\system32\msiexec.exe /V' },
    [pscustomobject]@{ Name = 'msiexec.exe'; ProcessId = 901; CommandLine = 'C:\WINDOWS\syswow64\MsiExec.exe -Embedding 6F1A' },
    [pscustomobject]@{ Name = 'CitrixWorkspaceApp.exe'; ProcessId = 902; CommandLine = 'CitrixWorkspaceApp.exe /silent' },
    [pscustomobject]@{ Name = 'vc_redist.x86.exe'; ProcessId = 903; CommandLine = '' },
    [pscustomobject]@{ Name = 'explorer.exe'; ProcessId = 904; CommandLine = 'C:\WINDOWS\Explorer.EXE' },
    [pscustomobject]@{ Name = 'powershell.exe'; ProcessId = 905; CommandLine = 'powershell -File Update-VCRedist.ps1' }
)
Assert-Eq ((Select-InstallerProcesses -Processes $procs -ExcludePid 905 | ForEach-Object { $_.ProcessId }) -join ',') '901,902,903' 'msiexec clients and setups named, idle service and self skipped'
Assert-Eq (@(Select-InstallerProcesses -Processes @() -ExcludePid 1).Count) '0' 'no processes'

# --- broken registrations ------------------------------------------------------
function New-Reg { param($Name, $Ver, $CacheOk) $r = ConvertTo-VcEntry $Name $Ver; $r | Add-Member CacheOk $CacheOk; $r | Add-Member Packed 'X'; $r }
$prods = @(
    (New-Reg 'Microsoft Visual C++ 2022 X86 Minimum Runtime - 14.42.34433' '14.42.34433' $false),
    (New-Reg 'Microsoft Visual C++ 2022 X86 Additional Runtime - 14.42.34433' '14.42.34433' $true),
    (New-Reg 'Microsoft Visual C++ 2010  x86 Redistributable - 10.0.40219' '10.0.40219' $false)
)
$bundles = @(
    ([pscustomobject]@{ DisplayName = 'Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.42.34433'; Kind = 'Redistributable'; Major = 14; Arch = 'x86'; BundleCachePath = 'C:\ProgramData\Package Cache\{x}\VC_redist.x86.exe'; CacheOk = $false }),
    ([pscustomobject]@{ DisplayName = 'Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.42.34433'; Kind = 'Redistributable'; Major = 14; Arch = 'x64'; BundleCachePath = 'C:\ProgramData\Package Cache\{y}\VC_redist.x64.exe'; CacheOk = $true }),
    ([pscustomobject]@{ DisplayName = 'Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.42.34433'; Kind = 'Minimum'; Major = 14; Arch = 'x64'; BundleCachePath = ''; CacheOk = $false })
)
$b = @(Select-BrokenVcRegistrations -Products $prods -Bundles $bundles -IncludeUnsupported $false)
Assert-Eq (($b | ForEach-Object { $_.Type + ':' + $_.Item.DisplayName }) -join ' / ') 'msi:Microsoft Visual C++ 2022 X86 Minimum Runtime - 14.42.34433 / bundle:Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.42.34433' 'CSPRLT-94: cache-less v14 MSI and bundle selected'
$b = @(Select-BrokenVcRegistrations -Products $prods -Bundles @() -IncludeUnsupported $true)
Assert-Eq $b.Count '2' '-RemoveUnsupported also clears a cache-less 2010'
Assert-Eq (@(Select-BrokenVcRegistrations -Products @() -Bundles @() -IncludeUnsupported $false).Count) '0' 'nothing broken'

# --- install plan ------------------------------------------------------------------
$t = @{ x86 = (ConvertTo-VcVersion '14.44.35211.0'); x64 = (ConvertTo-VcVersion '14.44.35211.0') }
$p = @(Get-VcInstallPlan -Archs @('x86', 'x64') -Installed @{ x86 = (ConvertTo-VcVersion '14.42.34433'); x64 = (ConvertTo-VcVersion '14.44.35211') } -Target $t -Cleared @() -InstallMissing $false)
Assert-Eq (($p | ForEach-Object { $_.Arch + ':' + $_.Reason }) -join ',') 'x86:below target' 'only the old architecture planned'
$p = @(Get-VcInstallPlan -Archs @('x86', 'x64') -Installed @{ x86 = $null; x64 = (ConvertTo-VcVersion '14.44.35211') } -Target $t -Cleared @('x86') -InstallMissing $false)
Assert-Eq (($p | ForEach-Object { $_.Arch + ':' + $_.Reason }) -join ',') 'x86:broken registration cleared' 'cleared architecture reinstalled'
$p = @(Get-VcInstallPlan -Archs @('x86', 'x64') -Installed @{ x86 = $null; x64 = $null } -Target $t -Cleared @() -InstallMissing $false)
Assert-Eq $p.Count '0' 'absent architectures left alone by default'
$p = @(Get-VcInstallPlan -Archs @('x86', 'x64') -Installed @{ x86 = $null; x64 = $null } -Target $t -Cleared @() -InstallMissing $true)
Assert-Eq $p.Count '2' '-InstallMissing installs both'
$p = @(Get-VcInstallPlan -Archs @('x86', 'x64') -Installed @{ x86 = (ConvertTo-VcVersion '14.42.34433'); x64 = $null } -Target @{ x64 = $t.x64 } -Cleared @() -InstallMissing $false)
Assert-Eq $p.Count '0' 'no verified installer for x86 -> not planned'
$p = @(Get-VcInstallPlan -Archs @('x86') -Installed @{ x86 = (ConvertTo-VcVersion '14.50.1.0') } -Target $t -Cleared @() -InstallMissing $false)
Assert-Eq $p.Count '0' 'newer than target -> nothing'
$p = @(Get-VcInstallPlan -Archs @('x86', 'x64') -Installed @{ x86 = (ConvertTo-VcVersion '14.44.35211'); x64 = (ConvertTo-VcVersion '14.44.35211') } -Target $t -Cleared @() -InstallMissing $false -Orphaned @('x86'))
Assert-Eq (($p | ForEach-Object { $_.Arch + ':' + $_.Reason }) -join ',') 'x86:bundle registered without its runtime' 'orphan bundle at target still reinstalled'

# --- outcomes, meanings, logs ---------------------------------------------------
Assert-Eq (Get-VcInstallOutcome 0) 'OK' '0 ok'
Assert-Eq (Get-VcInstallOutcome 3010) 'REBOOT' '3010 reboot'
Assert-Eq (Get-VcInstallOutcome 1638) 'NEWER' '1638 newer present'
Assert-Eq (Get-VcInstallOutcome 1618) 'BUSY' '1618 busy'
Assert-Eq (Get-VcInstallOutcome 1603) 'FAIL' '1603 fail'
Assert-Eq (Get-VcInstallOutcome $null) 'UNKNOWN' 'blank -> unknown, not 0'
Assert-Eq (Get-VcExitMeaning 1612) '1612: the installation source (cached installer) is not available' '1612 meaning'
Assert-Eq (Get-VcExitMeaning 42) '' 'unknown meaning empty'

# Verbatim CSPRLT-94 MSI log line and a Burn line of the same failure.
$log = @'
MSI (s) (2C:40) [08:48:42:511]: Product: Microsoft Visual C++ 2022 X86 Minimum Runtime - 14.42.34433 -- Error 1714. The older version of Microsoft Visual C++ 2022 X86 Minimum Runtime - 14.42.34433 cannot be removed.  Contact your technical support group.  System Error 1612.
Action ended 8:48:42: RemoveExistingProducts. Return value 3.
Action ended 8:48:40: CostFinalize. Return value 1.
[0F2C:1A10][2026-10-26T08:48:43]e000: Error 0x80070643: Failed to install MSI package.
'@
$el = @(Get-VcLogErrorLines -Text $log -Max 6)
Assert-Eq $el.Count '3' 'error lines kept, success line dropped'
Assert-Eq ($el[2] -match '0x80070643') 'True' 'Burn error kept'
Assert-Eq (Get-VcLogHint $log) 'an older VC++ runtime cannot be removed because its cached installer is missing (1714 / 1612); run without -SkipBrokenCleanup' 'CSPRLT-94 cause named'
Assert-Eq (Get-VcLogHint 'e000: Error 0x80070666: Cannot install a product when a newer version is installed.') 'a newer version of this runtime is already installed (0x80070666)' 'newer version named'
Assert-Eq (Get-VcLogHint 'nothing here') '' 'no hint'
$burn = @'
[1A2C:0F10][2026-10-26T09:37:40]i319: Applied execute package: vcRuntimeMinimum_x86, result: 0x0, restart: None
[1A2C:0F10][2026-10-26T09:37:41]i319: Applied execute package: vcRuntimeAdditional_x86, result: 0x80070652, restart: None
'@
$el = @(Get-VcLogErrorLines -Text $burn -Max 6)
Assert-Eq ('' + $el.Count + '|' + ($el[0] -match 'vcRuntimeAdditional_x86')) '1|True' 'failed Burn package named, succeeded one dropped'
Assert-Eq (Get-VcLogHint $burn) 'another installation was in progress (0x80070652 / 1618)' '1618 in Burn log named'

# --- signer, architectures, exit, relaunch ----------------------------------------
Assert-Eq (Test-MicrosoftSigner 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US') 'True' 'Microsoft signer accepted'
Assert-Eq (Test-MicrosoftSigner 'CN=Microsoft Corporation, O=Evil Microsoft Corporation Ltd, C=US') 'False' 'look-alike O= refused'
Assert-Eq (Test-MicrosoftSigner '') 'False' 'unsigned refused'
Assert-Eq ((Get-VcArchsForOs 'AMD64' '') -join ',') 'x86,x64' 'x64 Windows'
Assert-Eq ((Get-VcArchsForOs 'x86' 'AMD64') -join ',') 'x86,x64' '32-bit process on x64 Windows'
Assert-Eq ((Get-VcArchsForOs 'ARM64' '') -join ',') 'x86,x64,arm64' 'ARM64 Windows'
Assert-Eq ((Get-VcArchsForOs 'x86' '') -join ',') 'x86' '32-bit Windows'
Assert-Eq (Get-FinalExitCode -Failed $true -NeedsHuman $true -Reboot $true) '1' 'failure wins'
Assert-Eq (Get-FinalExitCode -Failed $false -NeedsHuman $true -Reboot $true) '2' 'needs human over reboot'
Assert-Eq (Get-FinalExitCode -Failed $false -NeedsHuman $false -Reboot $true) '3010' 'reboot'
Assert-Eq (Get-FinalExitCode -Failed $false -NeedsHuman $false -Reboot $false) '0' 'clean'
Assert-Eq (Test-Needs64BitRelaunch -Is64BitOS $true -Is64BitProcess $false) 'True' 'EC 32-bit agent relaunches'
$ra = Get-RelaunchArguments -ScriptPath 'C:\x\Update-VCRedist.ps1' -Bound @{ RemoveUnsupported = [System.Management.Automation.SwitchParameter]$true; DryRun = [System.Management.Automation.SwitchParameter]$false }
Assert-Eq ($ra -join ' ') '-NoProfile -ExecutionPolicy Bypass -File C:\x\Update-VCRedist.ps1 -RemoveUnsupported' 'switches carried into the relaunch'

if ($failed -gt 0) { Write-Host "$failed test(s) failed"; exit 1 }
Write-Host 'All tests passed'
exit 0
