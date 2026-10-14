# Unit tests for Install-SqlExpress2022.ps1 decision helpers.
# Run: pwsh -NoProfile -File windows/tests/Install-SqlExpress2022.Tests.ps1
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path (Split-Path -Parent $here) 'Install-SqlExpress2022.ps1'
$env:SQLEXPRESS_DOTSOURCE = '1'
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

# --- Instance names / services ----------------------------------------------
Assert-Eq (Test-SqlInstanceName -Name 'SQLEXPRESS') 'True' 'default name'
Assert-Eq (Test-SqlInstanceName -Name 'MSSQLSERVER') 'True' 'default instance'
Assert-Eq (Test-SqlInstanceName -Name 'APP_DB$1') 'True' 'underscore and dollar'
Assert-Eq (Test-SqlInstanceName -Name '1SQL') 'False' 'starts with digit'
Assert-Eq (Test-SqlInstanceName -Name 'SQL EXPRESS') 'False' 'space'
Assert-Eq (Test-SqlInstanceName -Name 'ABCDEFGHIJKLMNOPQ') 'False' '17 characters'
Assert-Eq (Test-SqlInstanceName -Name 'DEFAULT') 'False' 'reserved'
Assert-Eq (Test-SqlInstanceName -Name '') 'False' 'empty'
Assert-Eq (Get-SqlServiceName -InstanceName 'SQLEXPRESS') 'MSSQL$SQLEXPRESS' 'named instance service'
Assert-Eq (Get-SqlServiceName -InstanceName 'MSSQLSERVER') 'MSSQLSERVER' 'default instance service'

# --- Existing instance -> action --------------------------------------------
Assert-Eq (Get-SqlMajorFromInstanceId -InstanceId 'MSSQL16.SQLEXPRESS') '16' '2022 id'
Assert-Eq (Get-SqlMajorFromInstanceId -InstanceId 'MSSQL15.SQLEXPRESS') '15' '2019 id'
Assert-Eq (Get-SqlMajorFromInstanceId -InstanceId 'garbage') '' 'unparsable id'
Assert-Eq (Get-SqlMajorFromInstanceId -InstanceId 'MSSQL10_50.SQLEXPRESS') '10' '2008 R2 id'
Assert-Eq (Get-InstanceAction -ExistingMajor $null -UpgradeExisting $false) 'Install' 'not installed'
Assert-Eq (Get-InstanceAction -ExistingMajor 16 -UpgradeExisting $false) 'Present' '2022 present'
Assert-Eq (Get-InstanceAction -ExistingMajor 17 -UpgradeExisting $true) 'Newer' 'newer left alone'
Assert-Eq (Get-InstanceAction -ExistingMajor 15 -UpgradeExisting $false) 'OlderNeedsSwitch' '2019 without switch'
Assert-Eq (Get-InstanceAction -ExistingMajor 15 -UpgradeExisting $true) 'Upgrade' '2019 with -UpgradeExisting'

# --- Media / update selection -----------------------------------------------
Assert-Eq (Test-FeaturesNeedAdvanced -Features 'SQLEngine') 'False' 'engine only'
Assert-Eq (Test-FeaturesNeedAdvanced -Features 'SQLEngine,FullText') 'True' 'full-text'
Assert-Eq (Test-FeaturesNeedAdvanced -Features 'SQLEngine, PolyBaseCore') 'True' 'polybase'
Assert-Eq (Test-FeaturesNeedAdvanced -Features 'SQLEngine,Replication') 'False' 'replication is in Core'
$both = @('SQLEXPRADV_x64_ENU.exe', 'SQLEXPR_x64_ENU.exe', 'SQLServer2022-KB5065865-x64.exe')
Assert-Eq (Select-SqlMedia -Names $both -NeedAdvanced $false) 'SQLEXPR_x64_ENU.exe' 'Core preferred'
Assert-Eq (Select-SqlMedia -Names $both -NeedAdvanced $true) 'SQLEXPRADV_x64_ENU.exe' 'Advanced when needed'
Assert-Eq (Select-SqlMedia -Names @('SQLEXPRADV_x64_ENU.exe') -NeedAdvanced $false) 'SQLEXPRADV_x64_ENU.exe' 'Advanced covers engine'
Assert-Eq (Select-SqlMedia -Names @('SQLEXPR_x64_ENU.exe') -NeedAdvanced $true) '' 'Core cannot do full-text'
Assert-Eq (Select-SqlMedia -Names @() -NeedAdvanced $false) '' 'nothing staged'
Assert-Eq (Select-SqlUpdatePackage -Names @('SQLServer2022-KB5042749-x64.exe', 'SQLServer2022-KB5065865-x64.exe', 'SQLEXPR_x64_ENU.exe')) 'SQLServer2022-KB5065865-x64.exe' 'highest KB'
Assert-Eq (Select-SqlUpdatePackage -Names @('SQLServer2019-KB5011644-x64.exe')) '' '2019 update ignored'
Assert-Eq (Test-UpdateNeeded -InstalledBuild ([version]'16.0.1000.6') -UpdateVersion ([version]'16.0.4210.1')) 'True' 'RTM needs CU'
Assert-Eq (Test-UpdateNeeded -InstalledBuild ([version]'16.0.4210.1') -UpdateVersion ([version]'16.0.4210.1')) 'False' 'already at CU'
Assert-Eq (Test-UpdateNeeded -InstalledBuild ([version]'16.0.4210.1') -UpdateVersion $null) '' 'unknown update version'

# --- Setup arguments --------------------------------------------------------
$dq = [string][char]34
$a = Get-SqlInstallArguments -InstanceName 'SQLEXPRESS' -Features 'SQLEngine' -SysAdmins @('BUILTIN\Administrators') `
    -SaPassword '' -EnableTcp $false -DataDir '' -UpdateSource '' -SkipRebootCheck $false
Assert-Eq ($a -join ' ') ('/Q /ACTION=Install /IACCEPTSQLSERVERLICENSETERMS /SUPPRESSPRIVACYSTATEMENTNOTICE /FEATURES=SQLEngine /INSTANCENAME=SQLEXPRESS /SQLSYSADMINACCOUNTS=' + $dq + 'BUILTIN\Administrators' + $dq + ' /ADDCURRENTUSERASSQLADMIN=False /SQLSVCSTARTUPTYPE=Automatic /TCPENABLED=0 /NPENABLED=0 /UPDATEENABLED=False') 'default install arguments'
$a = Get-SqlInstallArguments -InstanceName 'APPDB' -Features 'SQLEngine, FullText' -SysAdmins @('BUILTIN\Administrators', ' CORP\SQL Admins') `
    -SaPassword 'P@ss word1' -EnableTcp $true -DataDir 'D:\SQLData' -UpdateSource 'C:\Windows\Temp\SQL2022Updates' -SkipRebootCheck $true
$j = $a -join ' '
Assert-Eq ($a -contains '/FEATURES=SQLEngine,FullText') 'True' 'features without spaces'
Assert-Eq ($a -contains ('/SQLSYSADMINACCOUNTS=' + $dq + 'BUILTIN\Administrators' + $dq + ' ' + $dq + 'CORP\SQL Admins' + $dq)) 'True' 'several sysadmins, each quoted'
Assert-Eq ($a -contains '/TCPENABLED=1') 'True' 'tcp on'
Assert-Eq ($a -contains '/UPDATEENABLED=True') 'True' 'slipstream on'
Assert-Eq ($a -contains ('/UPDATESOURCE=' + $dq + 'C:\Windows\Temp\SQL2022Updates' + $dq)) 'True' 'update source'
Assert-Eq ($a -contains '/SECURITYMODE=SQL') 'True' 'mixed mode'
Assert-Eq ($a -contains ('/INSTALLSQLDATADIR=' + $dq + 'D:\SQLData' + $dq)) 'True' 'data dir'
Assert-Eq ($a -contains '/SKIPRULES=RebootRequiredCheck') 'True' 'skip reboot rule'
Assert-Eq ((Format-ArgsForLog -Arguments $a) -match 'P@ss') 'False' 'password masked in log'
Assert-Eq ((Format-ArgsForLog -Arguments $a) -match '/SAPWD=\*{8}') 'True' 'mask shown'
$u = Get-SqlUpgradeArguments -InstanceName 'SQLEXPRESS' -UpdateSource '' -SkipRebootCheck $false
Assert-Eq ($u -join ' ') '/Q /ACTION=Upgrade /IACCEPTSQLSERVERLICENSETERMS /SUPPRESSPRIVACYSTATEMENTNOTICE /INSTANCENAME=SQLEXPRESS /UPDATEENABLED=False' 'upgrade arguments'
Assert-Eq ((Get-SqlPatchArguments -InstanceName 'SQLEXPRESS') -join ' ') '/Q /ACTION=Patch /IACCEPTSQLSERVERLICENSETERMS /INSTANCENAME=SQLEXPRESS' 'patch arguments'

# --- Outcomes / summary -----------------------------------------------------
Assert-Eq (Get-SetupOutcome -ExitCode 0) 'OK' 'exit 0'
Assert-Eq (Get-SetupOutcome -ExitCode 3010) 'REBOOT' 'exit 3010'
Assert-Eq (Get-SetupOutcome -ExitCode -2068052377) 'FAIL' 'setup failure code'
Assert-Eq (Get-SetupOutcome -ExitCode -1) 'FAIL' 'timeout'
Assert-Eq (Get-SetupOutcome -ExitCode $null) 'UNKNOWN' 'no exit code'
$summary = @'
Overall summary:
  Final result:                  Failed: see details below
  Exit code (Decimal):           -2068643839
  Start time:                    2026-10-14 10:02:11
  End time:                      2026-10-14 10:04:52
  Requested action:              Install

Setup completed with required actions for features.
  Exit message:                  The instance name SQLEXPRESS is already in use.
'@
$s = Get-SetupSummary -Text $summary
Assert-Eq $s.FinalResult 'Failed: see details below' 'summary final result'
Assert-Eq $s.ExitCode '-2068643839' 'summary exit code'
Assert-Eq $s.ExitMessage 'The instance name SQLEXPRESS is already in use.' 'summary exit message'
Assert-Eq (Get-SetupSummary -Text '').FinalResult '' 'empty summary'

Assert-Eq (Get-FinalExitCode -Failed $true -NeedsHuman $true -Reboot $true) '1' 'failed wins'
Assert-Eq (Get-FinalExitCode -Failed $false -NeedsHuman $true -Reboot $true) '2' 'needs human'
Assert-Eq (Get-FinalExitCode -Failed $false -NeedsHuman $false -Reboot $true) '3010' 'reboot'
Assert-Eq (Get-FinalExitCode -Failed $false -NeedsHuman $false -Reboot $false) '0' 'ok'
Assert-Eq (Test-Needs64BitRelaunch -Is64BitOS $true -Is64BitProcess $false) 'True' '32-bit EC agent relaunches'
$r = Get-RelaunchArguments -ScriptPath 'C:\s.ps1' -Bound @{ InstanceName = 'APPDB'; EnableTcp = [switch]$true; DryRun = [switch]$false }
Assert-Eq ($r -join ' ') '-NoProfile -ExecutionPolicy Bypass -File C:\s.ps1 -EnableTcp -InstanceName APPDB' 'relaunch arguments'

if ($failed -gt 0) { Write-Host "$failed test(s) failed"; exit 1 }
Write-Host 'All tests passed'
