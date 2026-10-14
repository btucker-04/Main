# Unit tests for Remove-UnsupportedSqlServer.ps1 decision helpers.
# Run: pwsh -NoProfile -File windows/tests/Remove-UnsupportedSqlServer.Tests.ps1
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path (Split-Path -Parent $here) 'Remove-UnsupportedSqlServer.ps1'
$env:SQLUNSUPPORTED_DOTSOURCE = '1'
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

# --- Support dates (CSLT-135 scan: 2026-10-14) ------------------------------
$scan = [datetime]'2026-10-14'
Assert-Eq (Test-SqlMajorUnsupported -Major 13 -Today $scan) 'True' '2016 ended 2026-07-14'
Assert-Eq (Test-SqlMajorUnsupported -Major 13 -Today ([datetime]'2026-07-14')) 'False' '2016 still supported on its last day'
Assert-Eq (Test-SqlMajorUnsupported -Major 12 -Today $scan) 'True' '2014'
Assert-Eq (Test-SqlMajorUnsupported -Major 11 -Today $scan) 'True' '2012'
Assert-Eq (Test-SqlMajorUnsupported -Major 10 -Today $scan) 'True' '2008 / 2008 R2'
Assert-Eq (Test-SqlMajorUnsupported -Major 14 -Today $scan) 'False' '2017 supported until 2027-10-12'
Assert-Eq (Test-SqlMajorUnsupported -Major 14 -Today ([datetime]'2027-10-13')) 'True' '2017 after end date'
Assert-Eq (Test-SqlMajorUnsupported -Major 16 -Today $scan) 'False' '2022 (CSLT-135 new install) never touched'
Assert-Eq (Test-SqlMajorUnsupported -Major 17 -Today $scan) 'False' 'unknown major is supported'

# --- Instance majors ----------------------------------------------------------
Assert-Eq (Get-SqlMajorFromInstanceId -InstanceId 'MSSQL13.SQLEXPRESS') '13' '2016 id'
Assert-Eq (Get-SqlMajorFromInstanceId -InstanceId 'MSSQL10_50.SQLEXPRESS') '10' '2008 R2 id'
Assert-Eq (Get-SqlMajorFromInstanceId -InstanceId 'MSSQL.1') '' '2005 id has no major'
Assert-Eq (Get-SqlInstanceMajor -Version '12.0.6024.0' -InstanceId 'MSSQL.1') '12' 'Setup version wins'
Assert-Eq (Get-SqlInstanceMajor -Version '' -InstanceId 'MSSQL11.APP') '11' 'id fallback'

# --- ARP names ----------------------------------------------------------------
Assert-Eq (Get-SqlYearFromName -Name 'SQL Server 2016 Database Engine Services') '2016' 'year'
Assert-Eq (Get-SqlYearFromName -Name 'Microsoft SQL Server 2008 R2 Setup (English)') '2008' '2008 R2 year'
Assert-Eq (Get-SqlYearFromName -Name 'Microsoft Edge') '' 'not SQL'
foreach ($n in @('SQL Server 2016 Database Engine Services', 'SQL Server 2016 Database Engine Shared', 'SQL Server 2016 Common Files',
        'SQL Server 2016 Connection Info', 'SQL Server 2016 Batch Parser', 'SQL Server 2016 DMF', 'SQL Server 2016 XEvent',
        'SQL Server 2016 SQL Diagnostics', 'Microsoft SQL Server 2016 Setup (English)', 'Microsoft SQL Server 2016 RsFx Driver',
        'Microsoft VSS Writer for SQL Server 2016', 'SQL Server Browser for SQL Server 2016', 'SQL Server 2014 Database Engine Services')) {
    Assert-Eq (Test-SqlLeftoverName -Name $n) 'True' ('leftover: ' + $n)
}
foreach ($n in @('Microsoft SQL Server 2012 Native Client', 'Microsoft ODBC Driver 17 for SQL Server', 'SQL Server 2016 Shared Management Objects',
        'Microsoft System CLR Types for SQL Server 2016', 'SQL Server Management Studio', 'Microsoft SQL Server 2016 T-SQL Language Service',
        'Microsoft SQL Server 2014 Express LocalDB', 'Microsoft SQL Server Data-Tier Application Framework', 'Microsoft SQL Server 2016 Policies')) {
    Assert-Eq (Test-SqlLeftoverName -Name $n) 'False' ('kept: ' + $n)
}
Assert-Eq (Test-SqlLocalDbName -Name 'Microsoft SQL Server 2014 Express LocalDB') 'True' 'LocalDB 2014'
Assert-Eq (Test-SqlLocalDbName -Name 'Microsoft SQL Server 2016 LocalDB') 'True' 'LocalDB 2016'
Assert-Eq (Test-SqlLocalDbName -Name 'SQL Server 2016 Common Files') 'False' 'not LocalDB'
Assert-Eq (Get-MsiProductCode -KeyName '{1B8CFC46-1F08-4DA7-9FEA-E1F523FBD67F}' -UninstallString 'MsiExec.exe /X{1B8CFC46-1F08-4DA7-9FEA-E1F523FBD67F}') '{1B8CFC46-1F08-4DA7-9FEA-E1F523FBD67F}' 'GUID key'
Assert-Eq (Get-MsiProductCode -KeyName 'Microsoft SQL Server SQL2016' -UninstallString 'C:\Program Files\Microsoft SQL Server\130\Setup Bootstrap\SQL2016\x64\SetupARP.exe') '' 'SetupARP entry is not an MSI'
Assert-Eq (Get-MsiProductCode -KeyName 'x' -UninstallString 'MsiExec.exe /I{1B8CFC46-1F08-4DA7-9FEA-E1F523FBD67F}') '{1B8CFC46-1F08-4DA7-9FEA-E1F523FBD67F}' 'code from uninstall string'

# CSLT-135 (2026-10-14): LocalDB 13.0 listed twice, once per registry view.
$ldb = @([pscustomobject]@{ Version = '13.0'; Major = 13; Dll = 'a' }, [pscustomobject]@{ Version = '13.0'; Major = 13; Dll = 'b' }, [pscustomobject]@{ Version = '15.0'; Major = 15; Dll = 'c' })
Assert-Eq ((Select-UniqueLocalDb -Entries $ldb | ForEach-Object { $_.Version }) -join ',') '13.0,15.0' 'LocalDB de-duplicated across registry views'
Assert-Eq (Test-SqlLocalDbName -Name 'Microsoft SQL Server 2016 LocalDB ') 'True' 'CSLT-135 ARP name (trailing space)'
Assert-Eq (Test-SqlLeftoverName -Name 'Microsoft SQL Server 2012 Command Line Utilities ') 'False' 'CSLT-135: 2012 command line utilities kept'

# --- User databases -----------------------------------------------------------
$data = @('master.mdf', 'mastlog.ldf', 'model.mdf', 'modellog.ldf', 'MSDBData.mdf', 'MSDBLog.ldf', 'tempdb.mdf', 'templog.ldf', 'ERRORLOG')
Assert-Eq (@(Get-UserDatabaseFiles -FileNames $data).Count) '0' 'system databases only'
Assert-Eq ((Get-UserDatabaseFiles -FileNames ($data + @('DellData.mdf', 'DellData_log.ldf'))) -join ',') 'DellData.mdf,DellData_log.ldf' 'user database found'

# --- Arguments / outcomes -----------------------------------------------------
Assert-Eq ((Get-SqlUninstallArguments -InstanceName 'SQLEXPRESS') -join ' ') '/Q /ACTION=Uninstall /FEATURES=SQL /INSTANCENAME=SQLEXPRESS' 'uninstall arguments'
Assert-Eq (Get-InstallOutcome -ExitCode 0) 'OK' '0'
Assert-Eq (Get-InstallOutcome -ExitCode 1605) 'OK' '1605 already gone'
Assert-Eq (Get-InstallOutcome -ExitCode 3010) 'REBOOT' '3010'
Assert-Eq (Get-InstallOutcome -ExitCode 1603) 'FAIL' '1603'
Assert-Eq (Get-InstallOutcome -ExitCode $null) 'UNKNOWN' 'no code'
Assert-Eq (Get-FinalExitCode -Failed $false -NeedsHuman $true -Reboot $true) '2' 'blocked'
Assert-Eq (Get-FinalExitCode -Failed $false -NeedsHuman $false -Reboot $true) '3010' 'reboot'
$r = Get-RelaunchArguments -ScriptPath 'C:\s.ps1' -Bound @{ DryRun = [switch]$true; KeepLocalDB = [switch]$false }
Assert-Eq ($r -join ' ') '-NoProfile -ExecutionPolicy Bypass -File C:\s.ps1 -DryRun' 'relaunch arguments'

if ($failed -gt 0) { Write-Host "$failed test(s) failed"; exit 1 }
Write-Host 'All tests passed'
