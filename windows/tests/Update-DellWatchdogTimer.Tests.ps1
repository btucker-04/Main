# Unit tests for Update-DellWatchdogTimer.ps1 helpers.
# Run: pwsh -NoProfile -File windows/tests/Update-DellWatchdogTimer.Tests.ps1
#
# Plugin 339708 (DSA-2026-248): csprpc-134 had WDTKernel.sys 1.2.1.0; fixed is 2.0.0.1.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path (Split-Path -Parent $here) 'Update-DellWatchdogTimer.ps1'
$env:DELLWDT_DOTSOURCE = '1'
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

# --- Version parsing ---------------------------------------------------------
Assert-Eq (ConvertTo-DriverVersion -Text '1.2.1.0') '1.2.1.0' 'csprpc-134 driver version 1.2.1.0'
Assert-Eq (ConvertTo-DriverVersion -Text '2.0.0.1 (WinBuild.160101.0800)') '2.0.0.1' 'trailing build text ignored'
Assert-True ($null -eq (ConvertTo-DriverVersion -Text '')) 'empty version is unknown'
Assert-True ((ConvertTo-DriverVersion -Text '1.2.1.0') -lt $FixedVersion) '1.2.1.0 is below the fixed version'
Assert-True ((ConvertTo-DriverVersion -Text '2.0.0.10') -gt $FixedVersion) '2.0.0.10 compares as a version, not a string'
Assert-Eq $FixedVersion '2.0.0.1' 'fixed version is 2.0.0.1 (DSA-2026-248)'

# --- DUP exit codes ----------------------------------------------------------
Assert-True ((Get-DupExitMeaning $null) -like 'UNKNOWN*') 'no exit code is UNKNOWN, not success'
Assert-Eq (Get-DupExitMeaning 2) 'REBOOT_REQUIRED' 'DUP 2 is reboot required'
Assert-True ((Get-DupExitMeaning 5) -like 'QUALIFICATION_ERROR*') 'DUP 5 is not applicable to this system'
Assert-True ((Get-DupExitMeaning 42) -like '*not in the DUP table*') 'unlisted code is reported as unlisted'

# --- Result decision -----------------------------------------------------------
$old = [version]'1.2.1.0'; $new = [version]'2.0.0.1'
$r = { param($a, $c, $p) (Get-WdtResult -After $a -Fixed $FixedVersion -DupCode $c -PendingRename $p).Exit }
Assert-Eq (& $r $new 0 $false) 0 'file updated, DUP 0: done'
Assert-Eq (& $r $new 2 $false) 3010 'file updated, DUP reboot required: 3010'
Assert-Eq (& $r $old 2 $false) 3010 'file still old, DUP reboot required: 3010 (replaced at restart)'
Assert-Eq (& $r $old 1 $true) 3010 'file still old but a pending rename replaces it: 3010'
Assert-Eq (& $r $old 0 $false) 2 'DUP says success but the file is still old: human must look'
Assert-Eq (& $r $old 3 $false) 2 'DUP says up to date but the file is still old: human must look'
Assert-Eq (& $r $old 5 $false) 2 'package not applicable to this model: human must look'
Assert-Eq (& $r $old 1 $false) 1 'DUP failed, file old: failure'
Assert-Eq (& $r $old $null $false) 1 'DUP timed out, file old: failure'
Assert-Eq (& $r $null 0 $false) 2 'driver missing after a DUP 0: human must look'
Assert-Eq (& $r ([version]'2.1.0.0') 3 $false) 0 'newer driver already present: done'

# --- Pending rename ------------------------------------------------------------
$ops = @('\??\C:\WINDOWS\system32\drivers\SETA1B2.tmp', '!\??\C:\WINDOWS\system32\drivers\WDTKernel.sys')
Assert-True (Test-PendingDriverRename -Operations $ops -Name 'WDTKernel.sys') 'pending rename onto WDTKernel.sys is found (case-insensitive)'
Assert-True (-not (Test-PendingDriverRename -Operations @('\??\C:\x\other.sys', '') -Name 'WDTKernel.sys')) 'other renames are ignored'
Assert-True (-not (Test-PendingDriverRename -Operations @() -Name 'WDTKernel.sys')) 'no pending renames'

# --- Payload lookup ------------------------------------------------------------
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('wdt_' + [guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Force -Path (Join-Path $tmp 'Drivers/x64') | Out-Null
    Set-Content -Path (Join-Path $tmp 'Drivers/x64/WDTKernel.sys') -Value 'x'
    Set-Content -Path (Join-Path $tmp 'Drivers/x64/WDTKernel.inf') -Value 'x'
    Assert-Eq (Find-PayloadDriver -Dir $tmp -Name 'WDTKernel.sys').Count 1 'driver found in a nested extract folder'
    Assert-Eq (Find-PayloadDriver -Dir (Join-Path $tmp 'missing') -Name 'WDTKernel.sys').Count 0 'missing extract folder yields nothing'
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

# --- 64-bit relaunch -------------------------------------------------------------
Assert-True (Test-Needs64BitRelaunch -Is64BitOS $true -Is64BitProcess $false) '32-bit EC agent on 64-bit Windows relaunches'
Assert-True (-not (Test-Needs64BitRelaunch -Is64BitOS $true -Is64BitProcess $true)) '64-bit process does not relaunch'
$ra = Get-RelaunchArguments -ScriptPath 'C:\x\s.ps1' -Bound @{ DryRun = [System.Management.Automation.SwitchParameter]$true; InstallerPath = 'C:\d\wdt.exe' }
Assert-Eq ($ra -join '|') '-NoProfile|-ExecutionPolicy|Bypass|-File|C:\x\s.ps1|-DryRun|-InstallerPath|C:\d\wdt.exe' 'switches and InstallerPath survive the relaunch'

if ($failed -gt 0) {
    Write-Host "`n$failed test(s) failed"
    exit 1
}
Write-Host "`nAll tests passed"
exit 0
