# Unit tests for Update-Python.ps1 decision helpers.
# Run: pwsh -NoProfile -File windows/tests/Update-Python.Tests.ps1
#
# Paths and versions are from the 2026-11-12 Tenable export of plugin 373609.
# The feed entries are the ones python.org served on 2026-11-12
# (index-windows.json, trimmed to id and sort-version).
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path (Split-Path -Parent $here) 'Update-Python.ps1'
$env:PYTHON_UPDATE_DOTSOURCE = '1'
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

# --- versions ----------------------------------------------------------------
Assert-Eq (ConvertTo-PythonVersion '3.13.2150.1013') '3.13.2' 'FILEVERSION micro*1000 decoded'
Assert-Eq (ConvertTo-PythonVersion '2.7.6150') '2.7.6' 'Tenable 2.7.6150 is 2.7.6'
Assert-Eq (ConvertTo-PythonVersion '3.14.10') '3.14.10' 'ProductVersion passes through'
Assert-Eq (ConvertTo-PythonVersion '3.15.0') '3.15.0' 'x.y.0 stays x.y.0'
Assert-Eq (ConvertTo-PythonVersion 'garbage') '' 'unparseable -> null'
Assert-Eq (Get-PythonBranch ([version]'3.13.11')) '3.13' 'branch'
Assert-Eq (ConvertTo-PythonArch 0x8664) 'amd64' 'PE amd64'
Assert-Eq (ConvertTo-PythonArch 0x14C) 'win32' 'PE x86'
Assert-Eq (ConvertTo-PythonArch 0xAA64) 'arm64' 'PE arm64'

# --- install kind from Tenable's paths ---------------------------------------
Assert-Eq (Get-PythonCopyKind 'C:\Program Files\Python313\python.exe') 'Machine' 'Program Files copy'
Assert-Eq (Get-PythonCopyKind 'C:\Python314\python.exe') 'Machine' 'drive-root copy'
Assert-Eq (Get-PythonCopyKind 'E:\Python38\python.exe') 'Machine' 'E: drive copy (ownership decided by registration)'
Assert-Eq (Get-PythonCopyKind 'C:\Users\cgolm\AppData\Local\Programs\Python\Python314\python.exe') 'UserInstaller' 'per-user python.org install'
Assert-Eq (Get-PythonCopyKind 'C:\Users\alowe\AppData\Local\Programs\Python\Python310\python.exe') 'UserInstaller' 'per-user 3.10'
Assert-Eq (Get-PythonCopyKind 'C:\Users\x\AppData\Local\Programs\Python\Python314-32\python.exe') 'UserInstaller' 'per-user 32-bit'
Assert-Eq (Get-PythonCopyKind 'C:\Users\aasamoah\AppData\Local\Python\pythoncore-3.14-64\python.exe') 'PyManager' 'install manager runtime'
Assert-Eq (Get-PythonCopyKind 'C:\Users\yzholdassov\AppData\Local\Python\pythoncore-3.15-64\python.exe') 'PyManager' 'install manager 3.15'
Assert-Eq (Get-PythonCopyKind 'C:\Users\x\Documents\tools\python\python.exe') 'Unmanaged' 'loose copy in a profile'
Assert-Eq (Get-ProfileFolder 'C:\Users\JeremyDriscoll\AppData\Local\Programs\Python\Python315\python.exe') 'C:\Users\JeremyDriscoll' 'profile folder'

# --- python.org feed ---------------------------------------------------------
$index = @{ versions = @(
    @{ id = 'pythoncore-3.16-64'; 'sort-version' = '3.16.0a2' }
    @{ id = 'pythoncore-3.15-64'; 'sort-version' = '3.15.2' }
    @{ id = 'pythoncore-3.14-32'; 'sort-version' = '3.14.10' }
    @{ id = 'pythoncore-3.14-64'; 'sort-version' = '3.14.10' }
    @{ id = 'pythoncore-3.14t-64'; 'sort-version' = '3.14.10' }
    @{ id = 'pythoncore-3.13-64'; 'sort-version' = '3.13.17' }
    @{ id = 'pythoncore-3.14-64'; 'sort-version' = '3.14.9' }
    @{ id = 'pythoncore-3.15-64'; 'sort-version' = '3.15.0rc3' }
    @{ id = 'pythoncore-3.13-64'; 'sort-version' = '3.13.16' }
    @{ id = 'pythoncore-3.12-64'; 'sort-version' = '3.12.10' }
    @{ id = 'pythoncore-3.11-64'; 'sort-version' = '3.11.9' }
) } | ConvertTo-Json -Depth 4
Assert-Eq (Get-NewestWindowsBuild $index '3.14' 'amd64') '3.14.10' '3.14.10 beats 3.14.9 (not a string sort)'
Assert-Eq (Get-NewestWindowsBuild $index '3.13' 'amd64') '3.13.17' '3.13 Windows builds stop at 3.13.17'
Assert-Eq (Get-NewestWindowsBuild $index '3.15' 'amd64') '3.15.2' 'rc ignored'
Assert-Eq (Get-NewestWindowsBuild $index '3.14' 'win32') '3.14.10' '32-bit id'
Assert-Eq (Get-NewestWindowsBuild $index '3.16' 'amd64') '' 'alpha-only branch has no build'
Assert-Eq (Get-NewestWindowsBuild $index '3.10' 'amd64') '' 'branch not in the feed'

$listing = '<a href="3.13.17/">3.13.17/</a>' + "`n" + '<a href="3.13.18/">3.13.18/</a>' + "`n" +
    '<a href="3.12.16/">3.12.16/</a>' + "`n" + '<a href="3.14.9/">3.14.9/</a>' + "`n" +
    '<a href="3.14.10/">3.14.10/</a>' + "`n" + '<a href="3.15.2/">3.15.2/</a>' + "`n" + '<a href="3.1.5/">3.1.5/</a>'
Assert-Eq (Get-NewestRelease $listing '3.13') '3.13.18' 'newest 3.13 release'
Assert-Eq (Get-NewestRelease $listing '3.14') '3.14.10' 'newest 3.14 release'
Assert-Eq (Get-NewestRelease $listing '3.1') '3.1.5' '3.1 does not match 3.13'

# --- plans for the export's copies -------------------------------------------
$today = [datetime]'2026-11-12'
$p = Get-PythonCopyPlan ([version]'3.14.6') 'Machine' '3.14.10' '3.14.10' $today
Assert-Eq ($p.Action + ' ' + $p.Target + ' ' + $p.SourceOnly) 'Update 3.14.10 False' 'cs-hd-01 C:\Python314 3.14.6 -> 3.14.10'
$p = Get-PythonCopyPlan ([version]'3.15.0') 'UserInstaller' '3.15.2' '3.15.2' $today
Assert-Eq ($p.Action + ' ' + $p.Target) 'Update 3.15.2' 'cslt-249 per-user 3.15.0 -> 3.15.2'
$p = Get-PythonCopyPlan ([version]'3.13.2') 'Machine' '3.13.17' '3.13.18' $today
Assert-Eq ($p.Action + ' ' + $p.Target + ' ' + $p.SourceOnly) 'Update 3.13.17 True' 'cslt-135 3.13.2 patched to 3.13.17 but still held'
Assert-Eq ($p.Reason -match '3.13.18 as source only') 'True' 'source-only reason names the release'
$p = Get-PythonCopyPlan ([version]'3.13.17') 'Machine' '3.13.17' '3.13.18' $today
Assert-Eq $p.Action 'Hold' 'on the last 3.13 build: held, nothing to install'
$p = Get-PythonCopyPlan ([version]'3.12.10') 'Machine' '3.12.10' '3.12.16' $today
Assert-Eq $p.Action 'Hold' 'csprpc-bc 3.12.10 is the last 3.12 build'
$p = Get-PythonCopyPlan ([version]'3.12.10') 'Unmanaged' '3.12.10' '3.12.16' $today
Assert-Eq ($p.Reason -match 'bundled') 'True' 'unregistered E:\Python38 is held as app-bundled'
$p = Get-PythonCopyPlan ([version]'3.10.4') 'UserInstaller' '' '3.10.19' $today
Assert-Eq ($p.Action + ' ' + ($p.Reason -match 'end-of-life')) 'Hold True' 'cslt-001 3.10 is EOL'
$p = Get-PythonCopyPlan ([version]'2.7.6') 'Machine' '' '2.7.18' $today
Assert-Eq ($p.Action + ' ' + ($p.Reason -match 'end-of-life')) 'Hold True' 'cspc-016 2.7 is EOL'
$p = Get-PythonCopyPlan ([version]'3.14.10') 'PyManager' '3.14.10' '3.14.10' $today
Assert-Eq $p.Action 'Current' 'already on the newest build'
$p = Get-PythonCopyPlan ([version]'3.11.9') 'UserInstaller' '3.11.9' '3.11.18' ([datetime]'2027-11-01')
Assert-Eq ($p.Reason -match 'end-of-life') 'True' '3.11 turns EOL after 2027-10-31'

# --- installers and commands -------------------------------------------------
Assert-Eq (Get-InstallerFileName '3.14.10' 'amd64') 'python-3.14.10-amd64.exe' 'amd64 installer name'
Assert-Eq (Get-InstallerFileName '3.14.10' 'win32') 'python-3.14.10.exe' 'win32 installer name'
Assert-Eq (Test-PsfSignature 'Valid' 'CN=Python Software Foundation, O=Python Software Foundation, L=Beaverton, S=Oregon, C=US') 'True' 'PSF signature accepted'
Assert-Eq (Test-PsfSignature 'NotSigned' '') 'False' 'unsigned rejected'
Assert-Eq (Test-PsfSignature 'Valid' 'CN=Zscaler Inc.') 'False' 'other signer rejected'
$cmd = Get-UserInstallerCommand 'C:\ProgramData\CompoSecure\Python\python-3.15.2-amd64.exe' 'C:\Users\jdriscoll\AppData\Local\Programs\Python\Python315' '3.15.2'
Assert-Eq $cmd 'cmd.exe /c ""C:\ProgramData\CompoSecure\Python\python-3.15.2-amd64.exe" /quiet InstallAllUsers=0 TargetDir="C:\Users\jdriscoll\AppData\Local\Programs\Python\Python315" /log "%TEMP%\CompoSecure_Python_3.15.2.log""' 'per-user RunOnce command'
Assert-Eq (Get-PyManagerCommand) 'cmd.exe /c "pymanager install --update --yes > "%TEMP%\CompoSecure_PythonManager.log" 2>&1"' 'install manager RunOnce command'
Assert-Eq (Get-PythonInstallerExitMeaning $null) 'UNKNOWN (Windows reported no exit code)' 'blank exit code is UNKNOWN'
Assert-Eq (Get-PythonInstallerExitMeaning 1618) 'another installation is in progress' '1618'
Assert-Eq (Get-FinalExitCode $false $true $true) '2' 'held beats reboot'
Assert-Eq (Get-FinalExitCode $true $true $false) '1' 'failure beats held'
Assert-Eq (Get-FinalExitCode $false $false $true) '3010' 'reboot only'

if ($failed -gt 0) { Write-Host "$failed test(s) failed"; exit 1 }
Write-Host 'All tests passed'
exit 0
