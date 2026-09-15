# Unit tests for Fix-InsecureServicePermissions.ps1 helpers.
# Run: pwsh -NoProfile -File windows/tests/Fix-InsecureServicePermissions.Tests.ps1
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path (Split-Path -Parent $here) 'Fix-InsecureServicePermissions.ps1'
$env:FIX_SERVICE_PERMS_DOTSOURCE = '1'
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
    if (-not $Cond) {
        Write-Host "FAIL $Name"
        $script:failed++
    } else {
        Write-Host "OK   $Name"
    }
}

# --- ImagePath -> exe (Nessus 65057 swissqprint / generic) ---
Assert-Eq (Get-ServiceExecutableFromImagePath -ImagePath '"C:\Program Files\swissqprint\mariadb-10.5.29\bin\mysqld.exe" --defaults-file=C:\foo.ini') `
    'C:\Program Files\swissqprint\mariadb-10.5.29\bin\mysqld.exe' `
    'quoted mysqld with args'

Assert-Eq (Get-ServiceExecutableFromImagePath -ImagePath 'C:\Program Files\SOLIDWORKS Corp\SOLIDWORKS Visualize\foo.exe') `
    'C:\Program Files\SOLIDWORKS Corp\SOLIDWORKS Visualize\foo.exe' `
    'unquoted path with spaces'

Assert-Eq (Get-ServiceExecutableFromImagePath -ImagePath '') $null 'empty ImagePath'
Assert-Eq (Get-ServiceExecutableFromImagePath -ImagePath '\SystemRoot\System32\drivers\acpi.sys') $null 'kernel driver path'
Assert-Eq (Get-ServiceExecutableFromImagePath -ImagePath 'C:\Windows\System32\drivers\acpi.sys') $null 'sys file skipped'

# --- Protected OS / Defender / Store paths (Nessus "Bad Shares" noise) ---
Assert-True (Test-ProtectedServicePath -Path 'C:\ProgramData\Microsoft\Windows Defender\platform\4.18.26080.3-0\nissrv.exe') `
    'skip Defender nissrv'
Assert-True (Test-ProtectedServicePath -Path 'C:\ProgramData\Microsoft\Windows Defender\platform\4.18.26080.3-0\mpdlpservice.exe') `
    'skip Defender mpdlpservice'
Assert-True (Test-ProtectedServicePath -Path 'C:\Windows\System32\svchost.exe') 'skip System32'
Assert-True (Test-ProtectedServicePath -Path 'C:\Program Files\WindowsApps\AppUp.IntelArcSoftware_1\foo.exe') 'skip WindowsApps'
Assert-True (-not (Test-ProtectedServicePath -Path 'C:\Program Files\swissqprint\mariadb-10.5.29\bin\mysqld.exe')) `
    'do not skip swissqprint MariaDB'
Assert-True (-not (Test-ProtectedServicePath -Path 'C:\Program Files\SOLIDWORKS Corp\SOLIDWORKS\swScheduler\sw.exe')) `
    'do not skip SolidWorks scheduler'

# --- Untrusted identities matching plugin 65057 ---
Assert-True (Test-UntrustedIdentity -SidOrName 'S-1-5-32-545') 'BUILTIN Users SID'
Assert-True (Test-UntrustedIdentity -SidOrName 'S-1-1-0') 'Everyone SID'
Assert-True (Test-UntrustedIdentity -SidOrName 'S-1-5-11') 'Authenticated Users SID'
Assert-True (Test-UntrustedIdentity -SidOrName 'S-1-5-21-111-222-333-513') 'Domain Users RID 513'
Assert-True (Test-UntrustedIdentity -SidOrName 'BUILTIN\Users') 'BUILTIN\Users name'
Assert-True (Test-UntrustedIdentity -SidOrName 'Everyone') 'Everyone name'
Assert-True (Test-UntrustedIdentity -SidOrName 'NT AUTHORITY\Authenticated Users') 'Authenticated Users name'
Assert-True (Test-UntrustedIdentity -SidOrName 'CORP\Domain Users') 'Domain Users name'
Assert-True (-not (Test-UntrustedIdentity -SidOrName 'S-1-5-32-544')) 'Administrators not untrusted'
Assert-True (-not (Test-UntrustedIdentity -SidOrName 'S-1-5-18')) 'SYSTEM not untrusted'
Assert-True (-not (Test-UntrustedIdentity -SidOrName 'NT AUTHORITY\SYSTEM')) 'SYSTEM name not untrusted'

# --- Directory chosen is the exe folder, not a parent tree ---
Assert-Eq (Get-ServiceDirectoryFromExe -ExePath 'C:\Program Files\swissqprint\mariadb-10.5.29\bin\mysqld.exe') `
    'C:\Program Files\swissqprint\mariadb-10.5.29\bin' `
    'MariaDB bin only, not swissqprint parent'
Assert-True (-not (Test-SafeServiceDirectory -Directory 'C:\')) 'refuse drive root'
Assert-True (-not (Test-SafeServiceDirectory -Directory 'C:\Program Files')) 'refuse Program Files root'
Assert-True (Test-SafeServiceDirectory -Directory 'C:\Program Files\swissqprint\mariadb-10.5.29\bin') 'accept MariaDB bin'

Assert-True (Test-ServiceNameAllowed -Name 'MariaDB' -Filter @('MariaDB')) 'filter exact MariaDB'
Assert-True (Test-ServiceNameAllowed -Name 'MariaDB' -Filter @('Maria*')) 'filter wildcard Maria*'
Assert-True (-not (Test-ServiceNameAllowed -Name 'WdNisSvc' -Filter @('MariaDB'))) 'filter excludes Defender svc'
Assert-True (Test-ServiceNameAllowed -Name 'Anything' -Filter @()) 'empty filter allows all'

Assert-True (Test-ShouldRegrantRx -SidOrName 'S-1-5-32-545') 'regrant Users RX'
Assert-True (Test-ShouldRegrantRx -SidOrName 'S-1-5-11') 'regrant Auth Users RX'
Assert-True (-not (Test-ShouldRegrantRx -SidOrName 'S-1-1-0')) 'do not regrant Everyone'

if ($failed -gt 0) {
    Write-Host "`n$failed test(s) failed"
    exit 1
}
Write-Host "`nAll tests passed"
exit 0
