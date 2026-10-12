# Unit tests for Remediate-OfficeMacroSecurity.ps1 decision helpers.
# Run: pwsh -NoProfile -File windows/tests/Remediate-OfficeMacroSecurity.Tests.ps1
#
# Plugin 123461 (AccessVBOM on) and plugin 123459 (VBAWarnings = 1, enable all
# macros) on CSLT-201 / CSPRLT-68, 2026-10-12. User and machine settings are
# fixed; Group Policy / Intune values are only reported unless -EnforcePolicy.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path (Split-Path -Parent $here) 'Remediate-OfficeMacroSecurity.ps1'
$env:OFFICE_MACRO_DOTSOURCE = '1'
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
$act = { param($n, $v, $pol, $enf) Get-MacroSettingAction -Name $n -Value $v -IsPolicy $pol -EnforcePolicy $enf }

# --- AccessVBOM (123461): any nonzero value is on -----------------------------
Assert-Eq (& $act 'AccessVBOM' 1 $false $false) 'FIX' 'AccessVBOM 1 is fixed'
Assert-Eq (& $act 'AccessVBOM' 0 $false $false) 'OK' 'AccessVBOM 0 is left'
Assert-Eq (& $act 'AccessVBOM' $null $false $false) 'OK' 'absent AccessVBOM is OK'
Assert-Eq (& $act 'AccessVBOM' 2 $false $false) 'FIX' 'AccessVBOM nonzero counts as on'
Assert-Eq (& $act 'AccessVBOM' 'junk' $false $false) 'FIX' 'unparseable AccessVBOM is treated as on'
Assert-Eq (Get-MacroSettingFixValue -Name 'AccessVBOM') 0 'AccessVBOM fixed to 0'

# --- VBAWarnings (123459): only 1 = enable all macros is flagged --------------
Assert-Eq (& $act 'VBAWarnings' 1 $false $false) 'FIX' 'VBAWarnings 1 (enable all) is fixed'
Assert-Eq (& $act 'VBAWarnings' 2 $false $false) 'OK' 'VBAWarnings 2 (disable with notification) is left'
Assert-Eq (& $act 'VBAWarnings' 3 $false $false) 'OK' 'VBAWarnings 3 (signed only) is left'
Assert-Eq (& $act 'VBAWarnings' 4 $false $false) 'OK' 'VBAWarnings 4 (disable all) is left'
Assert-Eq (& $act 'VBAWarnings' 'junk' $false $false) 'OK' 'unparseable VBAWarnings is not guessed at'
Assert-Eq (Get-MacroSettingFixValue -Name 'VBAWarnings') 2 'VBAWarnings fixed to 2, the Office default'

# --- Outlook Level (123459) ---------------------------------------------------
Assert-Eq (& $act 'Level' 1 $false $false) 'FIX' 'Outlook Level 1 (no security check) is fixed'
Assert-Eq (& $act 'Level' 2 $false $false) 'OK' 'Outlook Level 2 is left'
Assert-Eq (Get-MacroSettingFixValue -Name 'Level') 2 'Outlook Level fixed to 2'
Assert-Eq ((Get-MacroSettingNames -App 'Outlook') -join ',') 'AccessVBOM,VBAWarnings,Level' 'Outlook also checks Level'
Assert-Eq ((Get-MacroSettingNames -App 'Excel') -join ',') 'AccessVBOM,VBAWarnings' 'Excel checks AccessVBOM and VBAWarnings only'

# --- Policy values ------------------------------------------------------------
Assert-Eq (& $act 'VBAWarnings' 1 $true $false) 'REPORT' 'policy VBAWarnings 1 is reported, not changed'
Assert-Eq (& $act 'AccessVBOM' 1 $true $false) 'REPORT' 'policy AccessVBOM 1 is reported, not changed'
Assert-Eq (& $act 'VBAWarnings' 1 $true $true) 'FIX' 'policy value overwritten with -EnforcePolicy'
Assert-Eq (& $act 'VBAWarnings' 2 $true $false) 'OK' 'policy VBAWarnings 2 is OK'

# --- Get-OfficeBaseKeys -------------------------------------------------------
$user = @(Get-OfficeBaseKeys -IsMachine $false)
Assert-Eq ($user | ForEach-Object { $_.Path }) 'SOFTWARE\Microsoft\Office SOFTWARE\Policies\Microsoft\Office' 'user hive: setting and policy subtrees'
$machine = @(Get-OfficeBaseKeys -IsMachine $true)
Assert-Eq $machine.Count 4 'machine hive adds both WOW6432Node subtrees'
Assert-Eq (($machine | Where-Object { $_.IsPolicy }).Count) 2 'two of the machine subtrees are policy'

# --- Select-UserProfiles ------------------------------------------------------
$entries = @(
    [pscustomobject]@{ Sid = 'S-1-5-18'; ProfilePath = 'C:\Windows\system32\config\systemprofile' },
    [pscustomobject]@{ Sid = 'S-1-5-21-111-222-333-1001'; ProfilePath = 'C:\Users\jdoe' },
    [pscustomobject]@{ Sid = 'S-1-5-21-111-222-333-1002'; ProfilePath = 'C:\Users\gone' },
    [pscustomobject]@{ Sid = 'S-1-5-21-111-222-333-1003.bak'; ProfilePath = 'C:\Users\temp' },
    [pscustomobject]@{ Sid = 'S-1-5-21-111-222-333-1004'; ProfilePath = '' }
)
$sel = @(Select-UserProfiles -Entries $entries -PathExists { param($p) $p -ne 'C:\Users\gone' })
Assert-Eq ($sel | ForEach-Object { $_.ProfilePath }) 'C:\Users\jdoe' 'only real user profiles with a folder are kept'

# --- Find-LoadedHiveKey: the in-use bypass ------------------------------------
# hivelist maps each loaded hive key to its file as a device path.
$hl = @{
    '\REGISTRY\MACHINE\SYSTEM' = '\Device\HarddiskVolume3\Windows\System32\config\SYSTEM'
    '\REGISTRY\USER\S-1-5-21-111-222-333-1001' = '\Device\HarddiskVolume3\Users\jdoe\NTUSER.DAT'
    '\REGISTRY\USER\S-1-5-21-111-222-333-1001_Classes' = '\Device\HarddiskVolume3\Users\jdoe\AppData\Local\Microsoft\Windows\UsrClass.dat'
    '\REGISTRY\USER\TempHive' = '\Device\HarddiskVolume3\Users\asmith\NTUSER.DAT'
    '\REGISTRY\USER\S-1-5-21-111-222-333-1005' = '\Device\HarddiskVolume3\Users\bob.smith\NTUSER.DAT'
    '\REGISTRY\USER\S-1-5-19' = ''
}
Assert-Eq (Find-LoadedHiveKey -HiveList $hl -NtUserPath 'C:\Users\jdoe\NTUSER.DAT') 'HKEY_USERS\S-1-5-21-111-222-333-1001' 'signed-in user found under its SID'
Assert-Eq (Find-LoadedHiveKey -HiveList $hl -NtUserPath 'C:\Users\asmith\NTUSER.DAT') 'HKEY_USERS\TempHive' 'hive left mounted by an earlier script is found'
Assert-Eq (Find-LoadedHiveKey -HiveList $hl -NtUserPath 'c:\users\ASMITH\ntuser.dat') 'HKEY_USERS\TempHive' 'match is case-insensitive'
Assert-Eq (Find-LoadedHiveKey -HiveList $hl -NtUserPath 'C:\Users\smith\NTUSER.DAT') '' 'no false match on a path suffix (bob.smith)'
Assert-Eq (Find-LoadedHiveKey -HiveList $hl -NtUserPath 'C:\Users\nobody\NTUSER.DAT') '' 'unloaded hive returns nothing'
Assert-Eq (Find-LoadedHiveKey -HiveList @{} -NtUserPath 'C:\Users\jdoe\NTUSER.DAT') '' 'empty hivelist returns nothing'

# --- Invoke-NativeCommand (CSPRLT-68, 2026-10-12) -----------------------------
# reg.exe load wrote to stderr; with $ErrorActionPreference = 'Stop' and 2>&1,
# Windows PowerShell 5.1 turned that into a terminating NativeCommandError and
# the run died at the second user. Failures must come back as data.
$ErrorActionPreference = 'Stop'
$sh = (Get-Command sh -ErrorAction SilentlyContinue).Source
if ($sh) {
    $r = Invoke-NativeCommand -FilePath $sh -Arguments @('-c', 'echo ERROR: in use 1>&2; exit 1')
    Assert-Eq $r.ExitCode 1 'native failure exit code is returned'
    Assert-Eq $r.Output 'ERROR: in use' 'native stderr is returned as text'
    $r = Invoke-NativeCommand -FilePath $sh -Arguments @('-c', 'echo loaded; exit 0')
    Assert-Eq $r.ExitCode 0 'native success exit code'
    Assert-Eq $r.Output 'loaded' 'native stdout is returned'
    Assert-Eq $ErrorActionPreference 'Stop' 'caller ErrorActionPreference is restored'
}

# --- 64-bit relaunch -----------------------------------------------------------
Assert-Eq (Test-Needs64BitRelaunch -Is64BitOS $true -Is64BitProcess $false) 'True' '32-bit PowerShell on 64-bit Windows relaunches'
Assert-Eq (Test-Needs64BitRelaunch -Is64BitOS $true -Is64BitProcess $true) 'False' '64-bit PowerShell does not relaunch'
Assert-Eq (Test-Needs64BitRelaunch -Is64BitOS $false -Is64BitProcess $false) 'False' '32-bit Windows does not relaunch'
Assert-Eq ((Get-RelaunchArguments -ScriptPath 'C:\x\s.ps1' -EnforcePolicy $true -DryRun $false) -join ' ') '-NoProfile -ExecutionPolicy Bypass -File C:\x\s.ps1 -EnforcePolicy' 'relaunch passes -EnforcePolicy'
Assert-Eq ((Get-RelaunchArguments -ScriptPath 'C:\x\s.ps1' -EnforcePolicy $false -DryRun $true) -join ' ') '-NoProfile -ExecutionPolicy Bypass -File C:\x\s.ps1 -DryRun' 'relaunch passes -DryRun'

# --- Sign-in fallback for locked hives ----------------------------------------
$logon = Get-LogonFixScript
$parseErrors = $null
$null = [System.Management.Automation.Language.Parser]::ParseInput($logon, [ref]$null, [ref]$parseErrors)
Assert-Eq @($parseErrors).Count 0 'sign-in fix script parses'
Assert-Eq ($logon -match 'HKCU:\\Software\\Microsoft\\Office') 'True' 'sign-in fix targets the user''s own hive'
Assert-Eq ($logon -match 'Policies') 'False' 'sign-in fix never touches policy keys'
$stub = Get-ActiveSetupStubPath -Script $logon
Assert-Eq ($stub -match '^powershell\.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand [A-Za-z0-9+/=]+$') 'True' 'StubPath is a single encoded PowerShell command'
$b64 = ($stub -split ' ')[-1]
Assert-Eq ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64))) $logon 'encoded command decodes to the fix script'
Assert-Eq ($stub.Length -lt 4000) 'True' 'StubPath stays well under the command-line limit'
Assert-Eq (Get-ActiveSetupVersion -Now ([datetime]'2026-10-12 09:05')) '2026,1012,905,0' 'version is numeric and increases with time'

if ($failed -gt 0) {
    Write-Host "`n$failed test(s) failed"
    exit 1
}
Write-Host "`nAll tests passed"
exit 0
