# Unit tests for Update-DotNetRuntimes.ps1 inventory helpers.
# Run: pwsh -NoProfile -File windows/tests/Update-DotNetRuntimes.Tests.ps1
#
# Covers CSPRLT-94 (2026-09-16): host\fxr\8.0.21 existed with no hostfxr.dll
# inside it, so 'dotnet --list-runtimes' emitted only an error and matched no
# runtime lines. Get-InstalledMap then reported the x64 root as EMPTY, which
# every later phase reads as "no .NET installed here".
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path (Split-Path -Parent $here) 'Update-DotNetRuntimes.ps1'
$env:UPDATE_DOTNET_DOTSOURCE = '1'
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

# --- Detect the broken-muxer error text -------------------------------------
# Verbatim stderr from the CSPRLT-94 run.
$csprlt94 = @(
    'Error: the required library hostfxr.dll could not be found in [C:\Program Files\dotnet\host\fxr\8.0.21]'
)
Assert-True (Test-HostFxrLoadFailure -Lines $csprlt94) 'CSPRLT-94 stderr is recognised as a muxer failure'

Assert-True (Test-HostFxrLoadFailure -Lines @('A fatal error occurred. The required library hostfxr.dll could not be found.')) `
    'alternate hostfxr wording recognised'
Assert-True (-not (Test-HostFxrLoadFailure -Lines @('Error: An assembly specified in the application dependencies manifest was not found'))) `
    'unrelated error is not a muxer failure'

# A healthy listing must NOT be flagged.
$healthy = @(
    'Microsoft.NETCore.App 9.0.20 [C:\Program Files\dotnet\shared\Microsoft.NETCore.App]',
    'Microsoft.WindowsDesktop.App 9.0.20 [C:\Program Files\dotnet\shared\Microsoft.WindowsDesktop.App]'
)
Assert-True (-not (Test-HostFxrLoadFailure -Lines $healthy)) 'healthy listing is not a muxer failure'
Assert-True (-not (Test-HostFxrLoadFailure -Lines @())) 'no output is not a muxer failure'
Assert-True (-not (Test-HostFxrLoadFailure -Lines $null)) 'null output is not a muxer failure'

# --- Disk fallback: enumerate shared\<flavor>\<version> ---------------------
# The script builds paths with a literal '\', so the fixture embeds one; this
# is the same string the live Windows path produces.
$tmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('dnupd_' + [guid]::NewGuid().ToString('N'))
try {
    $fakeRoot = Join-Path $tmpRoot 'dotnet'
    foreach ($pair in @(
        @('Microsoft.NETCore.App', '9.0.20'),
        @('Microsoft.NETCore.App', '8.0.21'),
        @('Microsoft.WindowsDesktop.App', '9.0.20'),
        @('Microsoft.AspNetCore.App', '8.0.21')
    )) {
        New-Item -ItemType Directory -Force -Path ($fakeRoot + '\shared\' + $pair[0] + '\' + $pair[1]) | Out-Null
    }
    # Noise that must be ignored: not a version folder.
    New-Item -ItemType Directory -Force -Path ($fakeRoot + '\shared\Microsoft.NETCore.App\notaversion') | Out-Null

    $disk = Get-RuntimeVersionsFromDisk -Root $fakeRoot
    $netcore = @($disk | Where-Object { $_.Flavor -eq 'Microsoft.NETCore.App' } |
                 ForEach-Object { $_.Version.ToString() } | Sort-Object)
    Assert-Eq ($netcore -join ',') '8.0.21,9.0.20' 'disk fallback finds both NETCore versions'

    $flavors = @($disk | ForEach-Object { $_.Flavor } | Sort-Object -Unique)
    Assert-Eq ($flavors -join ',') 'Microsoft.AspNetCore.App,Microsoft.NETCore.App,Microsoft.WindowsDesktop.App' `
        'disk fallback finds all three flavors'
    Assert-Eq $disk.Count 4 'disk fallback ignores non-version folders'

    $empty = Get-RuntimeVersionsFromDisk -Root (Join-Path $tmpRoot 'nonexistent')
    Assert-Eq @($empty).Count 0 'missing root yields nothing'
} finally {
    Remove-Item -LiteralPath $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue
}

# --- Integration: Get-InstalledMap against a muxer that cannot load hostfxr --
# Before this change the map came back EMPTY for such a root, which every
# later phase reads as "no .NET installed here".
$tmp2 = Join-Path ([System.IO.Path]::GetTempPath()) ('dnmux_' + [guid]::NewGuid().ToString('N'))
try {
    $rootDir = Join-Path $tmp2 'dotnet'
    New-Item -ItemType Directory -Force -Path $rootDir | Out-Null
    # Payload folders exist on disk even though the muxer is broken.
    New-Item -ItemType Directory -Force -Path ($rootDir + '\shared\Microsoft.NETCore.App\9.0.20') | Out-Null
    New-Item -ItemType Directory -Force -Path ($rootDir + '\shared\Microsoft.WindowsDesktop.App\9.0.20') | Out-Null

    # Stand-in for dotnet.exe reproducing the CSPRLT-94 stderr.
    $fakeExe = Join-Path $rootDir 'dotnet.exe'
    # printf '%s\n', not echo: dash's echo expands the \f in host\fxr.
    Set-Content -LiteralPath $fakeExe -Value @'
#!/bin/sh
printf '%s\n' 'Error: the required library hostfxr.dll could not be found in [C:\Program Files\dotnet\host\fxr\8.0.21]' 1>&2
exit 1
'@
    if ($IsLinux -or $IsMacOS) { & chmod +x $fakeExe }

    $script:MuxerBroken = $false
    $script:MuxerBrokenRoots = @()
    $map = Get-InstalledMap @(@{ Arch = 'x64'; Exe = $fakeExe })

    Assert-True $script:MuxerBroken 'broken muxer is flagged, not silently ignored'
    Assert-Eq ($script:MuxerBrokenRoots -join ',') 'x64' 'affected root recorded'
    Assert-True ($map.ContainsKey('x64|Microsoft.NETCore.App')) 'map populated from disk despite broken muxer'
    Assert-Eq ($map['x64|Microsoft.NETCore.App'] -join ',') '9.0.20' 'disk-sourced version is correct'
    Assert-Eq $map.Keys.Count 2 'both on-disk flavors recovered'
} finally {
    Remove-Item -LiteralPath $tmp2 -Recurse -Force -ErrorAction SilentlyContinue
}

# --- CSLT-015 (2026-10-28): host\fxr folder missing entirely ----------------
# Verbatim stderr. Windows PowerShell 5.1 turned it into a terminating
# NativeCommandError under ErrorActionPreference Stop, so v3.9 died at
# 'dotnet --list-runtimes' before the broken-host check ran.
$cslt015 = @('A fatal error occurred. The folder [C:\Program Files\dotnet\host\fxr] does not exist')
Assert-Eq (Get-HostFxrFailure -Lines $cslt015) 'MissingFolder' 'CSLT-015: missing host\fxr folder recognised'
Assert-Eq (Get-HostFxrFailure -Lines $csprlt94) 'MissingDll' 'CSPRLT-94: missing hostfxr.dll recognised'
Assert-Eq (Get-HostFxrFailure -Lines $healthy) '' 'healthy listing: no host failure'
Assert-Eq (Get-HostFxrFailure -Lines @('The folder [C:\Program Files\dotnet\shared] does not exist')) '' 'other missing folder is not a host failure'
Assert-True (Test-HostFxrLoadFailure -Lines $cslt015) 'CSLT-015 counts as a muxer failure'

$tmp3 = Join-Path ([System.IO.Path]::GetTempPath()) ('dnfxr_' + [guid]::NewGuid().ToString('N'))
try {
    $rootDir = Join-Path $tmp3 'dotnet'
    New-Item -ItemType Directory -Force -Path ($rootDir + '\shared\Microsoft.NETCore.App\8.0.21') | Out-Null
    $fakeExe = Join-Path $rootDir 'dotnet.exe'
    Set-Content -LiteralPath $fakeExe -Value @'
#!/bin/sh
printf '%s\n' 'A fatal error occurred. The folder [C:\Program Files\dotnet\host\fxr] does not exist' 1>&2
exit 1
'@
    if ($IsLinux -or $IsMacOS) { & chmod +x $fakeExe }

    $script:MuxerBroken = $false
    $script:MuxerBrokenRoots = @()
    $script:MuxerFailures = @()
    # PowerShell 7 does not throw on native stderr; this preference makes it
    # throw on the non-zero exit instead, standing in for 5.1's behaviour.
    $PSNativeCommandUseErrorActionPreference = $true
    $threw = ''
    try { $map = Get-InstalledMap @(@{ Arch = 'x64'; Exe = $fakeExe }) } catch { $threw = $_.Exception.Message }
    $PSNativeCommandUseErrorActionPreference = $false
    Assert-Eq $threw '' 'CSLT-015: dotnet stderr under Stop does not end the run'
    Assert-True $script:MuxerBroken 'CSLT-015: broken host flagged'
    Assert-Eq ($script:MuxerFailures -join ',') 'MissingFolder' 'CSLT-015: failure kind recorded'
    Assert-Eq ($map['x64|Microsoft.NETCore.App'] -join ',') '8.0.21' 'CSLT-015: inventory from disk'
    $listed = @(Invoke-DotNetListRuntimes -Exe $fakeExe)
    Assert-Eq $listed.Count 1 'final inventory listing returns the error as text'
    Assert-True ($listed[0] -is [string]) 'listing lines are strings, not ErrorRecords'
} finally {
    Remove-Item -LiteralPath $tmp3 -Recurse -Force -ErrorAction SilentlyContinue
}

# --- SDK DisplayName parsing (CSPC-004, 2026-10-06) --------------------------
# The x86 SDK parsed as major 0 because the '(x86)' arch match overwrote
# $matches, so Phase 1c fetched https://aka.ms/dotnet/0.0/dotnet-sdk-win-x86.exe.
$x86 = ConvertTo-SdkEntryInfo -DisplayName 'Microsoft .NET SDK 8.0.420 (x86)'
Assert-Eq $x86.Major 8 'x86 SDK major is 8, not 0'
Assert-Eq $x86.Arch 'x86' 'x86 SDK arch'
Assert-Eq $x86.Version '8.0.420' 'x86 SDK version'
$x64 = ConvertTo-SdkEntryInfo -DisplayName 'Microsoft .NET SDK 8.0.420 (x64)'
Assert-Eq $x64.Major 8 'x64 SDK major'
Assert-Eq $x64.Arch 'x64' 'x64 SDK arch'
$arm = ConvertTo-SdkEntryInfo -DisplayName 'Microsoft .NET SDK 10.0.100 (arm64)'
Assert-Eq $arm.Major 10 'arm64 SDK major'
Assert-Eq $arm.Arch 'arm64' 'arm64 SDK arch'
Assert-True ($null -eq (ConvertTo-SdkEntryInfo -DisplayName 'Microsoft .NET Runtime - 8.0.27 (x86)')) 'non-SDK name is rejected'

# --- Support status and -InstallSuccessorMajor targets (CSPC-072, 2026-10-12) --
# .NET 8 was 29 days from end of support; v3.7 only treated $EolMajors (9) as
# EOL, so -InstallSuccessorMajor did nothing on an 8-only host.
$dates = @{ 8 = '2026-11-10'; 10 = '2028-11-14' }
$oct12 = [datetime]'2026-10-12'
$st = { param($m, $now) Get-MajorSupportStatus -Major $m -EolMajors @(9) -MinSupported 8 -EolDates $dates -WarnDays 180 -Now $now }
Assert-Eq (& $st 8 $oct12) 'SOON' '.NET 8 on 2026-10-12 is near EOL'
Assert-Eq (& $st 8 ([datetime]'2026-11-11')) 'EOL' '.NET 8 after its end date is EOL without editing $EolMajors'
Assert-Eq (& $st 8 ([datetime]'2026-01-01')) 'OK' '.NET 8 outside the warn window is OK'
Assert-Eq (& $st 9 $oct12) 'EOL' '.NET 9 listed in EolMajors is EOL'
Assert-Eq (& $st 6 $oct12) 'EOL' '.NET 6 below MinSupported is EOL'
Assert-Eq (& $st 10 $oct12) 'OK' '.NET 10 is OK'

$map = @{ 8 = 10; 9 = 10 }
$t = @(Get-SuccessorTargets -EolSeen @() -EolSoonSeen @(8) -Map $map)
Assert-Eq $t.Count 1 'near-EOL 8 yields one successor target'
Assert-Eq ('' + $t[0].From + '->' + $t[0].To) '8->10' 'near-EOL 8 maps to 10'
$t = @(Get-SuccessorTargets -EolSeen @(9) -EolSoonSeen @(8) -Map $map)
Assert-Eq (($t | ForEach-Object { '' + $_.From + '->' + $_.To }) -join ',') '8->10,9->10' 'EOL and near-EOL majors both targeted, sorted'
$t = @(Get-SuccessorTargets -EolSeen @(7) -EolSoonSeen @() -Map $map)
Assert-Eq $t.Count 0 'major with no mapping yields nothing'
$t = @(Get-SuccessorTargets -EolSeen @(8) -EolSoonSeen @(8) -Map $map)
Assert-Eq $t.Count 1 'duplicate major targeted once'

# --- -RemoveRetiredMajor: which apps need .NET 8 --------------------------------
$fd8 = '{ "runtimeOptions": { "tfm": "net8.0", "framework": { "name": "Microsoft.NETCore.App", "version": "8.0.0" } } }'
Assert-True (Test-RuntimeConfigNeedsMajor -Json $fd8 -Major 8) 'framework-dependent net8.0 app needs 8'
Assert-True (-not (Test-RuntimeConfigNeedsMajor -Json $fd8 -Major 9)) 'net8.0 app does not need 9'
$lm = '{ "runtimeOptions": { "tfm": "net8.0", "rollForward": "LatestMajor", "framework": { "name": "Microsoft.NETCore.App", "version": "8.0.0" } } }'
Assert-True (-not (Test-RuntimeConfigNeedsMajor -Json $lm -Major 8)) 'rollForward LatestMajor moves to 10'
$mj = '{ "runtimeOptions": { "rollForward": "Major", "framework": { "name": "Microsoft.NETCore.App", "version": "8.0.0" } } }'
Assert-True (-not (Test-RuntimeConfigNeedsMajor -Json $mj -Major 8)) 'rollForward Major moves to 10'
$mn = '{ "runtimeOptions": { "rollForward": "Minor", "framework": { "name": "Microsoft.NETCore.App", "version": "8.0.0" } } }'
Assert-True (Test-RuntimeConfigNeedsMajor -Json $mn -Major 8) 'rollForward Minor stays on 8'
$legacy = '{ "runtimeOptions": { "rollForwardOnNoCandidateFx": 2, "framework": { "name": "Microsoft.NETCore.App", "version": "8.0.0" } } }'
Assert-True (-not (Test-RuntimeConfigNeedsMajor -Json $legacy -Major 8)) 'legacy rollForwardOnNoCandidateFx 2 crosses majors'
$multi = '{ "runtimeOptions": { "tfm": "net8.0-windows", "frameworks": [ { "name": "Microsoft.NETCore.App", "version": "8.0.0" }, { "name": "Microsoft.WindowsDesktop.App", "version": "8.0.0" } ] } }'
Assert-True (Test-RuntimeConfigNeedsMajor -Json $multi -Major 8) 'WinForms/WPF frameworks array needs 8'
$sc = '{ "runtimeOptions": { "tfm": "net8.0", "includedFrameworks": [ { "name": "Microsoft.NETCore.App", "version": "8.0.11" } ] } }'
Assert-True (-not (Test-RuntimeConfigNeedsMajor -Json $sc -Major 8)) 'self-contained app carries its own runtime'
Assert-True (Test-RuntimeConfigNeedsMajor -Json '{ // comment
  "runtimeOptions": { "framework": { "version": "8.0.0" } } }' -Major 8) 'unparseable file naming 8.x counts as a dependency'
Assert-True (-not (Test-RuntimeConfigNeedsMajor -Json '' -Major 8)) 'empty file is not a dependency'
Assert-True (-not (Test-RuntimeConfigNeedsMajor -Json '{ "runtimeOptions": { "framework": { "version": "18.0.0" } } }' -Major 8)) '18.x is not 8.x'

# --- -RemoveRetiredMajor: go/no-go ------------------------------------------------
$after = @{
    'x64|Microsoft.NETCore.App'        = @([version]'8.0.21', [version]'10.0.11')
    'x64|Microsoft.WindowsDesktop.App' = @([version]'8.0.21', [version]'10.0.11')
    'x86|Microsoft.NETCore.App'        = @([version]'8.0.21')
}
$ok = { param($keys, $pins, $sdks, $hb, $failedRun, $reboot, $found)
    Get-RetireDecision -Major 8 -Successor 10 -KeysWithMajor $keys -After $after -AppPinCount $pins -Sdks $sdks -HostingBundles $hb -RunFailed $failedRun -RebootPending $reboot -RemoverFound $found }
$d = & $ok @('x64|Microsoft.NETCore.App', 'x64|Microsoft.WindowsDesktop.App') 0 @() @() $false $false $true
Assert-True $d.Remove 'successor on every flavor/arch, nothing pinned -> remove'
$d = & $ok @('x64|Microsoft.NETCore.App', 'x86|Microsoft.NETCore.App') 0 @() @() $false $false $true
Assert-Eq ('' + $d.Remove + '|' + ($d.Reasons -join ';')) 'False|x86|Microsoft.NETCore.App has no .NET 10 on disk' 'x86 without 10 blocks removal'
$d = & $ok @('x64|Microsoft.NETCore.App') 2 @() @() $false $false $true
Assert-Eq ($d.Reasons -join ';') '2 app(s) on disk target .NET 8 without rolling forward' 'pinned apps block removal'
$d = & $ok @('x64|Microsoft.NETCore.App') 0 @('Microsoft .NET SDK 8.0.421 (x64)') @() $false $false $true
Assert-True (-not $d.Remove) 'SDK 8 blocks removal'
$d = & $ok @('x64|Microsoft.NETCore.App') 0 @() @('Microsoft .NET 8.0.21 - Windows Server Hosting') $false $false $true
Assert-True (-not $d.Remove) 'hosting bundle 8 blocks removal'
$d = & $ok @('x64|Microsoft.NETCore.App') 0 @() @() $true $false $true
Assert-Eq ($d.Reasons -join ';') 'an earlier step of this run failed' 'failed run blocks removal'
$d = & $ok @('x64|Microsoft.NETCore.App') 0 @() @() $false $true $true
Assert-Eq ($d.Reasons -join ';') 'an install this run needs a reboot first' 'pending reboot blocks removal'
$d = & $ok @('x64|Microsoft.NETCore.App') 0 @() @() $false $false $false
Assert-True (($d.Reasons -join ';') -match 'not staged') 'missing Remove-DotNetEolChannel.ps1 blocks removal'
$d = Get-RetireDecision -Major 10 -Successor 12 -KeysWithMajor @() -After @{} -AppPinCount 0 -Sdks @() -HostingBundles @() -RunFailed $false -RebootPending $false -RemoverFound $true
Assert-True (-not $d.Remove) 'a major the remover has no switch for is refused'

# --- CSLT-174 (2026-10-29): Phase 1c called an undefined Invoke-Msi ----------
# Every Verb-Noun command the script calls must be defined in it or be a cmdlet.
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
$defined = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
             ForEach-Object { $_.Name })
$called = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
            ForEach-Object { $_.GetCommandName() } | Where-Object { $_ -match '^[A-Za-z]+-[A-Za-z]+$' } | Sort-Object -Unique)
$windowsOnly = @('Get-CimInstance', 'Get-WmiObject')
$unknown = @($called | Where-Object {
    $defined -notcontains $_ -and $windowsOnly -notcontains $_ -and -not (Get-Command $_ -ErrorAction SilentlyContinue)
})
Assert-Eq ($unknown -join ',') '' 'every Verb-Noun command the script calls exists'
Assert-True ($defined -contains 'Invoke-Msi') 'Invoke-Msi is defined in this script'

# --- CSLT-174: Phase 2 ARP entries whose exact version has no files ----------
# Runtime 9.0.16 / 8.0.27 were registered in ARP but not on disk; their
# uninstall exited 0 and left the entry, and Phase 2 had no fallback.
$disk174 = @{
    'x64|Microsoft.NETCore.App'        = @([version]'8.0.33', [version]'9.0.22', [version]'10.0.14')
    'x86|Microsoft.WindowsDesktop.App' = @([version]'8.0.33', [version]'9.0.22')
}
Assert-True (-not (Test-ArpVersionOnDisk -DiskMap $disk174 -Prefix 'Microsoft .NET Runtime' -Arch 'x64' -Version ([version]'9.0.16'))) `
    'CSLT-174: .NET Runtime 9.0.16 x64 has no files on disk'
Assert-True (Test-ArpVersionOnDisk -DiskMap $disk174 -Prefix 'Microsoft .NET Runtime' -Arch 'x64' -Version ([version]'9.0.22')) `
    'kept 9.0.22 x64 is on disk'
Assert-True (-not (Test-ArpVersionOnDisk -DiskMap $disk174 -Prefix 'Microsoft Windows Desktop Runtime' -Arch 'x86' -Version ([version]'8.0.27'))) `
    'CSLT-174: Windows Desktop 8.0.27 x86 has no files on disk'
Assert-True (Test-ArpVersionOnDisk -DiskMap $disk174 -Prefix 'Microsoft Windows Desktop Runtime' -Arch 'x86' -Version ([version]'8.0.33')) `
    'Windows Desktop 8.0.33 x86 is on disk'
Assert-True (Test-ArpVersionOnDisk -DiskMap $disk174 -Prefix 'Microsoft Unknown Runtime' -Arch 'x64' -Version ([version]'9.0.16')) `
    'unrecognised flavor is treated as on disk, never hard-removed'

if ($failed -gt 0) {
    Write-Host "`n$failed test(s) failed"
    exit 1
}
Write-Host "`nAll tests passed"
exit 0
