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

# --- SDK DisplayName parsing (CSPC-004) -------------------------------------
# The arch check used to run BETWEEN capturing the version groups and reading
# $matches[1] for Major. A successful '\(x86\)' match replaces $matches with a
# group-less collection, so Major came out 0 for x86/arm64 -- which built the
# URL https://aka.ms/dotnet/0.0/dotnet-sdk-win-x86.exe.
$x64 = Get-SdkEntryFromDisplayName -DisplayName 'Microsoft .NET SDK 8.0.425 (x64)'
Assert-Eq $x64.Major 8 'x64 SDK major'
Assert-Eq $x64.Arch 'x64' 'x64 SDK arch'
Assert-Eq $x64.Version '8.0.425' 'x64 SDK version'

$x86 = Get-SdkEntryFromDisplayName -DisplayName 'Microsoft .NET SDK 8.0.420 (x86)'
Assert-Eq $x86.Major 8 'x86 SDK major is 8, not 0 (the CSPC-004 bug)'
Assert-Eq $x86.Arch 'x86' 'x86 SDK arch'
Assert-Eq $x86.Version '8.0.420' 'x86 SDK version'

$arm = Get-SdkEntryFromDisplayName -DisplayName 'Microsoft .NET SDK 10.0.101 (arm64)'
Assert-Eq $arm.Major 10 'arm64 SDK major is 10, not 0'
Assert-Eq $arm.Arch 'arm64' 'arm64 SDK arch'
Assert-Eq $arm.Version '10.0.101' 'arm64 SDK version'

# No arch suffix at all defaults to x64 and must still parse the major.
$bare = Get-SdkEntryFromDisplayName -DisplayName 'Microsoft .NET SDK 9.0.304'
Assert-Eq $bare.Major 9 'bare SDK major'
Assert-Eq $bare.Arch 'x64' 'bare SDK defaults to x64'

Assert-Eq (Get-SdkEntryFromDisplayName -DisplayName 'Microsoft .NET Runtime - 8.0.31 (x86)') $null `
    'a runtime entry is not an SDK'
Assert-Eq (Get-SdkEntryFromDisplayName -DisplayName '') $null 'empty DisplayName'

# Grouping key must put both 8.x SDKs in comparable groups by arch.
Assert-Eq ('' + $x86.Major + '|' + $x86.Arch) '8|x86' 'x86 grouping key is 8|x86, not 0|x86'

# --- Install-Sdk must refuse an implausible major ---------------------------
# Defence in depth: even if a parse regresses, never request a 0.0 URL.
Assert-True (-not (Test-PlausibleDotNetMajor -Major 0)) 'major 0 rejected'
Assert-True (-not (Test-PlausibleDotNetMajor -Major -1)) 'negative major rejected'
Assert-True (-not (Test-PlausibleDotNetMajor -Major 99)) 'absurd major rejected'
Assert-True (Test-PlausibleDotNetMajor -Major 8) 'major 8 accepted'
Assert-True (Test-PlausibleDotNetMajor -Major 10) 'major 10 accepted'

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

if ($failed -gt 0) {
    Write-Host "`n$failed test(s) failed"
    exit 1
}
Write-Host "`nAll tests passed"
exit 0
