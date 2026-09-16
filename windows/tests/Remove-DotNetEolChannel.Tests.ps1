# Unit tests for Remove-DotNetEolChannel.ps1 artifact-detection helpers.
# Run: pwsh -NoProfile -File windows/tests/Remove-DotNetEolChannel.Tests.ps1
#
# Covers the CSLT-020 gap: msiexec 1612 left 6.0.18 FILES on disk while the
# ARP key was stripped, so ARP + shared/fxr folder checks + --list-runtimes
# all looked clean and Tenable 172179 still reported 6.0.18.32522.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path (Split-Path -Parent $here) 'Remove-DotNetEolChannel.ps1'
$env:REMOVE_DOTNET_EOL_DOTSOURCE = '1'
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

# --- Version string -> major -------------------------------------------------
# Tenable reported the 4-part file version 6.0.18.32522, not a folder name.
Assert-True (Test-VersionInMajor -Version '6.0.18.32522' -Maj 6) 'CSLT-020 reported file version is major 6'
Assert-True (Test-VersionInMajor -Version '6.0.18' -Maj 6) 'three-part 6.0.18'
Assert-True (Test-VersionInMajor -Version '6.0.1823.32522' -Maj 6) 'dotnet internal file version form'
Assert-True (-not (Test-VersionInMajor -Version '16.0.18' -Maj 6)) '16.x is not 6.x'
Assert-True (-not (Test-VersionInMajor -Version '9.0.20' -Maj 6)) '9.0.20 is not 6.x'
Assert-True (-not (Test-VersionInMajor -Version '' -Maj 6)) 'empty version'
Assert-True (-not (Test-VersionInMajor -Version $null -Maj 6)) 'null version'
# DisplayVersion on these MSIs is an internal 48.x scheme and must never pick a major.
Assert-True (-not (Test-VersionInMajor -Version '48.75.61559' -Maj 6)) 'internal 48.75 scheme is not 6.x'

# --- SWID tag file names (installed by the .NET Host / FX Resolver MSIs) -----
Assert-Eq (Get-VersionFromArtifactName -Name 'Microsoft .NET Host - 6.0.18.swidtag') '6.0.18' 'swidtag Host 6.0.18'
Assert-Eq (Get-VersionFromArtifactName -Name 'Microsoft .NET Host FX Resolver - 6.0.18.swidtag') '6.0.18' 'swidtag FX Resolver'
Assert-Eq (Get-VersionFromArtifactName -Name 'Microsoft .NET Runtime - 9.0.20.swidtag') '9.0.20' 'swidtag 9.0.20'
Assert-Eq (Get-VersionFromArtifactName -Name 'no-version-here.swidtag') $null 'swidtag with no version'

Assert-True (Test-ArtifactNameInMajor -Name 'Microsoft .NET Host - 6.0.18.swidtag' -Maj 6) 'swidtag matches major 6'
Assert-True (-not (Test-ArtifactNameInMajor -Name 'Microsoft .NET Runtime - 9.0.20.swidtag' -Maj 6)) 'swidtag 9.0.20 not major 6'

# --- SWID tag XML content ----------------------------------------------------
$swidXml = '<?xml version="1.0" encoding="utf-8"?><SoftwareIdentity xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" name="Microsoft .NET Host" tagId="abc" version="6.0.18" versionScheme="multipartnumeric"></SoftwareIdentity>'
Assert-Eq (Get-VersionFromSwidContent -Content $swidXml) '6.0.18' 'swidtag version attribute'
Assert-Eq (Get-VersionFromSwidContent -Content '<SoftwareIdentity name="x"></SoftwareIdentity>') $null 'swidtag without version attribute'

# --- The shared muxer must never be deleted ---------------------------------
# <root>\dotnet.exe is used by EVERY installed major. Removing it to clear a
# 6.x finding would break 9.0.20 on this host.
Assert-True (Test-IsSharedMuxerPath -Path 'C:\Program Files\dotnet\dotnet.exe') 'x64 muxer is shared'
Assert-True (Test-IsSharedMuxerPath -Path 'C:\Program Files (x86)\dotnet\dotnet.exe') 'x86 muxer is shared'
Assert-True (-not (Test-IsSharedMuxerPath -Path 'C:\Program Files\dotnet\swidtag\Microsoft .NET Host - 6.0.18.swidtag')) 'swidtag is not the muxer'
Assert-True (-not (Test-IsSharedMuxerPath -Path 'C:\Program Files\dotnet\host\fxr\6.0.18\hostfxr.dll')) 'versioned hostfxr is not the muxer'

# --- Is a leftover artifact safe to delete outright? ------------------------
Assert-True (Test-IsDeletableArtifact -Path 'C:\Program Files\dotnet\swidtag\Microsoft .NET Host - 6.0.18.swidtag') 'swidtag deletable (metadata only)'
Assert-True (-not (Test-IsDeletableArtifact -Path 'C:\Program Files\dotnet\dotnet.exe')) 'muxer not deletable'

# --- Regression: the exact CSLT-020 end state -------------------------------
# The 2026-09-15 run finished with ARP 0, folders 0, --list-runtimes clean,
# and still had a 6.0.18 artifact under C:\Program Files\dotnet\. The old
# verify (ARP + folders + list-runtimes only) called that "gone" and exited 0.
Assert-True (-not (Test-ChannelFullyRemoved -ArpCount 0 -FolderCount 0 -SwidCount 1 -HostFileCount 0 -StillListed $false)) `
    'CSLT-020: leftover SWID tag must NOT count as removed'
Assert-True (-not (Test-ChannelFullyRemoved -ArpCount 0 -FolderCount 0 -SwidCount 0 -HostFileCount 1 -StillListed $false)) `
    'CSLT-020: leftover host file must NOT count as removed'
Assert-True (Test-ChannelFullyRemoved -ArpCount 0 -FolderCount 0 -SwidCount 0 -HostFileCount 0 -StillListed $false) `
    'genuinely clean channel counts as removed'
Assert-True (-not (Test-ChannelFullyRemoved -ArpCount 1 -FolderCount 0 -SwidCount 0 -HostFileCount 0 -StillListed $false)) `
    'surviving ARP still fails'
Assert-True (-not (Test-ChannelFullyRemoved -ArpCount 0 -FolderCount 1 -SwidCount 0 -HostFileCount 0 -StillListed $false)) `
    'surviving folder still fails'
Assert-True (-not (Test-ChannelFullyRemoved -ArpCount 0 -FolderCount 0 -SwidCount 0 -HostFileCount 0 -StillListed $true)) `
    'list-runtimes hit still fails'

# --- Integration: real Get-ChannelSwidTags against a simulated dotnet root ---
# Exercises Test-Path / Get-ChildItem / name match / XML-content fallback, not
# just the pure string helpers. The script builds paths with a literal '\', so
# the fixture directory name embeds one; that is the same string the live
# Windows path produces.
$tmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('dotnettest_' + [guid]::NewGuid().ToString('N'))
try {
    $fakeRoot = Join-Path $tmpRoot 'dotnet'
    $swidDir  = $fakeRoot + '\swidtag'
    New-Item -ItemType Directory -Path $swidDir -Force | Out-Null

    # Leftover from the failed 6.0.18 uninstall (version in the file name).
    Set-Content -LiteralPath (Join-Path $swidDir 'Microsoft .NET Host - 6.0.18.swidtag') `
        -Value '<SoftwareIdentity name="Microsoft .NET Host" version="6.0.18"></SoftwareIdentity>'
    # Supported runtime that must NOT be touched.
    Set-Content -LiteralPath (Join-Path $swidDir 'Microsoft .NET Runtime - 9.0.20.swidtag') `
        -Value '<SoftwareIdentity name="Microsoft .NET Runtime" version="9.0.20"></SoftwareIdentity>'
    # Version only in the XML body, not the file name -- content fallback path.
    Set-Content -LiteralPath (Join-Path $swidDir 'dotnet-host-legacy.swidtag') `
        -Value '<SoftwareIdentity name="Microsoft .NET Host" version="6.0.18"></SoftwareIdentity>'

    $DotNetRoots = @($fakeRoot)

    $found6 = @(Get-ChannelSwidTags 6)
    Assert-Eq $found6.Count 2 'discovery finds both 6.0.18 tags (name + XML content)'
    Assert-True ([bool]($found6 -match 'Microsoft \.NET Host - 6\.0\.18\.swidtag')) 'named 6.0.18 tag found'
    Assert-True ([bool]($found6 -match 'dotnet-host-legacy\.swidtag')) 'content-only 6.0.18 tag found'
    Assert-True (-not [bool]($found6 -match '9\.0\.20')) 'supported 9.0.20 tag not selected for removal'

    $found9 = @(Get-ChannelSwidTags 9)
    Assert-Eq $found9.Count 1 'major 9 selects only its own tag'

    $found8 = @(Get-ChannelSwidTags 8)
    Assert-Eq $found8.Count 0 'absent major finds nothing'

    # With these tags present, the channel must not be reported as removed.
    Assert-True (-not (Test-ChannelFullyRemoved -ArpCount 0 -FolderCount 0 `
        -SwidCount $found6.Count -HostFileCount 0 -StillListed $false)) `
        'discovered tags block a false success'
} finally {
    Remove-Item -LiteralPath $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failed -gt 0) {
    Write-Host "`n$failed test(s) failed"
    exit 1
}
Write-Host "`nAll tests passed"
exit 0
