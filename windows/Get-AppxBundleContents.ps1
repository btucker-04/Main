<#
.SYNOPSIS
    Read-only: report what version(s) an .msixbundle / .msix actually CONTAINS,
    so a staged installer can be verified before (or after) it is provisioned.

.DESCRIPTION
    Written after three consecutive Update-WinGet.ps1 runs on CSLT-001
    (2026-08-26) each reported a SUCCESSFUL provision while the installed
    version never moved off 1.29.290.0. The remediation script's download
    validation checks only the zip magic header and a size floor -- that proves
    the file is a real archive of plausible size, and nothing about which
    version is inside it. A wrong or stale staged bundle provisions
    "successfully" forever and is indistinguishable from the per-user AppX
    logon-reconciliation lag unless you look inside the package.

    THE BUNDLE'S OWN VERSION IS NOT THE APP VERSION. This is the specific trap
    that prompted this script: CSLT-001's provisioned entry read
    2026.728.1707.0 -- a date-style version on the BUNDLE's Identity -- while
    the Tenable target was 1.30.80. Those are different numbering schemes for
    different things, so the bundle-level number tells you nothing on its own.
    The versions that matter are the contained Type="application" packages.

    An .msixbundle is a zip, so this reads AppxMetadata\AppxBundleManifest.xml
    straight out of the archive's central directory. It never extracts the
    payload, so it is fast even on a 200 MB+ bundle, and it changes nothing.

    Also handles a plain .msix / .appx (single AppxManifest.xml at the root).

.PARAMETER BundlePath
    Path to the .msixbundle/.msix to inspect. If omitted, searches beside this
    script and then C:\ for Microsoft.DesktopAppInstaller*.msixbundle (the
    staging location Update-WinGet.ps1 uses).

.PARAMETER TargetVersion
    Optional. When given, the contained application-package versions are
    compared against it and a pass/fail verdict is reported. Defaults to
    1.30.80, the fixed version for plugin 334617 / CVE-2026-68821.

.PARAMETER ExpectedName
    Optional package Identity name to sanity-check, so a completely wrong
    artifact is called out. Default Microsoft.DesktopAppInstaller.

.NOTES
    Read-only -- changes nothing. Deploy via Endpoint Central (SYSTEM),
    Repository mode, -File invocation only. Do NOT paste this logic as an
    inline -Command string: EC mangles $variables and quotes, and a snippet
    that relies on newlines as statement separators breaks when they are
    collapsed onto one line (which is exactly how this script came to exist).
    Logs: C:\Logs\CompoSecure\AppxBundleContents_<timestamp>.log
    Exit: 0 = contains TargetVersion or better / 1 = below TargetVersion
          2 = could not read a manifest / no bundle found (needs a human)
#>

[CmdletBinding()]
param(
    [string]$BundlePath    = '',
    [string]$TargetVersion = '1.30.80',
    [string]$ExpectedName  = 'Microsoft.DesktopAppInstaller'
)

$ErrorActionPreference = 'Stop'
$LogDir  = 'C:\Logs\CompoSecure'
$LogFile = Join-Path $LogDir ('AppxBundleContents_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

# Same reader as Update-WinGet.ps1's step [2b]. Duplicated deliberately: every
# script here is deployed standalone via EC, so shared helpers are copied
# rather than imported (same pattern as Convert-CompressedGuid across the
# Nessus scripts).
function Get-BundleManifestInfo {
    param([string]$Path)
    if (-not ('System.IO.Compression.ZipFile' -as [type])) {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    }
    $zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $isBundle = $true
        $entry = $zip.Entries | Where-Object { $_.Name -eq 'AppxBundleManifest.xml' } | Select-Object -First 1
        if (-not $entry) {
            $entry = $zip.Entries | Where-Object { $_.Name -eq 'AppxManifest.xml' } | Select-Object -First 1
            $isBundle = $false
        }
        if (-not $entry) { return $null }
        $manifestEntryPath = $entry.FullName
        $reader = New-Object System.IO.StreamReader($entry.Open())
        try { $xmlText = $reader.ReadToEnd() } finally { $reader.Dispose() }
    } finally {
        $zip.Dispose()
    }

    $xml = [xml]$xmlText
    if ($isBundle) {
        $pkgs = @($xml.Bundle.Packages.Package)
        return [pscustomobject]@{
            IsBundle      = $true
            ManifestEntry = $manifestEntryPath
            IdentityName  = '' + $xml.Bundle.Identity.Name
            BundleVersion = '' + $xml.Bundle.Identity.Version
            Packages      = @($pkgs | ForEach-Object {
                [pscustomobject]@{
                    Type         = '' + $_.Type
                    Version      = '' + $_.Version
                    Architecture = '' + $_.Architecture
                    ResourceId   = '' + $_.ResourceId
                }
            })
        }
    }
    return [pscustomobject]@{
        IsBundle      = $false
        ManifestEntry = $manifestEntryPath
        IdentityName  = '' + $xml.Package.Identity.Name
        BundleVersion = '' + $xml.Package.Identity.Version
        Packages      = @([pscustomobject]@{
            Type         = 'application'
            Version      = '' + $xml.Package.Identity.Version
            Architecture = '' + $xml.Package.Identity.ProcessorArchitecture
            ResourceId   = ''
        })
    }
}

Write-Log '=============================================='
Write-Log ' AppX/MSIX Bundle Contents (read-only)'
Write-Log (' Host   : ' + $env:COMPUTERNAME)
Write-Log (' Target : ' + $TargetVersion)
Write-Log '=============================================='

# --------------------------------------------------------------
# 1. Resolve the file to inspect
# --------------------------------------------------------------
Write-Log ''
Write-Log '[1/3] Resolving bundle...'
if ([string]::IsNullOrWhiteSpace($BundlePath)) {
    $searchDirs = @()
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    if ($scriptDir) { $searchDirs += $scriptDir }
    $searchDirs += 'C:\'
    foreach ($dir in $searchDirs) {
        $cand = Get-ChildItem -Path $dir -Filter 'Microsoft.DesktopAppInstaller*.msixbundle' -File -ErrorAction SilentlyContinue |
                Sort-Object Name -Descending | Select-Object -First 1
        if ($cand) { $BundlePath = $cand.FullName; break }
    }
}
if ([string]::IsNullOrWhiteSpace($BundlePath) -or -not (Test-Path $BundlePath)) {
    Write-Log '  No bundle found. Pass -BundlePath, or stage' -Level WARN
    Write-Log '  Microsoft.DesktopAppInstaller*.msixbundle beside this script or in C:\.' -Level WARN
    Write-Log '=============================================='
    exit 2
}
$item = Get-Item $BundlePath
Write-Log ('  File : ' + $item.FullName)
Write-Log ('  Size : ' + [math]::Round($item.Length / 1MB, 1) + ' MB')

# --------------------------------------------------------------
# 2. Read the manifest out of the archive
# --------------------------------------------------------------
Write-Log ''
Write-Log '[2/3] Reading package manifest from the archive...'
$info = $null
try {
    $info = Get-BundleManifestInfo -Path $BundlePath
} catch {
    Write-Log ('  Failed to read the archive: ' + $_) -Level ERROR
}
if (-not $info) {
    Write-Log '  No AppxBundleManifest.xml or AppxManifest.xml found in this file.' -Level ERROR
    Write-Log '  Either it is not an MSIX/AppX package, or the download is truncated or' -Level ERROR
    Write-Log '  is a proxy block page that happened to pass the zip-header check.' -Level ERROR
    Write-Log '=============================================='
    exit 2
}

Write-Log ('  Manifest entry : ' + $info.ManifestEntry)
Write-Log ('  Is bundle      : ' + $info.IsBundle)
Write-Log ('  Identity name  : ' + $info.IdentityName)
Write-Log ('  Identity ver   : ' + $info.BundleVersion + '   <-- the BUNDLE''s own version, NOT the app version')
if ($ExpectedName -and $info.IdentityName -and $info.IdentityName -ne $ExpectedName) {
    Write-Log ('  WARNING: identity is not ' + $ExpectedName + '. Wrong artifact staged?') -Level WARN
}

Write-Log ''
Write-Log '  Contained packages:'
foreach ($p in ($info.Packages | Sort-Object Type, Architecture, Version)) {
    $extra = ''
    if ($p.ResourceId) { $extra = '  resourceId=' + $p.ResourceId }
    Write-Log ('    ' + $p.Type.PadRight(12) + ' ' + $p.Version.PadRight(18) + ' ' + ('' + $p.Architecture).PadRight(8) + $extra)
}

# --------------------------------------------------------------
# 3. Verdict against the target
# --------------------------------------------------------------
Write-Log ''
Write-Log '[3/3] Verdict...'
$appVersions = @($info.Packages | Where-Object { $_.Type -eq 'application' } | ForEach-Object { $_.Version } | Sort-Object -Unique)
if ($appVersions.Count -eq 0) {
    Write-Log '  No Type="application" packages listed in the manifest.' -Level WARN
    Write-Log '  Cannot judge this bundle against a target version.' -Level WARN
    Write-Log '=============================================='
    exit 2
}
Write-Log ('  Application package version(s): ' + ($appVersions -join ', '))

$best = $null
foreach ($v in $appVersions) {
    $parsed = $null
    try { $parsed = [version]$v } catch { }
    if ($parsed -and (-not $best -or $parsed -gt $best)) { $best = $parsed }
}
if (-not $best) {
    Write-Log '  No parseable application version; cannot judge.' -Level WARN
    Write-Log '=============================================='
    exit 2
}

$targetObj = $null
try { $targetObj = [version]$TargetVersion } catch { }
if (-not $targetObj) {
    Write-Log ('  -TargetVersion "' + $TargetVersion + '" is not a parseable version.') -Level WARN
    Write-Log '=============================================='
    exit 2
}

Write-Log ('  Highest application version in the file : ' + $best)
Write-Log ('  Required target                         : ' + $targetObj)
Write-Log ''
if ($best -ge $targetObj) {
    Write-Log 'RESULT: this bundle DOES contain the target version.'
    Write-Log '        If a host still reports the old version after provisioning it, the'
    Write-Log '        remaining cause is per-user AppX registration reconciling at next'
    Write-Log '        logon -- reboot (or have the user log off/on) and rescan.'
    Write-Log '=============================================='
    exit 0
}
Write-Log 'RESULT: this bundle does NOT contain the target version.' -Level ERROR
Write-Log '        Provisioning it can never clear the finding: it will report success' -Level ERROR
Write-Log '        and leave the version unmoved, which looks exactly like the per-user' -Level ERROR
Write-Log '        logon-reconciliation lag but is not. Replace the staged file with a' -Level ERROR
Write-Log '        build containing the target (https://aka.ms/getwinget) and re-run the' -Level ERROR
Write-Log '        remediation. No amount of rebooting will fix this one.' -Level ERROR
Write-Log '=============================================='
exit 1
