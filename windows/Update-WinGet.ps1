<#
.SYNOPSIS
    Updates Windows Package Manager (WinGet / App Installer) to the fixed
    version. Nessus Plugin 334617 (CVE-2026-68821, elevation of privilege).

.DESCRIPTION
    WinGet is Microsoft.DesktopAppInstaller, an AppX package. The obvious fix
    -- run 'winget upgrade' -- is UNRELIABLE from Endpoint Central: EC runs as
    SYSTEM, and winget.exe is registered as a per-user App Execution Alias.
    SYSTEM frequently cannot resolve it at all (the same class of problem as
    Cursor and Claude Code being per-user installs), so a script that just
    shells out to 'winget' can silently do nothing on a fraction of the fleet.

    This script instead works at the AppX package layer, which is queryable
    and updatable from SYSTEM context without needing a logged-on user:
      1. Reads the installed version via Get-AppxPackage -AllUsers (works from
         SYSTEM; this is what Tenable's finding is keyed on).
      2. Resolves the installer: -InstallerPath, then a staged
         *.msixbundle beside the script or in C:\, then downloads the latest
         from https://aka.ms/getwinget (Microsoft's stable redirect to the
         current GitHub release).
      3. Validates the download: msixbundle is zip-based, so it checks the
         'PK' zip magic header plus a size floor -- the same discipline as
         every other downloader in this library, so a Zscaler block page can
         never reach Add-AppxPackage.
      4. Installs via Add-AppxProvisionedPackage (DISM layer), which is the
         SYSTEM-safe, no-logged-on-user-required path, and also stages it for
         any new user profile created after this runs.
      5. Verifies by re-reading the AppX version -- not by trusting the
         install command's exit code.

    KNOWN LIMITATION, stated rather than hidden: Add-AppxProvisionedPackage
    updates the machine-wide provisioned package. An already-logged-on user's
    OWN registration of the app may not reflect the new version until their
    next logon, because AppX per-user registration reconciles at logon. This
    still corrects what Tenable/EC read (the provisioned/installed package
    version), and is consistent with how Store-delivered AppX updates behave
    generally on this fleet. If the finding does not clear after this runs and
    a rescan, a reboot (which forces a logon cycle) is the next step -- not a
    re-run of this script.

    v2 (from the 2026-08-26 Tenable group export, plugin 334617, 315 hosts):
    72 of those 315 hosts (~23%) ALREADY had two simultaneous
    Microsoft.DesktopAppInstaller versions registered under different users
    before this script ever ran -- direct evidence of the known limitation
    above occurring at scale, not a rare edge case. Step [1/5] now inventories
    every distinct registered version and which user/state holds each one, so
    a host already in that state is called out up front rather than only
    being a surprise at verification (exit 2).

    v3 (from the CSLT-001 pilot run, 2026-08-26): step [4/5]'s "register for
    the current session" loop was resolving the NEW provisioned package but
    then never actually using it -- it looped over the OLD, already-
    registered packages and re-registered each one with ITS OWN (old)
    manifest, which cannot advance anything under any circumstance. CSLT-001
    had only ONE registered version before this script ran (not the v2
    dual-registration case) and still exited 2, which is exactly what that
    bug predicts. Fixed to resolve and register the NEW provisioned
    package's own manifest instead. NOTE this still runs as SYSTEM, so it
    can only affect SYSTEM's own AppX context -- it still cannot push a
    registration into an ALREADY-logged-on human user's session (that is an
    AppX/Windows limitation, not something a SYSTEM-context script can work
    around). Practical effect: expect a reboot (or the user logging off/on)
    to be the normal second step on any host with an active interactive
    session, not just the ~23% flagged in v2 -- the true fraction needing
    that second pass is very likely higher than 23%.

    v4 (from the CSLT-001 re-run after v3, 2026-08-26): the v3 fix could not
    actually register anything for THIS app, because App Installer ships as
    an .msixbundle and Get-AppxProvisionedPackage's entry for it is the
    BUNDLE's own PackageFullName (architecture 'neutral', resource id '~' --
    e.g. 'Microsoft.DesktopAppInstaller_2026.728.1707.0_neutral_~_...'),
    not a concrete per-architecture Main package (same '_~_' pattern already
    documented in Remove-3DViewer.ps1). There is no
    WindowsApps\<that name>\AppxManifest.xml to register: the concrete
    package only materializes when a user's OWN registration reconciles
    against the provisioned list, at THEIR next logon. Step [4/5] now
    detects this and reports it precisely instead of a generic "manifest not
    found". PRACTICAL UPSHOT FOR THIS SPECIFIC PLUGIN: because App Installer
    is always bundle-packaged, there is NO SYSTEM-context registration path
    at all for an already-logged-on user -- exit 2 (reboot/logoff required)
    should be treated as the EXPECTED, standard first-pass outcome for any
    host with a logged-on (or previously logged-on, not-yet-rebooted) user
    profile, not an exception. Plan this as a two-phase rollout: provision
    fleet-wide first, then a follow-up reboot pass, then rescan.

    v5 (from the third CSLT-001 run, 2026-08-26): three consecutive runs each
    reported a SUCCESSFUL provision and the version never moved off
    1.29.290.0. The zip-header and size checks in step [2/5] only prove the
    file is a real archive of plausible size -- they say nothing about which
    version is inside it. A wrong or stale staged bundle therefore provisions
    "successfully" forever and is indistinguishable from the logon-
    reconciliation lag above unless you actually look inside the package. New
    step [2b] reads AppxMetadata/AppxBundleManifest.xml out of the bundle (it
    is just a zip) and compares the contained Type="application" package
    versions against -TargetVersion. Note the bundle's OWN Identity version is
    NOT the app version -- CSLT-001's provisioned entry read 2026.728.1707.0,
    a date-style bundle version, against a 1.30.80 target, which is exactly
    the kind of mismatch that makes this worth checking explicitly. A definite
    mismatch now fails closed (exit 1) rather than becoming a silent
    fleet-wide no-op across all 315 hosts; an unparseable manifest fails open
    with a warning so an unexpected-but-valid bundle shape cannot block
    remediation. -IgnoreBundleVersionMismatch overrides the hard failure.

    DEPENDENCY NOTE: the App Installer bundle depends on the Microsoft.VCLibs
    and Microsoft.UI.Xaml frameworks. These ship with current Windows 10/11
    builds and the Microsoft Store, so they are normally already present. If
    the install fails citing a missing dependency, that is a signal the
    machine's Store/framework state is unhealthy -- not something to route
    around by disabling checks.

.PARAMETER TargetVersion
    Minimum acceptable version. Default 1.30.80 (the fixed version for
    CVE-2026-68821).

.PARAMETER InstallerPath
    Path to a staged Microsoft.DesktopAppInstaller*.msixbundle.

.PARAMETER DryRun
    Report current version and resolved installer without changing anything.

.PARAMETER IgnoreBundleVersionMismatch
    Provision the staged bundle even when its contained application-package
    version is below -TargetVersion. Escape hatch only, for a bundle whose
    manifest this script reads wrongly; normally a mismatch means the wrong
    artifact is staged and provisioning it can never clear the finding.

.NOTES
    Deploy via Endpoint Central (SYSTEM), Repository mode, arguments as bare
    switches only (no $ or quotes, so EC's argument handling cannot mangle
    them). Logs: C:\Logs\CompoSecure\WinGetUpdate_<timestamp>.log
    EC exit code config: success codes 0,3010 (2 = needs a reboot/logon cycle
    to confirm, not a failure; 1 = genuine failure).
    Plan on TWO passes fleet-wide (see v4 above): this run provisions the
    fix; a reboot pass afterward is what actually clears the finding on any
    host that has a logged-on (or not-yet-rebooted) user profile, which is
    expected to be a large majority of the fleet for this specific plugin.
#>

[CmdletBinding()]
param(
    [string]$TargetVersion = '1.30.80',
    [string]$InstallerPath = '',
    [switch]$DryRun,
    # Provision even if the staged bundle's contained app version is below
    # -TargetVersion. Escape hatch only -- see the .PARAMETER note above.
    [switch]$IgnoreBundleVersionMismatch
)

$ErrorActionPreference = 'Stop'
$LogDir  = 'C:\Logs\CompoSecure'
$LogFile = Join-Path $LogDir ('WinGetUpdate_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

Write-Log '=============================================='
Write-Log ' WinGet / App Installer Update -- Plugin 334617 (CVE-2026-68821)'
Write-Log (' Host    : ' + $env:COMPUTERNAME)
Write-Log (' Running as : ' + [Security.Principal.WindowsIdentity]::GetCurrent().Name)
Write-Log (' Target  : ' + $TargetVersion)
Write-Log (' DryRun  : ' + $DryRun)
Write-Log '=============================================='

function Get-DesktopAppInstallerVersion {
    $pkgs = Get-AppxPackage -AllUsers -Name 'Microsoft.DesktopAppInstaller' -ErrorAction SilentlyContinue
    if (-not $pkgs) { return $null }
    return ($pkgs | Sort-Object Version -Descending | Select-Object -First 1)
}

# ==============================================================
# 1. Current version (works from SYSTEM; this is what Tenable reads)
# ==============================================================
Write-Log ''
Write-Log '[1/5] Reading installed version (Get-AppxPackage -AllUsers)...'
$pkg = Get-DesktopAppInstallerVersion
if (-not $pkg) {
    Write-Log '  Microsoft.DesktopAppInstaller not found on this machine at all.' -Level ERROR
    Write-Log '  Nothing for this script to update; investigate separately.' -Level ERROR
    exit 1
}
Write-Log ('  Installed: ' + $pkg.Version + '  (' + $pkg.PackageFullName + ')')

# Diagnostic: multiple simultaneously-registered versions is direct evidence
# of the KNOWN LIMITATION above (per-user AppX registration lag) already
# being in effect on this host -- seen on ~23% of the fleet in the 334617
# export. Surfacing it here means exit 2 later is an expected confirmation,
# not a surprise.
$allPkgs = Get-AppxPackage -AllUsers -Name 'Microsoft.DesktopAppInstaller' -ErrorAction SilentlyContinue
$distinctVersions = @($allPkgs | Select-Object -ExpandProperty Version -Unique)
if ($distinctVersions.Count -gt 1) {
    Write-Log ('  NOTE: ' + $distinctVersions.Count + ' distinct versions are already simultaneously') -Level WARN
    Write-Log '  registered on this host (per-user AppX registrations at different' -Level WARN
    Write-Log '  versions). Expect this host to need a reboot/logon cycle after this run' -Level WARN
    Write-Log '  before Tenable stops flagging the older registration(s) too.' -Level WARN
    foreach ($pv in ($allPkgs | Sort-Object Version)) {
        $users = @($pv.PackageUserInformation | ForEach-Object {
            $u = $_.UserSecurityId.Username
            if ([string]::IsNullOrWhiteSpace($u)) { $u = '(orphaned SID)' }
            $u + ':' + $_.InstallState
        })
        $userList = if ($users.Count -gt 0) { $users -join ', ' } else { '(none enumerated)' }
        Write-Log ('    ' + $pv.Version + '  users: ' + $userList)
    }
}

$curVer = $null
try { $curVer = [version]$pkg.Version } catch { }
$targetVerObj = [version]$TargetVersion

if ($curVer -and $curVer -ge $targetVerObj) {
    Write-Log '  Already at or above target. Nothing to do.'
    Write-Log '=============================================='
    exit 0
}

# ==============================================================
# 2. Resolve the installer
# ==============================================================
Write-Log ''
Write-Log '[2/5] Resolving installer...'
$downloaded = $false
if ([string]::IsNullOrWhiteSpace($InstallerPath)) {
    $searchDirs = @()
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    if ($scriptDir) { $searchDirs += $scriptDir }
    $searchDirs += 'C:\'
    foreach ($dir in $searchDirs) {
        $cand = Get-ChildItem -Path $dir -Filter 'Microsoft.DesktopAppInstaller*.msixbundle' -File -ErrorAction SilentlyContinue |
                Sort-Object Name -Descending | Select-Object -First 1
        if ($cand) { $InstallerPath = $cand.FullName; Write-Log ('  Found staged installer: ' + $InstallerPath); break }
    }
}

if ([string]::IsNullOrWhiteSpace($InstallerPath)) {
    $url  = 'https://aka.ms/getwinget'
    $dest = Join-Path $env:TEMP 'Microsoft.DesktopAppInstaller.msixbundle'
    Write-Log ('  No staged installer. Downloading: ' + $url)
    if ($DryRun) {
        Write-Log '  [DRYRUN] Would download and install.'
        Write-Log '=============================================='
        exit 0
    }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    try {
        Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing -MaximumRedirection 10
    } catch {
        Write-Log ('  Download failed: ' + $_) -Level ERROR
        Write-Log '  If Zscaler blocks aka.ms/GitHub releases, stage the .msixbundle in' -Level ERROR
        Write-Log '  C:\ and re-run.' -Level ERROR
        exit 1
    }
    $InstallerPath = $dest
    $downloaded = $true
} elseif ($DryRun) {
    Write-Log ('  [DRYRUN] Would install staged: ' + $InstallerPath)
    Write-Log '=============================================='
    exit 0
}

if (-not (Test-Path $InstallerPath)) {
    Write-Log ('  Installer not found: ' + $InstallerPath) -Level ERROR
    exit 1
}

# Validate: msixbundle is zip-based ("PK" magic), plus a size floor, so a
# Zscaler/proxy block page can never be handed to Add-AppxProvisionedPackage.
$item = Get-Item $InstallerPath
$szMB = [math]::Round($item.Length / 1MB, 1)
$fs = [System.IO.File]::OpenRead($InstallerPath)
$b1 = $fs.ReadByte(); $b2 = $fs.ReadByte()
$fs.Close(); $fs.Dispose()
$isZip = ($b1 -eq 0x50 -and $b2 -eq 0x4B)   # 'P' 'K'
Write-Log ('  Installer: ' + $InstallerPath + '  (' + $szMB + ' MB, zip header: ' + $isZip + ')')
if (-not $isZip -or $item.Length -lt 10MB) {
    Write-Log '  Not a valid msixbundle (block page?). Aborting.' -Level ERROR
    if ($downloaded) { Remove-Item $InstallerPath -Force -ErrorAction SilentlyContinue }
    exit 1
}

# --------------------------------------------------------------
# 2b. Does the bundle actually CONTAIN the target version?
#
# The zip-header + size checks above only prove "this is a real archive of
# plausible size" -- they say nothing about what version is inside. A wrong or
# stale staged bundle provisions "successfully" and then leaves the version
# unmoved forever, which is indistinguishable from the per-user logon
# reconciliation lag unless you look inside. CSLT-001 (2026-08-26) ran three
# times, each reporting a successful provision, and never moved off 1.29.290.0.
#
# NOTE the bundle's OWN Identity version is NOT the app version: CSLT-001's
# provisioned entry read 2026.728.1707.0 (a date-style bundle version) while
# the target is 1.30.80. The versions that matter are the contained
# Type="application" packages in AppxMetadata/AppxBundleManifest.xml.
#
# Risk posture: a DEFINITE mismatch (manifest parsed, contained version below
# target) fails closed -- provisioning it can never clear the finding, and
# doing it on 315 hosts would be a silent fleet-wide no-op. A manifest we
# cannot parse fails OPEN with a warning, so an unexpected-but-valid bundle
# shape does not block remediation fleet-wide.
function Get-BundleManifestInfo {
    param([string]$BundlePath)
    if (-not ('System.IO.Compression.ZipFile' -as [type])) {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    }
    $zip = [System.IO.Compression.ZipFile]::OpenRead($BundlePath)
    try {
        $isBundle = $true
        $entry = $zip.Entries | Where-Object { $_.Name -eq 'AppxBundleManifest.xml' } | Select-Object -First 1
        if (-not $entry) {
            $entry = $zip.Entries | Where-Object { $_.Name -eq 'AppxManifest.xml' } | Select-Object -First 1
            $isBundle = $false
        }
        if (-not $entry) { return $null }
        $reader = New-Object System.IO.StreamReader($entry.Open())
        try { $xmlText = $reader.ReadToEnd() } finally { $reader.Dispose() }
    } finally {
        $zip.Dispose()
    }
    $xml = [xml]$xmlText
    if ($isBundle) {
        return [pscustomobject]@{
            IdentityName  = '' + $xml.Bundle.Identity.Name
            BundleVersion = '' + $xml.Bundle.Identity.Version
            AppVersions   = @(@($xml.Bundle.Packages.Package |
                              Where-Object { $_.Type -eq 'application' }) |
                              ForEach-Object { '' + $_.Version } | Sort-Object -Unique)
        }
    }
    return [pscustomobject]@{
        IdentityName  = '' + $xml.Package.Identity.Name
        BundleVersion = '' + $xml.Package.Identity.Version
        AppVersions   = @('' + $xml.Package.Identity.Version)
    }
}

$bundleInfo = $null
try {
    $bundleInfo = Get-BundleManifestInfo -BundlePath $InstallerPath
} catch {
    Write-Log ('  Could not inspect the bundle manifest: ' + $_) -Level WARN
}

if (-not $bundleInfo) {
    Write-Log '  Could not read a package manifest from this file. Continuing anyway' -Level WARN
    Write-Log '  (not blocking remediation on a diagnostic read), but the version it' -Level WARN
    Write-Log '  actually contains is therefore unverified.' -Level WARN
} else {
    Write-Log ('  Bundle identity : ' + $bundleInfo.IdentityName)
    Write-Log ('  Bundle version  : ' + $bundleInfo.BundleVersion + '   (the BUNDLE''s own version, not the app version)')
    Write-Log ('  Contained app version(s): ' + (($bundleInfo.AppVersions) -join ', '))

    if ($bundleInfo.IdentityName -and $bundleInfo.IdentityName -ne 'Microsoft.DesktopAppInstaller') {
        Write-Log ('  WARNING: identity is not Microsoft.DesktopAppInstaller. Wrong artifact staged?') -Level WARN
    }

    $bestInBundle = $null
    foreach ($v in $bundleInfo.AppVersions) {
        $parsed = $null
        try { $parsed = [version]$v } catch { }
        if ($parsed -and (-not $bestInBundle -or $parsed -gt $bestInBundle)) { $bestInBundle = $parsed }
    }

    if (-not $bestInBundle) {
        Write-Log '  No parseable application-package version in the manifest; cannot verify' -Level WARN
        Write-Log '  the bundle contents. Continuing.' -Level WARN
    } elseif ($bestInBundle -lt $targetVerObj) {
        Write-Log ('  This bundle contains ' + $bestInBundle + ', which is BELOW the target ' + $TargetVersion + '.') -Level ERROR
        Write-Log '  Provisioning it can never clear plugin 334617 -- it would report success' -Level ERROR
        Write-Log '  and leave the version unmoved, which looks exactly like the per-user' -Level ERROR
        Write-Log '  logon-reconciliation lag but is not. Replace the staged bundle with a' -Level ERROR
        Write-Log ('  build containing ' + $TargetVersion + '+ (https://aka.ms/getwinget) and re-run.') -Level ERROR
        if ($IgnoreBundleVersionMismatch) {
            Write-Log '  -IgnoreBundleVersionMismatch set: continuing anyway (not recommended).' -Level WARN
        } else {
            if ($downloaded) { Remove-Item $InstallerPath -Force -ErrorAction SilentlyContinue }
            Write-Log '=============================================='
            exit 1
        }
    } else {
        Write-Log ('  Bundle contains ' + $bestInBundle + ' >= target ' + $TargetVersion + '. Proceeding.')
    }
}

# ==============================================================
# 3. Install via DISM/AppX provisioning (SYSTEM-safe, no logon required)
# ==============================================================
Write-Log ''
Write-Log '[3/5] Installing (Add-AppxProvisionedPackage)...'
try {
    $result = Add-AppxProvisionedPackage -Online -PackagePath $InstallerPath -SkipLicense -ErrorAction Stop
    Write-Log ('  Provisioning result: ' + ($result | Out-String).Trim())
} catch {
    Write-Log ('  Add-AppxProvisionedPackage failed: ' + $_) -Level ERROR
    if ($_.Exception.Message -match 'depend|prerequisite|0x80073CF9|0x80073D02') {
        Write-Log '  This looks like a missing dependency (Microsoft.VCLibs or' -Level ERROR
        Write-Log '  Microsoft.UI.Xaml). These normally ship with current Windows/Store;' -Level ERROR
        Write-Log '  their absence indicates unhealthy Store/AppX state on this machine' -Level ERROR
        Write-Log '  rather than something to route around here.' -Level ERROR
    }
    if ($downloaded) { Remove-Item $InstallerPath -Force -ErrorAction SilentlyContinue }
    exit 1
}
if ($downloaded) { Remove-Item $InstallerPath -Force -ErrorAction SilentlyContinue }

# Also register for the currently logged-on interactive user, if any, so an
# already-signed-in user does not have to log off/on to pick up the change.
#
# v2 bug fix (from the CSLT-001 pilot run, 2026-08-26): this loop previously
# iterated Get-AppxPackage -AllUsers (the OLD, already-registered packages)
# and called Add-AppxPackage -Register on each one's OWN InstallLocation --
# i.e. it re-registered the version that was ALREADY there. $pkgFullName (the
# NEW provisioned package) was resolved but never actually used. That is a
# guaranteed no-op: it cannot advance anything, on ANY host, regardless of
# whether a stale multi-version state pre-existed. CSLT-001 had only ONE
# registered version before this script ran and still exited 2, which is
# exactly what this bug predicts. Fixed to register the NEW provisioned
# package's own manifest instead.
Write-Log ''
Write-Log '[4/5] Registering for the current session (if applicable)...'
try {
    $provPkg = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq 'Microsoft.DesktopAppInstaller' } |
               Sort-Object Version -Descending | Select-Object -First 1
    if (-not $provPkg) {
        Write-Log '  No provisioned Microsoft.DesktopAppInstaller entry found (unexpected after step 3).' -Level WARN
    } elseif ($provPkg.PackageName -like '*_~_*') {
        # Confirmed on CSLT-001, 2026-08-26: PackageName was
        # 'Microsoft.DesktopAppInstaller_2026.728.1707.0_neutral_~_8wekyb3d8bbwe'.
        # The '_~_' segment (architecture=neutral, resource id=~) is the BUNDLE's
        # own PackageFullName, not a concrete per-architecture Main package --
        # the same pattern already documented in Remove-3DViewer.ps1. There is no
        # WindowsApps\<that name>\AppxManifest.xml to register: App Installer
        # ships as an .msixbundle, DISM provisions the bundle itself, and the
        # concrete architecture-specific package only gets materialized when a
        # user's OWN registration reconciles against the provisioned list -- at
        # THEIR next logon. No SYSTEM-context action can force that early for an
        # already-logged-on user.
        Write-Log ('  Provisioned entry is the BUNDLE registration (' + $provPkg.PackageName + '),') -Level WARN
        Write-Log '  not a concrete per-architecture package -- there is nothing on disk yet' -Level WARN
        Write-Log '  for this script to register from SYSTEM context. Expect exit 2 below;' -Level WARN
        Write-Log '  that is a Windows/AppX platform limit for bundle-packaged apps like this' -Level WARN
        Write-Log '  one, not a failure of this step.' -Level WARN
    } else {
        $newManifest = Join-Path $env:ProgramFiles ('WindowsApps\' + $provPkg.PackageName + '\AppxManifest.xml')
        if (-not (Test-Path $newManifest)) {
            Write-Log ('  New package manifest not found at expected path: ' + $newManifest) -Level WARN
        } else {
            try {
                Add-AppxPackage -Register $newManifest -DisableDevelopmentMode -ErrorAction Stop
                Write-Log ('  Registered new package manifest: ' + $newManifest)
            } catch {
                Write-Log ('  Could not register the new manifest: ' + $_) -Level WARN
            }
        }
    }
    Write-Log '  Note: this registers for the SYSTEM account''s own context (this script'
    Write-Log '  always runs as SYSTEM under EC) -- it cannot push a per-user AppX'
    Write-Log '  registration into an already-logged-on HUMAN user''s session. That user'
    Write-Log '  may still need to log off/on (or the machine reboot) before their own'
    Write-Log '  registration reconciles. This is standard AppX behaviour, not specific'
    Write-Log '  to this script.'
} catch {
    Write-Log ('  Re-registration step skipped: ' + $_) -Level WARN
}

# ==============================================================
# 5. Verify -- re-read, do not trust the install command's exit code
# ==============================================================
Write-Log ''
Write-Log '[5/5] Verification...'
Start-Sleep -Seconds 3
$after = Get-DesktopAppInstallerVersion
if (-not $after) {
    Write-Log '  Microsoft.DesktopAppInstaller not found after install.' -Level ERROR
    exit 1
}
Write-Log ('  Now: ' + $after.Version)
$afterVer = $null
try { $afterVer = [version]$after.Version } catch { }

Write-Log ''
Write-Log '=============================================='
if ($afterVer -and $afterVer -ge $targetVerObj) {
    Write-Log ('SUCCESS: ' + $pkg.Version + ' -> ' + $after.Version)
    Write-Log 'Re-run a Nessus scan to confirm plugin 334617 clears.'
    Write-Log '=============================================='
    exit 0
}
Write-Log 'Provisioned package updated, but AllUsers version does not yet reflect the' -Level WARN
Write-Log 'target. This is consistent with AppX per-user registration reconciling at' -Level WARN
Write-Log 'next logon rather than immediately. If this persists after a reboot, treat' -Level WARN
Write-Log 'it as a real failure and investigate. Exiting 2 (needs confirmation), not 0.' -Level WARN
Write-Log '=============================================='
exit 2
