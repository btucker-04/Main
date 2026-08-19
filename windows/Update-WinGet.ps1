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

.NOTES
    Deploy via Endpoint Central (SYSTEM), Repository mode, arguments as bare
    switches only (no $ or quotes, so EC's argument handling cannot mangle
    them). Logs: C:\Logs\CompoSecure\WinGetUpdate_<timestamp>.log
    EC exit code config: success codes 0,3010 (2 = needs a reboot/logon cycle
    to confirm, not a failure; 1 = genuine failure).
#>

[CmdletBinding()]
param(
    [string]$TargetVersion = '1.30.80',
    [string]$InstallerPath = '',
    [switch]$DryRun
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
Write-Log ''
Write-Log '[4/5] Registering for the current session (if applicable)...'
try {
    $pkgFullName = (Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq 'Microsoft.DesktopAppInstaller' } |
                    Sort-Object Version -Descending | Select-Object -First 1).PackageName
    if ($pkgFullName) {
        Get-AppxPackage -AllUsers -Name 'Microsoft.DesktopAppInstaller' -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                Add-AppxPackage -Register ($_.InstallLocation + '\AppXManifest.xml') -DisableDevelopmentMode -ErrorAction Stop
            } catch { }
        }
    }
    Write-Log '  Attempted. Note: a user already logged on may still need to log off/on'
    Write-Log '  for their own registration to fully reconcile -- this is standard AppX'
    Write-Log '  behaviour, not specific to this script.'
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
