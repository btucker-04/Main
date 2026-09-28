<#
.SYNOPSIS
    Remediation: update WSL to the current release (Nessus plugin 275468 /
    CVE-2025-53788, CVE-2025-62220).

.DESCRIPTION
    WSL is an MSIX/Store package, not in Endpoint Central's patch catalog.
    wsl.exe --update --web-download pulls the current MSIX from the GitHub
    release, which works in the SYSTEM context where the Store does not.

    There is no minimum version in this script. wsl --update installs the
    latest release, and a completed update is success. Reading the installed
    version back through Get-AppxPackage fails under SYSTEM on some hosts
    (the package is per-user), and treating that miss as 0.0.0 then failing
    it against a floor reported a successful 2.7.14 update as a failure.
    The version printed by wsl itself ("Updating ... to version: 2.7.14")
    is recorded when present. An unreadable version after exit 0 is a
    warning, not a failure.

.NOTES
    Deploy via Endpoint Central (SYSTEM). Exit: 0 ok / 1 failure.
    A WSL update does not disturb distro data; it may restart the WSL
    service, so running Linux sessions are terminated. Schedule off-hours
    for developer machines.
    Warning 1946 (System.AppUserModel.ID on WSL.lnk) is cosmetic and does
    not mean the update failed.
#>

$ErrorActionPreference = 'Stop'

function Get-WslVersionFromText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    if ($Text -match '(?i)version:\s*([0-9]+(?:\.[0-9]+){1,3})') { return $Matches[1] }
    return ''
}

function Get-WslUpdateOutcome {
    param(
        [int]$ExitCode,
        [string]$OutputText,
        [string]$ReportedVersion
    )
    $fromOutput = Get-WslVersionFromText -Text $OutputText
    $version = ''
    if (-not [string]::IsNullOrWhiteSpace($ReportedVersion)) { $version = $ReportedVersion }
    elseif (-not [string]::IsNullOrWhiteSpace($fromOutput)) { $version = $fromOutput }
    if ($ExitCode -eq 0 -or -not [string]::IsNullOrWhiteSpace($fromOutput)) {
        return [pscustomobject]@{ Ok = $true; Version = $version }
    }
    return [pscustomobject]@{ Ok = $false; Version = $version }
}

if ($env:WSL_UPDATE_DOTSOURCE -eq '1') { return }

$LogDir  = 'C:\Logs\CompoSecure'
$LogFile = Join-Path $LogDir ('WSL2Update_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

Write-Log '=== WSL2 Update ==='
Write-Log ('Host: ' + $env:COMPUTERNAME)
Write-Log 'No minimum version. wsl --update installs the current release.'

$pkg = Get-AppxPackage -AllUsers -Name 'MicrosoftCorporationII.WindowsSubsystemForLinux' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($pkg) { Write-Log ('Installed WSL package version: ' + $pkg.Version) }
else { Write-Log 'Could not read the installed WSL version (Appx). Proceeding with the update.' -Level WARN }

Write-Log 'Running: wsl.exe --update --web-download'
$out = & wsl.exe --update --web-download 2>&1
$text = ($out | ForEach-Object { "$_" }) -join "`n"
foreach ($line in ($text -split "`n")) {
    if ($line) { Write-Log ('  ' + ($line -replace "`0", '')) }
}
$rc = $LASTEXITCODE
Write-Log ('wsl --update exit code: ' + $rc)

Start-Sleep -Seconds 5
$pkgAfter = Get-AppxPackage -AllUsers -Name 'MicrosoftCorporationII.WindowsSubsystemForLinux' -ErrorAction SilentlyContinue | Select-Object -First 1
$reported = ''
if ($pkgAfter) {
    $reported = [string]$pkgAfter.Version
    Write-Log ('Post-update WSL package version: ' + $reported)
}

$outcome = Get-WslUpdateOutcome -ExitCode $rc -OutputText $text -ReportedVersion $reported
if ($outcome.Ok) {
    if ($outcome.Version) {
        Write-Log ('SUCCESS: WSL update completed. Version: ' + $outcome.Version)
    } else {
        Write-Log 'SUCCESS: wsl --update completed. The installed version could not be read back; re-scan to confirm.' -Level WARN
    }
    Write-Log 'Re-run a Nessus scan to confirm the WSL finding clears.'
    exit 0
}
Write-Log 'WSL update did not complete. If Zscaler blocks GitHub release' -Level ERROR
Write-Log 'downloads, stage the .msixbundle and Add-AppxProvisionedPackage.' -Level ERROR
exit 1
