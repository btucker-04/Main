<#
.SYNOPSIS
    Remediation: WSL2 < 2.6.2 RCE (Nessus Plugin 275468)
    Target: cslt-164 (2.6.1.0 -> 2.6.2+)
.DESCRIPTION
    WSL is an MSIX/Store package -- not in EC's patch catalog. Uses
    wsl.exe --update --web-download (pulls the MSIX from GitHub releases,
    avoiding Store dependency in SYSTEM context).
.NOTES
    Deploy via Endpoint Central (SYSTEM). Exit: 0 ok / 1 failure.
    A WSL update does not disturb running distros' data; it may restart
    the WSL service, so any running Linux sessions are terminated --
    schedule off-hours for developer machines.
#>

$ErrorActionPreference = 'Stop'
$LogDir  = 'C:\Logs\CompoSecure'
$LogFile = Join-Path $LogDir ('WSL2Update_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

Write-Log '=== WSL2 Update -- Plugin 275468 ==='
Write-Log ('Host: ' + $env:COMPUTERNAME)

$pkg = Get-AppxPackage -AllUsers -Name 'MicrosoftCorporationII.WindowsSubsystemForLinux' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($pkg) { Write-Log ('Installed WSL package version: ' + $pkg.Version) }
else { Write-Log 'WSL MSIX package not detected via Appx (may still be present).' -Level WARN }

Write-Log 'Running: wsl.exe --update --web-download'
$out = & wsl.exe --update --web-download 2>&1
foreach ($line in $out) { Write-Log ('  ' + ($line -replace "`0", '')) }
$rc = $LASTEXITCODE
Write-Log ('wsl --update exit code: ' + $rc)

Start-Sleep -Seconds 5
$pkgAfter = Get-AppxPackage -AllUsers -Name 'MicrosoftCorporationII.WindowsSubsystemForLinux' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($pkgAfter) {
    Write-Log ('Post-update WSL package version: ' + $pkgAfter.Version)
    if ([version]$pkgAfter.Version -ge [version]'2.6.2.0') {
        Write-Log 'SUCCESS: WSL at or above 2.6.2. Re-scan to confirm 275468 clears.'
        exit 0
    }
}
if ($rc -eq 0) { Write-Log 'Update command succeeded; verify version on next inventory.' ; exit 0 }
Write-Log 'WSL update did not complete successfully. If Zscaler blocks GitHub' -Level ERROR
Write-Log 'release downloads, stage the .msixbundle and Add-AppxProvisionedPackage.' -Level ERROR
exit 1
