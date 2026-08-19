<#
.SYNOPSIS
    Remediation: Google Chrome Multiple Vulnerabilities
    Nessus Plugin IDs : 317483 (< 148.0.7778.216), 319297 (< 149.0.7827.53)
    Affected Asset    : csprpc-64 (10.3.20.81) -- and any others with stale Chrome

.DESCRIPTION
    Downloads the latest Google Chrome stable enterprise MSI from Google's
    permalink (always current stable -- covers both plugin findings and any
    future ones at deploy time), closes running Chrome instances after a
    user warning, installs silently, and verifies the resulting version.

    Deploy via Endpoint Central (runs as SYSTEM).
    All strings use concatenation (no interpolation) to survive the EC editor.

.NOTES
    Exit codes: 0 = success, 3010 = success + reboot recommended, 1 = failure
#>

[CmdletBinding()]
param(
    [switch]$DryRun,
    # Minimum acceptable version -- the higher of the two plugin thresholds.
    # The permalink always serves >= this, but we verify anyway.
    [string]$MinVersion = '149.0.7827.53'
)

$ErrorActionPreference = 'Stop'

$LogDir  = 'C:\Logs\CompoSecure'
$LogFile = Join-Path $LogDir ('ChromeUpdate_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')
$MsiUrl  = 'https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi'
$MsiPath = Join-Path $env:TEMP 'googlechromestandaloneenterprise64.msi'
$MinDownloadBytes = 10MB   # Google endpoints can return HTML error pages; validate size

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

function Get-ChromeVersion {
    $paths = @(
        'C:\Program Files\Google\Chrome\Application\chrome.exe',
        'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe'
    )
    foreach ($p in $paths) {
        if (Test-Path $p) {
            $v = (Get-Item $p).VersionInfo.ProductVersion
            if ($v) { return @{ Version = $v; Path = $p } }
        }
    }
    return $null
}

Write-Log '=============================================='
Write-Log ' Chrome Update -- Plugins 317483 / 319297'
Write-Log (' Host       : ' + $env:COMPUTERNAME)
Write-Log (' Date       : ' + (Get-Date))
Write-Log (' MinVersion : ' + $MinVersion)
Write-Log (' DryRun     : ' + $DryRun)
Write-Log '=============================================='

# ------------------------------------------------------------------
# 1. Check current version
# ------------------------------------------------------------------
Write-Log ''
Write-Log '[1/5] Checking installed Chrome version...'

$chrome = Get-ChromeVersion
if ($null -eq $chrome) {
    Write-Log '  Chrome not found on this machine. Nothing to update.' -Level WARN
    exit 0
}

Write-Log ('  Installed : ' + $chrome.Version + '  (' + $chrome.Path + ')')

if ([version]$chrome.Version -ge [version]$MinVersion) {
    Write-Log ('  Already at or above ' + $MinVersion + '. No update needed.') -Level OK
    exit 0
}
Write-Log ('  Below required ' + $MinVersion + ' -- update needed.') -Level WARN

# ------------------------------------------------------------------
# 2. Download the latest stable enterprise MSI
# ------------------------------------------------------------------
Write-Log ''
Write-Log '[2/5] Downloading latest Chrome enterprise MSI...'
Write-Log ('  URL: ' + $MsiUrl)

if ($DryRun) {
    Write-Log '  [DRYRUN] Would download MSI.'
} else {
    if (Test-Path $MsiPath) { Remove-Item $MsiPath -Force -ErrorAction SilentlyContinue }

    # TLS 1.2 for older PowerShell defaults
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    try {
        Invoke-WebRequest -Uri $MsiUrl -OutFile $MsiPath -UseBasicParsing
    } catch {
        Write-Log ('  Download failed: ' + $_) -Level ERROR
        exit 1
    }

    $size = (Get-Item $MsiPath).Length
    Write-Log ('  Downloaded ' + [math]::Round($size / 1MB, 1) + ' MB')

    # Validate: Google endpoints sometimes return an HTML error page instead
    # of the MSI. A real Chrome MSI is well over 10 MB.
    if ($size -lt $MinDownloadBytes) {
        Write-Log ('  Download is suspiciously small (< 10 MB) -- likely an error page, not an MSI. Aborting.') -Level ERROR
        exit 1
    }
}

# ------------------------------------------------------------------
# 3. Warn user (if logged in) and close running Chrome
# ------------------------------------------------------------------
Write-Log ''
Write-Log '[3/5] Handling running Chrome instances...'

$chromeProcs = Get-Process -Name 'chrome' -ErrorAction SilentlyContinue
if ($chromeProcs) {
    Write-Log ('  Chrome is running (' + ($chromeProcs | Measure-Object).Count + ' processes).')

    # Best-effort user warning via msg.exe (works for console sessions)
    if (-not $DryRun) {
        try {
            & msg.exe * /TIME:60 'IT Security: Google Chrome will close in 60 seconds to install a required security update. Please save your work / tabs now.' 2>$null
            Write-Log '  User warning sent. Waiting 60 seconds...'
            Start-Sleep -Seconds 60
        } catch {
            Write-Log '  Could not send user warning (no interactive session?). Proceeding.' -Level WARN
        }

        Get-Process -Name 'chrome' -ErrorAction SilentlyContinue | Stop-Process -Force
        Start-Sleep -Seconds 5
        Write-Log '  Chrome processes closed.'
    } else {
        Write-Log '  [DRYRUN] Would warn user (60s) then close Chrome.'
    }
} else {
    Write-Log '  Chrome is not running.'
}

# ------------------------------------------------------------------
# 4. Install the MSI silently
# ------------------------------------------------------------------
Write-Log ''
Write-Log '[4/5] Installing Chrome update...'

if ($DryRun) {
    Write-Log ('  [DRYRUN] Would run: msiexec /i "' + $MsiPath + '" /qn /norestart')
    exit 0
}

$msiLog = Join-Path $LogDir 'msi_chrome_install.log'
$args   = '/i "' + $MsiPath + '" /qn /norestart /l*v "' + $msiLog + '"'
$proc   = Start-Process -FilePath 'msiexec.exe' -ArgumentList $args -Wait -PassThru
Write-Log ('  msiexec exit code: ' + $proc.ExitCode)

$rebootNeeded = $false
if ($proc.ExitCode -eq 3010) {
    $rebootNeeded = $true
} elseif ($proc.ExitCode -ne 0) {
    Write-Log ('  Install FAILED. See ' + $msiLog) -Level ERROR
    exit 1
}

# ------------------------------------------------------------------
# 5. Verify
# ------------------------------------------------------------------
Write-Log ''
Write-Log '[5/5] Verifying installed version...'
Start-Sleep -Seconds 5

$after = Get-ChromeVersion
if ($null -eq $after) {
    Write-Log '  Chrome not found after install!' -Level ERROR
    exit 1
}
Write-Log ('  Now installed: ' + $after.Version)

if ([version]$after.Version -ge [version]$MinVersion) {
    Write-Log ('  SUCCESS: ' + $chrome.Version + ' -> ' + $after.Version) -Level OK
} else {
    Write-Log ('  Version still below ' + $MinVersion + ' after install.') -Level ERROR
    exit 1
}

# Cleanup
Remove-Item $MsiPath -Force -ErrorAction SilentlyContinue
Write-Log ''
Write-Log ' Re-run a Nessus scan to confirm plugins 317483 and 319297 clear.'
Write-Log '=============================================='

if ($rebootNeeded) { exit 3010 }
exit 0
