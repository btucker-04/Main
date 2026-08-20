<#
.SYNOPSIS
    Updates Node.js to the fixed release of ITS OWN major line
    (Nessus Plugin 322793 -- June 18 2026 security releases):
        22.x -> 22.23.0   24.x -> 24.17.0   26.x -> 26.3.1

.DESCRIPTION
    Targets the MSI install flagged by Tenable (C:\Program Files\nodejs\).

    Stays on the installed major line by design -- a developer on 22.x is
    moved to 22.23.0, NOT jumped to 26.x, because a major bump can break
    their projects. Override with -TargetVersion for a deliberate jump.

    Installer sourcing (in order):
      1. -InstallerPath if given
      2. A staged node-v*-<arch>.msi beside this script, then in C:\
      3. Download from https://nodejs.org/dist/v<ver>/node-v<ver>-<arch>.msi
    Downloads are validated by SIZE and by the MSI/OLE magic header
    (D0 CF 11 E0) so a Zscaler block page can never be handed to msiexec.

    Running node.exe ABORTS the run (exit 2) rather than interrupting a
    developer's dev server / build, unless -ForceCloseNode is passed.

.PARAMETER TargetVersion
    Explicit version to install (e.g. '22.23.0'). Default: resolved from the
    installed major line using the advisory's fixed-version map.

.PARAMETER InstallerPath
    Full path to a staged node MSI.

.PARAMETER ForceCloseNode
    Kill running node.exe before installing. WARNING: interrupts dev servers.

.PARAMETER DryRun
    Report what would happen without changing anything.

.NOTES
    Deploy via Endpoint Central (SYSTEM). Logs: C:\Logs\CompoSecure.
    The MSI upgrade replaces the install in place (no side-by-side folder to
    clean up, unlike the Homebrew/Cellar case on macOS).
    Exit: 0 = updated/already current / 2 = skipped (node running) / 1 = failure.
#>

[CmdletBinding()]
param(
    [string]$TargetVersion  = '',
    [string]$InstallerPath  = '',
    [switch]$ForceCloseNode,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$LogDir  = 'C:\Logs\CompoSecure'
$LogFile = Join-Path $LogDir ('NodeJSUpdate_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

# Fixed versions per major line, from the June 18 2026 advisory.
$FixedFor = @{
    '22' = '22.23.0'
    '24' = '24.17.0'
    '26' = '26.3.1'
}

Write-Log '=============================================='
Write-Log ' Node.js Update -- Plugin 322793'
Write-Log (' Host   : ' + $env:COMPUTERNAME)
Write-Log (' DryRun : ' + $DryRun)
Write-Log '=============================================='

# ==============================================================
# 1. Detect installed Node
# ==============================================================
Write-Log ''
Write-Log '[1/5] Detecting installed Node.js...'

$nodeExe = 'C:\Program Files\nodejs\node.exe'
if (-not (Test-Path $nodeExe)) {
    $alt = 'C:\Program Files (x86)\nodejs\node.exe'
    if (Test-Path $alt) { $nodeExe = $alt }
}
if (-not (Test-Path $nodeExe)) {
    Write-Log '  Node.js not found in Program Files. Nothing to update.'
    Write-Log '  (A per-user or nvm-for-Windows install would not be covered here.)'
    Write-Log '=============================================='
    exit 0
}

$rawVer = (& $nodeExe --version 2>&1) -replace '^v', ''
$rawVer = ($rawVer | Select-Object -First 1).Trim()
try { $curVer = [version]$rawVer } catch {
    Write-Log ('  Could not parse node --version output: ' + $rawVer) -Level ERROR
    exit 1
}
$major = $curVer.Major.ToString()
Write-Log ('  Path      : ' + $nodeExe)
Write-Log ('  Installed : ' + $curVer + '  (major line ' + $major + '.x)')

# Resolve the target
if ([string]::IsNullOrWhiteSpace($TargetVersion)) {
    if ($FixedFor.ContainsKey($major)) {
        $TargetVersion = $FixedFor[$major]
        Write-Log ('  Target    : ' + $TargetVersion + '  (fixed release for ' + $major + '.x)')
    } else {
        Write-Log ('  Major line ' + $major + '.x is not named in the advisory.') -Level WARN
        Write-Log '  It may be an EOL/odd-numbered line with no fix in-branch --' -Level WARN
        Write-Log '  migrate to a supported LTS line, or pass -TargetVersion explicitly.' -Level WARN
        exit 1
    }
} else {
    Write-Log ('  Target    : ' + $TargetVersion + '  (explicit -TargetVersion)')
}

$targetVerObj = [version]$TargetVersion
if ($curVer -ge $targetVerObj) {
    Write-Log '  Already at or above target. Nothing to do.'
    Write-Log '=============================================='
    exit 0
}

# ==============================================================
# 2. Check for running node.exe
# ==============================================================
Write-Log ''
Write-Log '[2/5] Checking for running Node processes...'
$nodeProcs = Get-Process -Name 'node' -ErrorAction SilentlyContinue
if ($nodeProcs) {
    foreach ($p in $nodeProcs) { Write-Log ('  RUNNING: node (PID ' + $p.Id + ')  ' + $p.Path) -Level WARN }
    if (-not $ForceCloseNode) {
        Write-Log '  Node is in use (dev server / build?). ABORTING so a human decides.' -Level WARN
        Write-Log '  Re-run when idle, or pass -ForceCloseNode. Exit 2.' -Level WARN
        exit 2
    }
    if ($DryRun) {
        Write-Log '  [DRYRUN] Would force-close the above node processes.'
    } else {
        Write-Log '  -ForceCloseNode set: stopping node processes...' -Level WARN
        $nodeProcs | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
    }
} else {
    Write-Log '  None running.'
}

# ==============================================================
# 3. Resolve the installer (staged first, then download)
# ==============================================================
Write-Log ''
Write-Log '[3/5] Resolving installer...'

$arch = 'x64'
if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { $arch = 'arm64' }
Write-Log ('  Architecture: ' + $arch)

$msiName = 'node-v' + $TargetVersion + '-' + $arch + '.msi'

if ([string]::IsNullOrWhiteSpace($InstallerPath)) {
    $searchDirs = @()
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    if ($scriptDir) { $searchDirs += $scriptDir }
    $searchDirs += 'C:\'
    foreach ($dir in $searchDirs) {
        $cand = Join-Path $dir $msiName
        if (Test-Path $cand) { $InstallerPath = $cand; Write-Log ('  Found staged installer: ' + $cand); break }
    }
}

$downloaded = $false
if ([string]::IsNullOrWhiteSpace($InstallerPath)) {
    $url  = 'https://nodejs.org/dist/v' + $TargetVersion + '/' + $msiName
    $dest = Join-Path $env:TEMP $msiName
    Write-Log ('  No staged MSI. Downloading: ' + $url)
    if ($DryRun) {
        Write-Log '  [DRYRUN] Would download and install.'
        Write-Log '=============================================='
        exit 0
    }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    try {
        Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
    } catch {
        Write-Log ('  Download failed: ' + $_) -Level ERROR
        Write-Log '  If Zscaler blocks nodejs.org, stage the MSI in C:\ and re-run.' -Level ERROR
        exit 1
    }
    $InstallerPath = $dest
    $downloaded = $true
}

if (-not (Test-Path $InstallerPath)) {
    Write-Log ('  Installer not found: ' + $InstallerPath) -Level ERROR
    exit 1
}

# Validate: real MSI (OLE compound-file magic D0 CF 11 E0) and non-trivial size
$item = Get-Item $InstallerPath
$szMB = [math]::Round($item.Length / 1MB, 1)
$fs = [System.IO.File]::OpenRead($InstallerPath)
$hdr = New-Object byte[] 4
$null = $fs.Read($hdr, 0, 4)
$fs.Close(); $fs.Dispose()
$isMsi = ($hdr[0] -eq 0xD0 -and $hdr[1] -eq 0xCF -and $hdr[2] -eq 0x11 -and $hdr[3] -eq 0xE0)
Write-Log ('  Installer: ' + $InstallerPath + '  (' + $szMB + ' MB, MSI header: ' + $isMsi + ')')
if (-not $isMsi -or $item.Length -lt 10MB) {
    Write-Log '  Not a valid MSI (block page?). Aborting.' -Level ERROR
    if ($downloaded) { Remove-Item $InstallerPath -Force -ErrorAction SilentlyContinue }
    exit 1
}

# ==============================================================
# 4. Install
# ==============================================================
Write-Log ''
Write-Log '[4/5] Installing...'
if ($DryRun) {
    Write-Log ('  [DRYRUN] Would run: msiexec /i "' + $InstallerPath + '" /qn /norestart')
    Write-Log '=============================================='
    exit 0
}

$msiLog = $LogDir + '\msi_nodejs_install.log'
$msiArgs = '/i "' + $InstallerPath + '" /qn /norestart /l*v "' + $msiLog + '"'
$proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -Wait -PassThru
Write-Log ('  msiexec exit code: ' + $proc.ExitCode + '  (see ' + $msiLog + ')')
if ($downloaded) { Remove-Item $InstallerPath -Force -ErrorAction SilentlyContinue }

$rebootNeeded = $false
if ($proc.ExitCode -eq 3010) { $rebootNeeded = $true }
elseif ($proc.ExitCode -ne 0) {
    Write-Log '  Install FAILED.' -Level ERROR
    exit 1
}

# ==============================================================
# 5. Verify
# ==============================================================
Write-Log ''
Write-Log '[5/5] Verification...'
Start-Sleep -Seconds 3
if (-not (Test-Path $nodeExe)) {
    Write-Log '  node.exe missing after install!' -Level ERROR
    exit 1
}
$newRaw = ((& $nodeExe --version 2>&1) -replace '^v', '' | Select-Object -First 1).Trim()
Write-Log ('  Installed now: ' + $newRaw)
try { $newVer = [version]$newRaw } catch { $newVer = [version]'0.0.0' }

if ($newVer -lt $targetVerObj) {
    Write-Log ('  Version did not reach target ' + $TargetVersion + '.') -Level ERROR
    exit 1
}

Write-Log ('  SUCCESS: Node.js ' + $curVer + ' -> ' + $newVer)
Write-Log '  Re-run a Nessus scan to confirm plugin 322793 clears.'
Write-Log '=============================================='
if ($rebootNeeded) { exit 3010 }
exit 0
