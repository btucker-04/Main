<#
.SYNOPSIS
    Updates the Program Files Node.js MSI install to the LATEST release of
    ITS OWN major line. No pinned target version.

.DESCRIPTION
    Targets the MSI install flagged by Tenable (C:\Program Files\nodejs\).

    v2 (CSRZ-002, 2026-10-07): v1 carried a fixed-version map per major. A
    stale copy still read 22.x -> 22.23.0, so a host on 22.23.0 logged
    "Already at or above target. Nothing to do." while Tenable (plugin
    330668) wanted 22.23.2 -- the same silent no-op already seen on CSLT-136
    when the map lagged an advisory. The map is gone. The target is looked up
    at run time from https://nodejs.org/dist/index.json: the newest release
    on the installed major that ships a Windows MSI for this architecture.

    Stays on the installed major line by design -- a developer on 22.x is
    moved to the newest 22.x, NOT jumped to 26.x, because a major bump can
    break their projects. Override with -TargetVersion for a deliberate jump.

    Installer sourcing (in order):
      1. -InstallerPath if given
      2. A staged node-v<target>-<arch>.msi beside this script, then in C:\
      3. Download from https://nodejs.org/dist/v<ver>/node-v<ver>-<arch>.msi
    If nodejs.org cannot be reached for the version lookup, the newest staged
    node-v<major>.*-<arch>.msi is used instead.
    Downloads are validated by SIZE and by the MSI/OLE magic header
    (D0 CF 11 E0) so a Zscaler block page can never be handed to msiexec.

    Running node.exe ABORTS the run (exit 2) rather than interrupting a
    developer's dev server / build, unless -ForceCloseNode is passed. This is
    also what makes EC's own Node patch fail with "application in use".

.PARAMETER TargetVersion
    Explicit version to install (e.g. '22.23.3'). Default: the latest release
    of the installed major line.

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
    Exit: 0 = updated/already latest / 2 = skipped (node running) / 1 = failure.
#>

[CmdletBinding()]
param(
    [string]$TargetVersion  = '',
    [string]$InstallerPath  = '',
    [switch]$ForceCloseNode,
    [switch]$DryRun
)

$NodeIndexUrl = 'https://nodejs.org/dist/index.json'

# Newest release on major line $Major with a Windows build for $Arch, from the
# text of nodejs.org/dist/index.json. '' when the line has none. The index
# never lists 'win-arm64-msi' even though node-v<ver>-arm64.msi is published
# beside the arm64 zip, so arm64 keys on the zip.
function Get-LatestNodeRelease {
    param([string]$IndexJson, [string]$Major, [string]$Arch)
    $releases = @($IndexJson | ConvertFrom-Json)
    $msiFile = 'win-' + $Arch + '-msi'
    if ($Arch -eq 'arm64') { $msiFile = 'win-arm64-zip' }
    $best = $null
    foreach ($r in $releases) {
        $v = ('' + $r.version) -replace '^v', ''
        if ($v -notmatch '^\d+\.\d+\.\d+$') { continue }
        if ($v.Split('.')[0] -ne $Major) { continue }
        if (@($r.files) -notcontains $msiFile) { continue }
        $vo = [version]$v
        if ($null -eq $best -or $vo -gt $best) { $best = $vo }
    }
    if ($null -eq $best) { return '' }
    return $best.ToString()
}

# Newest staged node-v<Major>.x.y-<Arch>.msi among $Names (file names).
function Select-StagedNodeMsi {
    param([string[]]$Names, [string]$Major, [string]$Arch)
    $best = $null; $bestName = ''
    $pattern = '^node-v(' + $Major + '\.\d+\.\d+)-' + $Arch + '\.msi$'
    foreach ($n in $Names) {
        if ($n -match $pattern) {
            $vo = [version]$Matches[1]
            if ($null -eq $best -or $vo -gt $best) { $best = $vo; $bestName = $n }
        }
    }
    return $bestName
}

if ($env:NODEJS_UPDATE_DOTSOURCE -eq '1') { return }

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

Write-Log '=============================================='
Write-Log ' Node.js Update (v2) -- latest release of the installed major'
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

$arch = 'x64'
if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { $arch = 'arm64' }

$searchDirs = @()
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($scriptDir) { $searchDirs += $scriptDir }
$searchDirs += 'C:\'

# Resolve the target
if ([string]::IsNullOrWhiteSpace($TargetVersion)) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $indexJson = ''
    try {
        $indexJson = (Invoke-WebRequest -Uri $NodeIndexUrl -UseBasicParsing -TimeoutSec 60).Content
    } catch {
        Write-Log ('  Could not read ' + $NodeIndexUrl + ': ' + $_) -Level WARN
    }
    if ($indexJson) {
        try {
            $TargetVersion = Get-LatestNodeRelease -IndexJson $indexJson -Major $major -Arch $arch
        } catch {
            Write-Log ('  Release index was not valid JSON (block page?): ' + $_) -Level WARN
        }
        if ($TargetVersion) {
            Write-Log ('  Target    : ' + $TargetVersion + '  (latest ' + $major + '.x on nodejs.org)')
        } else {
            Write-Log ('  nodejs.org lists no ' + $major + '.x release with a ' + $arch + ' MSI.') -Level WARN
        }
    }
    if (-not $TargetVersion) {
        foreach ($dir in $searchDirs) {
            $names = @(Get-ChildItem -Path $dir -Filter ('node-v' + $major + '.*-' + $arch + '.msi') -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
            $pick = Select-StagedNodeMsi -Names $names -Major $major -Arch $arch
            if ($pick) {
                $InstallerPath = Join-Path $dir $pick
                $TargetVersion = ($pick -replace '^node-v', '') -replace ('-' + $arch + '\.msi$'), ''
                Write-Log ('  Target    : ' + $TargetVersion + '  (newest staged MSI: ' + $InstallerPath + ')')
                break
            }
        }
    }
    if (-not $TargetVersion) {
        Write-Log '  No target version: nodejs.org unreachable and no staged MSI for this line.' -Level ERROR
        Write-Log ('  Stage node-v' + $major + '.x.y-' + $arch + '.msi beside this script or in C:\,') -Level ERROR
        Write-Log '  or pass -TargetVersion.' -Level ERROR
        exit 1
    }
    if (($curVer.Major % 2) -eq 1) {
        Write-Log ('  ' + $major + '.x is an odd-numbered (non-LTS) line. Updating within it, but it') -Level WARN
        Write-Log '  goes end-of-life quickly -- plan a move to an even-numbered LTS line.' -Level WARN
    }
} else {
    Write-Log ('  Target    : ' + $TargetVersion + '  (explicit -TargetVersion)')
}

$targetVerObj = [version]$TargetVersion
if ($curVer -ge $targetVerObj) {
    Write-Log '  Already on the latest release of this line. Nothing to do.'
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
Write-Log ('  Architecture: ' + $arch)

$msiName = 'node-v' + $TargetVersion + '-' + $arch + '.msi'

if ([string]::IsNullOrWhiteSpace($InstallerPath)) {
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
Write-Log '  Re-run a Nessus scan to confirm the Node.js finding clears.'
Write-Log '=============================================='
if ($rebootNeeded) { exit 3010 }
exit 0
