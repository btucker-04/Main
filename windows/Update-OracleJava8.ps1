<#
.SYNOPSIS
    Updates Oracle Java SE 8 JRE to 8u491+ (Nessus Plugin 309197,
    April 2026 CPU) on a machine where an older 8uXXX JRE is installed.

.DESCRIPTION
    ** SCOPE WARNING - READ BEFORE DEPLOYING **
    csprpc-98 is a PRODUCTION SHOPFLOOR machine (Shopfloor VLAN, 'Pierce'
    asset, 10.3.91.x production subnet, CSPR prefix). Java is almost
    certainly present to support a line application. This update is
    within-train (8u481 -> 8u491: security fixes, same APIs) and low risk,
    but:
      - Confirm ownership/change-approval with Marvin / OT first.
      - Confirm the Pierce/production app tolerates 8u491.
      - Run during a maintenance window; the script refuses to proceed if
        Java is actively running unless -ForceCloseJava is given.

    The Oracle JRE installer must be STAGED beside this script (EC copies
    deployment files next to it) or pointed to with -InstallerPath. Oracle
    JRE 8 is not publicly downloadable without an account, so this script
    never attempts a download.

    Silent install uses REMOVEOUTOFDATEJRES=1 so the old jre1.8.0_XXX folder
    is removed -- required because Tenable keys on the version folder on
    disk, not just ARP. WEB_JAVA=0 disables the browser plugin (hardening).

.PARAMETER InstallerPath
    Full path to jre-8u491(or later)-windows-x64.exe. Defaults to the first
    jre-8u*-windows-x64.exe found beside this script.

.PARAMETER ForceCloseJava
    Kill running java.exe / javaw.exe before installing. WARNING: this can
    interrupt a running production application. Default is to ABORT (exit 2)
    if Java is running, so a human decides.

.PARAMETER DryRun
    Report what would happen without changing anything.

.NOTES
    Deploy via Endpoint Central (SYSTEM). Logs: C:\Logs\CompoSecure.
    No reboot issued. Exit: 0 = updated / 2 = skipped (Java running) /
    1 = failure.
#>

[CmdletBinding()]
param(
    [string]$InstallerPath = '',
    [switch]$ForceCloseJava,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$LogDir  = 'C:\Logs\CompoSecure'
$LogFile = Join-Path $LogDir ('OracleJRE8Update_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

# 8u491 expressed as the file-version Oracle reports (8.0.4910.x). We compare
# on the update number (491) parsed from the jre1.8.0_XXX folder / ARP name.
$TargetUpdate = 491
$JavaRoot     = 'C:\Program Files\Java'

Write-Log '=============================================='
Write-Log ' Oracle JRE 8 Update -- Plugin 309197'
Write-Log (' Host   : ' + $env:COMPUTERNAME)
Write-Log (' DryRun : ' + $DryRun)
Write-Log '=============================================='
Write-Log 'SCOPE: production shopfloor (Pierce). Ensure Marvin/OT approval and'
Write-Log 'that the line application tolerates 8u491 before proceeding.'

# ==============================================================
# 1. Inventory installed Oracle JRE 8
# ==============================================================
Write-Log ''
Write-Log '[1/5] Inventorying installed Java 8 JREs...'
$jreFolders = @()
if (Test-Path $JavaRoot) {
    $jreFolders = Get-ChildItem $JavaRoot -Directory -ErrorAction SilentlyContinue |
                  Where-Object { $_.Name -match '^jre1\.8\.0_(\d+)$' }
}
if (-not $jreFolders) {
    Write-Log '  No jre1.8.0_XXX folder found under C:\Program Files\Java.'
    Write-Log '  Nothing for this script to update (Java 8 may be elsewhere or gone).'
    Write-Log '=============================================='
    exit 0
}
$maxInstalled = 0
foreach ($f in $jreFolders) {
    if ($f.Name -match '_(\d+)$') {
        $u = [int]$matches[1]
        Write-Log ('  Found: ' + $f.Name + '  (8u' + $u + ')')
        if ($u -gt $maxInstalled) { $maxInstalled = $u }
    }
}
if ($maxInstalled -ge $TargetUpdate) {
    Write-Log ('  Highest installed is 8u' + $maxInstalled + ' >= target 8u' + $TargetUpdate + '. Nothing to do.')
    Write-Log '=============================================='
    exit 0
}
Write-Log ('  Highest installed: 8u' + $maxInstalled + '  Target: 8u' + $TargetUpdate)

# ==============================================================
# 2. Resolve staged installer
# ==============================================================
Write-Log ''
Write-Log '[2/5] Resolving staged installer...'
if ([string]::IsNullOrWhiteSpace($InstallerPath)) {
    # Search order: beside the script (EC-staged), then C:\ root (manual staging).
    $searchDirs = @()
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    if ($scriptDir) { $searchDirs += $scriptDir }
    $searchDirs += 'C:\'
    foreach ($dir in $searchDirs) {
        $cand = Get-ChildItem -Path $dir -Filter 'jre-8u*-windows-x64.exe' -ErrorAction SilentlyContinue |
                Sort-Object Name -Descending | Select-Object -First 1
        if ($cand) { $InstallerPath = $cand.FullName; break }
    }
}
if ([string]::IsNullOrWhiteSpace($InstallerPath) -or -not (Test-Path $InstallerPath)) {
    Write-Log '  Installer not found. Stage jre-8u491-windows-x64.exe beside this' -Level ERROR
    Write-Log '  script or in C:\, or pass -InstallerPath. (Oracle JRE 8 is not downloadable' -Level ERROR
    Write-Log '  without an account, so this script will not fetch it.)' -Level ERROR
    exit 1
}
Write-Log ('  Installer: ' + $InstallerPath)

# ==============================================================
# 3. Check for running Java (production-app safety)
# ==============================================================
Write-Log ''
Write-Log '[3/5] Checking for running Java processes...'
$javaProcs = Get-Process -Name 'java','javaw' -ErrorAction SilentlyContinue
if ($javaProcs) {
    foreach ($p in $javaProcs) {
        Write-Log ('  RUNNING: ' + $p.Name + ' (PID ' + $p.Id + ')  Path: ' + $p.Path) -Level WARN
    }
    if (-not $ForceCloseJava) {
        Write-Log '  Java is in use -- likely the production application. ABORTING so a' -Level WARN
        Write-Log '  human decides. Re-run in a maintenance window, or pass -ForceCloseJava' -Level WARN
        Write-Log '  once it is confirmed safe to interrupt. Exit 2.' -Level WARN
        exit 2
    }
    if ($DryRun) {
        Write-Log '  [DRYRUN] Would force-close the above Java processes.'
    } else {
        Write-Log '  -ForceCloseJava set: stopping Java processes...' -Level WARN
        $javaProcs | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
    }
} else {
    Write-Log '  No java.exe / javaw.exe running.'
}

# ==============================================================
# 4. Install
# ==============================================================
Write-Log ''
Write-Log '[4/5] Installing updated JRE...'
$installLog = $LogDir + '\jre_install.log'
# Oracle JRE 8 silent options:
#   /s                  silent
#   STATIC=0            normal (patch-in-place family) install
#   AUTO_UPDATE=0       no Oracle auto-updater
#   WEB_JAVA=0          disable browser plugin (hardening)
#   REMOVEOUTOFDATEJRES=1  remove older JRE folders (clears Tenable finding)
#   NOSTARTMENU=1 SPONSORS=0  no shortcuts / no sponsor offers
$installArgs = '/s STATIC=0 AUTO_UPDATE=0 WEB_JAVA=0 REMOVEOUTOFDATEJRES=1 NOSTARTMENU=1 SPONSORS=0 /L "' + $installLog + '"'

if ($DryRun) {
    Write-Log ('  [DRYRUN] Would run: "' + $InstallerPath + '" ' + $installArgs)
} else {
    $proc = Start-Process -FilePath $InstallerPath -ArgumentList $installArgs -Wait -PassThru
    Write-Log ('  Installer exit code: ' + $proc.ExitCode + '  (see ' + $installLog + ')')
    if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {
        Write-Log '  Install FAILED.' -Level ERROR
        exit 1
    }
}

# ==============================================================
# 5. Verify -- new version present, old folders gone
# ==============================================================
Write-Log ''
Write-Log '[5/5] Verification...'
if ($DryRun) {
    Write-Log '  [DRYRUN] Skipping verification.'
    Write-Log '=============================================='
    exit 0
}

Start-Sleep -Seconds 3
$after = Get-ChildItem $JavaRoot -Directory -ErrorAction SilentlyContinue |
         Where-Object { $_.Name -match '^jre1\.8\.0_(\d+)$' }
$stillOld = @()
$haveTarget = $false
foreach ($f in $after) {
    if ($f.Name -match '_(\d+)$') {
        $u = [int]$matches[1]
        if ($u -ge $TargetUpdate) { $haveTarget = $true; Write-Log ('  Present: ' + $f.Name + '  (OK)') }
        else { $stillOld += $f.Name; Write-Log ('  Present: ' + $f.Name + '  (STILL VULNERABLE)') -Level ERROR }
    }
}

if (-not $haveTarget) {
    Write-Log ('  Target 8u' + $TargetUpdate + '+ not present after install.') -Level ERROR
    exit 1
}
if ($stillOld.Count -gt 0) {
    Write-Log '  Old JRE folder(s) remain -- Tenable will still flag. If REMOVEOUTOFDATEJRES' -Level ERROR
    Write-Log '  did not clear them, an app may be pinning the folder; remove manually after' -Level ERROR
    Write-Log '  confirming nothing depends on it, or uninstall via its ARP entry.' -Level ERROR
    exit 1
}

Write-Log '  Updated JRE present and no vulnerable 8u folders remain.'
Write-Log '  Re-run a Nessus scan to confirm plugin 309197 clears.'
Write-Log '=============================================='
exit 0
