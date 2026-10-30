<#
.SYNOPSIS
    Updates Oracle Java SE 8 JRE (64-bit and 32-bit) to 8u511 b32 BPR or
    later. Nessus plugin 371349 (CVE-2026-91403 Security Alert); also
    clears the older 338352 / 329223 / 309197 findings.

.DESCRIPTION
    ** SCOPE WARNING - READ BEFORE DEPLOYING **
    csprpc-98 is a PRODUCTION SHOPFLOOR machine (Shopfloor VLAN, 'Pierce'
    asset, 10.3.91.x production subnet, CSPR prefix). Java is almost
    certainly present to support a line application. This update is
    within-train (e.g. 8u503 -> 8u511: security fixes, same APIs) and low risk,
    but:
      - Confirm ownership/change-approval with Marvin / OT first.
      - Confirm the Pierce/production app tolerates 8u511.
      - Run during a maintenance window; the script refuses to proceed if
        Java is actively running unless -ForceCloseJava is given.

    The Oracle JRE installers must be STAGED beside this script (EC copies
    deployment files next to it) or pointed to with -InstallerPath /
    -InstallerPathX86. Oracle JRE 8 is not publicly downloadable without an
    account, so this script never attempts a download.

    Silent install uses REMOVEOUTOFDATEJRES=1 so the old jre1.8.0_XXX folder
    is removed -- required because Tenable keys on the version folder on
    disk, not just ARP. WEB_JAVA=0 disables the browser plugin (hardening).

    v2 (2026-10-30, plugin 371349): the fix is the 8u511 b32 Bundle Patch
    Release. It installs into the same jre1.8.0_511 folder as the vulnerable
    8u511 GA build, so versions are now read from bin\java.exe (FileVersion
    8.0.5110.32), not the folder name. Program Files (x86)\Java is now
    updated too: 12 of the 17 flagged hosts had a 32-bit JRE, and CSLT-158
    and CSLT-159 had only that one. A staged installer whose own version is
    below the target is refused before anything runs.

.PARAMETER InstallerPath
    Full path to the 64-bit jre-8u511-windows-x64.exe (b32 BPR or later).
    Defaults to the newest jre-8u*-windows-x64.exe beside this script, then C:\.

.PARAMETER InstallerPathX86
    Full path to the 32-bit jre-8u511-windows-i586.exe (b32 BPR or later).
    Defaults to the newest jre-8u*-windows-i586.exe beside this script, then C:\.
    Only needed when a 32-bit JRE is installed.

.PARAMETER ForceCloseJava
    Kill running java.exe / javaw.exe before installing. WARNING: this can
    interrupt a running production application. Default is to ABORT (exit 2)
    if Java is running, so a human decides.

.PARAMETER DryRun
    Report what would happen without changing anything.

.NOTES
    Deploy via Endpoint Central (SYSTEM). Logs: C:\Logs\CompoSecure.
    No reboot issued. Exit: 0 = updated or nothing to do / 2 = skipped
    (Java running) / 1 = failure.
#>

[CmdletBinding()]
param(
    [string]$InstallerPath = '',
    [string]$InstallerPathX86 = '',
    [switch]$ForceCloseJava,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$LogDir  = 'C:\Logs\CompoSecure'
# Concatenated, not Join-Path: Join-Path validates the drive qualifier, which
# makes this file impossible to dot-source for unit tests off Windows.
$LogFile = $LogDir + '\OracleJRE8Update_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log'

# KEEP THIS CURRENT: the "already at or above target" check EXITS 0, so a
# stale value makes this script silently do nothing on a host that is
# genuinely vulnerable. Observed on CSLT-136 (2026-08-26) with 8u491 against
# a stale 491 target, and again for plugin 371349 (2026-10-30), where 8u503
# hosts would have passed a 503 target. The build matters: 8u511 GA is
# vulnerable, 8u511 b32 (BPR) is the fix.
$TargetUpdate = 511
$TargetBuild  = 32

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

function ConvertTo-JavaVersion {
    # '8.0.5110.32' (java.exe / installer FileVersion) or '8.0.511.32'
    # (Tenable style) -> Update 511, Build 32. $null if not a Java 8 version.
    param([string]$Text)
    if ($Text -notmatch '^\s*8\.0\.(\d+)\.(\d+)') { return $null }
    $u = [int]$matches[1]
    if ($u -ge 1000) { $u = [int][math]::Floor($u / 10) }
    return [pscustomobject]@{ Update = $u; Build = [int]$matches[2] }
}

function Test-JavaAtTarget {
    # An unknown build at the target update counts as vulnerable: it may be GA.
    param($Version, [int]$TargetUpdate, [int]$TargetBuild)
    if ($null -eq $Version) { return $false }
    if ($Version.Update -gt $TargetUpdate) { return $true }
    if ($Version.Update -lt $TargetUpdate) { return $false }
    return ($null -ne $Version.Build -and $Version.Build -ge $TargetBuild)
}

function Get-JavaExeVersion {
    param([string]$JreDir)
    $exe = Join-Path $JreDir 'bin\java.exe'
    if (-not (Test-Path -LiteralPath $exe)) { return '' }
    return [string](Get-Item -LiteralPath $exe).VersionInfo.FileVersion
}

function Get-JreInventory {
    # jre1.8.0_NNN folders under one root, versioned from bin\java.exe; the
    # folder name is the fallback (build unknown).
    param([string]$Root)
    $out = @()
    if (-not (Test-Path -LiteralPath $Root)) { return $out }
    Get-ChildItem -LiteralPath $Root -Directory -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -match '^jre1\.8\.0_(\d+)$' } | ForEach-Object {
        $folderUpdate = [int]($_.Name -replace '^jre1\.8\.0_', '')
        $v = ConvertTo-JavaVersion -Text (Get-JavaExeVersion -JreDir $_.FullName)
        if ($v) {
            $out += [pscustomobject]@{ Name = $_.Name; Path = $_.FullName; Update = $v.Update; Build = $v.Build; Source = 'java.exe' }
        } else {
            $out += [pscustomobject]@{ Name = $_.Name; Path = $_.FullName; Update = $folderUpdate; Build = $null; Source = 'folder' }
        }
    }
    return $out
}

function Format-JavaVersion {
    param($Version)
    $b = if ($null -ne $Version.Build) { ' b' + $Version.Build } else { ' (build unknown)' }
    return ('8u' + $Version.Update + $b)
}

# Unit tests dot-source this file for the helpers above; stop before the run.
if ($env:ORACLEJAVA8_DOTSOURCE -eq '1') { return }

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$targetLabel = '8u' + $TargetUpdate + ' b' + $TargetBuild

$arches = @(
    @{ Arch = 'x64'; Root = 'C:\Program Files\Java';       Pattern = 'jre-8u*-windows-x64.exe';  Installer = $InstallerPath },
    @{ Arch = 'x86'; Root = 'C:\Program Files (x86)\Java'; Pattern = 'jre-8u*-windows-i586.exe'; Installer = $InstallerPathX86 }
)

Write-Log '=============================================='
Write-Log ' Oracle JRE 8 Update (v2) -- Plugins 371349 / 338352 / 329223'
Write-Log (' Host   : ' + $env:COMPUTERNAME)
Write-Log (' Target : ' + $targetLabel + ' (BPR) or later')
Write-Log (' DryRun : ' + $DryRun)
Write-Log '=============================================='
Write-Log 'SCOPE: production shopfloor (Pierce). Ensure Marvin/OT approval and'
Write-Log ('that the line application tolerates ' + $targetLabel + ' before proceeding.')

# ==============================================================
# 1. Inventory installed Oracle JRE 8 (64-bit and 32-bit)
# ==============================================================
Write-Log ''
Write-Log '[1/5] Inventorying installed Java 8 JREs...'
$needed = @()
foreach ($a in $arches) {
    $inv = @(Get-JreInventory -Root $a.Root)
    if ($inv.Count -eq 0) { Write-Log ('  ' + $a.Arch + ': no jre1.8.0_XXX folder under ' + $a.Root); continue }
    $old = @()
    foreach ($j in $inv) {
        $ok = Test-JavaAtTarget -Version $j -TargetUpdate $TargetUpdate -TargetBuild $TargetBuild
        $state = if ($ok) { 'OK' } else { 'VULNERABLE' }
        Write-Log ('  ' + $a.Arch + ': ' + $j.Name + '  ' + (Format-JavaVersion $j) + '  [' + $j.Source + ']  ' + $state)
        if (-not $ok) { $old += $j }
    }
    if ($old.Count -gt 0) { $needed += $a }
}
if ($needed.Count -eq 0) {
    Write-Log ('  Every installed Java 8 JRE is at ' + $targetLabel + ' or later. Nothing to do.')
    Write-Log '=============================================='
    exit 0
}

# ==============================================================
# 2. Resolve and check the staged installers
# ==============================================================
Write-Log ''
Write-Log '[2/5] Resolving staged installer(s)...'
$searchDirs = @()
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($scriptDir) { $searchDirs += $scriptDir }
$searchDirs += 'C:\'
foreach ($a in $needed) {
    if ([string]::IsNullOrWhiteSpace($a.Installer)) {
        foreach ($dir in $searchDirs) {
            $cand = Get-ChildItem -Path $dir -Filter $a.Pattern -ErrorAction SilentlyContinue |
                    Sort-Object Name -Descending | Select-Object -First 1
            if ($cand) { $a.Installer = $cand.FullName; break }
        }
    }
    if ([string]::IsNullOrWhiteSpace($a.Installer) -or -not (Test-Path $a.Installer)) {
        Write-Log ('  ' + $a.Arch + ' installer not found. Stage ' + ($a.Pattern -replace '\*', $TargetUpdate) + ' (' + $targetLabel + ' BPR)') -Level ERROR
        Write-Log '  beside this script or in C:\, or pass -InstallerPath / -InstallerPathX86.' -Level ERROR
        Write-Log '  (Oracle JRE 8 is not downloadable without an account, so this script will not fetch it.)' -Level ERROR
        exit 1
    }
    $iv = ConvertTo-JavaVersion -Text ([string](Get-Item -LiteralPath $a.Installer).VersionInfo.FileVersion)
    if ($null -eq $iv) {
        Write-Log ('  ' + $a.Arch + ' installer: ' + $a.Installer + '  (version unreadable -- verification after install decides)') -Level WARN
    } elseif (-not (Test-JavaAtTarget -Version $iv -TargetUpdate $TargetUpdate -TargetBuild $TargetBuild)) {
        Write-Log ('  ' + $a.Arch + ' installer ' + $a.Installer + ' is ' + (Format-JavaVersion $iv) + ', below ' + $targetLabel + '.') -Level ERROR
        Write-Log '  Installing it would leave the finding open. Stage the 8u511 b32 BPR' -Level ERROR
        Write-Log '  (My Oracle Support patch, not the public 8u511 GA download).' -Level ERROR
        exit 1
    } else {
        Write-Log ('  ' + $a.Arch + ' installer: ' + $a.Installer + '  (' + (Format-JavaVersion $iv) + ')')
    }
}

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
Write-Log '[4/5] Installing updated JRE(s)...'
# Oracle JRE 8 silent options:
#   /s                  silent
#   STATIC=0            normal (patch-in-place family) install
#   AUTO_UPDATE=0       no Oracle auto-updater
#   WEB_JAVA=0          disable browser plugin (hardening)
#   REMOVEOUTOFDATEJRES=1  remove older JRE folders (clears Tenable finding)
#   NOSTARTMENU=1 SPONSORS=0  no shortcuts / no sponsor offers
foreach ($a in $needed) {
    $installLog = $LogDir + '\jre_install_' + $a.Arch + '.log'
    $installArgs = '/s STATIC=0 AUTO_UPDATE=0 WEB_JAVA=0 REMOVEOUTOFDATEJRES=1 NOSTARTMENU=1 SPONSORS=0 /L "' + $installLog + '"'
    if ($DryRun) {
        Write-Log ('  [DRYRUN] ' + $a.Arch + ': would run ' + $a.Installer + ' ' + $installArgs)
        continue
    }
    Write-Log ('  ' + $a.Arch + ': ' + $a.Installer)
    $proc = Start-Process -FilePath $a.Installer -ArgumentList $installArgs -Wait -PassThru
    Write-Log ('  ' + $a.Arch + ' installer exit code: ' + $proc.ExitCode + '  (see ' + $installLog + ')')
    if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {
        Write-Log ('  ' + $a.Arch + ' install FAILED.') -Level ERROR
        exit 1
    }
}

# ==============================================================
# 5. Verify -- target present, no older 8u folders, per architecture
# ==============================================================
Write-Log ''
Write-Log '[5/5] Verification...'
if ($DryRun) {
    Write-Log '  [DRYRUN] Skipping verification.'
    Write-Log '=============================================='
    exit 0
}

Start-Sleep -Seconds 3
$bad = $false
foreach ($a in $needed) {
    $inv = @(Get-JreInventory -Root $a.Root)
    $haveTarget = $false
    $stillOld = @()
    foreach ($j in $inv) {
        if (Test-JavaAtTarget -Version $j -TargetUpdate $TargetUpdate -TargetBuild $TargetBuild) {
            $haveTarget = $true
            Write-Log ('  ' + $a.Arch + ': ' + $j.Name + '  ' + (Format-JavaVersion $j) + '  (OK)')
        } else {
            $stillOld += $j.Name
            Write-Log ('  ' + $a.Arch + ': ' + $j.Name + '  ' + (Format-JavaVersion $j) + '  (STILL VULNERABLE)') -Level ERROR
        }
    }
    if (-not $haveTarget) {
        Write-Log ('  ' + $a.Arch + ': ' + $targetLabel + '+ not present after install.') -Level ERROR
        $bad = $true
    }
    if ($stillOld.Count -gt 0) {
        Write-Log ('  ' + $a.Arch + ': old JRE folder(s) remain -- Tenable will still flag. If') -Level ERROR
        Write-Log '  REMOVEOUTOFDATEJRES did not clear them, an app may be pinning the folder;' -Level ERROR
        Write-Log '  remove manually after confirming nothing depends on it, or uninstall via its ARP entry.' -Level ERROR
        $bad = $true
    }
}
if ($bad) {
    Write-Log '=============================================='
    exit 1
}

Write-Log ('  ' + $targetLabel + '+ present and no vulnerable 8u folders remain.')
Write-Log '  Re-run a Nessus scan to confirm plugin 371349 clears.'
Write-Log '=============================================='
exit 0
