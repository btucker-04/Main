<#
.SYNOPSIS
    Updates Oracle Java SE 8 JRE (64-bit and 32-bit) to 8u511 b33 or later.
    Nessus plugin 372933 (CVE-2026-114820) and 371349 (CVE-2026-91403 Security
    Alert); also clears the older 338352 / 329223 / 309197 findings.

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

    v3 (2026-11-03, CSLT-136): the minimum is 8u511 b33 (Oracle, 2026-10-24;
    security baseline 1.8.0_511-b33). b33 fixes CVE-2026-114820, which
    Oracle lists as affecting b32, and plugin 372933 flags anything below
    8u511-b33. Plugin 371349 (last updated 2026-10-23, before b33 shipped)
    still names b32 and flags 8.0.511.33 on CSLT-136; that is a stale plugin,
    not a reason to downgrade. An older build of the target update (GA, b31,
    b32) is uninstalled (msiexec /x, product code from Add/Remove Programs,
    both registry views) before the installer runs, because every 8u511 build
    shares the jre1.8.0_511 folder and product code and the installer cannot
    replace it in place.

.PARAMETER InstallerPath
    Full path to the 64-bit jre-8u511-windows-x64.exe (b33 or later; file version 8.0.5110.33).
    Defaults to the newest jre-8u*-windows-x64.exe beside this script, then C:\.

.PARAMETER InstallerPathX86
    Full path to the 32-bit jre-8u511-windows-i586.exe (b33 or later; file version 8.0.5110.33).
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
# vulnerable, b32 fixed CVE-2026-91403, and b33 also fixes CVE-2026-114820.
$TargetUpdate = 511
$TargetBuild  = 33

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

function Test-NeedsSameUpdateRemoval {
    # Every build of one update shares the jre1.8.0_NNN folder and the MSI product
    # code, so the installer cannot replace an older build of the target update in
    # place. That install has to be removed first.
    param($Version, [int]$TargetUpdate, [int]$TargetBuild)
    if ($null -eq $Version -or $Version.Update -ne $TargetUpdate) { return $false }
    return -not (Test-JavaAtTarget -Version $Version -TargetUpdate $TargetUpdate -TargetBuild $TargetBuild)
}

function Select-JavaArpEntry {
    # The Add/Remove Programs entry for one JRE folder: InstallLocation match first,
    # then display name + architecture when InstallLocation is blank.
    param($Entries, [string]$JrePath, [int]$Update, [string]$Arch)
    $want = $JrePath.TrimEnd('\').ToLowerInvariant()
    foreach ($e in @($Entries)) {
        if (-not $e.ProductCode) { continue }
        $loc = ('' + $e.InstallLocation).TrimEnd('\').ToLowerInvariant()
        if ($loc -and $loc -eq $want) { return $e }
    }
    foreach ($e in @($Entries)) {
        if (-not $e.ProductCode -or ('' + $e.InstallLocation)) { continue }
        if ($e.DisplayName -notmatch ('^Java 8 Update ' + $Update + '(\s|$)')) { continue }
        $is64 = $e.DisplayName -match '\(64-bit\)'
        if (($Arch -eq 'x64') -eq $is64) { return $e }
    }
    return $null
}

function Get-JavaArpEntries {
    # Both registry views: the EC agent is 32-bit, and the 64-bit JRE registers only
    # in the 64-bit view.
    $out = @()
    $sub = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
        try { $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view) } catch { continue }
        $root = $base.OpenSubKey($sub)
        if (-not $root) { continue }
        foreach ($name in $root.GetSubKeyNames()) {
            $k = $root.OpenSubKey($name)
            if (-not $k) { continue }
            $dn = '' + $k.GetValue('DisplayName')
            if ($dn -match '^Java 8 Update \d+') {
                $pc = if ($name -match '^\{[0-9A-Fa-f-]{36}\}$') { $name } else { $null }
                $out += [pscustomobject]@{ DisplayName = $dn; DisplayVersion = '' + $k.GetValue('DisplayVersion'); InstallLocation = '' + $k.GetValue('InstallLocation'); ProductCode = $pc; View = '' + $view }
            }
            $k.Close()
        }
        $root.Close()
    }
    return $out
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
    @{ Arch = 'x64'; Root = 'C:\Program Files\Java';       Pattern = 'jre-8u*-windows-x64.exe';  Installer = $InstallerPath;    Remove = @() },
    @{ Arch = 'x86'; Root = 'C:\Program Files (x86)\Java'; Pattern = 'jre-8u*-windows-i586.exe'; Installer = $InstallerPathX86; Remove = @() }
)

Write-Log '=============================================='
Write-Log ' Oracle JRE 8 Update (v3) -- Plugins 372933 / 371349 / 338352 / 329223'
Write-Log (' Host   : ' + $env:COMPUTERNAME)
Write-Log (' Target : ' + $targetLabel + ' or later')
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
        if (Test-NeedsSameUpdateRemoval -Version $j -TargetUpdate $TargetUpdate -TargetBuild $TargetBuild) {
            Write-Log ('  ' + $a.Arch + ': ' + $j.Name + ' is an older build of the target update; it must be uninstalled before ' + $targetLabel + ' can install.') -Level WARN
            $a.Remove += $j
        }
    }
    if ($old.Count -gt 0) { $needed += $a }
}
if ($needed.Count -eq 0) {
    Write-Log ('  Every installed Java 8 JRE is ' + $targetLabel + ' or a later update. Nothing to do.')
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
        Write-Log ('  ' + $a.Arch + ' installer not found. Stage ' + ($a.Pattern -replace '\*', $TargetUpdate) + ' (' + $targetLabel + ')') -Level ERROR
        Write-Log '  beside this script or in C:\, or pass -InstallerPath / -InstallerPathX86.' -Level ERROR
        Write-Log '  (Oracle JRE 8 is not downloadable without an account, so this script will not fetch it.)' -Level ERROR
        exit 1
    }
    $iv = ConvertTo-JavaVersion -Text ([string](Get-Item -LiteralPath $a.Installer).VersionInfo.FileVersion)
    if ($null -eq $iv) {
        Write-Log ('  ' + $a.Arch + ' installer: ' + $a.Installer + '  (version unreadable -- verification after install decides)') -Level WARN
    } elseif (-not (Test-JavaAtTarget -Version $iv -TargetUpdate $TargetUpdate -TargetBuild $TargetBuild)) {
        Write-Log ('  ' + $a.Arch + ' installer ' + $a.Installer + ' is ' + (Format-JavaVersion $iv) + ', below ' + $targetLabel + '.') -Level ERROR
        Write-Log ('  Installing it would leave plugin 372933 open (CVE-2026-114820 affects b32). Stage ' + $targetLabel + ' or later:') -Level ERROR
        Write-Log ('  the installer file version must read 8.0.' + $TargetUpdate + '0.' + $TargetBuild + ' or higher.') -Level ERROR
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
    if ($a.Remove.Count -gt 0) {
        $arp = @(Get-JavaArpEntries)
        foreach ($j in $a.Remove) {
            $e = Select-JavaArpEntry -Entries $arp -JrePath $j.Path -Update $j.Update -Arch $a.Arch
            if (-not $e) {
                Write-Log ('  ' + $a.Arch + ': no Add/Remove Programs entry with a product code for ' + $j.Path + '.') -Level ERROR
                Write-Log ('  Uninstall Java 8 Update ' + $j.Update + ' (' + (Format-JavaVersion $j) + ') by hand, then re-run. Nothing was changed.') -Level ERROR
                exit 1
            }
            $uLog = $LogDir + '\jre_uninstall_' + $a.Arch + '_' + $j.Update + '.log'
            $q = [string][char]34
            $uArgs = '/x ' + $e.ProductCode + ' /qn /norestart /L*v ' + $q + $uLog + $q
            if ($DryRun) {
                Write-Log ('  [DRYRUN] ' + $a.Arch + ': would uninstall ' + $e.DisplayName + ' ' + $e.DisplayVersion + ' (' + $e.ProductCode + ') first')
                continue
            }
            Write-Log ('  ' + $a.Arch + ': uninstalling ' + $e.DisplayName + ' ' + $e.DisplayVersion + ' (' + $e.ProductCode + ') so ' + $targetLabel + ' can install into ' + $j.Name) -Level WARN
            Write-Log ('  Java ' + $j.Update + ' (' + $a.Arch + ') is absent until the install below finishes.') -Level WARN
            $msiexec = $env:WINDIR + '\System32\msiexec.exe'
            $up = Start-Process -FilePath $msiexec -ArgumentList $uArgs -Wait -PassThru -NoNewWindow
            Write-Log ('  uninstall exit code: ' + $up.ExitCode + '  (see ' + $uLog + ')')
            Start-Sleep -Seconds 3
            $leftVersion = ConvertTo-JavaVersion -Text (Get-JavaExeVersion -JreDir $j.Path)
            if ($leftVersion -and $leftVersion.Build -eq $j.Build) {
                Write-Log ('  ' + $j.Path + ' is still ' + (Format-JavaVersion $leftVersion) + ' after uninstall. Not installing over it.') -Level ERROR
                exit 1
            }
        }
    }
    if ($DryRun) {
        Write-Log ('  [DRYRUN] ' + $a.Arch + ': would run ' + $a.Installer + ' ' + $installArgs)
        continue
    }
    Write-Log ('  ' + $a.Arch + ': ' + $a.Installer)
    $proc = Start-Process -FilePath $a.Installer -ArgumentList $installArgs -Wait -PassThru
    Write-Log ('  ' + $a.Arch + ' installer exit code: ' + $proc.ExitCode + '  (see ' + $installLog + ')')
    if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {
        Write-Log ('  ' + $a.Arch + ' install FAILED.') -Level ERROR
        if ($a.Remove.Count -gt 0) {
            Write-Log ('  The older 8u' + $TargetUpdate + ' build was already uninstalled, so this host has no ' + $a.Arch + ' Java 8u' + $TargetUpdate + ' now. Re-run promptly.') -Level ERROR
        }
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
        Write-Log ('  ' + $a.Arch + ': ' + $targetLabel + ' (or a later update) not present after install.') -Level ERROR
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

Write-Log ('  ' + $targetLabel + ' (or a later update) present and no vulnerable 8u folders remain.')
Write-Log '  Re-run a Nessus scan to confirm plugin 372933 clears. Plugin 371349 may still'
Write-Log ('  flag ' + $targetLabel + ' until Tenable updates it past b32; that finding is stale, do not downgrade.')
Write-Log '=============================================='
exit 0
