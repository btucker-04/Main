<#
.SYNOPSIS
    Updates every installed Notepad++ to the LATEST release. No pinned target.

.DESCRIPTION
    Clears the Notepad++ version findings, e.g. on swissqp-02 (2026-10-21):
      327203  Notepad++ < 8.9.7    Multiple Vulnerabilities
      318684  Notepad++ < 8.9.6.1  Multiple Vulnerabilities
      299664  Notepad++ < 8.9.2    Unsafe Search Path
    All three came back as RESURFACED: Update-ThirdPartyAppBundle.ps1 pins
    8.9.6.1, which cleared the older plugins until 327203 asked for 8.9.7.
    This script resolves the target at run time instead:
      1. -TargetVersion if given
      2. Where github.com/notepad-plus-plus/notepad-plus-plus/releases/latest
         redirects (/tag/v<ver>). The page redirect, not the REST API, so a
         fleet behind one egress IP does not hit the API rate limit.
      3. The newest staged installer beside this script, then in C:\
    Notepad++'s own update feed (getDownloadUrl.php) is NOT used: it answers
    NeedToBeUpdated=no for releases Tenable flags.

    Finds installs in C:\Program Files\Notepad++, C:\Program Files (x86)\
    Notepad++ and any Notepad++ uninstall entry's InstallLocation (both
    registry views; this works from the 32-bit EC agent). Each install is
    upgraded in place with the installer for ITS architecture (read from the
    notepad++.exe PE header), so an x86 install never gains an x64 twin.
    MSI-managed x64 installs get the release MSI; others the NSIS exe /S.

    Installers are checked before running: PE (or MSI) header and size, the
    SHA-256 in the release's npp.<ver>.checksums.sha256, and an Authenticode
    signature that is Valid with signer CN=NOTEPAD++. Any failure stops that
    install (a Zscaler block page or a tampered file is never executed).

    Running notepad++.exe defers the update (exit 2) and asks the user to
    close it, unless -ForceClose is passed. Notepad++ normally restores
    unsaved tabs from its session backup after a kill, but that is a user
    setting and not guaranteed.

    Success is judged by re-reading notepad++.exe's version after the
    installer, never by the installer's exit code.

.PARAMETER TargetVersion
    Explicit version (e.g. 8.9.8.1). Default: the latest GitHub release.

.PARAMETER ForceClose
    Kill running notepad++.exe before installing.

.PARAMETER DryRun
    Report what would be installed and change nothing (exit 2 if work is due).

.NOTES
    Deploy via Endpoint Central (SYSTEM, 32-bit agent OK). Bare switches only.
    Logs: C:\Logs\CompoSecure\NotepadPP_Update_<timestamp>.log
    Staged installers (offline/Zscaler): npp.<ver>.Installer.x64.exe,
    npp.<ver>.Installer.exe (x86), npp.<ver>.Installer.arm64.exe or
    npp.<ver>.Installer.x64.msi in Dependency Files or C:\.
    Exit: 0 = every install current (or none installed)
          2 = a human must look: deferred (running), not verified after
              install, dry run with work (EC success codes: 0,3010)
          1 = could not run: no target version, download, checksum or
              signature failed
#>

[CmdletBinding()]
param(
    [string]$TargetVersion = '',
    [switch]$ForceClose,
    [switch]$DryRun
)

$NppRepo       = 'https://github.com/notepad-plus-plus/notepad-plus-plus'
$InstallTimeoutMinutes = 10

# '8.9.7', 'v8.9.6.1', '8.9.8.1 ' -> [version] with four parts (8.9.7.0), so
# 8.9.7 and 8.9.7.0 compare equal. $null when it is not a version.
function ConvertTo-NppVersion {
    param([string]$Text)
    $t = ('' + $Text).Trim() -replace '^[vV]', ''
    if ($t -notmatch '^\d+(\.\d+){0,3}$') { return $null }
    $parts = @($t.Split('.') | ForEach-Object { [int]$_ })
    while ($parts.Count -lt 4) { $parts += 0 }
    return New-Object System.Version($parts[0], $parts[1], $parts[2], $parts[3])
}

# .../releases/tag/v8.9.8.1 -> '8.9.8.1'; '' otherwise.
function Get-VersionFromReleaseUrl {
    param([string]$Url)
    if (('' + $Url) -match '/releases/tag/v?(\d+(?:\.\d+){1,3})/?$') {
        $v = $Matches[1]
        return $v
    }
    return ''
}

# Release asset for an architecture: x64 / x86 / arm64, exe or msi.
function Get-NppAssetName {
    param([string]$Version, [string]$Arch, [string]$Kind = 'exe')
    if ($Kind -eq 'msi') { return 'npp.' + $Version + '.Installer.x64.msi' }
    switch ($Arch) {
        'x64'   { return 'npp.' + $Version + '.Installer.x64.exe' }
        'arm64' { return 'npp.' + $Version + '.Installer.arm64.exe' }
        'x86'   { return 'npp.' + $Version + '.Installer.exe' }
        default { throw ('Unknown architecture: ' + $Arch) }
    }
}

# IMAGE_FILE_HEADER.Machine -> architecture name; '' when unknown.
function ConvertFrom-PeMachine {
    param([int]$Machine)
    switch ($Machine) {
        0x8664  { return 'x64' }
        0xAA64  { return 'arm64' }
        0x014C  { return 'x86' }
        default { return '' }
    }
}

# Machine field of a PE file's bytes (at least the first 4 KB); -1 if not PE.
function Get-PeMachine {
    param([byte[]]$Bytes)
    if ($Bytes.Length -lt 64 -or $Bytes[0] -ne 0x4D -or $Bytes[1] -ne 0x5A) { return -1 }
    $peOff = [BitConverter]::ToInt32($Bytes, 0x3C)
    if ($peOff -lt 0 -or ($peOff + 6) -gt $Bytes.Length) { return -1 }
    if ($Bytes[$peOff] -ne 0x50 -or $Bytes[$peOff + 1] -ne 0x45) { return -1 }
    return [int][BitConverter]::ToUInt16($Bytes, $peOff + 4)
}

# SHA-256 for $Name from the text of npp.<ver>.checksums.sha256; '' if absent.
function Get-ChecksumForAsset {
    param([string]$ChecksumText, [string]$Name)
    foreach ($line in (('' + $ChecksumText) -split '\r?\n')) {
        if ($line -match '^\s*([0-9a-fA-F]{64})\s+\*?(.+?)\s*$') {
            $hash = $Matches[1]; $file = $Matches[2]
            if ($file -eq $Name) { return $hash.ToLowerInvariant() }
        }
    }
    return ''
}

# Invoke-WebRequest .Content is byte[] for GitHub release assets
# (application/octet-stream); '' + byte[] would give '97 53 51 ...'.
function ConvertTo-ResponseText {
    param($Content)
    if ($Content -is [byte[]]) { return [System.Text.Encoding]::UTF8.GetString($Content) }
    return '' + $Content
}

# Authenticode signer subject -> $true for the Notepad++ publisher certificate.
function Test-NppSigner {
    param([string]$Subject)
    return (('' + $Subject) -match '(^|,\s*)CN=NOTEPAD\+\+\s*(,|$)')
}

# Newest staged installer among $Names for $Arch/$Kind -> @(name, version) or $null.
function Select-StagedNppInstaller {
    param([string[]]$Names, [string]$Arch, [string]$Kind = 'exe')
    $best = $null; $bestName = ''; $bestText = ''
    foreach ($n in $Names) {
        if ($n -notmatch '^npp\.(\d+(?:\.\d+){1,3})\.Installer') { continue }
        $v = $Matches[1]
        if ($n -ne (Get-NppAssetName -Version $v -Arch $Arch -Kind $Kind)) { continue }
        $vo = ConvertTo-NppVersion $v
        if ($null -eq $best -or $vo -gt $best) { $best = $vo; $bestName = $n; $bestText = $v }
    }
    if ($null -eq $best) { return $null }
    return @($bestName, $bestText)
}

if ($env:NOTEPADPP_UPDATE_DOTSOURCE -eq '1') { return }

# -----------------------------------------------------------------------------
$ErrorActionPreference = 'Stop'
$LogDir  = 'C:\Logs\CompoSecure'
$LogFile = Join-Path $LogDir ('NotepadPP_Update_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$TempDir = Join-Path $env:WINDIR 'Temp\NotepadPP_Update'
$Q = [string][char]34

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}
$Issues = New-Object System.Collections.ArrayList
function Add-Issue {
    param([string]$Msg)
    [void]$Issues.Add($Msg)
    Write-Log ('  PROBLEM: ' + $Msg) -Level WARN
}
$Fatal = $false
$Deferred = $false

# msg.exe lives only in the 64-bit System32; a 32-bit agent must use Sysnative.
function Send-UserMessage {
    param([string]$Msg)
    foreach ($exe in @(($env:WINDIR + '\Sysnative\msg.exe'), ($env:WINDIR + '\System32\msg.exe'))) {
        if (Test-Path $exe) {
            try { & $exe '*' '/TIME:300' $Msg 2>$null | Out-Null } catch { }
            return
        }
    }
}

function Get-NppUninstallEntries {
    $out = @()
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
            $un = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
            if ($null -eq $un) { continue }
            foreach ($name in $un.GetSubKeyNames()) {
                $k = $un.OpenSubKey($name)
                if ($null -eq $k) { continue }
                $dn = '' + $k.GetValue('DisplayName')
                if ($dn -like 'Notepad++*') {
                    $out += [pscustomobject]@{
                        Key = $name; View = '' + $view; DisplayName = $dn
                        DisplayVersion = '' + $k.GetValue('DisplayVersion')
                        InstallLocation = ('' + $k.GetValue('InstallLocation')).Trim().TrimEnd('\')
                        UninstallString = '' + $k.GetValue('UninstallString')
                        IsMsi = (('' + $k.GetValue('WindowsInstaller')) -eq '1')
                    }
                }
                $k.Close()
            }
            $un.Close(); $base.Close()
        } catch {
            Write-Log ('  Could not read the ' + $view + ' uninstall keys: ' + $_) -Level WARN
        }
    }
    return $out
}

function Get-InstalledNppVersion {
    param([string]$Exe)
    try {
        $vi = (Get-Item -LiteralPath $Exe).VersionInfo
        return New-Object System.Version($vi.FileMajorPart, $vi.FileMinorPart, $vi.FileBuildPart, $vi.FilePrivatePart)
    } catch { return $null }
}

function Get-FileArch {
    param([string]$Path)
    try {
        $fs = [System.IO.File]::OpenRead($Path)
        $buf = New-Object byte[] 4096
        $n = $fs.Read($buf, 0, 4096)
        $fs.Close()
        if ($n -lt 64) { return '' }
        return ConvertFrom-PeMachine (Get-PeMachine $buf)
    } catch { return '' }
}

function Read-Head {
    param([string]$Path, [int]$Count)
    $fs = [System.IO.File]::OpenRead($Path)
    $buf = New-Object byte[] $Count
    $null = $fs.Read($buf, 0, $Count)
    $fs.Close()
    return ,$buf
}

function Invoke-Download {
    param([string]$Url, [string]$Dest)
    foreach ($attempt in 1..3) {
        try {
            Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing -TimeoutSec 300
            return $true
        } catch {
            Write-Log ('  Download attempt ' + $attempt + ' of 3 failed: ' + $_) -Level WARN
            Start-Sleep -Seconds 10
        }
    }
    return $false
}

function Invoke-Bounded {
    param([string]$Path, [string]$Arguments, [int]$TimeoutMinutes)
    Write-Log ('  Running: ' + $Path + ' ' + $Arguments)
    $p = Start-Process -FilePath $Path -ArgumentList $Arguments -NoNewWindow -PassThru
    $null = $p.Handle
    if (-not $p.WaitForExit($TimeoutMinutes * 60 * 1000)) {
        Write-Log ('  Still running after ' + $TimeoutMinutes + ' minutes; killing the installer tree.') -Level ERROR
        & ($env:WINDIR + '\System32\taskkill.exe') '/PID' $p.Id '/T' '/F' 2>&1 | Out-Null
        return $null
    }
    $p.WaitForExit()
    return $p.ExitCode
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Log '=============================================='
Write-Log ' Notepad++ Update -- latest release, every install'
Write-Log (' Host   : ' + $env:COMPUTERNAME)
Write-Log (' DryRun : ' + $DryRun + '   ForceClose : ' + $ForceClose)
Write-Log '=============================================='

# ==============================================================
# 1. Inventory
# ==============================================================
Write-Log ''
Write-Log '[1/5] Finding Notepad++ installs...'
$arp = @(Get-NppUninstallEntries)
foreach ($e in $arp) {
    Write-Log ('  Uninstall entry: ' + $e.DisplayName + '  ' + $e.DisplayVersion + '  (' + $e.View + ', MSI: ' + $e.IsMsi + ')  ' + $e.InstallLocation)
}
$dirs = @('C:\Program Files\Notepad++', 'C:\Program Files (x86)\Notepad++')
foreach ($e in $arp) { if ($e.InstallLocation) { $dirs += $e.InstallLocation } }
$seen = @{}
$Installs = @()
foreach ($d in $dirs) {
    $exe = Join-Path $d 'notepad++.exe'
    $key = $exe.ToLowerInvariant()
    if ($seen.ContainsKey($key) -or -not (Test-Path -LiteralPath $exe)) { continue }
    $seen[$key] = $true
    $ver = Get-InstalledNppVersion $exe
    $arch = Get-FileArch $exe
    $isMsi = $false
    foreach ($e in $arp) { if ($e.IsMsi -and $e.InstallLocation -and ((Join-Path $e.InstallLocation 'notepad++.exe').ToLowerInvariant() -eq $key)) { $isMsi = $true } }
    Write-Log ('  ' + $exe + '  ' + $ver + '  ' + $arch + $(if ($isMsi) { '  (MSI)' } else { '' }))
    if (-not $arch) { Add-Issue ($exe + ': could not read its architecture; not updated'); continue }
    if ($isMsi -and $arch -ne 'x64') { Add-Issue ($exe + ': MSI-managed ' + $arch + ' install; Notepad++ ships an MSI for x64 only. Update it by hand'); continue }
    $Installs += [pscustomobject]@{ Exe = $exe; Dir = $d; Version = $ver; Arch = $arch; IsMsi = $isMsi }
}
if ($Installs.Count -eq 0 -and $Issues.Count -eq 0) {
    Write-Log '  Notepad++ is not installed. Nothing to do.'
    if ($arp.Count -gt 0) { Write-Log '  (An uninstall entry exists without notepad++.exe; a rescan should drop the finding.)' -Level WARN }
    Write-Log '=============================================='
    exit 0
}

# ==============================================================
# 2. Target version
# ==============================================================
Write-Log ''
Write-Log '[2/5] Resolving the target version...'
$searchDirs = @()
if ($PSScriptRoot) { $searchDirs += $PSScriptRoot }
$searchDirs += 'C:\'
$searchDirs = @($searchDirs | Where-Object { Test-Path -LiteralPath $_ })
$stagedNames = @()
foreach ($sd in $searchDirs) {
    $stagedNames += @(Get-ChildItem -LiteralPath $sd -Filter 'npp.*.Installer*' -ErrorAction SilentlyContinue |
        Where-Object { -not $_.PSIsContainer } | ForEach-Object { $_.Name })
}

$targetSource = ''
if ($TargetVersion) {
    $targetSource = 'explicit -TargetVersion'
} else {
    try {
        $req = [System.Net.HttpWebRequest]::Create($NppRepo + '/releases/latest')
        $req.Method = 'HEAD'
        $req.AllowAutoRedirect = $false
        $req.Timeout = 30000
        $req.UserAgent = 'CompoSecure-Remediation'
        $resp = $req.GetResponse()
        $loc = '' + $resp.Headers['Location']
        $resp.Close()
        $TargetVersion = Get-VersionFromReleaseUrl $loc
        if ($TargetVersion) { $targetSource = 'latest GitHub release' }
        else { Write-Log ('  Unexpected redirect from releases/latest: ' + $loc) -Level WARN }
    } catch {
        Write-Log ('  Could not reach ' + $NppRepo + '/releases/latest: ' + $_) -Level WARN
    }
    if (-not $TargetVersion) {
        $best = $null
        foreach ($i in $Installs) {
            $kind = $(if ($i.IsMsi) { 'msi' } else { 'exe' })
            $pick = Select-StagedNppInstaller -Names $stagedNames -Arch $i.Arch -Kind $kind
            if ($pick -and ($null -eq $best -or (ConvertTo-NppVersion $pick[1]) -gt (ConvertTo-NppVersion $best))) { $best = $pick[1] }
        }
        if ($best) { $TargetVersion = $best; $targetSource = 'newest staged installer (GitHub unreachable)' }
    }
}
$targetObj = ConvertTo-NppVersion $TargetVersion
if ($null -eq $targetObj) {
    Write-Log '  No target version: GitHub unreachable and no staged installer.' -Level ERROR
    Write-Log '  Stage npp.<ver>.Installer.x64.exe beside this script or in C:\, or pass -TargetVersion.' -Level ERROR
    Write-Log '=============================================='
    exit 1
}
$TargetVersion = ('' + $TargetVersion).Trim() -replace '^[vV]', ''
Write-Log ('  Target: ' + $TargetVersion + '  (' + $targetSource + ')')

$Outdated = @($Installs | Where-Object { $null -eq $_.Version -or $_.Version -lt $targetObj })
foreach ($i in $Installs) {
    if ($Outdated -notcontains $i) { Write-Log ('  Current: ' + $i.Exe + '  ' + $i.Version) }
}

if ($Outdated.Count -gt 0) {
    # ==========================================================
    # 3. Running?
    # ==========================================================
    Write-Log ''
    Write-Log '[3/5] Is Notepad++ running?'
    $procs = @(Get-Process -Name 'notepad++' -ErrorAction SilentlyContinue)
    $proceed = $true
    if ($procs.Count -eq 0) {
        Write-Log '  Not running.'
    } elseif (-not $ForceClose) {
        Write-Log ('  RUNNING (PID ' + (($procs | ForEach-Object { $_.Id }) -join ', ') + ').') -Level WARN
        Add-Issue 'Notepad++ is running; update deferred so no unsaved work is lost. Re-run when it is closed, or pass -ForceClose'
        if (-not $DryRun) { Send-UserMessage 'IT Security: please save your work and close Notepad++ so a security update can install. It will be retried automatically.' }
        $proceed = $false; $Deferred = $true
    } elseif ($DryRun) {
        Write-Log '  RUNNING. [DRYRUN] Would force-close it.'
    } else {
        Write-Log '  RUNNING. -ForceClose: stopping notepad++.exe' -Level WARN
        $procs | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        if (@(Get-Process -Name 'notepad++' -ErrorAction SilentlyContinue).Count -gt 0) {
            Add-Issue 'Notepad++ would not close; not updated'
            $proceed = $false; $Deferred = $true
        }
    }

    # ==========================================================
    # 4. Get, check and run the installer for each outdated install
    # ==========================================================
    if ($proceed) {
        Write-Log ''
        Write-Log '[4/5] Installing...'
        if (-not (Test-Path $TempDir)) { New-Item -ItemType Directory -Path $TempDir -Force | Out-Null }
        $checksums = $null
        foreach ($i in $Outdated) {
            $kind = $(if ($i.IsMsi) { 'msi' } else { 'exe' })
            $asset = Get-NppAssetName -Version $TargetVersion -Arch $i.Arch -Kind $kind
            Write-Log ('  ' + $i.Exe + '  ' + $i.Version + ' -> ' + $TargetVersion + '  (' + $asset + ')')
            if ($DryRun) {
                Add-Issue ('DRYRUN: would install ' + $asset + ' for ' + $i.Exe)
                continue
            }
            $installer = ''
            $downloaded = $false
            foreach ($sd in $searchDirs) {
                $cand = Join-Path $sd $asset
                if (Test-Path -LiteralPath $cand) { $installer = $cand; Write-Log ('  Staged installer: ' + $cand); break }
            }
            if (-not $installer) {
                $url = $NppRepo + '/releases/download/v' + $TargetVersion + '/' + $asset
                $installer = Join-Path $TempDir $asset
                Write-Log ('  Downloading ' + $url)
                if (-not (Invoke-Download -Url $url -Dest $installer)) {
                    Write-Log '  Download failed. If Zscaler blocks github.com, stage the installer and re-run.' -Level ERROR
                    $Fatal = $true; continue
                }
                $downloaded = $true
            }

            $item = Get-Item -LiteralPath $installer
            $head = Read-Head -Path $installer -Count 8
            $isMsiFile = ($head[0] -eq 0xD0 -and $head[1] -eq 0xCF -and $head[2] -eq 0x11 -and $head[3] -eq 0xE0)
            $isExeFile = ($head[0] -eq 0x4D -and $head[1] -eq 0x5A)
            $okHeader = $(if ($kind -eq 'msi') { $isMsiFile } else { $isExeFile })
            Write-Log ('  ' + [math]::Round($item.Length / 1MB, 1) + ' MB, header OK: ' + $okHeader)
            if (-not $okHeader -or $item.Length -lt 2MB) {
                Write-Log '  Not a real installer (block page?). Not running it.' -Level ERROR
                if ($downloaded) { Remove-Item -LiteralPath $installer -Force -ErrorAction SilentlyContinue }
                $Fatal = $true; continue
            }

            if ($null -eq $checksums) {
                $checksums = ''
                $sumUrl = $NppRepo + '/releases/download/v' + $TargetVersion + '/npp.' + $TargetVersion + '.checksums.sha256'
                try { $checksums = ConvertTo-ResponseText (Invoke-WebRequest -Uri $sumUrl -UseBasicParsing -TimeoutSec 60).Content }
                catch { Write-Log ('  Could not read ' + $sumUrl + ': ' + $_) -Level WARN }
            }
            $want = Get-ChecksumForAsset -ChecksumText $checksums -Name $asset
            $got = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($want) {
                if ($got -ne $want) {
                    Write-Log ('  SHA-256 MISMATCH: ' + $got + ' (release lists ' + $want + '). Not running it.') -Level ERROR
                    if ($downloaded) { Remove-Item -LiteralPath $installer -Force -ErrorAction SilentlyContinue }
                    $Fatal = $true; continue
                }
                Write-Log '  SHA-256 matches the release checksum file.'
            } else {
                Write-Log ('  No release checksum available (SHA-256 ' + $got + '); relying on the signature.') -Level WARN
            }

            $sigStatus = 'Error'; $subject = ''
            try {
                $sig = Get-AuthenticodeSignature -LiteralPath $installer
                $sigStatus = '' + $sig.Status
                if ($sig.SignerCertificate) { $subject = $sig.SignerCertificate.Subject }
            } catch {
                Write-Log ('  Signature check failed to run: ' + $_) -Level ERROR
            }
            Write-Log ('  Signature: ' + $sigStatus + '  ' + $subject)
            if ($sigStatus -ne 'Valid' -or -not (Test-NppSigner $subject)) {
                Write-Log '  Not validly signed by NOTEPAD++. Not running it.' -Level ERROR
                if ($downloaded) { Remove-Item -LiteralPath $installer -Force -ErrorAction SilentlyContinue }
                $Fatal = $true; continue
            }

            if ($kind -eq 'msi') {
                $msiLog = Join-Path $LogDir 'msi_notepadpp_install.log'
                $msiArgs = '/i ' + $Q + $installer + $Q + ' /qn /norestart /l*v ' + $Q + $msiLog + $Q
                $code = Invoke-Bounded -Path ($env:WINDIR + '\System32\msiexec.exe') -Arguments $msiArgs -TimeoutMinutes $InstallTimeoutMinutes
            } else {
                # NSIS: /D= must be last and unquoted; it keeps the install where it is.
                $code = Invoke-Bounded -Path $installer -Arguments ('/S /D=' + $i.Dir) -TimeoutMinutes $InstallTimeoutMinutes
            }
            if ($null -eq $code) { Write-Log '  Installer exit code: UNKNOWN (timed out)' -Level WARN }
            else { Write-Log ('  Installer exit code: ' + $code + '  (judged by the version re-read, not this code)') }
            if ($downloaded) { Remove-Item -LiteralPath $installer -Force -ErrorAction SilentlyContinue }
        }
    }
}

# ==============================================================
# 5. Verify by re-reading every install
# ==============================================================
Write-Log ''
Write-Log '[5/5] Verification...'
if (-not $DryRun) { Start-Sleep -Seconds 3 }
foreach ($i in $Installs) {
    $now = Get-InstalledNppVersion $i.Exe
    if ($null -eq $now) {
        Add-Issue ($i.Exe + ' is missing or unreadable after the run')
    } elseif ($now -lt $targetObj) {
        Write-Log ('  ' + $i.Exe + '  ' + $now + '  BELOW ' + $TargetVersion)
        if (-not $DryRun -and -not $Deferred) {
            Add-Issue ($i.Exe + ' is ' + $now + ' after this run, not ' + $TargetVersion)
        }
    } else {
        Write-Log ('  ' + $i.Exe + '  ' + $now + '  OK')
    }
}
foreach ($e in @(Get-NppUninstallEntries)) {
    Write-Log ('  Uninstall entry now: ' + $e.DisplayName + '  ' + $e.DisplayVersion + '  (' + $e.View + ')')
}

Write-Log ''
if ($Fatal) {
    Write-Log 'Problems:'
    foreach ($m in $Issues) { Write-Log ('  - ' + $m) }
    Write-Log 'RESULT: could not install Notepad++ (download, checksum or signature failed; see above).' -Level ERROR
    Write-Log '=============================================='
    exit 1
}
if ($Issues.Count -gt 0) {
    Write-Log 'Problems:'
    foreach ($m in $Issues) { Write-Log ('  - ' + $m) }
    Write-Log 'RESULT: Notepad++ NOT fully updated (see Problems).' -Level WARN
    Write-Log '=============================================='
    exit 2
}
if ($Outdated.Count -gt 0) {
    Write-Log ('RESULT: every Notepad++ install is now ' + $TargetVersion + ' or later. Rescan to confirm the findings clear.')
} else {
    Write-Log ('RESULT: every Notepad++ install is already ' + $TargetVersion + ' or later.')
}
Write-Log '=============================================='
exit 0
