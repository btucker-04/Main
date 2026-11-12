<#
.SYNOPSIS
    Updates every python.org Python on the machine to the newest Windows
    build of its own branch (3.13.x stays 3.13.x). Machine-wide installs are
    upgraded now; per-user installs are staged to run as that user at their
    next sign-in. Nessus plugin 373609. (v1)

.DESCRIPTION
    Written for the 2026-11-12 group export of plugin 373609 (17 hosts):
      C:\Program Files\Python313\python.exe                          3.13.2
      C:\Python314\python.exe                                         3.14.6
      C:\Users\cgolm\AppData\Local\Programs\Python\Python314\python.exe 3.14.0
      C:\Users\aasamoah\AppData\Local\Python\pythoncore-3.14-64\python.exe 3.14.6
      C:\Python27\python.exe                                          2.7.6150
      E:\Python38\python.exe                                          3.12.10

    WINDOWS BUILDS STOP BEFORE THE FIXED VERSION ON OLDER BRANCHES. Once a
    branch enters security-only support, python.org publishes its releases as
    source only. On 2026-11-12 the newest Windows builds were 3.11.9, 3.12.10
    and 3.13.17, while the plugin wants 3.11.18 / 3.12.16 / 3.13.18. This
    script still moves such a copy to the newest Windows build of its branch
    (fewer open CVEs), then HOLDS it (exit 2): the finding only clears by
    moving that copy to a newer Python, which can break the user's virtual
    environments and installed packages, so it is a decision for a human.
    3.14 and 3.15 have Windows builds of their fixed versions.

    Targets come from https://www.python.org/ftp/python/index-windows.json
    (the feed the Python install manager uses): the newest final release
    with an id of pythoncore-<branch>-<64|32|arm64>. The newest release of
    any kind on a branch comes from the https://www.python.org/ftp/python/
    directory listing. No version is pinned here.

    What each copy gets:
      * Machine-wide python.org install (registered under
        HKLM\SOFTWARE\Python\PythonCore\<branch>): the python.org installer
        for the target runs now as SYSTEM, /quiet InstallAllUsers=1 into the
        same folder, and the version is re-read from python.exe afterwards.
      * Per-user python.org install (%LOCALAPPDATA%\Programs\Python\Python3xx):
        the installer is downloaded and signature-checked now, and a RunOnce
        entry in that user's hive runs it AS THAT USER, InstallAllUsers=0, at
        their next sign-in. SYSTEM cannot run a per-user installer for them.
      * Python install manager runtime (%LOCALAPPDATA%\Python\pythoncore-*):
        RunOnce runs 'pymanager install --update --yes' as that user.
      * End-of-life branch (2.7, 3.10, ...), or a copy no installer owns (no
        PythonCore registration, e.g. one bundled with an application):
        reported and left alone.
    A copy with a python process running from its folder is skipped unless
    -ForceClose is given.

    Downloads must start with MZ and carry a valid Authenticode signature from
    the Python Software Foundation, so a proxy block page is never run.

.PARAMETER ForceClose
    Stop python processes running from a machine-wide copy's folder before
    upgrading it. WARNING: interrupts scripts and services using it.

.PARAMETER DryRun
    Report every copy and the planned action; change nothing.

.NOTES
    Deploy via Endpoint Central (SYSTEM). Bare switches only.
    Configure EC 'Specify exit code(s)' as 0,3010.
    Logs: C:\Logs\CompoSecure\PythonUpdate_*.log; installer logs beside it.
    Per-user installers are kept in C:\ProgramData\CompoSecure\Python until
    the user signs in. Re-running the script reports whether they ran.
    Exit: 0 = every copy on the newest Windows build of a supported branch
          3010 = as 0, and an installer asked for a reboot
          2 = something needs a human or a sign-in: an update staged for
              next sign-in, a branch whose fixed version has no Windows build,
              an end-of-life or unowned copy, or a copy in use
          1 = could not run (feed unreachable) or an upgrade failed
#>

[CmdletBinding()]
param(
    [switch]$ForceClose,
    [switch]$DryRun
)

$IndexUrl   = 'https://www.python.org/ftp/python/index-windows.json'
$ListingUrl = 'https://www.python.org/ftp/python/'
$FtpBase    = 'https://www.python.org/ftp/python/'

# End of support per branch (python.org release status, five years from x.y.0).
$PythonEol = @{
    '3.9'  = '2025-10-31'
    '3.10' = '2026-10-31'
    '3.11' = '2027-10-31'
    '3.12' = '2028-10-31'
    '3.13' = '2029-10-31'
    '3.14' = '2030-10-31'
    '3.15' = '2031-10-31'
}

# python.exe FILEVERSION is major, minor, micro*1000 + level*10 + serial, api:
# 3.13.2150.1013 is 3.13.2 final, and Tenable's '2.7.6150' is 2.7.6.
# A ProductVersion such as '3.13.2' passes through unchanged.
function ConvertTo-PythonVersion {
    param([string]$Text)
    $m = [regex]::Match(('' + $Text), '^\s*(\d+)\.(\d+)\.(\d+)')
    if (-not $m.Success) { return $null }
    $major = [int]$m.Groups[1].Value
    $minor = [int]$m.Groups[2].Value
    $micro = [int]$m.Groups[3].Value
    if ($micro -ge 1000) { $micro = [int][math]::Floor($micro / 1000) }
    return [version]('' + $major + '.' + $minor + '.' + $micro)
}

function Get-PythonBranch {
    param([version]$Version)
    return ('' + $Version.Major + '.' + $Version.Minor)
}

# IMAGE_FILE_HEADER.Machine -> the python.org architecture name.
function ConvertTo-PythonArch {
    param([int]$PeMachine)
    switch ($PeMachine) {
        0x8664  { return 'amd64' }
        0x014C  { return 'win32' }
        0xAA64  { return 'arm64' }
        default { return '' }
    }
}

# How a python.exe got there, from its path. 'Machine' still needs a
# PythonCore registration to count as installer-owned.
function Get-PythonCopyKind {
    param([string]$Path)
    if ($Path -match '(?i)^[a-z]:\\Users\\[^\\]+\\AppData\\Local\\Python\\pythoncore-[^\\]+\\python\.exe$') { return 'PyManager' }
    if ($Path -match '(?i)^[a-z]:\\Users\\[^\\]+\\AppData\\Local\\Programs\\Python\\Python\d+(-32|-arm64)?\\python\.exe$') { return 'UserInstaller' }
    if ($Path -match '(?i)^[a-z]:\\Users\\') { return 'Unmanaged' }
    return 'Machine'
}

function Get-ProfileFolder {
    param([string]$Path)
    $m = [regex]::Match($Path, '(?i)^([a-z]:\\Users\\[^\\]+)\\')
    if ($m.Success) { return $m.Groups[1].Value }
    return ''
}

# Newest final release with a Windows build for $Branch / $Arch, from the
# install manager feed. '' when the feed has none (end-of-life branches).
function Get-NewestWindowsBuild {
    param([string]$IndexJson, [string]$Branch, [string]$Arch)
    $suffix = @{ amd64 = '64'; win32 = '32'; arm64 = 'arm64' }[$Arch]
    if (-not $suffix) { return '' }
    $id = 'pythoncore-' + $Branch + '-' + $suffix
    $best = $null
    foreach ($v in @(($IndexJson | ConvertFrom-Json).versions)) {
        if (('' + $v.id) -ne $id) { continue }
        $sv = '' + $v.'sort-version'
        if ($sv -notmatch '^\d+\.\d+\.\d+$') { continue }
        $vo = [version]$sv
        if ($null -eq $best -or $vo -gt $best) { $best = $vo }
    }
    if ($null -eq $best) { return '' }
    return $best.ToString()
}

# Newest x.y.z directory for $Branch in the python.org/ftp/python/ listing,
# source-only releases included.
function Get-NewestRelease {
    param([string]$ListingHtml, [string]$Branch)
    $best = $null
    $pattern = 'href=.(' + [regex]::Escape($Branch) + '\.\d+)/'
    foreach ($m in [regex]::Matches(('' + $ListingHtml), $pattern)) {
        $vo = [version]$m.Groups[1].Value
        if ($null -eq $best -or $vo -gt $best) { $best = $vo }
    }
    if ($null -eq $best) { return '' }
    return $best.ToString()
}

function Test-BranchEol {
    param([string]$Branch, [datetime]$Today)
    $v = [version]($Branch + '.0')
    if ($v.Major -lt 3 -or ($v.Major -eq 3 -and $v.Minor -lt 9)) { return $true }
    $d = $PythonEol[$Branch]
    if (-not $d) { return $false }
    return ($Today -gt [datetime]$d)
}

# Action for one copy: Current, Update or Hold. Update can also carry a hold
# reason (SourceOnly) for after the update.
function Get-PythonCopyPlan {
    param([version]$Installed, [string]$Kind, [string]$NewestBuild,
          [string]$NewestRelease, [datetime]$Today)
    $branch = Get-PythonBranch $Installed
    $plan = [pscustomobject]@{ Action = 'Current'; Target = ''; SourceOnly = $false; Reason = '' }
    if (Test-BranchEol -Branch $branch -Today $Today) {
        $eol = $PythonEol[$branch]
        if (-not $eol) { $eol = 'long ago' }
        $plan.Action = 'Hold'
        $plan.Reason = 'Python ' + $branch + ' is end-of-life (' + $eol + '); no fixed release will come. Move to a supported Python or remove it.'
        return $plan
    }
    if ($Kind -eq 'Unmanaged') {
        $plan.Action = 'Hold'
        $plan.Reason = 'No Python installer owns this copy (no PythonCore registration); it is likely bundled with an application. Update or remove it through that application.'
        return $plan
    }
    if (-not $NewestBuild) {
        $plan.Action = 'Hold'
        $plan.Reason = 'python.org lists no Windows build for Python ' + $branch + '.'
        return $plan
    }
    $build = [version]$NewestBuild
    if ($NewestRelease -and ([version]$NewestRelease -gt $build)) {
        $plan.SourceOnly = $true
        $plan.Reason = 'python.org released ' + $NewestRelease + ' as source only; Windows builds of ' + $branch + ' stop at ' + $NewestBuild + '. A scanner that wants ' + $NewestRelease + ' keeps flagging this copy until it moves to a newer Python.'
    }
    if ($Installed -lt $build) {
        $plan.Action = 'Update'
        $plan.Target = $NewestBuild
    } elseif ($plan.SourceOnly) {
        $plan.Action = 'Hold'
    }
    return $plan
}

function Get-InstallerFileName {
    param([string]$Version, [string]$Arch)
    if ($Arch -eq 'win32') { return 'python-' + $Version + '.exe' }
    return 'python-' + $Version + '-' + $Arch + '.exe'
}

function Test-PsfSignature {
    param([string]$Status, [string]$Subject)
    return ($Status -eq 'Valid' -and ('' + $Subject) -match 'Python Software Foundation')
}

# RunOnce command lines. cmd.exe expands %TEMP% in the user's own context;
# with more than two quotes it strips only the outermost pair.
function Get-UserInstallerCommand {
    param([string]$InstallerPath, [string]$TargetDir, [string]$Version)
    $q = [char]34
    return 'cmd.exe /c ' + $q + $q + $InstallerPath + $q + ' /quiet InstallAllUsers=0 TargetDir=' + $q + $TargetDir + $q +
        ' /log ' + $q + '%TEMP%\CompoSecure_Python_' + $Version + '.log' + $q + $q
}

function Get-PyManagerCommand {
    $q = [char]34
    return 'cmd.exe /c ' + $q + 'pymanager install --update --yes > ' + $q + '%TEMP%\CompoSecure_PythonManager.log' + $q + ' 2>&1' + $q
}

function Get-PythonInstallerExitMeaning {
    param($Code)
    if ($null -eq $Code) { return 'UNKNOWN (Windows reported no exit code)' }
    switch ([int64]$Code) {
        0       { return 'success' }
        3010    { return 'success, reboot required' }
        1602    { return 'cancelled' }
        1603    { return 'fatal error during installation (see the installer log)' }
        1618    { return 'another installation is in progress' }
        1638    { return 'another version of this product is already installed' }
        -1      { return 'timed out' }
        default { return 'failed (code ' + $Code + ')' }
    }
}

function Get-FinalExitCode {
    param([bool]$Failed, [bool]$NeedsHuman, [bool]$Reboot)
    if ($Failed) { return 1 }
    if ($NeedsHuman) { return 2 }
    if ($Reboot) { return 3010 }
    return 0
}

if ($env:PYTHON_UPDATE_DOTSOURCE -eq '1') { return }

$ErrorActionPreference = 'Stop'
$LogDir   = 'C:\Logs\CompoSecure'
$Stamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
$LogFile  = $LogDir + '\PythonUpdate_' + $Stamp + '.log'
$StageDir = $env:ProgramData + '\CompoSecure\Python'
$InstallTimeoutMinutes = 20
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

function Get-PeMachine {
    param([string]$Path)
    try {
        $fs = [System.IO.File]::OpenRead($Path)
        try {
            $br = New-Object System.IO.BinaryReader($fs)
            if ($fs.Length -lt 0x40) { return 0 }
            $fs.Position = 0x3C
            $pe = $br.ReadInt32()
            if ($pe -lt 0 -or ($pe + 6) -gt $fs.Length) { return 0 }
            $fs.Position = $pe
            if ($br.ReadUInt32() -ne 0x00004550) { return 0 }
            return [int]$br.ReadUInt16()
        } finally { $fs.Close() }
    } catch { return 0 }
}

function Get-FileVersionOf {
    param([string]$Exe)
    $vi = (Get-Item -LiteralPath $Exe -ErrorAction SilentlyContinue).VersionInfo
    if (-not $vi) { return $null }
    $v = ConvertTo-PythonVersion ('' + $vi.FileMajorPart + '.' + $vi.FileMinorPart + '.' + $vi.FileBuildPart)
    if ($v -and $v.Major -gt 0) { return $v }
    return (ConvertTo-PythonVersion ('' + $vi.ProductVersion))
}

# InstallPath of every HKLM PythonCore registration, both registry views.
function Get-RegisteredMachineDirs {
    $dirs = @()
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
            $core = $base.OpenSubKey('SOFTWARE\Python\PythonCore')
            if (-not $core) { continue }
            foreach ($tag in $core.GetSubKeyNames()) {
                $ip = $core.OpenSubKey($tag + '\InstallPath')
                if (-not $ip) { continue }
                $p = '' + $ip.GetValue('')
                if ($p) { $dirs += $p.TrimEnd('\') }
            }
        } catch { }
    }
    return ($dirs | Select-Object -Unique)
}

function Find-PythonCopies {
    $paths = @()
    foreach ($d in [System.IO.DriveInfo]::GetDrives()) {
        if ($d.DriveType -ne 'Fixed' -or -not $d.IsReady) { continue }
        $paths += @(Get-ChildItem -Path ($d.RootDirectory.FullName + 'Python*\python.exe') -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    }
    foreach ($pf in @('C:\Program Files', 'C:\Program Files (x86)')) {
        $paths += @(Get-ChildItem -Path ($pf + '\Python*\python.exe') -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    }
    foreach ($dir in (Get-RegisteredMachineDirs)) {
        $exe = $dir + '\python.exe'
        if (Test-Path -LiteralPath $exe) { $paths += $exe }
    }
    foreach ($u in @(Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
        $paths += @(Get-ChildItem -Path ($u.FullName + '\AppData\Local\Programs\Python\Python*\python.exe') -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
        $paths += @(Get-ChildItem -Path ($u.FullName + '\AppData\Local\Python\pythoncore-*\python.exe') -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    }
    $seen = @{}
    $out = @()
    foreach ($p in $paths) {
        $k = $p.ToLowerInvariant()
        if ($seen.ContainsKey($k)) { continue }
        $seen[$k] = $true
        $out += $p
    }
    return $out
}

function Get-ProfileSid {
    param([string]$ProfilePath)
    $base = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    foreach ($k in (Get-ChildItem $base -ErrorAction SilentlyContinue)) {
        $p = (Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
        if ($p -and ($p.TrimEnd('\') -eq $ProfilePath.TrimEnd('\'))) { return $k.PSChildName }
    }
    return $null
}

function Invoke-Reg {
    param([string[]]$Arguments)
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & ($env:WINDIR + '\System32\reg.exe') @Arguments 2>&1
        $text = @($out | ForEach-Object { if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { '' + $_ } }) -join ' '
        return [pscustomobject]@{ Code = $LASTEXITCODE; Output = $text.Trim() }
    } finally { $ErrorActionPreference = $old }
}

# Writes RunOnce\$Name = $Command into the user's hive, loading NTUSER.DAT
# when they are signed out. Returns '' on success or the error.
function Set-UserRunOnce {
    param([string]$ProfilePath, [string]$Name, [string]$Command)
    $sid = Get-ProfileSid -ProfilePath $ProfilePath
    if (-not $sid) { return 'no ProfileList entry for ' + $ProfilePath }
    $loaded = $false
    $hive = 'HKU\' + $sid
    try {
        if (-not (Test-Path ('Registry::HKEY_USERS\' + $sid))) {
            $ntuser = $ProfilePath + '\NTUSER.DAT'
            if (-not (Test-Path -LiteralPath $ntuser)) { return 'hive not loaded and ' + $ntuser + ' missing' }
            $r = Invoke-Reg @('load', $hive, $ntuser)
            if ($r.Code -ne 0) { return 'reg load failed: ' + $r.Output }
            $loaded = $true
        }
        $key = 'Registry::HKEY_USERS\' + $sid + '\Software\Microsoft\Windows\CurrentVersion\RunOnce'
        if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
        Set-ItemProperty -Path $key -Name $Name -Value $Command -ErrorAction Stop
        return ''
    } catch {
        return 'could not write RunOnce: ' + $_
    } finally {
        if ($loaded) {
            [gc]::Collect()
            $u = Invoke-Reg @('unload', $hive)
            if ($u.Code -ne 0) { Write-Log ('    WARNING: reg unload ' + $hive + ' failed: ' + $u.Output) -Level WARN }
        }
    }
}

function Get-ProcessesIn {
    param([string]$Dir)
    $prefix = $Dir.TrimEnd('\') + '\'
    return @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) })
}

# Downloaded or cached installer for $Version/$Arch, checked for MZ and the
# PSF signature. Returns the path, or '' after logging why not.
function Get-VerifiedInstaller {
    param([string]$Version, [string]$Arch)
    $name = Get-InstallerFileName -Version $Version -Arch $Arch
    $dest = $StageDir + '\' + $name
    if (-not (Test-Path -LiteralPath $StageDir)) { New-Item -ItemType Directory -Path $StageDir -Force | Out-Null }
    if (-not (Test-Path -LiteralPath $dest)) {
        $url = $FtpBase + $Version + '/' + $name
        Write-Log ('    Downloading ' + $url)
        try {
            Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing -TimeoutSec 600
        } catch {
            Write-Log ('    Download failed: ' + $_) -Level ERROR
            Remove-Item -LiteralPath $dest -Force -ErrorAction SilentlyContinue
            return ''
        }
    }
    $fs = [System.IO.File]::OpenRead($dest)
    try { $b1 = $fs.ReadByte(); $b2 = $fs.ReadByte() } finally { $fs.Close() }
    $sig = Get-AuthenticodeSignature -LiteralPath $dest
    $subject = ''
    if ($sig.SignerCertificate) { $subject = $sig.SignerCertificate.Subject }
    if ($b1 -ne 0x4D -or $b2 -ne 0x5A -or -not (Test-PsfSignature -Status ('' + $sig.Status) -Subject $subject)) {
        Write-Log ('    ' + $name + ' is not a PSF-signed executable (signature ' + $sig.Status + ', ' + $subject + '). A proxy block page? Deleted.') -Level ERROR
        Remove-Item -LiteralPath $dest -Force -ErrorAction SilentlyContinue
        return ''
    }
    Write-Log ('    Installer: ' + $dest + ' (signed by the Python Software Foundation)')
    return $dest
}

function Invoke-Installer {
    param([string]$Path, [string[]]$Arguments, [int]$TimeoutMinutes)
    Write-Log ('    Running: ' + $Path + ' ' + ($Arguments -join ' '))
    $p = Start-Process -FilePath $Path -ArgumentList $Arguments -NoNewWindow -PassThru
    $null = $p.Handle
    if (-not $p.WaitForExit($TimeoutMinutes * 60 * 1000)) { return -1 }
    $p.WaitForExit()
    return $p.ExitCode
}

Write-Log '=============================================='
Write-Log ' Python Update (v1) -- newest Windows build of each installed branch'
Write-Log (' Host   : ' + $env:COMPUTERNAME)
Write-Log (' DryRun : ' + $DryRun + '   ForceClose : ' + $ForceClose)
Write-Log '=============================================='

Write-Log ''
Write-Log '[1/3] Finding Python copies...'
$registered = @(Get-RegisteredMachineDirs)
$copies = @()
foreach ($exe in (Find-PythonCopies)) {
    $ver = Get-FileVersionOf -Exe $exe
    $dir = Split-Path -Parent $exe
    $kind = Get-PythonCopyKind -Path $exe
    if ($kind -eq 'Machine') {
        $owned = $false
        foreach ($r in $registered) { if ($r -ieq $dir) { $owned = $true } }
        if (-not $owned) { $kind = 'Unmanaged' }
    }
    $arch = ConvertTo-PythonArch -PeMachine (Get-PeMachine -Path $exe)
    $copies += [pscustomobject]@{ Exe = $exe; Dir = $dir; Version = $ver; Kind = $kind; Arch = $arch }
    Write-Log ('  ' + $exe + '  ' + $ver + '  ' + $kind + '  ' + $arch)
}
if ($copies.Count -eq 0) {
    Write-Log '  No Python found. Nothing to do.'
    Write-Log 'RESULT: nothing to update.'
    exit 0
}

Write-Log ''
Write-Log '[2/3] Reading python.org release data...'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {
    $indexJson = (Invoke-WebRequest -Uri $IndexUrl -UseBasicParsing -TimeoutSec 60).Content
    $listing   = (Invoke-WebRequest -Uri $ListingUrl -UseBasicParsing -TimeoutSec 60).Content
    $null = $indexJson | ConvertFrom-Json
} catch {
    Write-Log ('  Could not read python.org release data: ' + $_) -Level ERROR
    Write-Log '  (Zscaler or a block page in front of www.python.org?) Nothing changed.' -Level ERROR
    Write-Log 'RESULT: could not run.'
    exit 1
}
Write-Log '  OK.'

Write-Log ''
Write-Log '[3/3] Updating...'
$today = Get-Date
$results = @()
$failed = $false; $needsHuman = $false; $reboot = $false
foreach ($c in $copies) {
    Write-Log ''
    Write-Log ('--- ' + $c.Exe)
    if (-not $c.Version) {
        Write-Log '    Could not read the version of python.exe. Left alone.' -Level WARN
        $results += 'HELD     ' + $c.Exe + ' -- version unreadable'
        $needsHuman = $true
        continue
    }
    $branch = Get-PythonBranch $c.Version
    $newestBuild = ''
    if ($c.Arch) { $newestBuild = Get-NewestWindowsBuild -IndexJson $indexJson -Branch $branch -Arch $c.Arch }
    $newestRelease = Get-NewestRelease -ListingHtml $listing -Branch $branch
    $plan = Get-PythonCopyPlan -Installed $c.Version -Kind $c.Kind -NewestBuild $newestBuild -NewestRelease $newestRelease -Today $today
    Write-Log ('    ' + $c.Version + ' (' + $c.Kind + ', ' + $c.Arch + ')  newest Windows build ' + $newestBuild + ', newest release ' + $newestRelease)
    if ($plan.Reason) { Write-Log ('    ' + $plan.Reason) -Level WARN }

    if ($plan.Action -eq 'Current') {
        $results += 'CURRENT  ' + $c.Exe + ' ' + $c.Version
        continue
    }
    if ($plan.Action -eq 'Hold') {
        $results += 'HELD     ' + $c.Exe + ' ' + $c.Version + ' -- ' + $plan.Reason
        $needsHuman = $true
        continue
    }

    $what = $c.Version.ToString() + ' -> ' + $plan.Target
    if ($plan.SourceOnly) { $needsHuman = $true }
    $tail = ''
    if ($plan.SourceOnly) { $tail = ' (still below the source-only ' + $newestRelease + ')' }

    if ($c.Kind -eq 'PyManager') {
        $cmd = Get-PyManagerCommand
        if ($DryRun) {
            Write-Log ('    [DRYRUN] Would stage RunOnce for this user: ' + $cmd)
            $results += 'DRYRUN   ' + $c.Exe + ' ' + $what + ' would be staged for next sign-in' + $tail
            continue
        }
        $err = Set-UserRunOnce -ProfilePath (Get-ProfileFolder $c.Exe) -Name 'CompoSecure_PythonManagerUpdate' -Command $cmd
        if ($err) {
            Write-Log ('    Could not stage: ' + $err) -Level ERROR
            $results += 'FAILED   ' + $c.Exe + ' ' + $what + ' -- ' + $err
            $failed = $true
        } else {
            Write-Log ('    Staged RunOnce: ' + $cmd)
            $results += 'STAGED   ' + $c.Exe + ' ' + $what + ' at the user''s next sign-in' + $tail
            $needsHuman = $true
        }
        continue
    }

    if ($DryRun) {
        Write-Log ('    [DRYRUN] Would install ' + (Get-InstallerFileName -Version $plan.Target -Arch $c.Arch) + ' (' + $c.Kind + ')')
        $results += 'DRYRUN   ' + $c.Exe + ' ' + $what + $tail
        continue
    }
    $installer = Get-VerifiedInstaller -Version $plan.Target -Arch $c.Arch
    if (-not $installer) {
        $results += 'FAILED   ' + $c.Exe + ' ' + $what + ' -- no verified installer'
        $failed = $true
        continue
    }

    if ($c.Kind -eq 'UserInstaller') {
        $cmd = Get-UserInstallerCommand -InstallerPath $installer -TargetDir $c.Dir -Version $plan.Target
        $err = Set-UserRunOnce -ProfilePath (Get-ProfileFolder $c.Exe) -Name ('CompoSecure_PythonUpdate_' + $branch) -Command $cmd
        if ($err) {
            Write-Log ('    Could not stage: ' + $err) -Level ERROR
            $results += 'FAILED   ' + $c.Exe + ' ' + $what + ' -- ' + $err
            $failed = $true
        } else {
            Write-Log ('    Staged RunOnce: ' + $cmd)
            $results += 'STAGED   ' + $c.Exe + ' ' + $what + ' at the user''s next sign-in' + $tail
            $needsHuman = $true
        }
        continue
    }

    $running = Get-ProcessesIn -Dir $c.Dir
    if ($running.Count -gt 0) {
        foreach ($p in $running) { Write-Log ('    RUNNING: ' + $p.Name + ' (PID ' + $p.ProcessId + ') ' + $p.ExecutablePath) -Level WARN }
        if (-not $ForceClose) {
            $results += 'HELD     ' + $c.Exe + ' ' + $what + ' -- in use (re-run when idle, or pass -ForceClose)'
            $needsHuman = $true
            continue
        }
        foreach ($p in $running) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Seconds 3
    }
    $q = [char]34
    $instLog = $LogDir + '\PythonInstall_' + $plan.Target + '_' + $Stamp + '.log'
    $code = Invoke-Installer -Path $installer -Arguments @('/quiet', 'InstallAllUsers=1', ('TargetDir=' + $q + $c.Dir + $q), '/log', ($q + $instLog + $q)) -TimeoutMinutes $InstallTimeoutMinutes
    Write-Log ('    Installer exit: ' + $code + ' -- ' + (Get-PythonInstallerExitMeaning $code) + '  (log ' + $instLog + ')')
    $after = Get-FileVersionOf -Exe $c.Exe
    if ($after -and $after -ge [version]$plan.Target) {
        Write-Log ('    Verified: python.exe is now ' + $after)
        $results += 'UPDATED  ' + $c.Exe + ' ' + $c.Version + ' -> ' + $after + $tail
        if ($code -eq 3010) { $reboot = $true }
    } else {
        Write-Log ('    python.exe still reads ' + $after + ' (wanted ' + $plan.Target + ').') -Level ERROR
        $results += 'FAILED   ' + $c.Exe + ' ' + $what + ' -- still ' + $after + ', installer ' + (Get-PythonInstallerExitMeaning $code)
        $failed = $true
    }
}

Write-Log ''
Write-Log '================ SUMMARY ================'
foreach ($r in $results) { Write-Log ('  ' + $r) }
if ($DryRun) {
    Write-Log 'RESULT: DRYRUN -- nothing was changed.'
    exit 0
}
$exitCode = Get-FinalExitCode -Failed $failed -NeedsHuman $needsHuman -Reboot $reboot
switch ($exitCode) {
    0       { Write-Log 'RESULT: every Python is on the newest Windows build of a supported branch.' }
    3010    { Write-Log 'RESULT: updated; reboot required.' }
    2       { Write-Log 'RESULT: see HELD / STAGED above -- a sign-in or a human decision is still needed.' }
    default { Write-Log 'RESULT: at least one update failed.' }
}
exit $exitCode
