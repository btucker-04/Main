<#
.SYNOPSIS
    Removes an end-of-support .NET Core / .NET runtime channel.
    Nessus Plugin 172179 (Microsoft .NET Core SEoL).

.DESCRIPTION
    Update-DotNetRuntimes.ps1 will PATCH an EOL major to its final build but
    will not REMOVE it -- SEoL findings only clear when the channel is gone,
    and apps pin to their major. This script is the removal half.

    Written for CSLT-043 (2026-08-20 Tenable export): plugin 172179 ACTIVE,
    .NET 6.0.36 under C:\Program Files\dotnet\, SEoL 2024-11-12. Same host
    also has current 8.0.30 and 10.0.11 -- those are left alone.

    CSMELT-19 (2026-09-02): plugin 172178 (ASP.NET Core SEoL, the sibling
    plugin for the ASP.NET Core shared framework specifically) RESURFACED
    on Microsoft.AspNetCore.App 7.0.20 under Program Files (x86)\dotnet --
    .NET 7 EOL since 2024-05-13, over two years ago. $SharedFlavors already
    covers Microsoft.AspNetCore.App, so -Major 7 removes it the same way as
    any other channel; added -DotNet7 as an EC-safe bare-switch alias for
    it, matching the existing -DotNet9 pattern (a valued -Major parameter
    is not safe to pass through EC's argument field).

    WHY ENDPOINT CENTRAL SOFTWARE-INVENTORY UNINSTALL FAILS HERE:
      * Every .NET 6 ARP UninstallString on CSLT-043 is
        'MsiExec.exe /X{GUID}'. Under EC's SYSTEM context a bare msiexec.exe
        filename goes through ShellExecute and errors with "No application
        is associated with the specified file." This script always invokes
        C:\Windows\System32\msiexec.exe by full path with -NoNewWindow.
      * 'Microsoft Windows Desktop Runtime - 6.0.36 (x64)' is a WiX/Burn
        bundle (Package Cache
        {0532b8f2-12d7-43de-95fc-7b87006758a8}\windowsdesktop-runtime-6.0.36-win-x64.exe)
        plus a child MSI. Uninstalling one MSI while the bundle still holds
        it is a no-op or a 1603 -- the bundle reports success and the
        payload stays. Tenable keys on FOLDER presence, so the finding
        does not clear. This script uninstalls the bundle first, then any
        leftover MSI components, then verifies by re-reading ARP and disk.

    Default target is major 6 (the CSLT-043 SEoL channel) when no -DotNetN
    switch is passed. Override locally with -Major N; do not pass a valued
    parameter through EC -- use the bare switches. Multiple -DotNetN
    switches in one run are allowed (CSLT-251 needed 6 and 9 together).

    CSLT-020 (2026-09-15): the run reported "RESULT: .NET 6.x is gone" and
    exited 0, but plugin 172179 RESURFACED on the agent scan reporting
    'C:\Program Files\dotnet\  6.0.18.32522'. Chain:
      * 'Microsoft .NET Host - 6.0.18 (x64)' and 'Host FX Resolver - 6.0.18
        (x64)' both returned 1612 (cached MSI missing) -- so NO FILES were
        removed.
      * The third pass then stripped both ARP keys registry-only, which made
        ARP look clean while the payload stayed on disk.
      * Verification checked ARP, shared\/host\fxr\/sdk\ folders, and
        'dotnet --list-runtimes'. None of those cover the .NET Host's own
        artifacts: <root>\swidtag\*.swidtag and <root>\dotnet.exe.
        --list-runtimes reports SHARED FRAMEWORKS only, never the host or
        muxer, and 6.0.18.32522 is a four-part FILE version, not a folder.
    So the script now also inventories, cleans, and verifies SWID tags and
    host binary file versions. SWID tags are ISO 19770-2 inventory records
    (metadata only -- safe to delete). <root>\dotnet.exe is the shared muxer
    every installed major runs through: it is reported and never deleted,
    since removing it to clear a 6.x finding would break 9.0.20 on this host.
    The fix there is to repair/reinstall the newest .NET Host.

    CSLT-251 (2026-09-09): -InstallSuccessorMajor on Update-DotNetRuntimes
    staged .NET 10 next to 9 and left 6.0.36 / 9.0.20 in place -- that
    script never deletes a major. This script is what removes them.
    -DotNet8 is included because 8 reaches SEoL on 2026-11-10; removing it
    before that date is still a human decision (apps pin to net8.0).

.PARAMETER Major
    Channel to remove. Default 6 when no -DotNetN switch is set.
    Local/terminal use only.

.PARAMETER DotNet5
    Same as -Major 5; a bare switch so it survives EC's argument field.

.PARAMETER DotNet6
    Same as -Major 6; a bare switch so it survives EC's argument field.
    Explicitly selecting 6 is useful when combining with other -DotNetN
    switches; with no switches the script already defaults to 6.

.PARAMETER DotNet7
    Same as -Major 7; a bare switch so it survives EC's argument field.

.PARAMETER DotNet8
    Same as -Major 8; a bare switch so it survives EC's argument field.
    .NET 8 is in support until 2026-11-10 -- the script warns and proceeds.

.PARAMETER DotNet9
    Same as -Major 9; a bare switch so it survives EC's argument field.

.PARAMETER Force
    Proceed even if a non-Microsoft product holds a WiX dependency on this
    channel (will break that app -- confirm with the owner first).

.PARAMETER RemoveStaleFolders
    After uninstall, delete leftover shared\ / host\fxr\ folders, SWID tags
    (<root>\swidtag) and versioned hostfxr.dll files, plus orphan Package
    Cache installers for this major, when no live WiX dependent remains.
    Same guard as Update-DotNetRuntimes: in-use folders are skipped. The
    shared muxer <root>\dotnet.exe is never deleted (exit 2 instead).

.PARAMETER DryRun
    Report what would be removed; change nothing.

.NOTES
    Deploy via Endpoint Central (SYSTEM). Repository, -File only.
    Script Arguments: bare switches, e.g. -DotNet8 -DotNet9 -RemoveStaleFolders
                      (no $ and no quotes -- EC mangles both)
    Specify exit code(s): 0,3010
    Exit 2 is a human decision (non-Microsoft dependent, in-use folder) and
    is deliberately NOT a success code.
    Logs: C:\Logs\CompoSecure
    Exit: 0 = channel gone or never present / 3010 = gone, reboot needed /
          2 = needs a human / 1 = still present
#>

[CmdletBinding()]
param(
    [int]$Major = 6,
    [switch]$DotNet5,
    [switch]$DotNet6,
    [switch]$DotNet7,
    [switch]$DotNet8,
    [switch]$DotNet9,
    [switch]$Force,
    [switch]$RemoveStaleFolders,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

# Bare EC switches select one or more majors. -Major is local/terminal only
# and is ignored when any -DotNetN switch is set, so `-DotNet8` does not
# also remove 6 just because $Major defaults to 6.
$script:TargetMajors = @()
if ($DotNet5) { $script:TargetMajors += 5 }
if ($DotNet6) { $script:TargetMajors += 6 }
if ($DotNet7) { $script:TargetMajors += 7 }
if ($DotNet8) { $script:TargetMajors += 8 }
if ($DotNet9) { $script:TargetMajors += 9 }
if ($script:TargetMajors.Count -eq 0) {
    $script:TargetMajors = @($Major)
} elseif ($PSBoundParameters -and $PSBoundParameters.ContainsKey('Major') -and ($script:TargetMajors -notcontains $Major)) {
    $script:TargetMajors += $Major
}
$script:TargetMajors = @($script:TargetMajors | Sort-Object -Unique)
$MajorLabel = ($script:TargetMajors -join '-')

$LogDir  = 'C:\Logs\CompoSecure'
# Concatenated, not Join-Path: Join-Path validates the drive qualifier, which
# makes this file impossible to dot-source for unit tests off Windows.
$LogFile = $LogDir + '\RemoveDotNetEol_' + $MajorLabel + '_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log'
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force -ErrorAction SilentlyContinue | Out-Null
}

$ArpPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$ArpHives = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\'
)
$DotNetRoots = @(
    'C:\Program Files\dotnet',
    'C:\Program Files (x86)\dotnet'
)
$SharedFlavors = @(
    'Microsoft.NETCore.App',
    'Microsoft.WindowsDesktop.App',
    'Microsoft.AspNetCore.App'
)

$script:Reboot       = $false
$script:NeedsHuman   = $false
$script:UninstallFail = $false

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

function Test-PendingReboot {
    $reasons = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        $reasons += 'Component Based Servicing: RebootPending'
    }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        $reasons += 'Windows Update: RebootRequired'
    }
    $pfro = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
    if ($pfro) { $reasons += ('PendingFileRenameOperations: ' + @($pfro).Count + ' entries') }
    return $reasons
}

function Merge-ChannelExit {
    # Prefer hard failure, then human decision, then reboot-needed success.
    param([int]$Current, [int]$Incoming)
    foreach ($p in @(1, 2, 3010, 0)) {
        if ($Current -eq $p -or $Incoming -eq $p) { return $p }
    }
    return $Incoming
}

function Invoke-ArpHardRemoval {
    # Registry-only strip of an ARP key whose uninstall was a no-op and which
    # has no foreign WiX holder. Same fallback Update-DotNetRuntimes uses for
    # dead 6.x/7.x entries (CSMELT-19: exit 0, entry survived).
    param($Entry)
    Write-Log '    No foreign WiX holder and uninstall did not drop the ARP key --' -Level WARN
    Write-Log '    stripping the registration directly (registry-only).' -Level WARN
    if ($DryRun) { Write-Log '    [DRYRUN] Would strip ARP key.'; return $true }
    try {
        Remove-Item -Path $Entry.PSPath -Recurse -Force -ErrorAction Stop
        Start-Sleep -Seconds 1
        $stillThere = Get-ItemProperty -Path $ArpPaths -ErrorAction SilentlyContinue |
                      Where-Object { $_.PSChildName -eq $Entry.PSChildName }
        if (-not $stillThere) {
            Write-Log '    Hard removal succeeded -- orphaned entry cleared.'
            return $true
        }
        Write-Log '    Hard removal did not stick. Leaving it; escalate manually.' -Level ERROR
        return $false
    } catch {
        Write-Log ('    Hard removal failed: ' + $_) -Level ERROR
        return $false
    }
}

function Invoke-Msi {
    # Full path + -NoNewWindow: a bare 'msiexec.exe' goes through ShellExecute
    # under EC SYSTEM and fails. 1618/1601 = installer busy, retry.
    param([string]$Arguments, [int]$Retries = 4)
    $msiexec = Join-Path $env:SystemRoot 'System32\msiexec.exe'
    if (-not (Test-Path $msiexec)) { $msiexec = 'msiexec.exe' }
    $attempt = 0
    while ($true) {
        $attempt++
        $p = Start-Process -FilePath $msiexec -ArgumentList $Arguments -Wait -PassThru -NoNewWindow
        $code = $p.ExitCode
        if ($code -ne 1618 -and $code -ne 1601) { return $code }
        if ($attempt -ge $Retries) {
            Write-Log ('    Still ' + $code + ' after ' + $attempt + ' attempts.') -Level ERROR
            return $code
        }
        $wait = 30 * $attempt
        Write-Log ('    ' + $code + ' = installer busy. Waiting ' + $wait + 's, retry ' + $attempt + '/' + $Retries + '...') -Level WARN
        Start-Sleep -Seconds $wait
    }
}

function Get-ProductGuid {
    param($Entry)
    if ($Entry.PSChildName -match '^\{[0-9A-Fa-f-]+\}$') { return $Entry.PSChildName }
    $blob = ''
    if ($Entry.QuietUninstallString) { $blob = $Entry.QuietUninstallString }
    if ($Entry.UninstallString) { $blob = $blob + ' ' + $Entry.UninstallString }
    if ($blob -match '\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}') {
        return $matches[0]
    }
    return $null
}

function Get-BundleExe {
    # WiX/Burn cached installer, if the Package Cache copy is still on disk.
    param($Entry)
    $candidates = @()
    if ($Entry.QuietUninstallString) { $candidates += $Entry.QuietUninstallString }
    if ($Entry.UninstallString)      { $candidates += $Entry.UninstallString }
    if ($Entry.DisplayIcon)          { $candidates += $Entry.DisplayIcon }
    foreach ($c in $candidates) {
        if ($c -match '(?i)(C:\\ProgramData\\Package Cache\\\{[0-9A-Fa-f-]+\}\\[^"\,]+\.exe)') {
            $exe = $matches[1]
            if (Test-Path -LiteralPath $exe) { return $exe }
        }
    }
    return $null
}

function Test-IsDotNetChannelEntry {
    param($Entry, [int]$Maj)
    $n = $Entry.DisplayName
    if (-not $n) { return $false }
    # DisplayName carries the real x.y.z; DisplayVersion is often an internal
    # 48.144.x / 64.120.x scheme and must NOT be used to pick the major.
    if ($n -notmatch ('(^|\s)' + $Maj + '\.\d+\.\d+')) { return $false }
    if ($n -match '^Microsoft \.NET SDK') { return $true }
    if ($n -match 'Windows Server Hosting') { return $true }
    if ($n -match '^Microsoft Windows Desktop Runtime') { return $true }
    if ($n -match '^Microsoft ASP\.NET Core') { return $true }
    if ($n -match '^Microsoft \.NET Runtime') { return $true }
    if ($n -match '^Microsoft \.NET Host( FX Resolver)?') { return $true }
    if ($n -match '^Microsoft \.NET \d') { return $true }
    return $false
}

function Get-UninstallRank {
    # Bundles before the MSI children they own. Host last -- other products
    # register dependents on it.
    param($Entry)
    $n = $Entry.DisplayName
    $hasBundle = [bool](Get-BundleExe $Entry)
    if ($n -match '^Microsoft \.NET SDK')                      { return 10 }
    if ($n -match 'Windows Server Hosting')                    { return 20 }
    if ($n -match 'Windows Desktop Runtime' -and $hasBundle)   { return 30 }
    if ($n -match 'Windows Desktop Runtime')                   { return 35 }
    if ($n -match 'ASP\.NET Core' -and $hasBundle)             { return 40 }
    if ($n -match 'ASP\.NET Core')                             { return 45 }
    if ($n -match '^Microsoft \.NET Runtime' -and $hasBundle)  { return 50 }
    if ($n -match '^Microsoft \.NET Runtime')                  { return 55 }
    if ($n -match 'Host FX Resolver')                          { return 60 }
    if ($n -match '^Microsoft \.NET Host')                     { return 70 }
    return 80
}

function Get-ChannelArp {
    param([int]$Maj)
    $out = @()
    Get-ItemProperty -Path $ArpPaths -ErrorAction SilentlyContinue | ForEach-Object {
        if (Test-IsDotNetChannelEntry -Entry $_ -Maj $Maj) { $out += $_ }
    }
    return $out
}

function Get-ChannelFolders {
    param([int]$Maj)
    $out = @()
    foreach ($root in $DotNetRoots) {
        if (-not (Test-Path $root)) { continue }
        foreach ($fl in $SharedFlavors) {
            $base = Join-Path $root ('shared\' + $fl)
            if (-not (Test-Path $base)) { continue }
            Get-ChildItem $base -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.Name -match ('^' + $Maj + '\.\d+\.\d+')) { $out += $_.FullName }
            }
        }
        $fxr = Join-Path $root 'host\fxr'
        if (Test-Path $fxr) {
            Get-ChildItem $fxr -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.Name -match ('^' + $Maj + '\.\d+\.\d+')) { $out += $_.FullName }
            }
        }
        $sdkRoot = Join-Path $root 'sdk'
        if (Test-Path $sdkRoot) {
            Get-ChildItem $sdkRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.Name -match ('^' + $Maj + '\.\d+\.\d+')) { $out += $_.FullName }
            }
        }
    }
    return $out
}

function Get-ChannelVersionsOnDisk {
    param([int]$Maj)
    $vers = @()
    foreach ($f in (Get-ChannelFolders $Maj)) {
        $leaf = Split-Path $f -Leaf
        if ($vers -notcontains $leaf) { $vers += $leaf }
    }
    return $vers
}

# ---- FILE-level artifacts (CSLT-020) ---------------------------------------
# Folder checks are not sufficient. On CSLT-020 the 6.0.18 'Host' and 'Host FX
# Resolver' MSIs both returned 1612 (cached MSI missing), so NO files were
# removed, yet the ARP keys were then stripped registry-only. shared\ /
# host\fxr\ / sdk\ were all clean and 'dotnet --list-runtimes' only reports
# SHARED FRAMEWORKS, never the host/muxer -- so the run declared success while
# Tenable 172179 kept reporting 'C:\Program Files\dotnet\ 6.0.18.32522'.
# 6.0.18.32522 is a four-part FILE version, not a folder name.

function Test-VersionInMajor {
    # Major must be the FIRST dotted component: '16.0.18' is not 6.x, and the
    # internal ARP DisplayVersion scheme (48.75.61559) is never a real major.
    param([string]$Version, [int]$Maj)
    if ([string]::IsNullOrWhiteSpace($Version)) { return $false }
    return ($Version.Trim() -match ('^' + $Maj + '\.\d+'))
}

function Get-VersionFromArtifactName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
    if ($Name -match '(\d+\.\d+\.\d+)') { return $Matches[1] }
    return $null
}

function Test-ArtifactNameInMajor {
    param([string]$Name, [int]$Maj)
    $v = Get-VersionFromArtifactName -Name $Name
    if (-not $v) { return $false }
    return (Test-VersionInMajor -Version $v -Maj $Maj)
}

function Get-VersionFromSwidContent {
    # SWID tags are the ISO 19770-2 inventory records vendors ship precisely so
    # scanners can identify an install without ARP.
    param([string]$Content)
    if ([string]::IsNullOrWhiteSpace($Content)) { return $null }
    if ($Content -match 'version\s*=\s*"(\d+\.\d+\.\d+[^"]*)"') { return $Matches[1] }
    return $null
}

function Test-IsSharedMuxerPath {
    # <root>\dotnet.exe is the muxer EVERY installed major runs through.
    # Deleting it to clear a 6.x finding would break 9.0.20 on this host.
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    return ($Path -match '(?i)\\dotnet\\dotnet\.exe$')
}

function Test-IsDeletableArtifact {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    if (Test-IsSharedMuxerPath -Path $Path) { return $false }
    return $true
}

function Get-HostFileRemovalTarget {
    # What to actually delete for a host file, or $null if nothing may be.
    #
    # CSPRLT-94 (2026-09-16) showed why this matters: dotnet.exe picks the
    # HIGHEST host\fxr\<ver> directory and loads hostfxr.dll out of it. A
    # directory that exists with no hostfxr.dll inside does not get skipped --
    # it breaks the muxer for EVERY major:
    #   "the required library hostfxr.dll could not be found in
    #    [C:\Program Files\dotnet\host\fxr\8.0.21]"
    # and then 'dotnet --list-runtimes' returns nothing at all. So a versioned
    # hostfxr.dll is removed by deleting its PARENT FOLDER, never the file on
    # its own.
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    if (-not (Test-IsDeletableArtifact -Path $Path)) { return $null }
    if ($Path -match '(?i)^(.*\\host\\fxr\\[^\\]+)\\hostfxr\.dll$') { return $Matches[1] }
    return $Path
}

function Get-ChannelSwidTags {
    param([int]$Maj)
    $out = @()
    foreach ($root in $DotNetRoots) {
        $swidDir = $root + '\swidtag'
        if (-not (Test-Path -LiteralPath $swidDir)) { continue }
        Get-ChildItem -LiteralPath $swidDir -File -ErrorAction SilentlyContinue | ForEach-Object {
            $hit = Test-ArtifactNameInMajor -Name $_.Name -Maj $Maj
            if (-not $hit -and $_.Extension -eq '.swidtag') {
                $content = Get-Content -LiteralPath $_.FullName -Raw -ErrorAction SilentlyContinue
                $cv = Get-VersionFromSwidContent -Content $content
                if ($cv) { $hit = Test-VersionInMajor -Version $cv -Maj $Maj }
            }
            if ($hit) { $out += $_.FullName }
        }
    }
    return $out
}

function Get-ChannelHostFiles {
    # Host-owned binaries whose FILE version can still report the EOL major
    # after a 1612 uninstall. Reported, and only the non-muxer ones deleted.
    param([int]$Maj)
    $out = @()
    foreach ($root in $DotNetRoots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        $candidates = @()
        $candidates += ($root + '\dotnet.exe')
        $fxr = $root + '\host\fxr'
        if (Test-Path -LiteralPath $fxr) {
            Get-ChildItem -LiteralPath $fxr -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $candidates += ($_.FullName + '\hostfxr.dll')
            }
        }
        foreach ($c in $candidates) {
            if (-not (Test-Path -LiteralPath $c)) { continue }
            $fv = $null
            $pv = $null
            try {
                $vi = (Get-Item -LiteralPath $c -ErrorAction Stop).VersionInfo
                $fv = $vi.FileVersion
                $pv = $vi.ProductVersion
            } catch {
                continue
            }
            if ((Test-VersionInMajor -Version $fv -Maj $Maj) -or
                (Test-VersionInMajor -Version $pv -Maj $Maj)) {
                $out += [pscustomobject]@{
                    Path           = $c
                    FileVersion    = $fv
                    ProductVersion = $pv
                    IsSharedMuxer  = [bool](Test-IsSharedMuxerPath -Path $c)
                }
            }
        }
    }
    return $out
}

function Test-ChannelFullyRemoved {
    # Single source of truth for "is this major gone". CSLT-020 passed the
    # first three checks and still had a 6.0.18 SWID/file artifact, so the
    # run reported success while plugin 172179 stayed up.
    param(
        [int]$ArpCount,
        [int]$FolderCount,
        [int]$SwidCount,
        [int]$HostFileCount,
        [bool]$StillListed
    )
    if ($StillListed) { return $false }
    return ($ArpCount -eq 0 -and $FolderCount -eq 0 -and $SwidCount -eq 0 -and $HostFileCount -eq 0)
}

function Remove-FileSafe {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $true }
    if ($DryRun) { Write-Log ('    [DRYRUN] Would delete ' + $Path); return $true }
    try {
        Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
        Write-Log ('    Deleted: ' + $Path)
        return $true
    } catch {
        Write-Log ('    IN USE / locked, skipped: ' + $Path) -Level WARN
        $script:NeedsHuman = $true
        return $false
    }
}

function Get-WixHolders {
    param([string[]]$Versions)
    $depRoot = 'HKLM:\SOFTWARE\Classes\Installer\Dependencies'
    $holders = @()
    foreach ($ver in $Versions) {
        $verEsc = [regex]::Escape($ver)
        Get-ChildItem $depRoot -ErrorAction SilentlyContinue |
          Where-Object { $_.PSChildName -match $verEsc } | ForEach-Object {
            $provider = $_.PSChildName
            $depPath = Join-Path $_.PSPath 'Dependents'
            if (-not (Test-Path $depPath)) {
                $holders += [pscustomobject]@{ Version = $ver; Provider = $provider; Guid = $null; Name = '(orphaned provider -- no Dependents)' }
                return
            }
            Get-ChildItem $depPath -ErrorAction SilentlyContinue | ForEach-Object {
                $g = $_.PSChildName
                $dn = '(no ARP name -- dependent product itself may be gone)'
                foreach ($hive in $ArpHives) {
                    $prop = Get-ItemProperty ($hive + $g) -ErrorAction SilentlyContinue
                    if ($prop -and $prop.DisplayName) { $dn = $prop.DisplayName; break }
                }
                $holders += [pscustomobject]@{ Version = $ver; Provider = $provider; Guid = $g; Name = $dn }
            }
        }
    }
    return $holders
}

function Test-IsOwnChannelProduct {
    param([string]$Name, [int]$Maj)
    if (-not $Name) { return $false }
    if ($Name -match 'orphaned provider' -or $Name -match 'no ARP name') { return $true }
    $fake = [pscustomobject]@{ DisplayName = $Name }
    return (Test-IsDotNetChannelEntry -Entry $fake -Maj $Maj)
}

function Invoke-UninstallEntry {
    param($Entry)
    $name = $Entry.DisplayName
    Write-Log ('  Uninstalling: ' + $name + '  [' + $Entry.DisplayVersion + ']  key=' + $Entry.PSChildName)
    if ($DryRun) { Write-Log '    [DRYRUN] Would uninstall.'; return $true }

    $rc = $null
    $bundle = Get-BundleExe $Entry
    try {
        if ($bundle) {
            Write-Log ('    Bundle exe: ' + $bundle)
            $u = Start-Process -FilePath $bundle -ArgumentList '/uninstall /quiet /norestart' -Wait -PassThru -NoNewWindow
            $rc = $u.ExitCode
        } elseif ($Entry.QuietUninstallString -and $Entry.QuietUninstallString -notmatch '(?i)msiexec') {
            $cmd  = $Entry.QuietUninstallString
            $exeQ = ($cmd -split '"')[1]
            if (-not $exeQ -or -not (Test-Path -LiteralPath $exeQ)) {
                Write-Log '    QuietUninstallString exe missing from Package Cache.' -Level WARN
            } else {
                $argsQ = ($cmd.Substring($cmd.IndexOf($exeQ) + $exeQ.Length + 1)).Trim()
                if ($argsQ -notmatch '/quiet') { $argsQ = ($argsQ + ' /quiet /norestart').Trim() }
                Write-Log ('    QuietUninstall: ' + $exeQ + ' ' + $argsQ)
                $u = Start-Process -FilePath $exeQ -ArgumentList $argsQ -Wait -PassThru -NoNewWindow
                $rc = $u.ExitCode
            }
        }
        if ($null -eq $rc) {
            $guid = Get-ProductGuid $Entry
            if ($guid) {
                $msiLog = Join-Path $LogDir ('msi_uninstall_dotnet' + $script:Major + '_' + ($guid.Trim('{}')) + '.log')
                Write-Log ('    msiexec /x ' + $guid)
                $rc = Invoke-Msi ('/x ' + $guid + ' /qn /norestart /l*v "' + $msiLog + '"')
            } else {
                Write-Log '    No bundle exe and no product GUID -- cannot uninstall this entry.' -Level ERROR
                $script:UninstallFail = $true
                return $false
            }
        }
    } catch {
        Write-Log ('    Uninstall error: ' + $_) -Level ERROR
        $script:UninstallFail = $true
        return $false
    }

    Write-Log ('    Exit: ' + $rc)
    if ($rc -eq 3010) { $script:Reboot = $true }
    if ($rc -ne 0 -and $rc -ne 3010) {
        Write-Log '    Uninstall returned a failure code.' -Level WARN
        if ($rc -eq 1603) {
            Write-Log '    1603 = rollback. Common causes: pending reboot, a loaded' -Level WARN
            Write-Log '    runtime file, or a bundle whose child MSI is still held.' -Level WARN
        }
        if ($rc -eq 1612) {
            Write-Log '    1612 = cached MSI missing. Will rely on leftover-MSI / folder cleanup.' -Level WARN
        }
    }
    Start-Sleep -Seconds 2
    $still = Get-ItemProperty -Path $ArpPaths -ErrorAction SilentlyContinue |
             Where-Object { $_.PSChildName -eq $Entry.PSChildName }
    if ($still) {
        Write-Log '    NOT ACTUALLY REMOVED -- ARP entry survived. A WiX bundle with' -Level WARN
        Write-Log '    registered dependents skips uninstall and returns success; or msiexec' -Level WARN
        Write-Log '    could not find its cached package. See dependency dump above.' -Level WARN
        $script:UninstallFail = $true
        return $false
    }
    Write-Log '    Removed (ARP entry gone).'
    return $true
}

function Remove-FolderSafe {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $true }
    if ($DryRun) { Write-Log ('    [DRYRUN] Would delete ' + $Path); return $true }
    $parent = Split-Path $Path -Parent
    $leaf   = Split-Path $Path -Leaf
    $tmp    = Join-Path $parent ($leaf + '.deleting')
    try {
        Rename-Item -LiteralPath $Path -NewName (Split-Path -Leaf $tmp) -ErrorAction Stop
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction Stop
        Write-Log ('    Deleted: ' + $Path)
        return $true
    } catch {
        if (Test-Path -LiteralPath $tmp) {
            Rename-Item -LiteralPath $tmp -NewName $leaf -ErrorAction SilentlyContinue
        }
        Write-Log ('    IN USE, skipped: ' + $Path) -Level WARN
        Write-Log '    Close the app using this runtime and re-run.' -Level WARN
        $script:NeedsHuman = $true
        return $false
    }
}

function Invoke-RemoveOneMajor {
    param([int]$Major)
    $script:Major = $Major
    $script:UninstallFail = $false
    $script:NeedsHuman = $false

    Write-Log ''
    Write-Log ('======== .NET ' + $Major + '.x ========')
    Write-Log '[1/5] Inventory'
$entries = @(Get-ChannelArp $Major | Sort-Object { Get-UninstallRank $_ }, DisplayName)
if ($entries.Count -eq 0) {
    Write-Log ('  No ARP entries for Microsoft .NET ' + $Major + '.x.')
} else {
    foreach ($e in $entries) {
        $kind = 'MSI'
        $bundle = Get-BundleExe $e
        if ($bundle) { $kind = 'BUNDLE ' + $bundle }
        Write-Log ('  ARP  ' + $e.DisplayName + '  [' + $e.DisplayVersion + ']  ' + $kind)
    }
}

$folders = @(Get-ChannelFolders $Major)
if ($folders.Count -eq 0) {
    Write-Log ('  No runtime/SDK folders for ' + $Major + '.x under Program Files\dotnet.')
} else {
    foreach ($f in $folders) { Write-Log ('  DISK ' + $f) }
}

$swidTags = @(Get-ChannelSwidTags $Major)
foreach ($s in $swidTags) { Write-Log ('  SWID ' + $s) }
$hostFiles = @(Get-ChannelHostFiles $Major)
foreach ($h in $hostFiles) {
    $tag = if ($h.IsSharedMuxer) { '  [SHARED MUXER]' } else { '' }
    Write-Log ('  FILE ' + $h.Path + '  [file ' + $h.FileVersion + ' / product ' + $h.ProductVersion + ']' + $tag)
}
if ($swidTags.Count -gt 0 -or $hostFiles.Count -gt 0) {
    Write-Log '  NOTE: the SWID/FILE artifacts above are what plugin 172179 reads when' -Level WARN
    Write-Log '  ARP and shared\ folders are already clean (CSLT-020).' -Level WARN
}

$versions = @(Get-ChannelVersionsOnDisk $Major)
foreach ($e in $entries) {
    if ($e.DisplayName -match '(\d+\.\d+\.\d+)') {
        $v = $matches[1]
        if ($versions -notcontains $v) { $versions += $v }
    }
}

Write-Log ''
Write-Log ('[2/5] WiX dependency holders for .NET ' + $Major + '.x')
$holders = @()
if ($versions.Count -gt 0) { $holders = @(Get-WixHolders $versions) }
if ($holders.Count -eq 0) {
    Write-Log '  None -- no Installer\\Dependencies providers for this channel.'
} else {
    foreach ($h in $holders) {
        Write-Log ('  ' + $h.Version + '  provider=' + $h.Provider + '  ->  ' + $h.Name)
    }
}

$foreign = @($holders | Where-Object { -not (Test-IsOwnChannelProduct -Name $_.Name -Maj $Major) } |
             Select-Object -ExpandProperty Name -Unique)
if ($foreign.Count -gt 0) {
    Write-Log ''
    Write-Log '  Non-Microsoft (or other-major) products hold this channel:' -Level WARN
    foreach ($n in $foreign) { Write-Log ('    * ' + $n) -Level WARN }
    Write-Log ('  Removing .NET ' + $Major + ' WILL break those apps -- they pin to this major') -Level WARN
    Write-Log '  and do not roll forward to a later major. Confirm with the machine owner' -Level WARN
    Write-Log '  before using -Force.' -Level WARN
    if (-not $Force) {
        Write-Log '  Refusing to remove this major. Re-run with -Force after the owner signs off.' -Level ERROR
        Write-Log '  Other selected majors (if any) will still be processed.' -Level WARN
        $script:NeedsHuman = $true
        return 2
    }
    Write-Log '  -Force set: continuing anyway.' -Level WARN
}

if ($entries.Count -eq 0 -and $folders.Count -eq 0 -and
    $swidTags.Count -eq 0 -and $hostFiles.Count -eq 0) {
    Write-Log ''
    Write-Log ('Nothing to remediate -- .NET ' + $Major + '.x is not present.')
    return 0
}

# ------------------------------------------------------------------
Write-Log ''
Write-Log '[3/5] Uninstall (bundle first, then leftover MSI components)'
foreach ($e in $entries) {
    Invoke-UninstallEntry $e | Out-Null
}

# Second pass: a child MSI that survived because we uninstalled it before its
# bundle, or because the bundle no-op'd the first time, gets another try now
# that holders may have been released.
Start-Sleep -Seconds 2
$leftArp = @(Get-ChannelArp $Major)
if ($leftArp.Count -gt 0 -and -not $DryRun) {
    Write-Log ''
    Write-Log '  Second pass -- ARP entries that survived the first uninstall:'
    foreach ($e in ($leftArp | Sort-Object { Get-UninstallRank $_ })) {
        Invoke-UninstallEntry $e | Out-Null
    }
}

# Third pass: uninstall no-op with no FOREIGN holder (own-channel WiX refs
# like "ASP.NET Core N.x Shared Framework" holding ".NET Runtime N.x" are
# expected during teardown). Strip leftover ARP so Tenable/Add-Remove
# Programs do not keep a dead DisplayVersion (CSMELT-19).
$leftArp = @(Get-ChannelArp $Major)
if ($leftArp.Count -gt 0 -and -not $DryRun) {
    $leftVersNow = @(Get-ChannelVersionsOnDisk $Major)
    foreach ($e in $leftArp) {
        if ($e.DisplayName -match '(\d+\.\d+\.\d+)') {
            $v = $matches[1]
            if ($leftVersNow -notcontains $v) { $leftVersNow += $v }
        }
    }
    $foreignLeft = @()
    if ($leftVersNow.Count -gt 0) {
        $foreignLeft = @(Get-WixHolders $leftVersNow | Where-Object {
            -not (Test-IsOwnChannelProduct -Name $_.Name -Maj $Major)
        })
    }
    if ($foreignLeft.Count -gt 0) {
        Write-Log '  Leftover ARP still has a foreign WiX holder -- not stripping:' -Level WARN
        foreach ($h in $foreignLeft) { Write-Log ('    ' + $h.Name) -Level WARN }
    } else {
        Write-Log '  Third pass -- stripping leftover ARP with no foreign holder:'
        foreach ($e in $leftArp) { Invoke-ArpHardRemoval $e | Out-Null }
    }
}

# ------------------------------------------------------------------
Write-Log ''
Write-Log '[4/5] Leftover folders / SWID tags / host files / Package Cache'
$leftFolders = @(Get-ChannelFolders $Major)
$leftArp     = @(Get-ChannelArp $Major)
$leftSwid    = @(Get-ChannelSwidTags $Major)
$leftHost    = @(Get-ChannelHostFiles $Major)
$leftVers    = @(Get-ChannelVersionsOnDisk $Major)
$liveHold    = @()
if ($leftVers.Count -gt 0) {
    $liveHold = @(Get-WixHolders $leftVers | Where-Object {
        $_.Name -notmatch 'orphaned provider' -and $_.Name -notmatch 'no ARP name' -and
        -not (Test-IsOwnChannelProduct -Name $_.Name -Maj $Major)
    })
}

if ($leftFolders.Count -eq 0 -and $leftArp.Count -eq 0 -and
    $leftSwid.Count -eq 0 -and $leftHost.Count -eq 0) {
    Write-Log '  No leftover ARP, runtime folders, SWID tags or host files for this channel.'
} elseif (-not $RemoveStaleFolders) {
    if ($leftFolders.Count -gt 0) {
        Write-Log '  Payload folders remain. Tenable plugin 172179 keys on folder presence,' -Level WARN
        Write-Log '  so the SEoL finding will not clear until they are gone. Re-run with' -Level WARN
        Write-Log '  -RemoveStaleFolders if the dependency dump shows no live foreign holder.' -Level WARN
        foreach ($f in $leftFolders) { Write-Log ('    ' + $f) -Level WARN }
        $script:UninstallFail = $true
    }
    if ($leftArp.Count -gt 0) {
        Write-Log '  ARP entries remain:' -Level WARN
        foreach ($e in $leftArp) { Write-Log ('    ' + $e.DisplayName) -Level WARN }
        $script:UninstallFail = $true
    }
    if ($leftSwid.Count -gt 0 -or $leftHost.Count -gt 0) {
        Write-Log '  SWID tags / host files remain -- re-run with -RemoveStaleFolders.' -Level WARN
        foreach ($s in $leftSwid) { Write-Log ('    ' + $s) -Level WARN }
        foreach ($h in $leftHost) { Write-Log ('    ' + $h.Path) -Level WARN }
        $script:UninstallFail = $true
    }
} else {
    if ($liveHold.Count -gt 0 -and -not $Force) {
        Write-Log '  REFUSING -RemoveStaleFolders -- live dependency holders remain:' -Level ERROR
        foreach ($h in $liveHold) { Write-Log ('    ' + $h.Name) -Level ERROR }
        $script:NeedsHuman = $true
    } else {
        foreach ($f in $leftFolders) { Remove-FolderSafe $f | Out-Null }

        # SWID tags are inventory metadata only -- nothing executes them, so
        # deleting the EOL major's tags cannot break a supported runtime.
        foreach ($s in $leftSwid) {
            Write-Log ('  SWID tag: ' + $s)
            Remove-FileSafe $s | Out-Null
        }

        # Host files: versioned hostfxr.dll under host\fxr\<ver> belongs to the
        # EOL major alone. <root>\dotnet.exe is shared by every major and is
        # never deleted -- the fix there is to repair/reinstall the NEWEST
        # .NET Host so the muxer's file version moves off the EOL major.
        foreach ($h in $leftHost) {
            $target = Get-HostFileRemovalTarget -Path $h.Path
            if ($target) {
                Write-Log ('  Host file: ' + $h.Path + '  [' + $h.FileVersion + ']')
                if ($target -ne $h.Path) {
                    # Deleting the folder, not the lone DLL: an empty
                    # host\fxr\<ver> directory breaks dotnet.exe (CSPRLT-94).
                    Write-Log ('    Removing the whole resolver folder: ' + $target)
                    Remove-FolderSafe $target | Out-Null
                } else {
                    Remove-FileSafe $h.Path | Out-Null
                }
            } else {
                Write-Log ('  SHARED MUXER still reports ' + $Major + '.x: ' + $h.Path) -Level WARN
                Write-Log ('    file ' + $h.FileVersion + ' / product ' + $h.ProductVersion) -Level WARN
                Write-Log '    NOT deleted -- every installed major runs through this binary.' -Level WARN
                Write-Log '    Repair/reinstall the newest .NET Host (x64 and/or x86) so the' -Level WARN
                Write-Log '    muxer version moves forward, then re-scan.' -Level WARN
                $script:NeedsHuman = $true
            }
        }

        # Orphan Package Cache installers for this major (CACHE-ONLY artifacts
        # have been observed to keep a Tenable version finding alive).
        $cacheRoot = 'C:\ProgramData\Package Cache'
        if (Test-Path $cacheRoot) {
            $rx = 'dotnet-runtime-' + $Major + '\.|windowsdesktop-runtime-' + $Major + '\.|aspnetcore-runtime-' + $Major + '\.|dotnet-sdk-' + $Major + '\.|dotnet-hosting-' + $Major + '\.'
            Get-ChildItem $cacheRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $hit = Get-ChildItem $_.FullName -Filter *.exe -File -ErrorAction SilentlyContinue |
                       Where-Object { $_.Name -match $rx }
                if ($hit) {
                    Write-Log ('  Package Cache: ' + $_.FullName + '  (' + $hit[0].Name + ')')
                    Remove-FolderSafe $_.FullName | Out-Null
                }
            }
        }
    }
}

# ------------------------------------------------------------------
Write-Log ''
Write-Log '[5/5] Verify'
$finalArp     = @(Get-ChannelArp $Major)
$finalFolders = @(Get-ChannelFolders $Major)
$finalSwid    = @(Get-ChannelSwidTags $Major)
$finalHost    = @(Get-ChannelHostFiles $Major)
$stillListed  = $false
foreach ($root in $DotNetRoots) {
    $exe = Join-Path $root 'dotnet.exe'
    if (-not (Test-Path $exe)) { continue }
    Write-Log ('  [' + $root + '] dotnet --list-runtimes')
    # foreach (not ForEach-Object): assignment inside a pipeline scriptblock
    # has been a real scoping bug in this fleet's scripts.
    foreach ($line in @(& $exe --list-runtimes 2>&1)) {
        Write-Log ('    ' + $line)
        if ($line -match ('Microsoft\.(?:NETCore|WindowsDesktop|AspNetCore)\.App\s+' + $Major + '\.')) {
            $stillListed = $true
        }
    }
}

Write-Log ''
if ($DryRun) {
    Write-Log 'DRY_RUN -- nothing was changed for this major.'
    return 0
}

Write-Log ('  SWID tags for ' + $Major + '.x remaining : ' + $finalSwid.Count)
Write-Log ('  Host files for ' + $Major + '.x remaining: ' + $finalHost.Count)

if (Test-ChannelFullyRemoved -ArpCount $finalArp.Count -FolderCount $finalFolders.Count `
        -SwidCount $finalSwid.Count -HostFileCount $finalHost.Count -StillListed $stillListed) {
    Write-Log ('RESULT: .NET ' + $Major + '.x is gone (ARP, folders, SWID tags, host file versions,')
    Write-Log '        and dotnet --list-runtimes).'
    Write-Log 'Re-run a Nessus scan to confirm plugin 172179 / 172178 clear.'
    if ($script:Reboot) { return 3010 }
    return 0
}

Write-Log ('RESULT: .NET ' + $Major + '.x is STILL present.') -Level ERROR
if ($finalArp.Count -gt 0) {
    Write-Log '  Remaining ARP:' -Level ERROR
    foreach ($e in $finalArp) { Write-Log ('    ' + $e.DisplayName) -Level ERROR }
}
if ($finalFolders.Count -gt 0) {
    Write-Log '  Remaining folders:' -Level ERROR
    foreach ($f in $finalFolders) { Write-Log ('    ' + $f) -Level ERROR }
}
if ($stillListed) {
    Write-Log '  dotnet --list-runtimes still reports this major.' -Level ERROR
}
if ($finalSwid.Count -gt 0) {
    Write-Log '  Remaining SWID tags (plugin 172179 reads these even with ARP clean):' -Level ERROR
    foreach ($s in $finalSwid) { Write-Log ('    ' + $s) -Level ERROR }
    Write-Log '  Re-run with -RemoveStaleFolders to delete them.' -Level ERROR
}
if ($finalHost.Count -gt 0) {
    Write-Log '  Remaining host files reporting this major:' -Level ERROR
    foreach ($h in $finalHost) {
        $tag = if ($h.IsSharedMuxer) { '  [SHARED MUXER -- repair newest .NET Host]' } else { '' }
        Write-Log ('    ' + $h.Path + '  [file ' + $h.FileVersion + ']' + $tag) -Level ERROR
    }
}
if (@(Test-PendingReboot).Count -gt 0) {
    Write-Log '  A reboot is still pending. Files scheduled via' -Level WARN
    Write-Log '  PendingFileRenameOperations are not gone until it happens -- reboot,' -Level WARN
    Write-Log '  then re-run this script before re-scanning.' -Level WARN
}
if ($script:NeedsHuman) { return 2 }
return 1
}

# ------------------------------------------------------------------
# Unit tests dot-source this file for the helpers above; stop before the run.
if ($env:REMOVE_DOTNET_EOL_DOTSOURCE -eq '1') { return }

Write-Log '=============================================='
Write-Log (' Remove-DotNetEolChannel -- plugin 172179/172178 -- .NET ' + $MajorLabel + '.x')
Write-Log (' Host   : ' + $env:COMPUTERNAME)
Write-Log ' Switches received:'
Write-Log ('   -Major              : ' + $Major + '  (used only when no -DotNetN switch is set)')
Write-Log ('   -DotNet5            : ' + $DotNet5)
Write-Log ('   -DotNet6            : ' + $DotNet6)
Write-Log ('   -DotNet7            : ' + $DotNet7)
Write-Log ('   -DotNet8            : ' + $DotNet8)
Write-Log ('   -DotNet9            : ' + $DotNet9)
Write-Log ('   -Force              : ' + $Force)
Write-Log ('   -RemoveStaleFolders : ' + $RemoveStaleFolders)
Write-Log ('   -DryRun             : ' + $DryRun)
Write-Log (' Targets : .NET ' + (($script:TargetMajors | ForEach-Object { "$_.x" }) -join ', .NET '))
if ($MyInvocation.Line) { Write-Log (' Invoked as: ' + $MyInvocation.Line.Trim()) }
Write-Log '=============================================='
Write-Log 'Each selected major is removed independently. Other majors stay.'

$pending = @(Test-PendingReboot)
if ($pending.Count -gt 0) {
    Write-Log ''
    Write-Log '*** PENDING REBOOT DETECTED -- uninstalls may 1603 / no-op ***' -Level WARN
    foreach ($r in $pending) { Write-Log ('***   ' + $r) -Level WARN }
    Write-Log '*** Reboot first for the most reliable result. Continuing anyway.' -Level WARN
}

if ($script:TargetMajors -contains 8) {
    Write-Log ''
    Write-Log '*** .NET 8 is in support until 2026-11-10 ***' -Level WARN
    Write-Log '*** Removing it now will break any app that targets net8.0 / net8.0-windows.' -Level WARN
    Write-Log '*** After that date it generates SEoL findings (172179) that patching cannot clear.' -Level WARN
}

$overall = 0
foreach ($m in $script:TargetMajors) {
    $code = Invoke-RemoveOneMajor -Major $m
    $overall = Merge-ChannelExit -Current $overall -Incoming $code
}

Write-Log ''
Write-Log '=============================================='
Write-Log (' Combined result for .NET ' + $MajorLabel + '.x : exit ' + $overall)
Write-Log '=============================================='
exit $overall
