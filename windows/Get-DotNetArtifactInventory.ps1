<#
.SYNOPSIS
    Read-only: for every .NET runtime version present on this machine, report
    WHICH artifact holds it -- the live runtime folder, the WiX bundle cache
    (C:\ProgramData\Package Cache), the host\fxr set, ARP, or the Installer
    database. Purpose: determine what a Tenable .NET Core finding is actually
    keying on when a finding will not clear.

.DESCRIPTION
    Cross-references five independent sources:
      1. dotnet --list-runtimes            (what the host will actually load)
      2. <root>\shared\<flavor>\<version>  (runtime payload folders on disk)
      3. <root>\host\fxr\<version>         (framework resolver versions)
      4. C:\ProgramData\Package Cache\{GUID}\*.exe|*.msi
                                           (WiX/Burn bundle cache -- the cached
                                           INSTALLER, not a loadable runtime)
      5. ARP + Installer database          (registration state per bundle GUID)

    For each version it prints where that version exists, then classifies:

      LIVE          present in a shared\ runtime folder -> genuinely installed,
                    normal remediation applies
      CACHE-ONLY    present ONLY in Package Cache -> the runtime is gone; only
                    the cached installer remains. If Tenable still reports this
                    version, the plugin is keying on the cached installer.
      ORPHAN-CACHE  Package Cache folder with NO matching ARP entry -> debris
                    from an interrupted or force-removed uninstall
      REGISTERED    ARP entry exists for the version

    Changes nothing. No deletions, no uninstalls, no downloads.

.NOTES
    Run: powershell -ExecutionPolicy Bypass -File .\Get-DotNetArtifactInventory.ps1
    Log: C:\Logs\CompoSecure\DotNetArtifacts_<timestamp>.log  (+ a CSV for fleet rollup)
    Exit: 0 = no cache-only or orphaned artifacts / 2 = found some / 1 = error
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'SilentlyContinue'

$LogDir  = 'C:\Logs\CompoSecure'
$LogFile = Join-Path $LogDir ('DotNetArtifacts_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')
$CsvFile = Join-Path $LogDir 'DotNetArtifacts.csv'
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

Write-Log '=============================================='
Write-Log ' .NET Artifact Inventory (read-only)'
Write-Log (' Host : ' + $env:COMPUTERNAME)
Write-Log '=============================================='

$roots = @(
    @{ Arch = 'x64'; Path = 'C:\Program Files\dotnet' },
    @{ Arch = 'x86'; Path = 'C:\Program Files (x86)\dotnet' }
)

# version -> hashtable of where it was seen
$seen = @{}
function Note {
    param([string]$Ver, [string]$Where, [string]$Detail)
    if (-not $Ver) { return }
    if (-not $seen.ContainsKey($Ver)) { $seen[$Ver] = @{ Where = @(); Detail = @() } }
    $seen[$Ver].Where  += $Where
    $seen[$Ver].Detail += $Detail
}

# ------------------------------------------------------------------
# 1. What the host will actually load
# ------------------------------------------------------------------
Write-Log ''
Write-Log '[1] dotnet --list-runtimes'
foreach ($r in $roots) {
    $exe = Join-Path $r.Path 'dotnet.exe'
    if (-not (Test-Path $exe)) { Write-Log ('  ' + $r.Arch + ': no dotnet.exe'); continue }
    $lines = & $exe --list-runtimes 2>&1
    foreach ($l in $lines) {
        if ($l -match '^(Microsoft\.[\w.]+)\s+(\d+\.\d+\.\d+)') {
            Write-Log ('  ' + $r.Arch + '  ' + $matches[1] + ' ' + $matches[2])
            Note $matches[2] 'LOADABLE' ($r.Arch + ' ' + $matches[1])
        }
    }
}

# ------------------------------------------------------------------
# 2. Runtime payload folders
# ------------------------------------------------------------------
Write-Log ''
Write-Log '[2] shared\<flavor>\<version> folders on disk'
foreach ($r in $roots) {
    $sharedRoot = Join-Path $r.Path 'shared'
    if (-not (Test-Path $sharedRoot)) { continue }
    Get-ChildItem $sharedRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $flavor = $_.Name
        Get-ChildItem $_.FullName -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Log ('  ' + $r.Arch + '  ' + $flavor + '  ' + $_.Name + '   ' + $_.FullName)
            Note $_.Name 'RUNTIME-FOLDER' ($r.Arch + ' ' + $flavor)
        }
    }
}

# ------------------------------------------------------------------
# 3. host\fxr
# ------------------------------------------------------------------
Write-Log ''
Write-Log '[3] host\fxr versions'
foreach ($r in $roots) {
    $fxr = Join-Path $r.Path 'host\fxr'
    if (-not (Test-Path $fxr)) { continue }
    Get-ChildItem $fxr -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Log ('  ' + $r.Arch + '  fxr ' + $_.Name)
        Note $_.Name 'HOST-FXR' $r.Arch
    }
}

# ------------------------------------------------------------------
# 4. ARP entries (bundle registrations)
# ------------------------------------------------------------------
Write-Log ''
Write-Log '[4] ARP entries for .NET runtimes'
$arpPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$arp = Get-ItemProperty -Path $arpPaths -ErrorAction SilentlyContinue | Where-Object {
    $_.DisplayName -match '^Microsoft (\.NET|ASP\.NET Core|Windows Desktop) (Runtime|SDK)'
}
$arpGuids = @{}
foreach ($e in $arp) {
    $nameVer = ''
    if ($e.DisplayName -match '(\d+\.\d+\.\d+)') { $nameVer = $matches[1] }
    $g = $e.PSChildName
    $arpGuids[$g.ToUpper()] = $e.DisplayName
    Write-Log ('  ' + $e.DisplayName + '  [' + $e.DisplayVersion + ']  ' + $g)
    if ($e.QuietUninstallString) {
        Write-Log ('      uninstall: ' + $e.QuietUninstallString)
    }
    Note $nameVer 'ARP' $e.DisplayName
}
if (-not $arp) { Write-Log '  (none)' }

# ------------------------------------------------------------------
# 5. Package Cache (WiX/Burn bundle cache)
# ------------------------------------------------------------------
Write-Log ''
Write-Log '[5] C:\ProgramData\Package Cache -- .NET bundles'
$pcRoot = 'C:\ProgramData\Package Cache'
$cacheRows = @()
if (Test-Path $pcRoot) {
    Get-ChildItem $pcRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $guid = $_.Name
        $payloads = Get-ChildItem $_.FullName -File -Include *.exe,*.msi -ErrorAction SilentlyContinue
        foreach ($p in $payloads) {
            if ($p.Name -notmatch 'dotnet|aspnetcore|windowsdesktop|netcore') { continue }
            $ver = ''
            if ($p.Name -match '(\d+\.\d+\.\d+)') { $ver = $matches[1] }
            $arch = 'x64'
            if ($p.Name -match 'win-x86|x86\.') { $arch = 'x86' }
            $registered = $arpGuids.ContainsKey($guid.ToUpper())
            $cacheRows += [pscustomobject]@{
                Guid = $guid; File = $p.Name; Version = $ver; Arch = $arch
                SizeMB = [math]::Round($p.Length/1MB,1); Registered = $registered
            }
            Write-Log ('  ' + $guid)
            Write-Log ('      ' + $p.Name + '   (' + [math]::Round($p.Length/1MB,1) + ' MB)  version=' + $ver + '  ARP-registered=' + $registered)
            Note $ver 'PACKAGE-CACHE' ($arch + ' ' + $p.Name + ' registered=' + $registered)
        }
    }
} else {
    Write-Log '  Package Cache directory not present.'
}
if ($cacheRows.Count -eq 0) { Write-Log '  No .NET bundles found in Package Cache.' }

# ------------------------------------------------------------------
# 6. SWID tags -- ISO 19770-2 inventory records under <root>\swidtag.
#    These survive a failed (1612) MSI uninstall and are read by scanners
#    even when ARP and shared\ are already clean (CSLT-020).
# ------------------------------------------------------------------
Write-Log ''
Write-Log '[6] <root>\swidtag -- SWID inventory tags'
$swidFound = 0
foreach ($r in $roots) {
    $swidDir = $r.Path + '\swidtag'
    if (-not (Test-Path -LiteralPath $swidDir)) { continue }
    Get-ChildItem -LiteralPath $swidDir -File -ErrorAction SilentlyContinue | ForEach-Object {
        $ver = ''
        if ($_.Name -match '(\d+\.\d+\.\d+)') {
            $ver = $matches[1]
        } else {
            $content = Get-Content -LiteralPath $_.FullName -Raw -ErrorAction SilentlyContinue
            if ($content -match 'version\s*=\s*"(\d+\.\d+\.\d+)') { $ver = $matches[1] }
        }
        Write-Log ('  ' + $r.Arch + '  ' + $_.Name + '   version=' + $ver)
        Note $ver 'SWIDTAG' ($r.Arch + ' ' + $_.Name)
        $swidFound++
    }
}
if ($swidFound -eq 0) { Write-Log '  (no swidtag directory or no tags)' }

# ------------------------------------------------------------------
# 7. Host binary FILE versions. 'dotnet --list-runtimes' reports SHARED
#    FRAMEWORKS only -- never the muxer or resolver -- so an EOL host left
#    behind by a failed uninstall is invisible to sections 1-3.
# ------------------------------------------------------------------
Write-Log ''
Write-Log '[7] host binary file versions (dotnet.exe / hostfxr.dll)'
$hostFound = 0
foreach ($r in $roots) {
    if (-not (Test-Path -LiteralPath $r.Path)) { continue }
    $candidates = @($r.Path + '\dotnet.exe')
    $fxrDir = $r.Path + '\host\fxr'
    if (Test-Path -LiteralPath $fxrDir) {
        Get-ChildItem -LiteralPath $fxrDir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $candidates += ($_.FullName + '\hostfxr.dll')
        }
    }
    foreach ($c in $candidates) {
        if (-not (Test-Path -LiteralPath $c)) { continue }
        $vi = (Get-Item -LiteralPath $c -ErrorAction SilentlyContinue).VersionInfo
        if (-not $vi) { continue }
        $pv = [string]$vi.ProductVersion
        $shortVer = ''
        if ($pv -match '^(\d+\.\d+\.\d+)') { $shortVer = $matches[1] }
        $isMuxer = ($c -match '(?i)\\dotnet\\dotnet\.exe$')
        $tag = if ($isMuxer) { '  [SHARED MUXER -- used by every major]' } else { '' }
        Write-Log ('  ' + $r.Arch + '  ' + $c)
        Write-Log ('        file=' + $vi.FileVersion + '  product=' + $pv + $tag)
        Note $shortVer 'HOST-FILE' ($r.Arch + ' ' + (Split-Path $c -Leaf) + ' file=' + $vi.FileVersion)
        $hostFound++
    }
}
if ($hostFound -eq 0) { Write-Log '  (no host binaries found)' }

# ------------------------------------------------------------------
# Cross-reference and classify
# ------------------------------------------------------------------
Write-Log ''
Write-Log '=============================================='
Write-Log ' PER-VERSION CLASSIFICATION'
Write-Log '=============================================='
$cacheOnly = @()
$orphanCache = @()
$fileOnly = @()

foreach ($ver in ($seen.Keys | Sort-Object { [version]$_ })) {
    $where = ($seen[$ver].Where | Sort-Object -Unique)
    $isLive  = ($where -contains 'RUNTIME-FOLDER') -or ($where -contains 'LOADABLE')
    $inCache = ($where -contains 'PACKAGE-CACHE')
    $inArp   = ($where -contains 'ARP')
    $inFile  = ($where -contains 'SWIDTAG') -or ($where -contains 'HOST-FILE')

    $class = 'LIVE'
    if ($isLive) { $class = 'LIVE' }
    elseif ($inCache) { $class = 'CACHE-ONLY' }
    elseif ($inFile)  { $class = 'FILE-ONLY' }
    elseif ($inArp)   { $class = 'REGISTERED-NO-PAYLOAD' }

    Write-Log ''
    Write-Log ('  ' + $ver + '   -> ' + $class)
    Write-Log ('     seen in : ' + ($where -join ', '))
    foreach ($det in ($seen[$ver].Detail | Sort-Object -Unique)) {
        Write-Log ('       - ' + $det)
    }
    if ($class -eq 'CACHE-ONLY') {
        $cacheOnly += $ver
        Write-Log '     NOTE: the runtime payload is GONE; only the cached installer remains.' -Level WARN
        Write-Log '     A cached .exe/.msi is not a loadable runtime. If Tenable still reports' -Level WARN
        Write-Log '     this version, the plugin is keying on the cached installer.' -Level WARN
    }
    if ($class -eq 'FILE-ONLY') {
        $fileOnly += $ver
        Write-Log '     NOTE: no runtime folder and no cached installer -- only a SWID tag' -Level WARN
        Write-Log '     and/or a host binary file version still reports this version. This is' -Level WARN
        Write-Log '     the CSLT-020 state: a 1612 uninstall removed nothing, the ARP key was' -Level WARN
        Write-Log '     stripped, and plugin 172179 keeps reporting from these files.' -Level WARN
        Write-Log '     SWID tags are safe to delete. <root>\dotnet.exe is NOT -- repair or' -Level WARN
        Write-Log '     reinstall the newest .NET Host so the muxer version moves forward.' -Level WARN
    }
}

foreach ($row in $cacheRows) {
    if (-not $row.Registered) {
        $orphanCache += $row
    }
}
if ($orphanCache.Count -gt 0) {
    Write-Log ''
    Write-Log ' ORPHANED PACKAGE CACHE FOLDERS (no matching ARP entry):' -Level WARN
    foreach ($row in $orphanCache) {
        Write-Log ('   ' + $row.Guid + '  ' + $row.File + '  (' + $row.SizeMB + ' MB)') -Level WARN
    }
    Write-Log ' These are debris from an interrupted or force-removed uninstall. They can' -Level WARN
    Write-Log ' be removed, but ONLY after confirming no ARP entry references the GUID --' -Level WARN
    Write-Log ' which is what the check above does.' -Level WARN
}

# CSV for fleet rollup
if (-not (Test-Path $CsvFile)) {
    Add-Content -Path $CsvFile -Value 'Timestamp,Host,Version,Classification,SeenIn' -ErrorAction SilentlyContinue
}
foreach ($ver in ($seen.Keys | Sort-Object)) {
    $where = ($seen[$ver].Where | Sort-Object -Unique) -join '+'
    $isLive  = ($seen[$ver].Where -contains 'RUNTIME-FOLDER') -or ($seen[$ver].Where -contains 'LOADABLE')
    $cls = if ($isLive) { 'LIVE' } elseif ($seen[$ver].Where -contains 'PACKAGE-CACHE') { 'CACHE-ONLY' } else { 'OTHER' }
    Add-Content -Path $CsvFile -Value ((Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ',' + $env:COMPUTERNAME + ',' + $ver + ',' + $cls + ',' + $where) -ErrorAction SilentlyContinue
}

Write-Log ''
Write-Log '=============================================='
Write-Log (' CACHE-ONLY versions      : ' + $(if ($cacheOnly.Count) { $cacheOnly -join ', ' } else { 'none' }))
Write-Log (' FILE-ONLY versions       : ' + $(if ($fileOnly.Count) { $fileOnly -join ', ' } else { 'none' }))
Write-Log (' Orphaned cache folders   : ' + $orphanCache.Count)
Write-Log (' CSV: ' + $CsvFile)
Write-Log '=============================================='

if ($cacheOnly.Count -gt 0 -or $orphanCache.Count -gt 0 -or $fileOnly.Count -gt 0) { exit 2 }
exit 0
