<#
.SYNOPSIS
    Remediates insecure Windows service permissions (Nessus Plugin 65057) (v3).

.DESCRIPTION
    Discovers Windows services whose executable (or its directory) grants
    write / modify / full control to Everyone, Users, Domain Users, or
    Authenticated Users -- the same groups plugin 65057 checks -- and
    tightens those directories to Read & Execute.

    v3 (from the 2026-09-15 swissqp-02/03/04/05 Nessus export):
      * Paths are discovered from service ImagePath values, not hardcoded.
        The swissQprint finding is MariaDB
        (C:\Program Files\swissqprint\mariadb-<ver>\bin\mysqld.exe). A
        hardcoded 10.5.29 path would miss the next MariaDB folder. The
        same discovery still catches leftover SolidWorks Visualize /
        swScheduler dirs if they remain writable to Users.
      * Nessus sometimes appends "Bad Shares" pointing at Windows
        Defender platform binaries. Those are skipped (Microsoft-owned).
        Windows, WinSxS, System32, SysWOW64, and WindowsApps are skipped
        unless -IncludeMicrosoft is set.
      * Only the directory that contains the service .exe is changed
        (for swissQprint: ...\mariadb-<ver>\bin), not the vendor tree
        and not the MariaDB datadir. Drive roots and 'Program Files'
        itself are refused.
      * Inherited write ACEs are converted with icacls /inheritance:d
        before remove (v2 lesson from CSLT-156). ACL backup is /T.
      * Running services are not stopped. No reboot. Change is on-disk
        ACL only; a process that already has the binary open is
        unaffected until the next start.

    Surgical per directory:
      1. Back up the current ACL (icacls /save /T).
      2. If a risky ACE is inherited, break inheritance on this
         directory only.
      3. Remove write-bearing grants for the untrusted identity.
      4. Re-grant Read & Execute for Users / Authenticated Users /
         Domain Users so the application still launches. Everyone is
         stripped and not re-granted.

.PARAMETER DryRun
    Show current ACLs and what would change, without modifying anything.

.PARAMETER Path
    Optional semicolon-separated extra directories to consider (in
    addition to discovery). Endpoint Central: -Path "D:\app\service".

.PARAMETER Service
    Optional semicolon-separated service name filter (registry key /
    Win32 Name). Example: -Service MariaDB  to only touch swissQprint
    MariaDB on OT hosts.

.PARAMETER IncludeMicrosoft
    Also consider services under Windows / Defender / WindowsApps.
    Off by default.

.NOTES
    Deploy via Endpoint Central (SYSTEM). Logs + ACL backups:
    C:\Logs\CompoSecure. Exit 0/1.
#>

[CmdletBinding()]
param(
    [switch]$DryRun,
    [string]$Path = '',
    [string]$Service = '',
    [switch]$IncludeMicrosoft
)

$ErrorActionPreference = 'Stop'

# ---- helpers (dotsourced by tests; no C:\ I/O here) -------------------------

function Get-ServiceExecutableFromImagePath {
    param([string]$ImagePath)
    if ([string]::IsNullOrWhiteSpace($ImagePath)) { return $null }
    $trimmed = $ImagePath.Trim().TrimStart()
    if ($trimmed -match '^\\(SystemRoot|System32|\?\?)' -or $trimmed -match '^\\(?!\\)') {
        return $null
    }
    $expanded = [Environment]::ExpandEnvironmentVariables($trimmed)
    $exe = $null
    if ($expanded.StartsWith('"')) {
        $end = $expanded.IndexOf('"', 1)
        if ($end -gt 1) { $exe = $expanded.Substring(1, $end - 1) }
    } else {
        if ($expanded -match '^(?i)(.+?\.exe)(\s+|$)') {
            $exe = $Matches[1].Trim()
        }
    }
    if ([string]::IsNullOrWhiteSpace($exe)) { return $null }
    if ($exe -notmatch '\.exe$') { return $null }
    if ($exe -match '\.sys$') { return $null }
    return $exe
}

function Get-ServiceDirectoryFromExe {
    param([string]$ExePath)
    if ([string]::IsNullOrWhiteSpace($ExePath)) { return $null }
    if ($ExePath -match '^(.*)\\[^\\]+$') { return $Matches[1] }
    if ($ExePath -match '^(.*)/[^/]+$') { return $Matches[1] }
    return $null
}

function Test-ProtectedServicePath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $true }
    $n = $Path.ToLowerInvariant() -replace '/', '\'
    if ($n -match '\\windowsapps\\') { return $true }
    if ($n -match '\\microsoft\\windows defender\\') { return $true }
    if ($n -match '\\microsoft\\windows defender advanced threat protection\\') { return $true }
    if ($n -match '\\winsxs\\') { return $true }
    if ($n -match '^[a-z]:\\windows(\\|$)') { return $true }
    if ($n -match '\\system32\\') { return $true }
    if ($n -match '\\syswow64\\') { return $true }
    return $false
}

function Test-SafeServiceDirectory {
    param([string]$Directory)
    if ([string]::IsNullOrWhiteSpace($Directory)) { return $false }
    $n = $Directory.TrimEnd('\', '/')
    $parts = @($n -split '[\\/]' | Where-Object { $_ -ne '' })
    if ($parts.Count -lt 3) { return $false }
    $lower = $n.ToLowerInvariant()
    if ($lower -match '^[a-z]:\\windows$') { return $false }
    if ($lower -match '^[a-z]:\\program files$') { return $false }
    if ($lower -match '^[a-z]:\\program files \(x86\)$') { return $false }
    if ($lower -match '^[a-z]:\\programdata$') { return $false }
    return $true
}

function Test-UntrustedIdentity {
    param([string]$SidOrName)
    if ([string]::IsNullOrWhiteSpace($SidOrName)) { return $false }
    $v = $SidOrName.Trim()
    if ($v -eq 'S-1-1-0' -or $v -eq 'S-1-5-11' -or $v -eq 'S-1-5-32-545') { return $true }
    if ($v -match '^S-1-5-21-\d+-\d+-\d+-513$') { return $true }
    $u = $v.ToUpperInvariant()
    if ($u -eq 'EVERYONE' -or $u -eq 'BUILTIN\USERS' -or $u -eq 'NT AUTHORITY\AUTHENTICATED USERS') { return $true }
    if ($u.EndsWith('\USERS') -and $u -ne 'NT AUTHORITY\USERS') { return $true }
    if ($u.EndsWith('\DOMAIN USERS') -or $u -eq 'DOMAIN USERS') { return $true }
    if ($u -eq 'AUTHENTICATED USERS' -or $u.EndsWith('\AUTHENTICATED USERS')) { return $true }
    return $false
}

function Test-ShouldRegrantRx {
    param([string]$SidOrName)
    if ([string]::IsNullOrWhiteSpace($SidOrName)) { return $false }
    if ($SidOrName -eq 'S-1-1-0') { return $false }
    if ($SidOrName.Trim().ToUpperInvariant() -eq 'EVERYONE') { return $false }
    return (Test-UntrustedIdentity -SidOrName $SidOrName)
}

function Test-WriteBearingRights {
    param([string]$Rights)
    if ([string]::IsNullOrWhiteSpace($Rights)) { return $false }
    return ($Rights -match 'FullControl|Modify|Write|WriteData|CreateFiles|Delete')
}

function Test-ServiceNameAllowed {
    param([string]$Name, [string[]]$Filter)
    if (-not $Filter -or $Filter.Count -eq 0) { return $true }
    foreach ($f in $Filter) {
        if ([string]::IsNullOrWhiteSpace($f)) { continue }
        if ($Name -like $f) { return $true }
    }
    return $false
}

if ($env:FIX_SERVICE_PERMS_DOTSOURCE -eq '1') { return }

# ---- live run (Windows / Endpoint Central) ----------------------------------

$LogDir  = 'C:\Logs\CompoSecure'
$AclBackupDir = Join-Path $LogDir 'ACLBackups'
$LogFile = Join-Path $LogDir ('FixServicePerms_65057_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')
if (-not (Test-Path $LogDir))       { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
if (-not (Test-Path $AclBackupDir)) { New-Item -ItemType Directory -Path $AclBackupDir -Force | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

function Get-AceSidOrName {
    param($Ace)
    try {
        return $Ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        return [string]$Ace.IdentityReference.Value
    }
}

function Get-UntrustedWriteAces {
    param($Acl)
    $hits = @()
    foreach ($ace in $Acl.Access) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        if (-not (Test-WriteBearingRights -Rights $ace.FileSystemRights.ToString())) { continue }
        $id = Get-AceSidOrName -Ace $ace
        if (Test-UntrustedIdentity -SidOrName $id) { $hits += $ace }
        elseif (Test-UntrustedIdentity -SidOrName ([string]$ace.IdentityReference.Value)) { $hits += $ace }
    }
    return $hits
}

function Get-DiscoveredServiceImagePaths {
    $out = @()
    $keyRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    $keys = Get-ChildItem -Path $keyRoot -ErrorAction SilentlyContinue
    foreach ($svcKey in $keys) {
        $imagePath = $null
        try { $imagePath = $svcKey.GetValue('ImagePath') } catch { continue }
        $out += [pscustomobject]@{
            Name      = $svcKey.PSChildName
            ImagePath = [string]$imagePath
        }
    }
    return $out
}

$serviceFilter = @()
if (-not [string]::IsNullOrWhiteSpace($Service)) {
    $serviceFilter = @($Service -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

$extraDirs = @()
if (-not [string]::IsNullOrWhiteSpace($Path)) {
    $extraDirs = @($Path -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

Write-Log '=============================================='
Write-Log ' Insecure Service Permissions Fix -- Plugin 65057 v3'
Write-Log (' Host             : ' + $env:COMPUTERNAME)
Write-Log (' DryRun           : ' + $DryRun)
Write-Log (' IncludeMicrosoft : ' + $IncludeMicrosoft)
if ($serviceFilter.Count -gt 0) {
    Write-Log (' Service filter   : ' + ($serviceFilter -join ', '))
} else {
    Write-Log ' Service filter   : <none -- all non-protected services>'
}
if ($extraDirs.Count -gt 0) {
    Write-Log (' Extra Path       : ' + ($extraDirs -join '; '))
}
Write-Log '=============================================='
Write-Log 'ACL-only. Does not stop services or reboot. Confirm with the'
Write-Log 'asset owner if a service binary directory is used as a writable'
Write-Log 'data/log folder by unprivileged users (Users lose write).'

$Failed = $false
$changed = 0
$skippedProtected = 0
$alreadyOk = 0
$missing = 0

$targetMap = @{}

foreach ($svc in Get-DiscoveredServiceImagePaths) {
    if (-not (Test-ServiceNameAllowed -Name $svc.Name -Filter $serviceFilter)) { continue }
    $exe = Get-ServiceExecutableFromImagePath -ImagePath $svc.ImagePath
    if (-not $exe) { continue }
    if (-not $IncludeMicrosoft -and (Test-ProtectedServicePath -Path $exe)) {
        $skippedProtected++
        continue
    }
    $dir = Get-ServiceDirectoryFromExe -ExePath $exe
    if (-not (Test-SafeServiceDirectory -Directory $dir)) { continue }
    $key = $dir.ToLowerInvariant()
    if (-not $targetMap.ContainsKey($key)) {
        $targetMap[$key] = [pscustomobject]@{
            Directory = $dir
            Services  = New-Object System.Collections.Generic.List[string]
            Exes      = New-Object System.Collections.Generic.List[string]
        }
    }
    if (-not $targetMap[$key].Services.Contains($svc.Name)) {
        [void]$targetMap[$key].Services.Add($svc.Name)
    }
    if (-not $targetMap[$key].Exes.Contains($exe)) {
        [void]$targetMap[$key].Exes.Add($exe)
    }
}

foreach ($d in $extraDirs) {
    if (-not (Test-SafeServiceDirectory -Directory $d)) {
        Write-Log (' Extra Path refused as too broad or invalid: ' + $d) -Level WARN
        continue
    }
    if (-not $IncludeMicrosoft -and (Test-ProtectedServicePath -Path $d)) {
        Write-Log (' Extra Path skipped (protected Microsoft path): ' + $d) -Level WARN
        continue
    }
    $key = $d.ToLowerInvariant()
    if (-not $targetMap.ContainsKey($key)) {
        $targetMap[$key] = [pscustomobject]@{
            Directory = $d
            Services  = New-Object System.Collections.Generic.List[string]
            Exes      = New-Object System.Collections.Generic.List[string]
        }
        [void]$targetMap[$key].Services.Add('(Path argument)')
    }
}

if ($targetMap.Count -eq 0) {
    Write-Log 'No candidate service directories after discovery/filters.'
    Write-Log '=============================================='
    exit 0
}

foreach ($entry in ($targetMap.Values | Sort-Object Directory)) {
    $dir = $entry.Directory
    Write-Log ''
    Write-Log ('--- ' + $dir + ' ---')
    Write-Log ('  Service(s): ' + ($entry.Services -join ', '))
    if ($entry.Exes.Count -gt 0) {
        foreach ($e in $entry.Exes) { Write-Log ('  Exe: ' + $e) }
    }
    if (-not (Test-Path -LiteralPath $dir)) {
        Write-Log '  Not present on this machine. Skipping.'
        $missing++
        continue
    }

    $acl = Get-Acl -LiteralPath $dir
    $usersAces = @(Get-UntrustedWriteAces -Acl $acl)
    if ($usersAces.Count -eq 0) {
        Write-Log '  No write/modify/full-control ACE for untrusted groups. Already compliant.'
        $alreadyOk++
        continue
    }
    foreach ($ace in $usersAces) {
        $inh = if ($ace.IsInherited) { 'inherited' } else { 'explicit' }
        Write-Log ('  Current risky ACE: ' + $ace.IdentityReference.Value + ' = ' + $ace.FileSystemRights + ' (' + $inh + ')') -Level WARN
    }

    if ($DryRun) {
        Write-Log '  [DRYRUN] Would back up ACL, then remove untrusted write/modify/full-control'
        Write-Log '  [DRYRUN] (keeping read & execute for Users-like groups) on this directory.'
        continue
    }

    $safeName = ($dir -replace '[:\\ ]', '_') + '.acl'
    $backupPath = Join-Path $AclBackupDir $safeName
    $null = & icacls "$dir" /save "$backupPath" /T /C 2>&1
    Write-Log ('  ACL backup: ' + $backupPath)

    $inheritedRisky = $false
    foreach ($ace in $usersAces) {
        if ($ace.IsInherited) { $inheritedRisky = $true }
    }
    if ($inheritedRisky) {
        Write-Log '  A risky ACE is INHERITED from a parent directory.' -Level WARN
        Write-Log '  Breaking inheritance on this directory only (/inheritance:d).' -Level WARN
        $null = & icacls "$dir" /inheritance:d /T /C 2>&1
        Write-Log '  Inheritance disabled (inherited ACEs converted to explicit).'
    }

    $seenIds = @{}
    foreach ($ace in $usersAces) {
        $sid = Get-AceSidOrName -Ace $ace
        $name = [string]$ace.IdentityReference.Value
        $removeKey = $sid
        if ($seenIds.ContainsKey($removeKey)) { continue }
        $seenIds[$removeKey] = $true
        $rmTarget = if ($sid -match '^S-1-') { '*' + $sid } else { $name }
        $null = & icacls "$dir" /remove:g "$rmTarget" /T /C 2>&1
        Write-Log ('  Removed grants for ' + $name + ' (' + $sid + ') recursive.')
        if ((Test-ShouldRegrantRx -SidOrName $sid) -or (Test-ShouldRegrantRx -SidOrName $name)) {
            $grantTarget = if ($sid -match '^S-1-') { '*' + $sid } else { $name }
            $null = & icacls "$dir" /grant:r "${grantTarget}:(OI)(CI)(RX)" /T /C 2>&1
            Write-Log ('  Re-granted Read & Execute (OI)(CI)(RX) to ' + $name + '.')
        } else {
            Write-Log ('  Not re-granting ' + $name + ' (Everyone / non-Users identity).')
        }
    }

    $aclAfter = Get-Acl -LiteralPath $dir
    $stillRisky = @(Get-UntrustedWriteAces -Acl $aclAfter)
    if ($stillRisky.Count -gt 0) {
        $anyInherited = $false
        foreach ($ace in $stillRisky) {
            if ($ace.IsInherited) {
                $anyInherited = $true
                Write-Log ('  STILL PRESENT (INHERITED): ' + $ace.IdentityReference.Value + ' = ' + $ace.FileSystemRights) -Level ERROR
            } else {
                Write-Log ('  STILL PRESENT (explicit): ' + $ace.IdentityReference.Value + ' = ' + $ace.FileSystemRights) -Level ERROR
            }
        }
        if ($anyInherited) {
            Write-Log '  An INHERITED write ACE remains -- parent ACL is the source.' -Level ERROR
            Write-Log '  This directory was isolated on purpose; raising the parent ACL is an owner decision.' -Level ERROR
        }
        $Failed = $true
    } else {
        Write-Log '  Verified: untrusted groups no longer have write on this directory.'
        $changed++
    }

    $parentDir = Split-Path -Parent $dir
    if ($parentDir -and (Test-Path -LiteralPath $parentDir)) {
        Write-Log ('  Parent ACL (not changed): ' + $parentDir)
        try {
            $pacl = Get-Acl -LiteralPath $parentDir
            foreach ($ace in $pacl.Access) {
                $id = Get-AceSidOrName -Ace $ace
                if (((Test-UntrustedIdentity -SidOrName $id) -or (Test-UntrustedIdentity -SidOrName ([string]$ace.IdentityReference.Value))) -and
                    (Test-WriteBearingRights -Rights $ace.FileSystemRights.ToString())) {
                    $inh = if ($ace.IsInherited) { 'inherited' } else { 'explicit' }
                    Write-Log ('    ' + $ace.IdentityReference.Value + ' = ' + $ace.FileSystemRights + '  (' + $inh + ')')
                }
            }
        } catch {
            Write-Log ('  Could not read parent ACL: ' + $_) -Level WARN
        }
    }
}

Write-Log ''
Write-Log '=============================================='
Write-Log (' Directories tightened : ' + $changed)
Write-Log (' Already compliant     : ' + $alreadyOk)
Write-Log (' Missing on disk       : ' + $missing)
Write-Log (' Protected skipped     : ' + $skippedProtected)
if ($Failed) {
    Write-Log ' Completed WITH ERRORS -- review log. ACL backups in:' -Level ERROR
    Write-Log ('   ' + $AclBackupDir) -Level ERROR
    Write-Log ' Roll back a path with:  icacls "<parent dir>" /restore "<backup.acl>"'
    Write-Log '=============================================='
    exit 1
}
Write-Log ' Untrusted users can no longer replace the service executable.'
Write-Log (' ACL backups (for rollback) in: ' + $AclBackupDir)
Write-Log ' Re-run a Nessus scan to confirm plugin 65057 clears.'
Write-Log '=============================================='
exit 0
