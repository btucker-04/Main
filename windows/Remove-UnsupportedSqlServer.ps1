<#
.SYNOPSIS
    Removes end-of-support Microsoft SQL Server database engine instances and
    LocalDB. Nessus plugin 64784 (Microsoft SQL Server Unsupported Version
    Detection).

.DESCRIPTION
    Installing a newer SQL Server does not clear 64784: the old engine stays
    installed side by side until it is uninstalled. CSLT-135 (2026-10-14):
    SQL Server 2022 Express was installed and 64784 stayed ACTIVE.

    Supported means Microsoft extended support has not ended:
        2005 (9) 2016-04-12    2008 / 2008 R2 (10) 2019-07-09
        2012 (11) 2022-07-12   2014 (12) 2024-07-09
        2016 (13) 2026-07-14   2017 (14) 2027-10-12
        2019 (15) 2030-01-08   2022 (16) 2033-01-11
    A major not in the table counts as supported.

    Steps:
      1. Inventory, both registry views (a 32-bit instance registers under
         WOW6432Node, which a 64-bit-only check misses):
           * engine instances: Microsoft SQL Server\Instance Names\SQL, with
             the version from <instance id>\Setup
           * LocalDB: Microsoft SQL Server Local DB\Installed Versions, and
             the matching 'SQL Server <year> ... LocalDB' MSI
           * Add/Remove Programs entries named for each SQL Server year
      2. Block (exit 2) an unsupported instance that has user databases in
         its DATA folder, unless -AllowUserDatabases. Uninstall keeps the
         .mdf/.ldf files, but the app that used them stops working.
      3. Uninstall each unsupported instance with its own setup.exe
         (<Program Files>\Microsoft SQL Server\<NNN>\Setup Bootstrap):
         /Q /ACTION=Uninstall /FEATURES=SQL /INSTANCENAME=<name>.
      4. Uninstall unsupported LocalDB MSIs (stopping their sqlservr.exe).
      5. Leftovers: when no instance of an unsupported year remains, its
         engine-side MSIs (Database Engine, Common Files, Setup, RsFx, VSS
         Writer, Browser, ...) are removed with msiexec /x. Client
         libraries (Native Client, ODBC / OLE DB, Management Objects, CLR
         Types, Management Studio, ...) are left: other apps load them and
         64784 does not report them. -KeepSharedComponents skips this step.
      6. Verify by re-reading the inventory.

    Supported instances (for example the SQL Server 2022 Express installed
    by Install-SqlExpress2022.ps1) are never touched.

    64-BIT. The EC agent runs scripts in 32-bit PowerShell; the script
    relaunches itself as 64-bit so both registry views are read correctly.

.PARAMETER AllowUserDatabases
    Uninstall an unsupported instance even if its DATA folder holds user
    database files. The files are kept on disk; attach them to the
    supported instance to keep the data.

.PARAMETER KeepLocalDB
    Do not remove unsupported LocalDB versions.

.PARAMETER KeepSharedComponents
    Do not remove the engine-side MSIs left after an uninstall.

.PARAMETER DryRun
    Report what would happen; change nothing.

.NOTES
    Deploy via Endpoint Central (SYSTEM), -File invocation.
    Script Arguments: bare switches only, e.g. -DryRun
    Specify exit code(s): 0,3010
    Log: C:\Logs\CompoSecure\RemoveUnsupportedSql_<timestamp>.log
    Exit: 0 = nothing unsupported left / 3010 = removed, reboot needed /
          2 = blocked (user databases) / 1 = failed or still present
#>
[CmdletBinding()]
param(
    [switch]$AllowUserDatabases,
    [switch]$KeepLocalDB,
    [switch]$KeepSharedComponents,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

$SqlEndOfSupport = @{
    9  = '2016-04-12'
    10 = '2019-07-09'
    11 = '2022-07-12'
    12 = '2024-07-09'
    13 = '2026-07-14'
    14 = '2027-10-12'
    15 = '2030-01-08'
    16 = '2033-01-11'
}
$SqlYearToMajor = @{ '2005' = 9; '2008' = 10; '2012' = 11; '2014' = 12; '2016' = 13; '2017' = 14; '2019' = 15; '2022' = 16; '2025' = 17 }
$SystemDbFiles = @('master.mdf', 'mastlog.ldf', 'model.mdf', 'modellog.ldf', 'msdbdata.mdf', 'msdblog.ldf',
    'tempdb.mdf', 'templog.ldf', 'model_msdbdata.mdf', 'model_msdblog.ldf',
    'model_replicatedmaster.mdf', 'model_replicatedmaster.ldf')
$LeftoverPattern = '(?i)(Database Engine|Common Files|Connection Info|Batch Parser|\bDMF\b|XEvent|SQL Diagnostics|Setup|RsFx|VSS Writer|Browser|Full[- ]?Text|Replication|\(64-bit\)|\(32-bit\))'
$ClientPattern   = '(?i)(Native Client|ODBC|OLE ?DB|Management Objects|CLR Types|Management Studio|T-SQL Language|Transact-SQL|Data-Tier|Command Line Utilities|Policies|Report Builder|LocalDB|Books Online|Documentation)'

# ---- Pure helpers (unit-tested) ---------------------------------------------

function ConvertTo-SafeVersion {
    param([string]$Text)
    if (-not $Text) { return $null }
    $m = [regex]::Match($Text, '\d+(\.\d+){1,3}')
    if (-not $m.Success) { return $null }
    $v = $null
    if ([version]::TryParse($m.Value, [ref]$v)) { return $v }
    return $null
}

function Test-SqlMajorUnsupported {
    param([int]$Major, [datetime]$Today)
    if (-not $SqlEndOfSupport.ContainsKey($Major)) { return $false }
    return ($Today.Date -gt [datetime]::ParseExact($SqlEndOfSupport[$Major], 'yyyy-MM-dd', $null))
}

function Get-SqlMajorFromInstanceId {
    # MSSQL13.SQLEXPRESS -> 13; MSSQL10_50.X -> 10; 2005's MSSQL.1 -> $null
    param([string]$InstanceId)
    $m = [regex]::Match('' + $InstanceId, '^MSSQL(\d+)(_\d+)?\.')
    if ($m.Success) { return [int]$m.Groups[1].Value }
    return $null
}

function Get-SqlInstanceMajor {
    # Setup\Version first; the instance id covers a missing Setup key.
    param([string]$Version, [string]$InstanceId)
    $v = ConvertTo-SafeVersion $Version
    if ($v) { return $v.Major }
    return (Get-SqlMajorFromInstanceId -InstanceId $InstanceId)
}

function Get-SqlYearFromName {
    # 'SQL Server 2016 Database Engine Services' -> '2016'; '' when none.
    param([string]$Name)
    $m = [regex]::Match('' + $Name, '(?i)SQL Server (2005|2008|2012|2014|2016|2017|2019|2022|2025)\b')
    if ($m.Success) { return $m.Groups[1].Value }
    return ''
}

function Test-SqlLeftoverName {
    # Engine-side MSI of an SQL Server year; client libraries excluded.
    param([string]$Name)
    if (-not (Get-SqlYearFromName -Name $Name)) { return $false }
    if ($Name -match $ClientPattern) { return $false }
    return ($Name -match $LeftoverPattern)
}

function Test-SqlLocalDbName {
    param([string]$Name)
    return ([bool](Get-SqlYearFromName -Name $Name) -and $Name -match '(?i)LocalDB')
}

function Get-UserDatabaseFiles {
    param([string[]]$FileNames)
    return @($FileNames | Where-Object { $_ -match '(?i)\.(mdf|ndf|ldf)$' -and $SystemDbFiles -notcontains $_.ToLowerInvariant() })
}

function Get-SqlUninstallArguments {
    param([string]$InstanceName)
    return @('/Q', '/ACTION=Uninstall', '/FEATURES=SQL', ('/INSTANCENAME=' + $InstanceName))
}

function Get-MsiProductCode {
    param([string]$KeyName, [string]$UninstallString)
    if ($KeyName -match '^\{[0-9A-Fa-f-]{36}\}$') { return $KeyName }
    $m = [regex]::Match('' + $UninstallString, '\{[0-9A-Fa-f-]{36}\}')
    if ($m.Success -and $UninstallString -match '(?i)msiexec') { return $m.Value }
    return ''
}

function Get-InstallOutcome {
    param($ExitCode)
    if ($null -eq $ExitCode -or ('' + $ExitCode) -eq '') { return 'UNKNOWN' }
    switch ([int]$ExitCode) {
        0       { return 'OK' }
        1605    { return 'OK' }
        3010    { return 'REBOOT' }
        1641    { return 'REBOOT' }
        default { return 'FAIL' }
    }
}

function Get-FinalExitCode {
    param([bool]$Failed, [bool]$NeedsHuman, [bool]$Reboot)
    if ($Failed) { return 1 }
    if ($NeedsHuman) { return 2 }
    if ($Reboot) { return 3010 }
    return 0
}

function Test-Needs64BitRelaunch {
    param([bool]$Is64BitOS, [bool]$Is64BitProcess)
    return ($Is64BitOS -and -not $Is64BitProcess)
}

function Get-RelaunchArguments {
    param([string]$ScriptPath, [hashtable]$Bound)
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $ScriptPath)
    foreach ($k in ($Bound.Keys | Sort-Object)) {
        $v = $Bound[$k]
        if ($v -is [System.Management.Automation.SwitchParameter]) {
            if ($v.IsPresent) { $a += ('-' + $k) }
        } elseif ($null -ne $v -and ('' + $v) -ne '') {
            $a += @(('-' + $k), ('' + $v))
        }
    }
    return $a
}

if ($env:SQLUNSUPPORTED_DOTSOURCE -eq '1') { return }

# ---- Runtime ---------------------------------------------------------------

if (Test-Needs64BitRelaunch -Is64BitOS ([Environment]::Is64BitOperatingSystem) -Is64BitProcess ([Environment]::Is64BitProcess)) {
    $ps64 = $env:WINDIR + '\Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $ps64) {
        $relaunchArgs = Get-RelaunchArguments -ScriptPath $PSCommandPath -Bound $PSBoundParameters
        & $ps64 @relaunchArgs
        exit $LASTEXITCODE
    }
}

$LogDir  = 'C:\Logs\CompoSecure'
$LogFile = $LogDir + '\RemoveUnsupportedSql_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log'
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$Msiexec = $env:WINDIR + '\System32\msiexec.exe'
$Today = Get-Date
$SqlViews = @(
    [pscustomobject]@{ View = '64-bit'; Root = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server' },
    [pscustomobject]@{ View = '32-bit'; Root = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server' }
)
$ProgramFilesRoots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ } | Select-Object -Unique

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

function Get-SqlEngineInstances {
    $out = @()
    foreach ($v in $SqlViews) {
        $names = Get-ItemProperty ($v.Root + '\Instance Names\SQL') -ErrorAction SilentlyContinue
        if (-not $names) { continue }
        foreach ($p in $names.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            $setup = Get-ItemProperty ($v.Root + '\' + $p.Value + '\Setup') -ErrorAction SilentlyContinue
            $ver = ''
            $edition = ''
            $dataRoot = ''
            if ($setup) {
                $ver = '' + $(if ($setup.PatchLevel) { $setup.PatchLevel } else { $setup.Version })
                $edition = '' + $setup.Edition
                $dataRoot = '' + $setup.SQLDataRoot
            }
            $out += [pscustomobject]@{
                Name = $p.Name; Id = '' + $p.Value; View = $v.View; Version = $ver; Edition = $edition
                Major = Get-SqlInstanceMajor -Version $ver -InstanceId $p.Value; DataRoot = $dataRoot
            }
        }
    }
    return $out
}

function Get-ArpEntries {
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    $out = @()
    foreach ($r in $roots) {
        foreach ($k in @(Get-ChildItem $r -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue
            if (-not $p -or -not $p.DisplayName) { continue }
            $year = Get-SqlYearFromName -Name $p.DisplayName
            if (-not $year) { continue }
            $out += [pscustomobject]@{
                Name = '' + $p.DisplayName; Version = '' + $p.DisplayVersion; Year = $year
                Major = $SqlYearToMajor[$year]; KeyName = $k.PSChildName
                ProductCode = Get-MsiProductCode -KeyName $k.PSChildName -UninstallString ('' + $p.UninstallString)
            }
        }
    }
    return ($out | Sort-Object Name -Unique)
}

function Get-LocalDbVersions {
    $out = @()
    foreach ($v in $SqlViews) {
        $k = $v.Root + ' Local DB\Installed Versions'
        foreach ($c in @(Get-ChildItem $k -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty $c.PSPath -ErrorAction SilentlyContinue
            $ver = ConvertTo-SafeVersion $c.PSChildName
            if ($ver) { $out += [pscustomobject]@{ Version = $c.PSChildName; Major = $ver.Major; Dll = '' + $p.InstanceAPIPath } }
        }
    }
    return $out
}

function Find-SqlSetupExe {
    param([int]$Major)
    foreach ($pf in $ProgramFilesRoots) {
        $boot = $pf + '\Microsoft SQL Server\' + ($Major * 10) + '\Setup Bootstrap'
        if (-not (Test-Path -LiteralPath $boot)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $boot -Filter 'setup.exe' -File -Recurse -Depth 2 -ErrorAction SilentlyContinue)) {
            $v = ConvertTo-SafeVersion ('' + $f.VersionInfo.ProductVersion)
            if ($v -and $v.Major -eq $Major) { return $f.FullName }
        }
    }
    return ''
}

function Invoke-Installer {
    # Full path + -NoNewWindow: a bare filename goes through ShellExecute and
    # can fail under EC's SYSTEM context.
    param([string]$Path, [string[]]$Arguments, [int]$TimeoutMinutes)
    Write-Log ('  Running: ' + $Path + ' ' + ($Arguments -join ' '))
    $p = Start-Process -FilePath $Path -ArgumentList $Arguments -NoNewWindow -PassThru
    # Without an open handle, ExitCode is empty after WaitForExit(timeout).
    $null = $p.Handle
    if (-not $p.WaitForExit($TimeoutMinutes * 60 * 1000)) {
        Write-Log ('  Still running after ' + $TimeoutMinutes + ' minutes; leaving it to finish.') -Level ERROR
        return -1
    }
    $p.WaitForExit()
    $code = $p.ExitCode
    Write-Log ('  Exit code: ' + $(if ($null -eq $code) { '(not reported)' } else { $code }))
    return $code
}

function Invoke-MsiUninstall {
    param([pscustomobject]$Entry)
    $log = $LogDir + '\RemoveUnsupportedSql_msi_' + ($Entry.ProductCode -replace '[{}]', '') + '.log'
    $dq = [string][char]34
    return (Invoke-Installer -Path $Msiexec -Arguments @('/x', $Entry.ProductCode, '/qn', '/norestart', '/l*v', ($dq + $log + $dq)) -TimeoutMinutes 20)
}

function Write-Inventory {
    param([object[]]$Instances, [object[]]$LocalDb, [object[]]$Arp)
    if ($Instances.Count -eq 0) { Write-Log '  Engine instances : none' }
    foreach ($i in $Instances) {
        $tag = $(if (Test-SqlMajorUnsupported -Major $i.Major -Today $Today) { 'UNSUPPORTED' } else { 'supported' })
        Write-Log ('  Instance ' + $i.Name + ' : ' + $i.Id + ' (' + $i.View + ')  ' + $i.Edition + '  ' + $i.Version + '  ' + $tag)
    }
    if ($LocalDb.Count -eq 0) { Write-Log '  LocalDB : none' }
    foreach ($l in $LocalDb) {
        $tag = $(if (Test-SqlMajorUnsupported -Major $l.Major -Today $Today) { 'UNSUPPORTED' } else { 'supported' })
        Write-Log ('  LocalDB ' + $l.Version + '  ' + $tag)
    }
    foreach ($a in $Arp) { Write-Log ('  ARP : ' + $a.Name + '  ' + $a.Version) }
}

$Failed = $false
$NeedsHuman = $false
$Reboot = $false
$heldInstances = @()

try {
    Write-Log '=============================================='
    Write-Log ' Remove unsupported SQL Server (plugin 64784)'
    Write-Log (' Host    : ' + $env:COMPUTERNAME)
    Write-Log (' Options : AllowUserDatabases=' + $AllowUserDatabases + ' KeepLocalDB=' + $KeepLocalDB +
        ' KeepSharedComponents=' + $KeepSharedComponents + ' DryRun=' + $DryRun)
    Write-Log '=============================================='

    # ---- 1. Inventory -------------------------------------------------------
    Write-Log '[1] Inventory'
    $instances = @(Get-SqlEngineInstances)
    $localDb = @(Get-LocalDbVersions)
    $arp = @(Get-ArpEntries)
    Write-Inventory -Instances $instances -LocalDb $localDb -Arp $arp
    $badInstances = @($instances | Where-Object { Test-SqlMajorUnsupported -Major $_.Major -Today $Today })
    $badLocalDbMsis = @($arp | Where-Object { (Test-SqlLocalDbName -Name $_.Name) -and (Test-SqlMajorUnsupported -Major $_.Major -Today $Today) })
    $badLocalDbOrphans = @($localDb | Where-Object { (Test-SqlMajorUnsupported -Major $_.Major -Today $Today) })

    # ---- 2. Instances -------------------------------------------------------
    Write-Log '[2] Unsupported engine instances'
    if ($badInstances.Count -eq 0) { Write-Log '  None.' }
    foreach ($i in $badInstances) {
        Write-Log ('  ' + $i.Name + ' (' + $i.Id + ', SQL Server major ' + $i.Major + ', support ended ' + $SqlEndOfSupport[$i.Major] + ')')
        $userDbs = @()
        if ($i.DataRoot -and (Test-Path -LiteralPath ($i.DataRoot + '\DATA'))) {
            $files = @(Get-ChildItem -LiteralPath ($i.DataRoot + '\DATA') -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
            $userDbs = @(Get-UserDatabaseFiles -FileNames $files)
        }
        if ($userDbs.Count -gt 0) {
            Write-Log ('  User database files in ' + $i.DataRoot + '\DATA: ' + ($userDbs -join ', ')) -Level WARN
            if (-not $AllowUserDatabases) {
                Write-Log '  Blocked: an app may still use this instance. Move its databases to a supported' -Level WARN
                Write-Log '  instance, or re-run with -AllowUserDatabases (the files stay on disk).' -Level WARN
                $NeedsHuman = $true
                $heldInstances += $i
                continue
            }
        } else {
            Write-Log '  No user database files in its DATA folder.'
        }
        $setupExe = Find-SqlSetupExe -Major $i.Major
        if (-not $setupExe) {
            Write-Log ('  No setup.exe for major ' + $i.Major + ' under Setup Bootstrap; the MSI pass below handles it.') -Level WARN
            continue
        }
        $uArgs = Get-SqlUninstallArguments -InstanceName $i.Name
        if ($DryRun) { Write-Log ('  [DRYRUN] Would run: ' + $setupExe + ' ' + ($uArgs -join ' ')); continue }
        $code = Invoke-Installer -Path $setupExe -Arguments $uArgs -TimeoutMinutes 60
        switch (Get-InstallOutcome -ExitCode $code) {
            'OK'      { }
            'REBOOT'  { $Reboot = $true }
            'UNKNOWN' { Write-Log '  No exit code; the verify step decides.' -Level WARN }
            'FAIL'    { Write-Log '  setup.exe uninstall failed; the MSI pass below retries the engine packages.' -Level WARN }
            default   { throw 'Unknown outcome' }
        }
    }

    # ---- 3. LocalDB ---------------------------------------------------------
    Write-Log '[3] Unsupported LocalDB'
    if ($KeepLocalDB) {
        Write-Log '  Skipped (-KeepLocalDB).'
    } elseif ($badLocalDbMsis.Count -eq 0 -and $badLocalDbOrphans.Count -eq 0) {
        Write-Log '  None.'
    } else {
        foreach ($l in $badLocalDbOrphans) {
            $msi = @($badLocalDbMsis | Where-Object { $_.Major -eq $l.Major })
            if ($msi.Count -eq 0) { Write-Log ('  LocalDB ' + $l.Version + ' has no uninstallable MSI entry.') -Level WARN }
        }
        foreach ($m in $badLocalDbMsis) {
            if (-not $m.ProductCode) { Write-Log ('  ' + $m.Name + ': no MSI product code; remove it by hand.') -Level WARN; continue }
            if ($DryRun) { Write-Log ('  [DRYRUN] Would remove ' + $m.Name + ' ' + $m.ProductCode); continue }
            $binn = '\Microsoft SQL Server\' + ($m.Major * 10) + '\LocalDB\Binn\'
            foreach ($p in @(Get-Process -Name sqlservr -ErrorAction SilentlyContinue)) {
                $path = ''
                try { $path = '' + $p.Path } catch { }
                if ($path -and $path.ToLowerInvariant().Contains($binn.ToLowerInvariant())) {
                    Write-Log ('  Stopping LocalDB sqlservr.exe PID ' + $p.Id)
                    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                }
            }
            Write-Log ('  Removing ' + $m.Name)
            switch (Get-InstallOutcome -ExitCode (Invoke-MsiUninstall -Entry $m)) {
                'OK'      { }
                'REBOOT'  { $Reboot = $true }
                'UNKNOWN' { }
                'FAIL'    { Write-Log ('  ' + $m.Name + ' did not uninstall.') -Level ERROR }
                default   { throw 'Unknown outcome' }
            }
        }
    }

    # ---- 4. Leftover engine MSIs -------------------------------------------
    Write-Log '[4] Leftover engine components'
    if ($KeepSharedComponents) {
        Write-Log '  Skipped (-KeepSharedComponents).'
    } else {
        $leftovers = @(Get-ArpEntries | Where-Object {
            (Test-SqlMajorUnsupported -Major $_.Major -Today $Today) -and (Test-SqlLeftoverName -Name $_.Name) -and $_.ProductCode
        })
        $removable = @()
        foreach ($e in $leftovers) {
            # Held instances keep their engine packages; a failed or missing
            # setup.exe uninstall falls through to this MSI pass.
            $blocked = @($heldInstances | Where-Object { $_.Major -eq $e.Major })
            if ($blocked.Count -gt 0) {
                Write-Log ('  Keeping ' + $e.Name + ': instance ' + $blocked[0].Name + ' was not removed.')
            } else {
                $removable += $e
            }
        }
        if ($removable.Count -eq 0) { Write-Log '  Nothing to remove.' }
        # Engine services before shared/setup packages, so dependencies go first.
        $ordered = @($removable | Sort-Object @{ Expression = { if ($_.Name -match '(?i)Database Engine Services') { 0 } elseif ($_.Name -match '(?i)Setup') { 2 } else { 1 } } }, Name)
        foreach ($e in $ordered) {
            if ($DryRun) { Write-Log ('  [DRYRUN] Would remove ' + $e.Name + ' ' + $e.ProductCode); continue }
            Write-Log ('  Removing ' + $e.Name)
            switch (Get-InstallOutcome -ExitCode (Invoke-MsiUninstall -Entry $e)) {
                'OK'      { }
                'REBOOT'  { $Reboot = $true }
                'UNKNOWN' { }
                'FAIL'    { Write-Log ('  ' + $e.Name + ' did not uninstall.') -Level WARN }
                default   { throw 'Unknown outcome' }
            }
        }
    }

    # ---- 5. Verify ----------------------------------------------------------
    if (-not $DryRun) {
        Write-Log '[5] Verify'
        $instances = @(Get-SqlEngineInstances)
        $localDb = @(Get-LocalDbVersions)
        $arp = @(Get-ArpEntries)
        Write-Inventory -Instances $instances -LocalDb $localDb -Arp $arp
        $left = @($instances | Where-Object { Test-SqlMajorUnsupported -Major $_.Major -Today $Today })
        if (-not $KeepLocalDB) {
            $left += @($localDb | Where-Object { Test-SqlMajorUnsupported -Major $_.Major -Today $Today } | ForEach-Object { [pscustomobject]@{ Name = ('LocalDB ' + $_.Version) } })
        }
        $blockedNames = @($heldInstances | ForEach-Object { $_.Name })
        $unexpected = @($left | Where-Object { $blockedNames -notcontains $_.Name })
        if ($unexpected.Count -gt 0) {
            if ($Reboot) {
                Write-Log ('  Still registered: ' + (($unexpected | ForEach-Object { $_.Name }) -join ', ') + ' -- expected until the reboot.') -Level WARN
            } else {
                Write-Log ('  Still installed: ' + (($unexpected | ForEach-Object { $_.Name }) -join ', ')) -Level ERROR
                Write-Log ('  Setup logs: <Program Files>\Microsoft SQL Server\<NNN>\Setup Bootstrap\Log; MSI logs: ' + $LogDir) -Level ERROR
                $Failed = $true
            }
        } elseif (-not $NeedsHuman) {
            Write-Log '  No unsupported SQL Server engine or LocalDB remains.'
        }
    }
} catch {
    Write-Log ('Unhandled: ' + $_.Exception.Message) -Level ERROR
    $Failed = $true
}

$final = Get-FinalExitCode -Failed $Failed -NeedsHuman $NeedsHuman -Reboot $Reboot
Write-Log ('===== END (exit ' + $final + ') =====')
Write-Log ('Log: ' + $LogFile)
exit $final
