<#
.SYNOPSIS
    Installs SQL Server 2022 Express from staged offline media, and applies a
    staged SQL Server 2022 cumulative / security update.

.DESCRIPTION
    Steps:
      1. Inventory: SQL Server instances already on the machine (registry
         Instance Names\SQL), .NET Framework release, pending reboot.
      2. Decide per -InstanceName (default SQLEXPRESS):
           * not installed            -> install
           * SQL Server 2022 (16.x)   -> leave; apply a staged update if it
                                         is newer than the instance's build
           * older (2019 = 15.x, ...) -> exit 2 unless -UpgradeExisting
           * newer than 2022          -> leave
      3. Media. Stage SQLEXPR_x64_ENU.exe (Express Core) or
         SQLEXPRADV_x64_ENU.exe (Express Advanced) beside the script. Get
         them from SQL2022-SSEI-Expr.exe -> Download Media. The package is
         extracted to C:\Windows\Temp\SQLEXPR2022 and setup.exe must report
         version 16.x: SQL Server 2019 Express uses the same file name.
         Advanced is picked when -Features needs it (FullText, PolyBase).
      4. Optional update. A staged SQLServer2022-KB<number>-x64.exe
         (cumulative update or GDR) is slipstreamed into a new install
         (/UPDATEENABLED=True /UPDATESOURCE), or applied with /ACTION=Patch
         to an existing 2022 instance. The RTM build (16.0.1000.6) has known
         vulnerabilities, so stage the latest update with the media.
      5. Run setup.exe quietly. Setup runs as SYSTEM under EC, so the
         sysadmins are given explicitly (-SqlSysAdmins, default
         BUILTIN\Administrators) instead of the current user.
      6. Verify: instance registered as MSSQL16.<name>, service running,
         build (PatchLevel) logged. -TcpPort fixes the TCP port afterwards.

    Setup's own logs: C:\Program Files\Microsoft SQL Server\160\Setup
    Bootstrap\Log\Summary.txt (the newest run's folder holds Detail.txt).
    Its Final result and Exit message lines are copied into this log.

    Pending reboot: SQL setup fails its RebootRequiredCheck rule when one is
    pending, so the script defers (exit 2) instead. -IgnorePendingReboot
    passes /SKIPRULES=RebootRequiredCheck.

    64-BIT. SQL Server 2022 is 64-bit only. The EC agent runs scripts in
    32-bit PowerShell, which sees the WOW6432Node registry view, so the
    script relaunches itself as 64-bit.

.PARAMETER InstanceName
    Instance to install. Default SQLEXPRESS (service MSSQL$SQLEXPRESS).
    MSSQLSERVER installs the default instance.

.PARAMETER Features
    Comma-separated setup features. Default SQLEngine. FullText or PolyBase
    need the Express Advanced media.

.PARAMETER SqlSysAdmins
    Comma-separated Windows accounts or groups made sysadmin. Default
    BUILTIN\Administrators.

.PARAMETER SaPassword
    Enables mixed-mode authentication with this sa password. Default is
    Windows authentication only. Masked in this log, but visible in the EC
    script arguments; prefer Windows authentication.

.PARAMETER EnableTcp
    Enable the TCP/IP protocol (off by default for Express). The Windows
    firewall is not changed.

.PARAMETER TcpPort
    Fixed TCP port (implies -EnableTcp). Default 0: dynamic port.

.PARAMETER DataDir
    Root folder for database files (/INSTALLSQLDATADIR). Default: setup's
    default under Program Files.

.PARAMETER MediaPath
    Full path to the SQLEXPR*.exe package, an extracted media folder, or
    its setup.exe. Default: the SQLEXPR*.exe beside the script, then C:\.

.PARAMETER UpgradeExisting
    Upgrade an older SQL Server instance of the same name in place
    (/ACTION=Upgrade). Back up its databases first.

.PARAMETER IgnorePendingReboot
    Install despite a pending reboot (/SKIPRULES=RebootRequiredCheck).

.PARAMETER DryRun
    Report what would happen; change nothing.

.NOTES
    Deploy via Endpoint Central (SYSTEM), -File invocation.
    Dependency files: SQLEXPR_x64_ENU.exe (or SQLEXPRADV_x64_ENU.exe);
    optionally SQLServer2022-KB<number>-x64.exe.
    Script Arguments: e.g. -InstanceName SQLEXPRESS -EnableTcp
    Specify exit code(s): 0,3010
    Log: C:\Logs\CompoSecure\SqlExpress2022_<timestamp>.log
    Exit: 0 = installed or already present / 3010 = done, reboot needed /
          2 = deferred or needs a human (pending reboot, older instance) /
          1 = failed
#>
[CmdletBinding()]
param(
    [string]$InstanceName = 'SQLEXPRESS',
    [string]$Features = 'SQLEngine',
    [string]$SqlSysAdmins = 'BUILTIN\Administrators',
    [string]$SaPassword = '',
    [switch]$EnableTcp,
    [int]$TcpPort = 0,
    [string]$DataDir = '',
    [string]$MediaPath = '',
    [switch]$UpgradeExisting,
    [switch]$IgnorePendingReboot,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

$SqlMajor = 16
$NetFx472Release = 461808
$ExtractTimeoutMinutes = 15
$SetupTimeoutMinutes = 60

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

function Test-SqlInstanceName {
    # Setup's rules: up to 16 characters, starts with a letter or _, then
    # letters, digits, _ or $; DEFAULT is reserved.
    param([string]$Name)
    if (-not $Name -or $Name.Length -gt 16) { return $false }
    if ($Name -eq 'DEFAULT') { return $false }
    return ($Name -match '^[A-Za-z_][A-Za-z0-9_$]*$')
}

function Get-SqlServiceName {
    param([string]$InstanceName)
    if ($InstanceName -eq 'MSSQLSERVER') { return 'MSSQLSERVER' }
    return ('MSSQL$' + $InstanceName)
}

function Get-SqlMajorFromInstanceId {
    # MSSQL16.SQLEXPRESS -> 16; MSSQL10_50.X (2008 R2) -> 10
    param([string]$InstanceId)
    $m = [regex]::Match('' + $InstanceId, '^MSSQL(\d+)(_\d+)?\.')
    if ($m.Success) { return [int]$m.Groups[1].Value }
    return $null
}

function Get-InstanceAction {
    param($ExistingMajor, [bool]$UpgradeExisting)
    if ($null -eq $ExistingMajor) { return 'Install' }
    if ($ExistingMajor -eq $SqlMajor) { return 'Present' }
    if ($ExistingMajor -gt $SqlMajor) { return 'Newer' }
    if ($UpgradeExisting) { return 'Upgrade' }
    return 'OlderNeedsSwitch'
}

function Test-FeaturesNeedAdvanced {
    param([string]$Features)
    return ($Features -match '(?i)(^|,)\s*(FullText|PolyBase\w*)\s*(,|$)')
}

function Select-SqlMedia {
    # Names of staged files -> the one to use, or '' when none fits.
    param([string[]]$Names, [bool]$NeedAdvanced)
    $adv  = @($Names | Where-Object { $_ -like 'SQLEXPRADV*.exe' } | Sort-Object)
    $core = @($Names | Where-Object { $_ -like 'SQLEXPR*.exe' -and $_ -notlike 'SQLEXPRADV*.exe' } | Sort-Object)
    if ($NeedAdvanced) {
        if ($adv.Count) { return $adv[0] }
        return ''
    }
    if ($core.Count) { return $core[0] }
    if ($adv.Count) { return $adv[0] }
    return ''
}

function Select-SqlUpdatePackage {
    # SQLServer2022-KB<number>-x64.exe; the highest KB number wins.
    param([string[]]$Names)
    $best = ''
    $bestKb = -1
    foreach ($n in $Names) {
        $m = [regex]::Match($n, '^(?i)SQLServer2022-KB(\d+)-x64\.exe$')
        if ($m.Success -and [int]$m.Groups[1].Value -gt $bestKb) {
            $bestKb = [int]$m.Groups[1].Value
            $best = $n
        }
    }
    return $best
}

function Test-UpdateNeeded {
    # Unknown update version: $null (do not guess).
    param($InstalledBuild, $UpdateVersion)
    if (-not $UpdateVersion) { return $null }
    if (-not $InstalledBuild) { return $true }
    return ($UpdateVersion -gt $InstalledBuild)
}

function ConvertTo-QuotedArg {
    param([string]$Value)
    $dq = [string][char]34
    return ($dq + $Value + $dq)
}

function Get-SqlInstallArguments {
    param(
        [string]$InstanceName, [string]$Features, [string[]]$SysAdmins,
        [string]$SaPassword, [bool]$EnableTcp, [string]$DataDir,
        [string]$UpdateSource, [bool]$SkipRebootCheck
    )
    $admins = @($SysAdmins | ForEach-Object { ConvertTo-QuotedArg $_.Trim() }) -join ' '
    $a = @(
        '/Q', '/ACTION=Install', '/IACCEPTSQLSERVERLICENSETERMS', '/SUPPRESSPRIVACYSTATEMENTNOTICE',
        ('/FEATURES=' + ($Features -replace '\s', '')),
        ('/INSTANCENAME=' + $InstanceName),
        ('/SQLSYSADMINACCOUNTS=' + $admins),
        '/ADDCURRENTUSERASSQLADMIN=False',
        '/SQLSVCSTARTUPTYPE=Automatic',
        ('/TCPENABLED=' + $(if ($EnableTcp) { '1' } else { '0' })),
        '/NPENABLED=0'
    )
    if ($UpdateSource) { $a += @('/UPDATEENABLED=True', ('/UPDATESOURCE=' + (ConvertTo-QuotedArg $UpdateSource))) }
    else { $a += '/UPDATEENABLED=False' }
    if ($SaPassword) { $a += @('/SECURITYMODE=SQL', ('/SAPWD=' + (ConvertTo-QuotedArg $SaPassword))) }
    if ($DataDir) { $a += ('/INSTALLSQLDATADIR=' + (ConvertTo-QuotedArg $DataDir)) }
    if ($SkipRebootCheck) { $a += '/SKIPRULES=RebootRequiredCheck' }
    return $a
}

function Get-SqlUpgradeArguments {
    param([string]$InstanceName, [string]$UpdateSource, [bool]$SkipRebootCheck)
    $a = @('/Q', '/ACTION=Upgrade', '/IACCEPTSQLSERVERLICENSETERMS', '/SUPPRESSPRIVACYSTATEMENTNOTICE', ('/INSTANCENAME=' + $InstanceName))
    if ($UpdateSource) { $a += @('/UPDATEENABLED=True', ('/UPDATESOURCE=' + (ConvertTo-QuotedArg $UpdateSource))) }
    else { $a += '/UPDATEENABLED=False' }
    if ($SkipRebootCheck) { $a += '/SKIPRULES=RebootRequiredCheck' }
    return $a
}

function Get-SqlPatchArguments {
    param([string]$InstanceName)
    return @('/Q', '/ACTION=Patch', '/IACCEPTSQLSERVERLICENSETERMS', ('/INSTANCENAME=' + $InstanceName))
}

function Format-ArgsForLog {
    param([string[]]$Arguments)
    return (($Arguments | ForEach-Object { $_ -replace '^(?i)(/SAPWD=).*$', '$1********' }) -join ' ')
}

function Get-SetupOutcome {
    # UNKNOWN: no exit code was reported; the registry check decides.
    param($ExitCode)
    if ($null -eq $ExitCode -or ('' + $ExitCode) -eq '') { return 'UNKNOWN' }
    switch ([int]$ExitCode) {
        0       { return 'OK' }
        3010    { return 'REBOOT' }
        default { return 'FAIL' }
    }
}

function Get-SetupSummary {
    # Summary.txt -> FinalResult, ExitCode, ExitMessage ('' when absent).
    param([string]$Text)
    $r = [pscustomobject]@{ FinalResult = ''; ExitCode = ''; ExitMessage = '' }
    if (-not $Text) { return $r }
    $m = [regex]::Match($Text, '(?m)^\s*Final result:\s*(.+?)\s*$')
    if ($m.Success) { $r.FinalResult = $m.Groups[1].Value }
    $m = [regex]::Match($Text, '(?m)^\s*Exit code \(Decimal\):\s*(-?\d+)')
    if ($m.Success) { $r.ExitCode = $m.Groups[1].Value }
    $m = [regex]::Match($Text, '(?m)^\s*Exit message:\s*(.+?)\s*$')
    if ($m.Success) { $r.ExitMessage = $m.Groups[1].Value }
    return $r
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

if ($env:SQLEXPRESS_DOTSOURCE -eq '1') { return }

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
$LogFile = $LogDir + '\SqlExpress2022_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log'
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$TempDir    = $env:WINDIR + '\Temp'
$ExtractDir = $TempDir + '\SQLEXPR2022'
$UpdateDir  = $TempDir + '\SQL2022Updates'
$SqlRegRoot = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server'
$SummaryTxt = $env:ProgramFiles + '\Microsoft SQL Server\160\Setup Bootstrap\Log\Summary.txt'

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

function Get-SqlInstances {
    # Objects: Name, Id, Major, Version, PatchLevel, Edition, View. Both
    # registry views: a 32-bit instance registers under WOW6432Node.
    $out = @()
    $roots = @(@('64-bit', $SqlRegRoot), @('32-bit', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server'))
    foreach ($r in $roots) {
        $names = Get-ItemProperty ($r[1] + '\Instance Names\SQL') -ErrorAction SilentlyContinue
        if (-not $names) { continue }
        foreach ($p in $names.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            $setup = Get-ItemProperty ($r[1] + '\' + $p.Value + '\Setup') -ErrorAction SilentlyContinue
            $out += [pscustomobject]@{
                Name       = $p.Name
                Id         = '' + $p.Value
                Major      = Get-SqlMajorFromInstanceId -InstanceId $p.Value
                Version    = $(if ($setup) { '' + $setup.Version } else { '' })
                PatchLevel = $(if ($setup) { '' + $setup.PatchLevel } else { '' })
                Edition    = $(if ($setup) { '' + $setup.Edition } else { '' })
                View       = $r[0]
            }
        }
    }
    return $out
}

function Get-NetFxRelease {
    $k = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction SilentlyContinue
    if ($k -and $k.Release) { return [int]$k.Release }
    return 0
}

function Get-PendingRebootReasons {
    $r = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $r += 'Component Based Servicing' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $r += 'Windows Update' }
    $sm = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
    if ($sm -and $sm.PendingFileRenameOperations) { $r += 'PendingFileRenameOperations' }
    return $r
}

function Get-StagedFiles {
    param([string]$Filter)
    $dirs = @()
    if ($PSScriptRoot) { $dirs += $PSScriptRoot }
    $dirs += 'C:\'
    $files = @()
    foreach ($d in $dirs) {
        if (-not (Test-Path -LiteralPath $d -PathType Container)) { continue }
        $files += @(Get-ChildItem -LiteralPath $d -Filter $Filter -File -ErrorAction SilentlyContinue)
    }
    return $files
}

function Get-FileProductVersion {
    param([string]$Path)
    $vi = (Get-Item -LiteralPath $Path).VersionInfo
    $v = ConvertTo-SafeVersion ('' + $vi.ProductVersion)
    if (-not $v) { $v = ConvertTo-SafeVersion ('' + $vi.FileVersion) }
    return $v
}

function Invoke-Installer {
    # Full path + -NoNewWindow: a bare filename goes through ShellExecute and
    # can fail under EC's SYSTEM context. Returns the exit code, -1 on timeout,
    # or $null if Windows did not report one.
    param([string]$Path, [string[]]$Arguments, [int]$TimeoutMinutes)
    Write-Log ('  Running: ' + $Path + ' ' + (Format-ArgsForLog -Arguments $Arguments))
    $p = Start-Process -FilePath $Path -ArgumentList $Arguments -NoNewWindow -PassThru
    # Without an open handle, ExitCode is empty after WaitForExit(timeout).
    $null = $p.Handle
    if (-not $p.WaitForExit($TimeoutMinutes * 60 * 1000)) {
        Write-Log ('  Still running after ' + $TimeoutMinutes + ' minutes; leaving it to finish.') -Level ERROR
        return -1
    }
    $p.WaitForExit()
    return $p.ExitCode
}

function Write-SetupSummary {
    if (-not (Test-Path -LiteralPath $SummaryTxt)) {
        Write-Log ('  No setup summary at ' + $SummaryTxt)
        return
    }
    $s = Get-SetupSummary -Text (Get-Content -LiteralPath $SummaryTxt -Raw -ErrorAction SilentlyContinue)
    Write-Log ('  Setup summary : ' + $SummaryTxt)
    if ($s.FinalResult) { Write-Log ('    Final result : ' + $s.FinalResult) }
    if ($s.ExitCode) { Write-Log ('    Exit code    : ' + $s.ExitCode) }
    if ($s.ExitMessage) { Write-Log ('    Exit message : ' + $s.ExitMessage) }
}

function Resolve-SetupExe {
    # -MediaPath or the staged package -> setup.exe path ('' on failure).
    param([string]$PackagePath)
    if (Test-Path -LiteralPath $PackagePath -PathType Container) {
        $s = Join-Path $PackagePath 'setup.exe'
        if (Test-Path -LiteralPath $s) { return $s }
        Write-Log ('  No setup.exe in ' + $PackagePath) -Level ERROR
        return ''
    }
    if ((Split-Path -Leaf $PackagePath) -ieq 'setup.exe') { return $PackagePath }
    if (Test-Path -LiteralPath $ExtractDir) { Remove-Item -LiteralPath $ExtractDir -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Log ('  Extracting to ' + $ExtractDir)
    $code = Invoke-Installer -Path $PackagePath -Arguments @('/Q', ('/X:' + $ExtractDir)) -TimeoutMinutes $ExtractTimeoutMinutes
    Write-Log ('  Exit code: ' + $(if ($null -eq $code) { '(not reported)' } else { $code }))
    $s = Join-Path $ExtractDir 'setup.exe'
    if (Test-Path -LiteralPath $s) { return $s }
    $found = Get-ChildItem -LiteralPath $ExtractDir -Filter 'setup.exe' -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { return $found.FullName }
    Write-Log '  Extraction produced no setup.exe.' -Level ERROR
    return ''
}

function Set-SqlTcpPort {
    param([string]$InstanceId, [int]$Port, [string]$ServiceName)
    $k = $SqlRegRoot + '\' + $InstanceId + '\MSSQLServer\SuperSocketNetLib\Tcp'
    if (-not (Test-Path $k)) {
        Write-Log ('  ' + $k + ' not found; TCP port not set.') -Level ERROR
        return $false
    }
    Set-ItemProperty -Path $k -Name Enabled -Value 1
    Set-ItemProperty -Path ($k + '\IPAll') -Name TcpPort -Value ('' + $Port)
    Set-ItemProperty -Path ($k + '\IPAll') -Name TcpDynamicPorts -Value ''
    Restart-Service -Name $ServiceName -Force
    Write-Log ('  TCP port ' + $Port + ' set; ' + $ServiceName + ' restarted.')
    return $true
}

$Failed = $false
$NeedsHuman = $false
$Reboot = $false
$tempUsed = $false

try {
    Write-Log '=============================================='
    Write-Log ' SQL Server 2022 Express install'
    Write-Log (' Host    : ' + $env:COMPUTERNAME)
    Write-Log (' Options : InstanceName=' + $InstanceName + ' Features=' + $Features + ' SqlSysAdmins=' + $SqlSysAdmins +
        ' MixedMode=' + [bool]$SaPassword + ' EnableTcp=' + [bool]($EnableTcp -or $TcpPort -gt 0) + ' TcpPort=' + $TcpPort +
        ' DataDir=' + $DataDir + ' UpgradeExisting=' + $UpgradeExisting + ' IgnorePendingReboot=' + $IgnorePendingReboot + ' DryRun=' + $DryRun)
    Write-Log '=============================================='

    if (-not (Test-SqlInstanceName -Name $InstanceName)) { throw ('Invalid instance name: ' + $InstanceName) }
    if ($Features -notmatch '^[A-Za-z, ]+$') { throw ('Invalid -Features: ' + $Features) }
    if ($SaPassword -and $SaPassword.Contains([string][char]34)) { throw '-SaPassword cannot contain a double quote.' }
    if ($TcpPort -lt 0 -or $TcpPort -gt 65535) { throw ('Invalid -TcpPort: ' + $TcpPort) }
    if (-not [Environment]::Is64BitOperatingSystem) { throw 'SQL Server 2022 needs 64-bit Windows.' }
    $useTcp = ($EnableTcp -or $TcpPort -gt 0)
    $serviceName = Get-SqlServiceName -InstanceName $InstanceName

    # ---- 1. Current state ---------------------------------------------------
    Write-Log '[1] Current state'
    $instances = @(Get-SqlInstances)
    if ($instances.Count -eq 0) { Write-Log '  SQL Server instances : none' }
    foreach ($i in $instances) {
        Write-Log ('  ' + $i.Name + ' : ' + $i.Id + ' (' + $i.View + ')  ' + $i.Edition + '  build ' + $i.PatchLevel)
    }
    $existing = $instances | Where-Object { $_.Name -eq $InstanceName } | Select-Object -First 1
    $netFx = Get-NetFxRelease
    Write-Log ('  .NET Framework 4.x release : ' + $netFx)
    $rebootReasons = @(Get-PendingRebootReasons)
    Write-Log ('  Pending reboot : ' + $(if ($rebootReasons.Count) { $rebootReasons -join ', ' } else { 'no' }))

    $action = Get-InstanceAction -ExistingMajor $(if ($existing) { $existing.Major } else { $null }) -UpgradeExisting ([bool]$UpgradeExisting)
    Write-Log ('  Action for ' + $InstanceName + ' : ' + $action)

    # ---- 2. Staged files ----------------------------------------------------
    Write-Log '[2] Staged files'
    $updateFile = $null
    $updateVersion = $null
    $updName = Select-SqlUpdatePackage -Names @(Get-StagedFiles -Filter 'SQLServer2022-KB*-x64.exe' | ForEach-Object { $_.Name })
    if ($updName) {
        $updateFile = Get-StagedFiles -Filter $updName | Select-Object -First 1
        $updateVersion = Get-FileProductVersion -Path $updateFile.FullName
        Write-Log ('  Update : ' + $updateFile.FullName + '  version ' + $(if ($updateVersion) { $updateVersion } else { 'unknown' }))
    } else {
        Write-Log '  Update : none staged (the instance stays at the media build)'
    }

    $setupExe = ''
    $packagePath = ''
    if ($action -eq 'Install' -or $action -eq 'Upgrade') {
        if ($MediaPath) {
            if (-not (Test-Path -LiteralPath $MediaPath)) { throw ('-MediaPath not found: ' + $MediaPath) }
            $packagePath = $MediaPath
        } else {
            $needAdv = Test-FeaturesNeedAdvanced -Features $Features
            $candidates = @(Get-StagedFiles -Filter 'SQLEXPR*.exe')
            $pick = Select-SqlMedia -Names @($candidates | ForEach-Object { $_.Name }) -NeedAdvanced $needAdv
            if (-not $pick) {
                if ($needAdv) { throw ('-Features ' + $Features + ' needs SQLEXPRADV_x64_ENU.exe (Express Advanced) staged beside the script.') }
                throw 'No SQLEXPR_x64_ENU.exe or SQLEXPRADV_x64_ENU.exe staged beside the script or in C:\.'
            }
            $packagePath = ($candidates | Where-Object { $_.Name -eq $pick } | Select-Object -First 1).FullName
        }
        $pkgVer = $null
        if (Test-Path -LiteralPath $packagePath -PathType Leaf) { $pkgVer = Get-FileProductVersion -Path $packagePath }
        Write-Log ('  Media : ' + $packagePath + '  version ' + $(if ($pkgVer) { $pkgVer } else { 'unknown' }))
        if ($pkgVer -and $pkgVer.Major -ne $SqlMajor) {
            throw ('Staged media is version ' + $pkgVer + ', not SQL Server 2022 (16.x). SQL Server 2019 Express uses the same file name.')
        }
    }

    switch ($action) {
        'Install' { }
        'Upgrade' { Write-Log ('  ' + $InstanceName + ' is ' + $existing.Id + '; upgrading it in place to 2022.') -Level WARN }
        'Present' { Write-Log ('  ' + $InstanceName + ' is already SQL Server 2022 (' + $existing.Edition + ', build ' + $existing.PatchLevel + ').') }
        'Newer' {
            Write-Log ('  ' + $InstanceName + ' is ' + $existing.Id + ', newer than 2022; leaving it.')
        }
        'OlderNeedsSwitch' {
            Write-Log ('  ' + $InstanceName + ' is ' + $existing.Id + ' (' + $existing.Edition + '), older than 2022.') -Level WARN
            Write-Log '  Back up its databases and re-run with -UpgradeExisting, or use another -InstanceName.' -Level WARN
            $NeedsHuman = $true
        }
        default { throw ('Unhandled action: ' + $action) }
    }

    # ---- 3. Prerequisites ---------------------------------------------------
    $runSetup = ($action -eq 'Install' -or $action -eq 'Upgrade')
    $runPatch = $false
    if ($action -eq 'Present' -and $updateFile) {
        $need = Test-UpdateNeeded -InstalledBuild (ConvertTo-SafeVersion $existing.PatchLevel) -UpdateVersion $updateVersion
        if ($null -eq $need) { Write-Log '  Cannot read the update version; not applying it.' -Level WARN }
        elseif ($need) { $runPatch = $true; Write-Log ('  Update ' + $updateVersion + ' is newer than build ' + $existing.PatchLevel + '; applying it.') }
        else { Write-Log '  Instance already at or above the staged update.' }
    }

    if ($runSetup -or $runPatch) {
        Write-Log '[3] Prerequisites'
        if ($runSetup -and $netFx -lt $NetFx472Release) {
            throw ('.NET Framework 4.7.2 or later is required (release ' + $netFx + ' < ' + $NetFx472Release + ').')
        }
        if ($rebootReasons.Count -gt 0) {
            if ($IgnorePendingReboot) {
                Write-Log '  Pending reboot ignored (-IgnorePendingReboot).' -Level WARN
            } else {
                Write-Log '  A reboot is pending; SQL setup would fail its RebootRequiredCheck rule.' -Level WARN
                Write-Log '  Reboot and re-run, or pass -IgnorePendingReboot.' -Level WARN
                $NeedsHuman = $true
                $runSetup = $false
                $runPatch = $false
            }
        }
        if ($runSetup -or $runPatch) { Write-Log '  OK' }
    }

    # ---- 4. Install / upgrade / patch --------------------------------------
    if ($runSetup) {
        Write-Log ('[4] ' + $(if ($action -eq 'Upgrade') { 'Upgrading' } else { 'Installing' }) + ' SQL Server 2022 Express')
        $updateSource = ''
        if ($updateFile) { $updateSource = $UpdateDir }
        $admins = @($SqlSysAdmins -split ',' | Where-Object { $_.Trim() })
        if ($action -eq 'Upgrade') {
            $setupArgs = Get-SqlUpgradeArguments -InstanceName $InstanceName -UpdateSource $updateSource -SkipRebootCheck ([bool]$IgnorePendingReboot)
        } else {
            $setupArgs = Get-SqlInstallArguments -InstanceName $InstanceName -Features $Features -SysAdmins $admins -SaPassword $SaPassword `
                -EnableTcp $useTcp -DataDir $DataDir -UpdateSource $updateSource -SkipRebootCheck ([bool]$IgnorePendingReboot)
        }
        if ($DryRun) {
            Write-Log ('  [DRYRUN] Would extract ' + $packagePath + ' and run setup.exe ' + (Format-ArgsForLog -Arguments $setupArgs))
        } else {
            $tempUsed = $true
            $setupExe = Resolve-SetupExe -PackagePath $packagePath
            if (-not $setupExe) { throw 'No setup.exe to run.' }
            $setupVer = Get-FileProductVersion -Path $setupExe
            Write-Log ('  setup.exe version ' + $setupVer)
            if (-not $setupVer -or $setupVer.Major -ne $SqlMajor) {
                throw ('setup.exe is version ' + $setupVer + ', not SQL Server 2022 (16.x).')
            }
            if ($updateFile) {
                if (Test-Path -LiteralPath $UpdateDir) { Remove-Item -LiteralPath $UpdateDir -Recurse -Force -ErrorAction SilentlyContinue }
                New-Item -ItemType Directory -Path $UpdateDir -Force | Out-Null
                Copy-Item -LiteralPath $updateFile.FullName -Destination $UpdateDir
                Write-Log ('  Slipstreaming ' + $updateFile.Name + ' from ' + $UpdateDir)
            }
            $code = Invoke-Installer -Path $setupExe -Arguments $setupArgs -TimeoutMinutes $SetupTimeoutMinutes
            Write-Log ('  Exit code: ' + $(if ($null -eq $code) { '(not reported)' } else { $code }))
            switch (Get-SetupOutcome -ExitCode $code) {
                'OK'      { }
                'REBOOT'  { $Reboot = $true; Write-Log '  Reboot required to finish.' }
                'UNKNOWN' { Write-Log '  No exit code reported; the registry check below decides.' -Level WARN }
                'FAIL'    { $Failed = $true; Write-Log '  Setup failed.' -Level ERROR }
                default   { throw 'Unknown setup outcome' }
            }
            Write-SetupSummary
        }
    } elseif ($runPatch) {
        Write-Log ('[4] Applying ' + $updateFile.Name)
        $patchArgs = Get-SqlPatchArguments -InstanceName $InstanceName
        if ($DryRun) {
            Write-Log ('  [DRYRUN] Would run: ' + $updateFile.FullName + ' ' + ($patchArgs -join ' '))
        } else {
            $code = Invoke-Installer -Path $updateFile.FullName -Arguments $patchArgs -TimeoutMinutes $SetupTimeoutMinutes
            Write-Log ('  Exit code: ' + $(if ($null -eq $code) { '(not reported)' } else { $code }))
            switch (Get-SetupOutcome -ExitCode $code) {
                'OK'      { }
                'REBOOT'  { $Reboot = $true; Write-Log '  Reboot required to finish.' }
                'UNKNOWN' { Write-Log '  No exit code reported; the build check below decides.' -Level WARN }
                'FAIL'    { $Failed = $true; Write-Log '  Update failed.' -Level ERROR }
                default   { throw 'Unknown setup outcome' }
            }
            Write-SetupSummary
        }
    }

    # ---- 5. Verify ----------------------------------------------------------
    if (($runSetup -or $runPatch) -and -not $DryRun) {
        Write-Log '[5] Verify'
        $now = @(Get-SqlInstances) | Where-Object { $_.Name -eq $InstanceName } | Select-Object -First 1
        if (-not $now -or $now.Major -ne $SqlMajor) {
            Write-Log ('  ' + $InstanceName + ' is not registered as SQL Server 2022.') -Level ERROR
            $Failed = $true
        } else {
            Write-Log ('  ' + $InstanceName + ' : ' + $now.Id + '  ' + $now.Edition + '  build ' + $now.PatchLevel)
            if ($runPatch -and $updateVersion -and (ConvertTo-SafeVersion $now.PatchLevel) -lt $updateVersion -and -not $Reboot) {
                Write-Log ('  Build is still below ' + $updateVersion + '.') -Level ERROR
                $Failed = $true
            }
            $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if (-not $svc) {
                Write-Log ('  Service ' + $serviceName + ' not found.') -Level ERROR
                $Failed = $true
            } else {
                if ($svc.Status -ne 'Running' -and -not $Reboot) {
                    Write-Log ('  ' + $serviceName + ' is ' + $svc.Status + '; starting it.') -Level WARN
                    Start-Service -Name $serviceName -ErrorAction SilentlyContinue
                    $svc.Refresh()
                }
                Write-Log ('  Service ' + $serviceName + ' : ' + $svc.Status + ' (' + $svc.StartType + ')')
                if ($svc.Status -ne 'Running' -and -not $Reboot) { $Failed = $true }
            }
            if ($runSetup -and $TcpPort -gt 0 -and -not $Failed) {
                if (-not (Set-SqlTcpPort -InstanceId $now.Id -Port $TcpPort -ServiceName $serviceName)) { $Failed = $true }
            }
        }
    }
} catch {
    Write-Log ('Unhandled: ' + $_.Exception.Message) -Level ERROR
    $Failed = $true
} finally {
    if ($tempUsed) {
        foreach ($d in @($ExtractDir, $UpdateDir)) {
            if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
}

$final = Get-FinalExitCode -Failed $Failed -NeedsHuman $NeedsHuman -Reboot $Reboot
Write-Log ('===== END (exit ' + $final + ') =====')
Write-Log ('Log: ' + $LogFile)
exit $final
