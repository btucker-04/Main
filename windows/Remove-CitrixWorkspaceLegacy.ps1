<#
.SYNOPSIS
    Removes old Citrix Workspace app / Citrix Receiver copies that
    Update-CitrixWorkspace.ps1 cannot see: per-user installs and leftover
    files. Nessus plugin 207238 (CTX691485) and other CWA version findings.

.DESCRIPTION
    CSPRLT-94 (2026-10-15): plugin 207238 RESURFACED (CWA older than 2402
    LTSR CU1), while Update-CitrixWorkspace.ps1 reported 'Citrix Workspace :
    not installed' -- it reads the machine-wide Add/Remove Programs entries
    only. The old copy is elsewhere:
      * a per-user install: CWA installed without admin rights lives in
        %LOCALAPPDATA%\Citrix\ICA Client and registers under that user's
        HKCU uninstall key, which SYSTEM does not read by default;
      * leftover files: an uninstall that left ICA Client binaries (and the
        PluginPackages version key) behind with no uninstall entry.

    Steps:
      1. Inventory, every source logged:
           * machine uninstall entries (both registry views)
           * every user's uninstall entries: loaded hives under HKEY_USERS,
             and each unloaded profile's NTUSER.DAT, loaded temporarily
           * ICA Client binaries (wfica32.exe / wfica.exe) in Program Files,
             Program Files (x86) and each profile's AppData\Local\Citrix
           * HKLM Citrix\PluginPackages\XenAppSuite\ICA_Client Version
         Anything below -MinVersion's default (26.7, the fleet target) is old.
      2. Defer (exit 2) while a Citrix session is open, unless -ForceClose.
      3. Per-user installs: run that install's TrolleyExpress.exe /uninstall
         /cleanup /silent. Whatever is left (files, uninstall key, Run
         entries pointing into the folder) is then deleted directly.
      4. Leftover machine files with no machine uninstall entry: delete
         ICA Client, SelfServicePlugin and AuthManager under Program Files
         \Citrix and the PluginPackages\XenAppSuite\ICA_Client key. Other
         Citrix products in Program Files\Citrix are not touched.
      5. An old machine-wide install (normal uninstall entry) is upgraded by
         Update-CitrixWorkspace.ps1, so it is only reported -- unless
         -IncludeMachineInstall, which uninstalls it with its TrolleyExpress.
      6. Verify by re-reading the inventory.
      7. -ReinstallMachineWide: run the staged Update-CitrixWorkspace.ps1
         -InstallIfMissing so the user keeps a current, machine-wide CWA.

.PARAMETER ForceClose
    Close open Citrix sessions and CWA processes instead of deferring.

.PARAMETER IncludeMachineInstall
    Also uninstall an old machine-wide CWA (normally left for
    Update-CitrixWorkspace.ps1 to upgrade).

.PARAMETER ReinstallMachineWide
    After cleanup, run Update-CitrixWorkspace.ps1 -InstallIfMissing (stage
    it and the CWA installers beside this script).

.PARAMETER DryRun
    Report what would happen; change nothing.

.NOTES
    Deploy via Endpoint Central (SYSTEM), -File invocation.
    Script Arguments: bare switches only, e.g. -ReinstallMachineWide
    Specify exit code(s): 0,3010
    Log: C:\Logs\CompoSecure\CitrixWorkspaceLegacy_<timestamp>.log
    Exit: 0 = nothing old left / 3010 = done, reboot needed /
          2 = deferred (session open) or old machine install left for the
              upgrade / 1 = failed or still present
#>
[CmdletBinding()]
param(
    [switch]$ForceClose,
    [switch]$IncludeMachineInstall,
    [switch]$ReinstallMachineWide,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

$MinVersion = [version]'26.7'
$SessionProcesses = @('wfica32', 'wfica', 'CDViewer')
$CwaProcesses     = @('wfica32', 'wfica', 'CDViewer', 'SelfService', 'SelfServicePlugin', 'Receiver', 'concentr', 'redirector', 'AuthManSvr', 'WebHelper', 'TrolleyExpress')
$MachineFolders   = @('ICA Client', 'SelfServicePlugin', 'AuthManager')
$UserFolders      = @('ICA Client', 'SelfService', 'AuthManager')

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

function Test-CwaMainEntryName {
    # Main product entries only. Component entries ('Citrix Workspace(DV)',
    # 'Citrix Workspace Inside', 'Citrix Authentication Manager') are
    # removed by the main entry's uninstaller.
    param([string]$Name)
    return ($Name -match '^Citrix Workspace \d{4}( \((x64|ARM64)\))?$' -or $Name -match '^Citrix Receiver( \d+(\.\d+)*)?( LTSR)?$')
}

function Test-CwaVersionOld {
    param($Version, [version]$Min)
    if (-not $Version) { return $true }
    return ($Version -lt $Min)
}

function Get-TrolleyExpressPath {
    # Quoted or bare C:\...\TrolleyExpress.exe followed by /uninstall /cleanup -> the exe path.
    param([string]$UninstallString)
    $m = [regex]::Match('' + $UninstallString, '(?i)^\s*' + [char]34 + '?([^' + [char]34 + ']*?TrolleyExpress\.exe)')
    if ($m.Success) { return $m.Groups[1].Value }
    return ''
}

function Get-TrolleyUninstallArguments {
    return @('/uninstall', '/cleanup', '/silent')
}

function Test-RunValueInFolder {
    # Run-key value data points into a folder being removed.
    param([string]$Data, [string]$Folder)
    if (-not $Data -or -not $Folder) { return $false }
    $f = $Folder.TrimEnd('\') + '\'
    return ($Data.Replace([string][char]34, '').ToLowerInvariant().Contains($f.ToLowerInvariant()))
}

function Get-InstallOutcome {
    param($ExitCode)
    if ($null -eq $ExitCode -or ('' + $ExitCode) -eq '') { return 'UNKNOWN' }
    switch ([int]$ExitCode) {
        0       { return 'OK' }
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

if ($env:CWA_LEGACY_DOTSOURCE -eq '1') { return }

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
$LogFile = $LogDir + '\CitrixWorkspaceLegacy_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log'
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$RegExe = $env:WINDIR + '\System32\reg.exe'
$UninstallSub = 'Software\Microsoft\Windows\CurrentVersion\Uninstall'
$RunSub = 'Software\Microsoft\Windows\CurrentVersion\Run'
$PluginKeys = @('HKLM:\SOFTWARE\Citrix\PluginPackages\XenAppSuite\ICA_Client', 'HKLM:\SOFTWARE\WOW6432Node\Citrix\PluginPackages\XenAppSuite\ICA_Client')
$ProgramFilesRoots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ } | Select-Object -Unique
$script:LoadedHives = @()

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

function Get-UserProfiles {
    # Objects: Sid, User, Path, Hive ('Registry::HKEY_USERS\<sid or temp>').
    # Unloaded hives are loaded under HKU\CWALEGACY_<n> until Close-UserHives.
    $out = @()
    $loaded = @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | ForEach-Object { $_.PSChildName })
    $n = 0
    foreach ($k in @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue)) {
        $sid = $k.PSChildName
        if ($sid -notmatch '^S-1-5-21-') { continue }
        $path = '' + (Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
        if (-not $path -or -not (Test-Path -LiteralPath $path)) { continue }
        $user = Split-Path -Leaf $path
        if ($loaded -contains $sid) {
            $out += [pscustomobject]@{ Sid = $sid; User = $user; Path = $path; Hive = ('Registry::HKEY_USERS\' + $sid) }
            continue
        }
        $dat = $path + '\NTUSER.DAT'
        if (-not (Test-Path -LiteralPath $dat)) { continue }
        $n++
        $name = 'CWALEGACY_' + $n
        & $RegExe load ('HKU\' + $name) $dat 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $script:LoadedHives += $name
            $out += [pscustomobject]@{ Sid = $sid; User = $user; Path = $path; Hive = ('Registry::HKEY_USERS\' + $name) }
        } else {
            Write-Log ('  Could not load the registry of ' + $user + ' (in use?); checking its files only.') -Level WARN
            $out += [pscustomobject]@{ Sid = $sid; User = $user; Path = $path; Hive = '' }
        }
    }
    return $out
}

function Close-UserHives {
    [gc]::Collect()
    [gc]::WaitForPendingFinalizers()
    foreach ($h in $script:LoadedHives) { & $RegExe unload ('HKU\' + $h) 2>&1 | Out-Null }
    $script:LoadedHives = @()
}

function Get-UninstallEntries {
    param([string]$Key, [string]$Scope, [string]$User)
    $out = @()
    foreach ($k in @(Get-ChildItem -LiteralPath $Key -ErrorAction SilentlyContinue)) {
        $p = Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue
        if (-not $p -or -not (Test-CwaMainEntryName -Name ('' + $p.DisplayName))) { continue }
        $out += [pscustomobject]@{
            Scope = $Scope; User = $User; Name = '' + $p.DisplayName
            Version = ConvertTo-SafeVersion ('' + $p.DisplayVersion); KeyPath = $k.PSPath
            Trolley = Get-TrolleyExpressPath -UninstallString ('' + $p.UninstallString)
        }
    }
    return $out
}

function Get-IcaBinary {
    # The first wfica32.exe / wfica.exe in an ICA Client folder, with its version.
    param([string]$Folder)
    foreach ($n in @('wfica32.exe', 'wfica.exe')) {
        $f = Join-Path $Folder $n
        if (Test-Path -LiteralPath $f) {
            $vi = (Get-Item -LiteralPath $f).VersionInfo
            $v = ConvertTo-SafeVersion ('' + $vi.ProductVersion)
            if (-not $v) { $v = ConvertTo-SafeVersion ('' + $vi.FileVersion) }
            return [pscustomobject]@{ Path = $f; Version = $v }
        }
    }
    return $null
}

function Get-Inventory {
    param([object[]]$Profiles)
    $inv = [pscustomobject]@{ Machine = @(); MachineFiles = @(); PluginVersions = @(); Users = @() }
    foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
        $inv.Machine += @(Get-UninstallEntries -Key $k -Scope 'Machine' -User '')
    }
    foreach ($pf in $ProgramFilesRoots) {
        $b = Get-IcaBinary -Folder ($pf + '\Citrix\ICA Client')
        if ($b) { $inv.MachineFiles += $b }
    }
    foreach ($k in $PluginKeys) {
        $p = Get-ItemProperty $k -ErrorAction SilentlyContinue
        if ($p -and $p.Version) { $inv.PluginVersions += [pscustomobject]@{ Key = $k; Version = ConvertTo-SafeVersion ('' + $p.Version) } }
    }
    foreach ($u in $Profiles) {
        $entries = @()
        if ($u.Hive) { $entries = @(Get-UninstallEntries -Key ($u.Hive + '\' + $UninstallSub) -Scope 'User' -User $u.User) }
        $citrixDir = $u.Path + '\AppData\Local\Citrix'
        $inv.Users += [pscustomobject]@{
            Profile = $u; Entries = $entries; CitrixDir = $citrixDir
            Binary = Get-IcaBinary -Folder ($citrixDir + '\ICA Client')
        }
    }
    return $inv
}

function Format-Ver { param($V) if ($V) { return ('' + $V) } else { return 'unknown' } }

function Write-Inventory {
    param($Inv)
    if ($Inv.Machine.Count -eq 0) { Write-Log '  Machine install : none in Add/Remove Programs' }
    foreach ($e in $Inv.Machine) { Write-Log ('  Machine install : ' + $e.Name + '  ' + (Format-Ver $e.Version) + $(if (Test-CwaVersionOld -Version $e.Version -Min $MinVersion) { '  OLD' } else { '' })) }
    foreach ($b in $Inv.MachineFiles) { Write-Log ('  Machine files   : ' + $b.Path + '  ' + (Format-Ver $b.Version) + $(if (Test-CwaVersionOld -Version $b.Version -Min $MinVersion) { '  OLD' } else { '' })) }
    foreach ($p in $Inv.PluginVersions) { Write-Log ('  Plugin key      : ' + $p.Key + '  ' + (Format-Ver $p.Version)) }
    $any = $false
    foreach ($u in $Inv.Users) {
        foreach ($e in $u.Entries) { $any = $true; Write-Log ('  User ' + $u.Profile.User + ' install : ' + $e.Name + '  ' + (Format-Ver $e.Version) + $(if (Test-CwaVersionOld -Version $e.Version -Min $MinVersion) { '  OLD' } else { '' })) }
        if ($u.Binary) { $any = $true; Write-Log ('  User ' + $u.Profile.User + ' files   : ' + $u.Binary.Path + '  ' + (Format-Ver $u.Binary.Version) + $(if (Test-CwaVersionOld -Version $u.Binary.Version -Min $MinVersion) { '  OLD' } else { '' })) }
    }
    if (-not $any) { Write-Log ('  Per-user installs : none (' + $Inv.Users.Count + ' profiles checked)') }
}

function Get-OldUserTargets {
    param($Inv)
    $t = @()
    foreach ($u in $Inv.Users) {
        $oldEntries = @($u.Entries | Where-Object { Test-CwaVersionOld -Version $_.Version -Min $MinVersion })
        $oldFiles = ($u.Binary -and (Test-CwaVersionOld -Version $u.Binary.Version -Min $MinVersion))
        $current = @($u.Entries | Where-Object { -not (Test-CwaVersionOld -Version $_.Version -Min $MinVersion) })
        if ($oldEntries.Count -gt 0 -or ($oldFiles -and $current.Count -eq 0)) {
            $t += [pscustomobject]@{ User = $u; OldEntries = $oldEntries }
        }
    }
    return $t
}

function Get-MachineLeftoverOld {
    # Old machine files / plugin key with no machine uninstall entry.
    param($Inv)
    if ($Inv.Machine.Count -gt 0) { return $false }
    $files = @($Inv.MachineFiles | Where-Object { Test-CwaVersionOld -Version $_.Version -Min $MinVersion })
    $keys = @($Inv.PluginVersions | Where-Object { Test-CwaVersionOld -Version $_.Version -Min $MinVersion })
    return ($files.Count -gt 0 -or $keys.Count -gt 0)
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

function Invoke-TrolleyUninstall {
    param($Entry)
    if (-not $Entry.Trolley -or -not (Test-Path -LiteralPath $Entry.Trolley)) {
        Write-Log ('  No TrolleyExpress.exe for ' + $Entry.Name + '; removing it directly.') -Level WARN
        return
    }
    $outcome = Get-InstallOutcome -ExitCode (Invoke-Installer -Path $Entry.Trolley -Arguments (Get-TrolleyUninstallArguments) -TimeoutMinutes 30)
    switch ($outcome) {
        'OK'      { }
        'REBOOT'  { $script:Reboot = $true }
        'UNKNOWN' { }
        'FAIL'    { Write-Log '  Uninstaller reported failure; removing what is left directly.' -Level WARN }
        default   { throw 'Unknown outcome' }
    }
}

function Remove-PathQuiet {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    try {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        Write-Log ('  Deleted ' + $Path)
    } catch {
        Write-Log ('  Could not delete ' + $Path + ': ' + $_.Exception.Message) -Level WARN
    }
}

function Remove-UserLeftovers {
    param($Target)
    $u = $Target.User
    foreach ($f in $UserFolders) { Remove-PathQuiet -Path ($u.CitrixDir + '\' + $f) }
    foreach ($d in @(Get-ChildItem -LiteralPath $u.CitrixDir -Directory -Filter 'Citrix Workspace *' -ErrorAction SilentlyContinue)) {
        Remove-PathQuiet -Path $d.FullName
    }
    if (-not $u.Profile.Hive) { return }
    foreach ($e in $Target.OldEntries) {
        if (Test-Path -LiteralPath $e.KeyPath) {
            Remove-Item -LiteralPath $e.KeyPath -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log ('  Removed uninstall entry ' + $e.Name + ' for ' + $u.Profile.User)
        }
    }
    $runKey = $u.Profile.Hive + '\' + $RunSub
    $run = Get-ItemProperty -LiteralPath $runKey -ErrorAction SilentlyContinue
    if ($run) {
        foreach ($p in $run.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            if (Test-RunValueInFolder -Data ('' + $p.Value) -Folder $u.CitrixDir) {
                Remove-ItemProperty -LiteralPath $runKey -Name $p.Name -ErrorAction SilentlyContinue
                Write-Log ('  Removed startup entry ' + $p.Name + ' for ' + $u.Profile.User)
            }
        }
    }
}

$Failed = $false
$NeedsHuman = $false
$Deferred = $false
$script:Reboot = $false

try {
    Write-Log '=============================================='
    Write-Log ' Remove old Citrix Workspace app copies'
    Write-Log (' Host    : ' + $env:COMPUTERNAME)
    Write-Log (' Options : ForceClose=' + $ForceClose + ' IncludeMachineInstall=' + $IncludeMachineInstall +
        ' ReinstallMachineWide=' + $ReinstallMachineWide + ' DryRun=' + $DryRun + '  (old = below ' + $MinVersion + ')')
    Write-Log '=============================================='

    # ---- 1. Inventory -------------------------------------------------------
    Write-Log '[1] Inventory'
    $profiles = @(Get-UserProfiles)
    $inv = Get-Inventory -Profiles $profiles
    Write-Inventory -Inv $inv
    $userTargets = @(Get-OldUserTargets -Inv $inv)
    $machineLeftover = Get-MachineLeftoverOld -Inv $inv
    $machineOld = @($inv.Machine | Where-Object { Test-CwaVersionOld -Version $_.Version -Min $MinVersion })
    $work = ($userTargets.Count -gt 0 -or $machineLeftover -or $machineOld.Count -gt 0)

    if (-not $work) {
        Write-Log '  Nothing old to remove.'
    } else {
        # ---- 2. Sessions ----------------------------------------------------
        Write-Log '[2] Open Citrix sessions'
        $open = @(Get-Process -Name $SessionProcesses -ErrorAction SilentlyContinue)
        if ($open.Count -gt 0 -and -not $ForceClose) {
            Write-Log ('  Session open (' + (($open | ForEach-Object { $_.ProcessName }) -join ', ') + '); deferring. Use -ForceClose to close it.') -Level WARN
            $NeedsHuman = $true
            $Deferred = $true
        } else {
            Write-Log $(if ($open.Count) { '  Closing them (-ForceClose).' } else { '  None.' })
            if (-not $DryRun) {
                Get-Process -Name $CwaProcesses -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            }

            # ---- 3. Per-user installs ---------------------------------------
            Write-Log '[3] Per-user installs'
            if ($userTargets.Count -eq 0) { Write-Log '  None old.' }
            foreach ($t in $userTargets) {
                Write-Log ('  ' + $t.User.Profile.User + ' (' + $t.User.CitrixDir + ')')
                if ($DryRun) {
                    foreach ($e in $t.OldEntries) { Write-Log ('  [DRYRUN] Would run ' + $e.Trolley + ' ' + ((Get-TrolleyUninstallArguments) -join ' ')) }
                    Write-Log '  [DRYRUN] Would then delete what is left (ICA Client, SelfService, AuthManager, uninstall entry, startup entries).'
                    continue
                }
                foreach ($e in $t.OldEntries) { Invoke-TrolleyUninstall -Entry $e }
                Remove-UserLeftovers -Target $t
            }

            # ---- 4. Machine leftovers ---------------------------------------
            Write-Log '[4] Machine-wide leftovers'
            if (-not $machineLeftover) {
                Write-Log '  None.'
            } else {
                foreach ($pf in $ProgramFilesRoots) {
                    foreach ($f in $MachineFolders) {
                        $p = $pf + '\Citrix\' + $f
                        if (-not (Test-Path -LiteralPath $p)) { continue }
                        if ($DryRun) { Write-Log ('  [DRYRUN] Would delete ' + $p) } else { Remove-PathQuiet -Path $p }
                    }
                }
                foreach ($k in $PluginKeys) {
                    if (-not (Test-Path $k)) { continue }
                    if ($DryRun) { Write-Log ('  [DRYRUN] Would delete ' + $k) }
                    else { Remove-Item -Path $k -Recurse -Force -ErrorAction SilentlyContinue; Write-Log ('  Deleted ' + $k) }
                }
            }

            # ---- 5. Old machine-wide install --------------------------------
            if ($machineOld.Count -gt 0) {
                Write-Log '[5] Old machine-wide install'
                foreach ($e in $machineOld) {
                    if ($ReinstallMachineWide -and -not $IncludeMachineInstall) {
                        Write-Log ('  ' + $e.Name + ' ' + (Format-Ver $e.Version) + ': upgraded in step 7.')
                    } elseif (-not $IncludeMachineInstall) {
                        Write-Log ('  ' + $e.Name + ' ' + (Format-Ver $e.Version) + ': upgrade it with Update-CitrixWorkspace.ps1, or re-run with -IncludeMachineInstall.') -Level WARN
                        $NeedsHuman = $true
                    } elseif ($DryRun) {
                        Write-Log ('  [DRYRUN] Would run ' + $e.Trolley + ' ' + ((Get-TrolleyUninstallArguments) -join ' '))
                    } else {
                        Invoke-TrolleyUninstall -Entry $e
                    }
                }
            }
        }
    }

    # ---- 6. Verify ----------------------------------------------------------
    if ($work -and -not $DryRun -and -not $Deferred) {
        Write-Log '[6] Verify'
        $inv = Get-Inventory -Profiles $profiles
        Write-Inventory -Inv $inv
        $leftUsers = @(Get-OldUserTargets -Inv $inv)
        $leftMachine = Get-MachineLeftoverOld -Inv $inv
        $leftMachineOld = @($inv.Machine | Where-Object { Test-CwaVersionOld -Version $_.Version -Min $MinVersion })
        if ($leftUsers.Count -gt 0 -or $leftMachine -or ($IncludeMachineInstall -and $leftMachineOld.Count -gt 0)) {
            if ($script:Reboot) {
                Write-Log '  Old files are still present; expected until the reboot.' -Level WARN
            } else {
                Write-Log '  Old Citrix Workspace files are still present (locked files are listed above).' -Level ERROR
                $Failed = $true
            }
        } else {
            Write-Log '  No old per-user or leftover Citrix Workspace copy remains.'
        }
    }
} catch {
    Write-Log ('Unhandled: ' + $_.Exception.Message) -Level ERROR
    $Failed = $true
} finally {
    Close-UserHives
}

# ---- 7. Reinstall machine-wide ---------------------------------------------
if ($ReinstallMachineWide -and -not $Failed -and -not $Deferred) {
    Write-Log '[7] Machine-wide install of the current version'
    $upd = $(if ($PSScriptRoot) { Join-Path $PSScriptRoot 'Update-CitrixWorkspace.ps1' } else { '' })
    if (-not $upd -or -not (Test-Path -LiteralPath $upd)) {
        Write-Log '  Update-CitrixWorkspace.ps1 is not staged beside this script.' -Level ERROR
        $Failed = $true
    } else {
        $ps = $env:WINDIR + '\System32\WindowsPowerShell\v1.0\powershell.exe'
        $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $upd, '-InstallIfMissing')
        if ($ForceClose) { $a += '-ForceClose' }
        if ($DryRun) { $a += '-DryRun' }
        Write-Log ('  Running: ' + $ps + ' ' + ($a -join ' '))
        & $ps @a
        $code = $LASTEXITCODE
        Write-Log ('  Update-CitrixWorkspace.ps1 exit code: ' + $code)
        switch ($code) {
            0       { }
            3010    { $script:Reboot = $true }
            2       { $NeedsHuman = $true }
            default { $Failed = $true }
        }
    }
}

$final = Get-FinalExitCode -Failed $Failed -NeedsHuman $NeedsHuman -Reboot $script:Reboot
Write-Log ('===== END (exit ' + $final + ') =====')
Write-Log ('Log: ' + $LogFile)
exit $final
