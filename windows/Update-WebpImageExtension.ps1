<#
.SYNOPSIS
    Remediation: Microsoft WebP Image Extension < 1.2.31.0 RCE
    (Nessus plugin 346896, CVE-2026-70351).

.DESCRIPTION
    Microsoft.WebpImageExtension is an inbox Store (AppX) app. It gives
    Explorer and Photos their .webp support; browsers have their own decoder
    and do not use it. Tenable reads the version in the payload folder name:
      Path : C:\Program Files\WindowsApps\Microsoft.WebpImageExtension_1.2.14.0_x64__8wekyb3d8bbwe
    so the finding clears only when no folder below the fixed version is
    left under WindowsApps.

    Default (update):
      1. Inventory every registration (all users, bundles included), the
         provisioned entry and the payload folders.
      2. Get a fixed build onto the machine:
         a. A staged package beside this script (EC Dependency File) or in
            C:\: Microsoft.WebpImageExtension*.appx/.msix/.appxbundle/
            .msixbundle, plus any Microsoft.VCLibs / UI.Xaml / NET.Native
            dependency packages staged with it. The version and publisher
            are read from the manifest inside the package, not the file
            name. It is provisioned with Add-AppxProvisionedPackage.
         b. Otherwise a Microsoft Store update scan through the MDM bridge
            (MDM_EnterpriseModernAppManagement_AppManagement01
            UpdateScanMethod), which works as SYSTEM. The method returns only
            when the Store finishes its whole update pass (2h51m on CSLT-171,
            7.5 min on CSLT-090), so it runs in its own process and the
            fixed build is polled for meanwhile, up to 15 minutes in all.
            That process is left running at the deadline so the Store can
            still deliver; a later run verifies and cleans up. Before the
            scan the log shows Store policy, the InstallService / wuauserv /
            DoSvc services and port 443 to the Store hosts, which is where
            a host that never gets the update (CSLT-090) differs.
      3. Clean up what still holds the old build. When the fixed build is
         provisioned, older registrations are removed for all users; each
         user gets the provisioned build at their next sign-in. When it
         came from the Store, an older provisioned entry is removed.
      4. Verify by the payload folders, not by any cmdlet's success.

    -Remove deletes the extension instead (all users plus provisioning), as
    Remove-3DViewer.ps1 does. Use it where neither a staged package nor the
    Store is available. Explorer and Photos then stop showing .webp files.

.PARAMETER Remove
    Remove the extension for every user and deprovision it, instead of
    updating it.

.PARAMETER DryRun
    Report the inventory and what would be done; change nothing.

.NOTES
    Deploy via Endpoint Central (SYSTEM), bare switches only. The 32-bit EC
    agent is relaunched into 64-bit PowerShell, which the AppX and DISM
    cmdlets need. Log: C:\Logs\CompoSecure\WebpImageExtension_<timestamp>.log
    Exit: 0 = no vulnerable build left (or not installed); 3010 = the fixed
    build is in place but an old folder is still held, reboot and re-run;
    1 = no fixed build could be installed, or removal failed. EC success
    codes 0,3010.
    To get a staged package: winget download --id 9PG2DK419DRG --source
    msstore on an admin workstation saves the package and its dependencies.
#>

[CmdletBinding()]
param(
    [switch]$Remove,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$PkgName = 'Microsoft.WebpImageExtension'
$FixedVersion = [version]'1.2.31.0'
$StoreWaitSeconds = 900

function Test-Needs64BitRelaunch {
    param([bool]$Is64BitOS, [bool]$Is64BitProcess)
    return ($Is64BitOS -and -not $Is64BitProcess)
}

function Get-RelaunchArguments {
    param([string]$ScriptPath, [bool]$Remove, [bool]$DryRun)
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $ScriptPath)
    if ($Remove) { $a += '-Remove' }
    if ($DryRun) { $a += '-DryRun' }
    return $a
}

function Get-HostAppxArch {
    # PROCESSOR_ARCHITEW6432 is set only inside a 32-bit process on 64-bit
    # Windows and holds the real architecture.
    param([string]$ProcArch, [string]$ProcArchW6432, [bool]$Is64BitOS)
    $a = $(if ($ProcArchW6432) { $ProcArchW6432 } else { $ProcArch })
    switch -Regex ($a) {
        '^(?i)AMD64$' { return 'x64' }
        '^(?i)ARM64$' { return 'arm64' }
        '^(?i)x86$'   { return 'x86' }
    }
    return $(if ($Is64BitOS) { 'x64' } else { 'x86' })
}

function ConvertFrom-PackageFullName {
    # 'Microsoft.WebpImageExtension_1.2.14.0_x64__8wekyb3d8bbwe' ->
    # Name, Version, Arch. A bundle reads ..._neutral_~_8wekyb3d8bbwe.
    param([string]$FullName)
    if ($FullName -notmatch '^([^_]+)_(\d+(?:\.\d+){1,3})_([^_]*)_([^_]*)_([^_]+)$') { return $null }
    $name = $matches[1]; $ver = $matches[2]; $arch = $matches[3]; $res = $matches[4]
    return [pscustomobject]@{ Name = $name; Version = [version]$ver; Arch = $arch; IsBundle = ($res -eq '~') }
}

function Get-PackageManifestInfo {
    # Identity of an .appx/.msix or .appxbundle/.msixbundle, read from the
    # manifest inside the zip. For a bundle, Version is the newest contained
    # application package, not the bundle's own (often date-style) version.
    param([string]$Path)
    if (-not ('System.IO.Compression.ZipFile' -as [type])) {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    }
    $zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $entry = $zip.Entries | Where-Object { $_.FullName -eq 'AppxMetadata/AppxBundleManifest.xml' } | Select-Object -First 1
        $isBundle = [bool]$entry
        if (-not $entry) { $entry = $zip.Entries | Where-Object { $_.FullName -eq 'AppxManifest.xml' } | Select-Object -First 1 }
        if (-not $entry) { return $null }
        $reader = New-Object System.IO.StreamReader($entry.Open())
        try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
    } finally {
        $zip.Dispose()
    }
    $xml = [xml]$text
    if ($isBundle) {
        $apps = @($xml.Bundle.Packages.Package | Where-Object { $_.Type -eq 'application' })
        $best = ($apps | ForEach-Object { [version]$_.Version } | Sort-Object -Descending | Select-Object -First 1)
        return [pscustomobject]@{
            Path = $Path; Name = '' + $xml.Bundle.Identity.Name; Version = $best
            Archs = @($apps | ForEach-Object { '' + $_.Architecture } | Sort-Object -Unique)
            Publisher = '' + $xml.Bundle.Identity.Publisher; IsBundle = $true
        }
    }
    $arch = '' + $xml.Package.Identity.ProcessorArchitecture
    if (-not $arch) { $arch = 'neutral' }
    return [pscustomobject]@{
        Path = $Path; Name = '' + $xml.Package.Identity.Name; Version = [version]$xml.Package.Identity.Version
        Archs = @($arch); Publisher = '' + $xml.Package.Identity.Publisher; IsBundle = $false
    }
}

function Select-StagedPackageSet {
    # From the manifests of every staged file: the newest Microsoft-published
    # main package for this arch, and the newest of each framework dependency.
    param($Infos, [string]$PackageName, [string]$Arch, [version]$Fixed)
    $fits = { param($i) ($i.Archs -contains $Arch) -or ($i.Archs -contains 'neutral') }
    $mains = @(@($Infos) | Where-Object { $_ -and $_.Name -eq $PackageName -and (& $fits $_) })
    $signed = @($mains | Where-Object { $_.Publisher -match 'O=Microsoft Corporation' })
    $best = ($signed | Sort-Object Version -Descending | Select-Object -First 1)
    $deps = @()
    $depNames = @(@($Infos) | Where-Object { $_ -and $_.Name -match '^Microsoft\.(VCLibs|UI\.Xaml|NET\.Native|WindowsAppRuntime)' -and (& $fits $_) } |
        ForEach-Object { $_.Name } | Sort-Object -Unique)
    foreach ($n in $depNames) {
        $deps += (@($Infos) | Where-Object { $_ -and $_.Name -eq $n -and (& $fits $_) } | Sort-Object Version -Descending | Select-Object -First 1)
    }
    $reason = ''
    if ($mains.Count -eq 0) { $reason = 'no ' + $PackageName + ' package for ' + $Arch + ' is staged' }
    elseif (-not $best) { $reason = 'the staged ' + $PackageName + ' package is not published by Microsoft Corporation' }
    elseif ($best.Version -lt $Fixed) { $reason = 'the staged package is ' + $best.Version + ', below the fixed ' + $Fixed }
    if ($reason) { $best = $null }
    return [pscustomobject]@{ Main = $best; Deps = $deps; Reason = $reason }
}

function Get-WebpState {
    # Packages: @{ FullName; Version; Users = @(@{ Sid; Name; State }) }.
    # ProvisionedNames and PayloadDirs are package full names / folder names.
    param($Packages, [string[]]$ProvisionedNames, [string[]]$PayloadDirs, [version]$Fixed)
    $vulnDirs = @(@($PayloadDirs) | Where-Object { $p = ConvertFrom-PackageFullName -FullName $_; $p -and $p.Version -lt $Fixed })
    $vulnPkgs = @(@($Packages) | Where-Object { $_ -and [version]$_.Version -lt $Fixed })
    $vulnProv = @(@($ProvisionedNames) | Where-Object { $p = ConvertFrom-PackageFullName -FullName $_; $p -and $p.Version -lt $Fixed })
    $fixedInstalled = [bool](@($Packages) | Where-Object { $_ -and [version]$_.Version -ge $Fixed })
    $fixedProv = [bool](@($ProvisionedNames) | Where-Object { $p = ConvertFrom-PackageFullName -FullName $_; $p -and $p.Version -ge $Fixed })
    $present = (@($Packages | Where-Object { $_ }).Count + @($PayloadDirs | Where-Object { $_ }).Count + @($ProvisionedNames | Where-Object { $_ }).Count) -gt 0
    $status = 'Fixed'
    if (-not $present) { $status = 'Absent' }
    elseif ($vulnDirs.Count -gt 0 -or $vulnPkgs.Count -gt 0 -or $vulnProv.Count -gt 0) { $status = 'Vulnerable' }
    return [pscustomobject]@{
        Status = $status; VulnerableDirs = $vulnDirs; VulnerablePackages = $vulnPkgs; VulnerableProvisioned = $vulnProv
        FixedInstalled = $fixedInstalled; FixedProvisioned = $fixedProv
    }
}

function Test-SystemStagedOnly {
    # True when every remaining registration is SYSTEM's own Staged entry,
    # which the AppX service finishes removing at the next restart.
    param($Packages)
    $users = @(@($Packages) | Where-Object { $_ } | ForEach-Object { $_.Users } | Where-Object { $_ })
    if ($users.Count -eq 0) { return $false }
    return (@($users | Where-Object { $_.Sid -ne 'S-1-5-18' -or ('' + $_.State) -notmatch 'Staged' }).Count -eq 0)
}

function Get-WebpOutcome {
    # Exit code and one-line result from the end-of-run state.
    param($State, [ValidateSet('update', 'remove')][string]$Mode, [bool]$SystemStagedOnly)
    if ($State.Status -eq 'Absent') {
        if ($Mode -eq 'remove') { return [pscustomobject]@{ Exit = 0; Summary = 'WebP Image Extension removed; nothing left on disk.' } }
        return [pscustomobject]@{ Exit = 0; Summary = 'WebP Image Extension is not installed.' }
    }
    if ($State.Status -eq 'Fixed') {
        return [pscustomobject]@{ Exit = 0; Summary = 'No WebP Image Extension build below the fixed version is left.' }
    }
    if ($Mode -eq 'remove') {
        if ($SystemStagedOnly) { return [pscustomobject]@{ Exit = 3010; Summary = 'Removal queued: only a SYSTEM-staged remnant is left, which a restart finishes. Reboot and re-run.' } }
        return [pscustomobject]@{ Exit = 1; Summary = 'The vulnerable build is still installed after removal.' }
    }
    if ($State.FixedInstalled -or $State.FixedProvisioned) {
        return [pscustomobject]@{ Exit = 3010; Summary = 'The fixed build is in place, but an old build is still held. Reboot (or have the users sign out and in) and re-run.' }
    }
    return [pscustomobject]@{ Exit = 1; Summary = 'No fixed build could be installed. Stage the package, allow the Microsoft Store, or re-run with -Remove.' }
}

function Get-StoreWaitStep {
    # One poll of the Store path. UpdateScanMethod blocks until the Store
    # finishes its whole update pass: 2h51m on CSLT-171 (2026-11-23), 7.5 min
    # on CSLT-090 (2026-11-24). It runs in its own process so the fixed build
    # is seen the moment it lands and the run keeps to its budget.
    param([bool]$FixedPresent, [string]$ScanState, [double]$Elapsed, [int]$Budget)
    if ($FixedPresent) { return 'Arrived' }
    if ($ScanState -eq 'Failed') { return 'ScanFailed' }
    if ($Elapsed -ge $Budget) { return 'TimedOut' }
    return 'Wait'
}

function Get-ScanProcessState {
    # The scan runs in its own powershell.exe so it outlives this script; it
    # exits with UpdateScanMethod's ReturnValue, or 99 when the call threw.
    param([bool]$HasExited, $ExitCode)
    if (-not $HasExited) { return 'Running' }
    if (('' + $ExitCode) -eq '0') { return 'Completed' }
    return 'Failed'
}

function Get-StoreScanCommand {
    param([string]$ResultFile)
    $q = [char]39
    $rf = $q + ($ResultFile -replace $q, ($q + $q)) + $q
    return ('try { $i = Get-CimInstance -Namespace ' + $q + 'root\cimv2\mdm\dmmap' + $q + ' -ClassName ' + $q + 'MDM_EnterpriseModernAppManagement_AppManagement01' + $q + ' -ErrorAction Stop; ' +
        '$r = Invoke-CimMethod -InputObject $i -MethodName UpdateScanMethod -ErrorAction Stop; ' +
        'Set-Content -Path ' + $rf + ' -Value (' + $q + 'ReturnValue ' + $q + ' + $r.ReturnValue); exit ([int]$r.ReturnValue) } ' +
        'catch { Set-Content -Path ' + $rf + ' -Value $_.Exception.Message; exit 99 }')
}

function Get-StorePolicyFindings {
    # HKLM\SOFTWARE\Policies\Microsoft\WindowsStore values that stop the
    # Store from delivering an app update.
    param([hashtable]$Values)
    $out = @()
    if (-not $Values) { return $out }
    if (('' + $Values['RemoveWindowsStore']) -eq '1') { $out += 'RemoveWindowsStore = 1 (Store turned off by policy)' }
    if (('' + $Values['DisableStoreApps']) -eq '1') { $out += 'DisableStoreApps = 1 (all Store apps disabled by policy)' }
    if (('' + $Values['AutoDownload']) -eq '2') { $out += 'AutoDownload = 2 (automatic Store app updates turned off by policy)' }
    if (('' + $Values['RequirePrivateStoreOnly']) -eq '1') { $out += 'RequirePrivateStoreOnly = 1 (only the private store is allowed)' }
    return $out
}

function Get-StoreServiceFindings {
    # Store app updates download through Windows Update and Delivery
    # Optimization and install through InstallService.
    param($Services, [string[]]$Required)
    $out = @()
    foreach ($n in $Required) {
        $s = @($Services | Where-Object { $_.Name -eq $n })[0]
        if (-not $s) { $out += ($n + ' is not present'); continue }
        if (('' + $s.StartType) -eq 'Disabled') { $out += ($n + ' is Disabled') }
    }
    return $out
}

if ($env:WEBP_UPDATE_DOTSOURCE -eq '1') { return }

if (Test-Needs64BitRelaunch -Is64BitOS ([Environment]::Is64BitOperatingSystem) -Is64BitProcess ([Environment]::Is64BitProcess)) {
    $ps64 = $env:WINDIR + '\Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $ps64) {
        $relaunchArgs = Get-RelaunchArguments -ScriptPath $PSCommandPath -Remove $Remove -DryRun $DryRun
        & $ps64 @relaunchArgs
        exit $LASTEXITCODE
    }
}

$LogDir  = 'C:\Logs\CompoSecure'
$LogFile = $LogDir + '\WebpImageExtension_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log'
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

function Read-WebpState {
    $raw = @(Get-AppxPackage -AllUsers -Name $PkgName -PackageTypeFilter All -ErrorAction SilentlyContinue)
    $pkgs = @()
    foreach ($p in $raw) {
        $users = @($p.PackageUserInformation | ForEach-Object {
            $n = $_.UserSecurityId.Username
            if ([string]::IsNullOrWhiteSpace($n)) { $n = '(orphaned SID)' }
            [pscustomobject]@{ Sid = '' + $_.UserSecurityId.Sid; Name = $n; State = '' + $_.InstallState }
        })
        $pkgs += [pscustomobject]@{ FullName = $p.PackageFullName; Version = [version]$p.Version; Users = $users }
    }
    $prov = @(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $PkgName } | ForEach-Object { $_.PackageName })
    $dirs = @(Get-ChildItem -LiteralPath ($env:ProgramFiles + '\WindowsApps') -Directory -Filter ($PkgName + '_*') -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    $state = Get-WebpState -Packages $pkgs -ProvisionedNames $prov -PayloadDirs $dirs -Fixed $FixedVersion
    $state | Add-Member -NotePropertyName Packages -NotePropertyValue $pkgs
    $state | Add-Member -NotePropertyName Provisioned -NotePropertyValue $prov
    $state | Add-Member -NotePropertyName Dirs -NotePropertyValue $dirs
    return $state
}

function Write-WebpState {
    param($State)
    if ($State.Packages.Count -eq 0) { Write-Log '  Registrations: none' }
    foreach ($p in $State.Packages) {
        Write-Log ('  Registered : ' + $p.FullName)
        foreach ($u in $p.Users) { Write-Log ('      ' + $u.Name + ' [' + $u.Sid + '] ' + $u.State) }
    }
    if ($State.Provisioned.Count -eq 0) { Write-Log '  Provisioned: none' }
    foreach ($n in $State.Provisioned) { Write-Log ('  Provisioned: ' + $n) }
    if ($State.Dirs.Count -eq 0) { Write-Log '  Payload    : none under WindowsApps' }
    foreach ($d in $State.Dirs) {
        $lvl = $(if ($State.VulnerableDirs -contains $d) { 'WARN' } else { 'INFO' })
        Write-Log ('  Payload    : ' + $env:ProgramFiles + '\WindowsApps\' + $d) -Level $lvl
    }
    Write-Log ('  Status     : ' + $State.Status + ' (fixed version ' + $FixedVersion + ')')
}

function Remove-WebpRegistrations {
    # Bundles first: a main package inside a staged bundle no-ops on removal
    # until the bundle registration is gone (Remove-3DViewer.ps1 v3).
    param($Packages)
    $ordered = @(@($Packages | Where-Object { $_.FullName -like '*_~_*' }) + @($Packages | Where-Object { $_.FullName -notlike '*_~_*' }))
    foreach ($p in $ordered) {
        Write-Log ('  Removing for all users: ' + $p.FullName)
        try {
            Remove-AppxPackage -Package $p.FullName -AllUsers -ErrorAction Stop
            Write-Log '    Remove-AppxPackage -AllUsers completed.'
        } catch {
            Write-Log ('    Remove-AppxPackage failed: ' + $_.Exception.Message) -Level WARN
        }
    }
}

function Remove-WebpProvisioned {
    param([string[]]$Names)
    foreach ($n in $Names) {
        Write-Log ('  Deprovisioning: ' + $n)
        try {
            Remove-AppxProvisionedPackage -Online -PackageName $n -ErrorAction Stop | Out-Null
            Write-Log '    Deprovisioned.'
        } catch {
            Write-Log ('    Remove-AppxProvisionedPackage failed: ' + $_.Exception.Message) -Level WARN
        }
    }
}

function Find-StagedPackageInfos {
    $infos = @()
    foreach ($d in @(@($PSScriptRoot, 'C:\') | Where-Object { $_ })) {
        if (-not (Test-Path -LiteralPath $d)) { continue }
        $files = @(Get-ChildItem -LiteralPath $d -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -match '^(?i)\.(appx|msix|appxbundle|msixbundle)$' })
        foreach ($f in $files) {
            try {
                $i = Get-PackageManifestInfo -Path $f.FullName
                if ($i) {
                    Write-Log ('  Staged: ' + $f.FullName + ' -> ' + $i.Name + ' ' + $i.Version + ' [' + ($i.Archs -join ',') + ']')
                    $infos += $i
                } else {
                    Write-Log ('  Staged: ' + $f.FullName + ' has no package manifest; ignored.') -Level WARN
                }
            } catch {
                Write-Log ('  Staged: ' + $f.FullName + ' could not be read: ' + $_.Exception.Message) -Level WARN
            }
        }
    }
    return $infos
}

function Write-StoreDiagnostics {
    # What decides whether the Store can deliver at all, logged before the
    # scan so a failed run (CSLT-090) says why.
    $vals = @{}
    $pol = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -ErrorAction SilentlyContinue
    foreach ($n in @('RemoveWindowsStore', 'DisableStoreApps', 'AutoDownload', 'RequirePrivateStoreOnly')) {
        if ($pol -and $null -ne $pol.$n) { $vals[$n] = $pol.$n }
    }
    $policy = @(Get-StorePolicyFindings -Values $vals)
    if ($policy.Count -eq 0) { Write-Log '  Store policy : nothing blocking' }
    foreach ($f in $policy) { Write-Log ('  Store policy : ' + $f) -Level WARN }

    $required = @('InstallService', 'wuauserv', 'DoSvc')
    $svcs = @(Get-Service -Name $required -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{ Name = $_.Name; StartType = ('' + $_.StartType); Status = ('' + $_.Status) }
    })
    Write-Log ('  Services     : ' + (($svcs | ForEach-Object { $_.Name + ' ' + $_.StartType + '/' + $_.Status }) -join ', '))
    foreach ($f in @(Get-StoreServiceFindings -Services $svcs -Required $required)) { Write-Log ('  Service      : ' + $f) -Level WARN }

    foreach ($h in @('storeedgefd.dsx.mp.microsoft.com', 'displaycatalog.mp.microsoft.com', 'fe3cr.delivery.mp.microsoft.com', 'tlu.dl.delivery.mp.microsoft.com')) {
        $r = Test-StoreHostReachable -HostName $h
        if ($r) { Write-Log ('  Reach 443    : ' + $h + ' NO (' + $r + ')') -Level WARN } else { Write-Log ('  Reach 443    : ' + $h + ' ok') }
    }
}

function Test-StoreHostReachable {
    # '' when TCP 443 connects within 5 s, else why not.
    param([string]$HostName)
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        if ($c.ConnectAsync($HostName, 443).Wait(5000) -and $c.Connected) { return '' }
        return 'timed out'
    } catch {
        $e = $_.Exception
        while ($e.InnerException) { $e = $e.InnerException }
        return $e.Message
    } finally { $c.Dispose() }
}

function Wait-StoreDelivery {
    # Returns $true when a fixed build arrived. The scan process is left
    # running at the deadline: the Store finishes its pass on its own.
    $resultFile = $LogDir + '\WebpStoreScan_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.txt'
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes((Get-StoreScanCommand -ResultFile $resultFile)))
    Write-Log '  Requesting a Store update scan. The call returns only when the Store has'
    Write-Log ('  finished its whole pass, so the fixed build is polled for meanwhile (up to ' + $StoreWaitSeconds + 's).')
    try {
        $p = Start-Process -FilePath ($PSHOME + '\powershell.exe') -ArgumentList @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $enc) -WindowStyle Hidden -PassThru
        # Without the handle, Windows PowerShell 5.1 reports no ExitCode once it exits.
        $null = $p.Handle
    } catch {
        Write-Log ('  Could not start the Store scan process: ' + $_.Exception.Message) -Level ERROR
        return $false
    }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $scanLogged = $false
    while ($true) {
        Start-Sleep -Seconds 30
        $state = Get-ScanProcessState -HasExited $p.HasExited -ExitCode $(if ($p.HasExited) { $p.ExitCode } else { $null })
        $result = ''
        if ($state -ne 'Running') { $result = (Get-Content -LiteralPath $resultFile -ErrorAction SilentlyContinue) -join ' ' }
        if (-not $scanLogged -and $state -eq 'Completed') {
            Write-Log ('  Store update scan finished after ' + [int]$sw.Elapsed.TotalSeconds + 's (' + $result + ').')
            $scanLogged = $true
        }
        $now = Read-WebpState
        $step = Get-StoreWaitStep -FixedPresent ($now.FixedInstalled -or $now.FixedProvisioned) -ScanState $state -Elapsed $sw.Elapsed.TotalSeconds -Budget $StoreWaitSeconds
        switch ($step) {
            'Wait'       { }
            'Arrived'    {
                Write-Log ('  Fixed build arrived from the Store after ' + [int]$sw.Elapsed.TotalSeconds + 's' + $(if ($state -eq 'Running') { ' (scan still running)' } else { '' }) + '.')
                return $true
            }
            'ScanFailed' {
                Write-Log ('  Store update scan failed (exit ' + $p.ExitCode + '): ' + $result) -Level ERROR
                Write-Log '  The MDM bridge is missing, or the Store is blocked by policy on this host.' -Level ERROR
                return $false
            }
            'TimedOut'   {
                Write-Log ('  The Store did not deliver ' + $FixedVersion + ' or later within ' + $StoreWaitSeconds + 's.') -Level ERROR
                if ($state -eq 'Running') {
                    Write-Log '  The Store was still working through its update pass. It may deliver later' -Level WARN
                    Write-Log '  (CSLT-171 took almost 3 hours); re-run then to verify and clean up.' -Level WARN
                } else {
                    Write-Log '  The scan finished without the fixed build. See the Store policy, Services' -Level WARN
                    Write-Log '  and Reach 443 lines above, or stage the package.' -Level WARN
                }
                return $false
            }
            default      { throw ('Unhandled Store wait step ' + $step) }
        }
    }
}

$hostArch = Get-HostAppxArch -ProcArch $env:PROCESSOR_ARCHITECTURE -ProcArchW6432 $env:PROCESSOR_ARCHITEW6432 -Is64BitOS ([Environment]::Is64BitOperatingSystem)

Write-Log '=============================================='
Write-Log ' WebP Image Extension -- plugin 346896 (CVE-2026-70351)'
Write-Log (' Host    : ' + $env:COMPUTERNAME + ' (' + $hostArch + ')')
Write-Log (' Mode    : ' + $(if ($Remove) { 'remove' } else { 'update' }))
Write-Log (' DryRun  : ' + $DryRun)
if ($MyInvocation.Line) { Write-Log (' Invoked as: ' + $MyInvocation.Line.Trim()) }
Write-Log '=============================================='

Write-Log ''
Write-Log '[1/4] Inventory'
$state = Read-WebpState
Write-WebpState -State $state
if ($state.Status -ne 'Vulnerable') {
    $o = Get-WebpOutcome -State $state -Mode 'update' -SystemStagedOnly $false
    Write-Log ''
    Write-Log $o.Summary
    Write-Log '=============================================='
    exit $o.Exit
}

if ($Remove) {
    Write-Log ''
    Write-Log '[2/4] Removing the extension (-Remove)'
    if ($DryRun) {
        foreach ($p in $state.Packages) { Write-Log ('  [DRYRUN] Would remove for all users: ' + $p.FullName) }
        foreach ($n in $state.Provisioned) { Write-Log ('  [DRYRUN] Would deprovision: ' + $n) }
        Write-Log '=============================================='
        exit 0
    }
    Remove-WebpRegistrations -Packages $state.Packages
    Write-Log ''
    Write-Log '[3/4] Deprovisioning'
    Remove-WebpProvisioned -Names $state.Provisioned
    Start-Sleep -Seconds 3
    Write-Log ''
    Write-Log '[4/4] Verification'
    $end = Read-WebpState
    Write-WebpState -State $end
    $o = Get-WebpOutcome -State $end -Mode 'remove' -SystemStagedOnly (Test-SystemStagedOnly -Packages $end.Packages)
    Write-Log ''
    Write-Log $o.Summary -Level $(if ($o.Exit -eq 0) { 'INFO' } else { 'WARN' })
    Write-Log '=============================================='
    exit $o.Exit
}

Write-Log ''
Write-Log '[2/4] Getting a fixed build onto the machine'
$source = ''
if ($state.FixedProvisioned -or $state.FixedInstalled) {
    Write-Log '  A fixed build is already installed or provisioned; only cleanup is needed.'
    $source = $(if ($state.FixedProvisioned) { 'provisioned' } else { 'store' })
} else {
    $set = Select-StagedPackageSet -Infos (Find-StagedPackageInfos) -PackageName $PkgName -Arch $hostArch -Fixed $FixedVersion
    if ($set.Main) {
        Write-Log ('  Using staged ' + $set.Main.Path + ' (' + $set.Main.Version + ').')
        foreach ($d in $set.Deps) { Write-Log ('    dependency: ' + $d.Path + ' (' + $d.Name + ' ' + $d.Version + ')') }
        if ($DryRun) {
            Write-Log '  [DRYRUN] Would provision it, then remove older registrations.'
            Write-Log '=============================================='
            exit 0
        }
        try {
            $provArgs = @{ Online = $true; PackagePath = $set.Main.Path; SkipLicense = $true; ErrorAction = 'Stop' }
            if ($set.Deps.Count -gt 0) { $provArgs.DependencyPackagePath = @($set.Deps | ForEach-Object { $_.Path }) }
            Add-AppxProvisionedPackage @provArgs | Out-Null
            Write-Log '  Add-AppxProvisionedPackage completed.'
            $source = 'provisioned'
        } catch {
            Write-Log ('  Add-AppxProvisionedPackage failed: ' + $_.Exception.Message) -Level ERROR
            if ($_.Exception.Message -match '0x80073CF3|0x80073CF9|depend') {
                Write-Log '  A framework dependency is missing. Stage the Microsoft.VCLibs / UI.Xaml' -Level ERROR
                Write-Log '  packages that winget download saved next to the main package.' -Level ERROR
            }
        }
    } else {
        Write-Log ('  No usable staged package: ' + $set.Reason + '.')
        Write-StoreDiagnostics
        if ($DryRun) {
            Write-Log '  [DRYRUN] Would start a Microsoft Store update scan and wait for the fixed build.'
            Write-Log '=============================================='
            exit 0
        }
        if (Wait-StoreDelivery) { $source = 'store' }
    }
}

Write-Log ''
Write-Log '[3/4] Removing what still holds the old build'
$mid = Read-WebpState
if (-not $source) {
    Write-Log '  Skipped: no fixed build is on the machine, so removing the old one would'
    Write-Log '  leave users without the extension. Use -Remove for that.'
} elseif ($DryRun) {
    Write-Log '  [DRYRUN] Would remove older registrations and provisioned entries.'
} else {
    if ($mid.FixedProvisioned -and $mid.VulnerablePackages.Count -gt 0) {
        Write-Log '  The fixed build is provisioned, so every user gets it at their next sign-in.'
        Remove-WebpRegistrations -Packages $mid.VulnerablePackages
    } elseif ($mid.VulnerablePackages.Count -gt 0) {
        Write-Log '  Older registrations are left for the Store to update at each user' -Level WARN
        Write-Log '  sign-in; the fixed build is not provisioned, so removing them would' -Level WARN
        Write-Log '  leave those users without the extension.' -Level WARN
    }
    if ($mid.VulnerableProvisioned.Count -gt 0) {
        Remove-WebpProvisioned -Names $mid.VulnerableProvisioned
    }
    if ($mid.VulnerablePackages.Count -eq 0 -and $mid.VulnerableProvisioned.Count -eq 0) { Write-Log '  Nothing to remove.' }
}

Write-Log ''
Write-Log '[4/4] Verification'
Start-Sleep -Seconds 3
$end = Read-WebpState
Write-WebpState -State $end
foreach ($p in $end.VulnerablePackages) {
    Write-Log ('  Still on the old build: ' + $p.FullName + ' for ' + (($p.Users | ForEach-Object { $_.Name }) -join ', ')) -Level WARN
}
$o = Get-WebpOutcome -State $end -Mode 'update' -SystemStagedOnly $false
Write-Log ''
Write-Log $o.Summary -Level $(if ($o.Exit -eq 0) { 'INFO' } elseif ($o.Exit -eq 3010) { 'WARN' } else { 'ERROR' })
if ($o.Exit -eq 0) { Write-Log 'Re-run a Nessus scan to confirm plugin 346896 clears.' }
Write-Log '=============================================='
exit $o.Exit
