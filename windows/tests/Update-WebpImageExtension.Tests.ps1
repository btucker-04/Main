# Unit tests for Update-WebpImageExtension.ps1 helpers.
# Run: pwsh -NoProfile -File windows/tests/Update-WebpImageExtension.Tests.ps1
#
# Plugin 346896 (2026-11-18 export: cslt-183, cspc-014, cspc-030, csprpc-27),
# each reporting
#   Path : C:\Program Files\WindowsApps\Microsoft.WebpImageExtension_1.2.14.0_x64__8wekyb3d8bbwe
#   Fixed version : 1.2.31.0
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path (Split-Path -Parent $here) 'Update-WebpImageExtension.ps1'
$env:WEBP_UPDATE_DOTSOURCE = '1'
. $scriptPath
$failed = 0
function Assert-Eq {
    param($Actual, $Expected, [string]$Name)
    if (('' + $Actual) -ne ('' + $Expected)) {
        Write-Host ('FAIL ' + $Name + ' : got ' + [char]39 + $Actual + [char]39 + ' expected ' + [char]39 + $Expected + [char]39)
        $script:failed++
    } else {
        Write-Host ('OK   ' + $Name)
    }
}
function Assert-True {
    param([bool]$Cond, [string]$Name)
    if (-not $Cond) { Write-Host ('FAIL ' + $Name); $script:failed++ } else { Write-Host ('OK   ' + $Name) }
}

$tenableDir = 'Microsoft.WebpImageExtension_1.2.14.0_x64__8wekyb3d8bbwe'
$fixed = [version]'1.2.31.0'

# --- Package full names -------------------------------------------------------
$p = ConvertFrom-PackageFullName -FullName $tenableDir
Assert-Eq ('' + $p.Name + '|' + $p.Version + '|' + $p.Arch + '|' + $p.IsBundle) 'Microsoft.WebpImageExtension|1.2.14.0|x64|False' 'Tenable path folder parses'
$b = ConvertFrom-PackageFullName -FullName 'Microsoft.WebpImageExtension_1.2.31.0_neutral_~_8wekyb3d8bbwe'
Assert-True $b.IsBundle 'bundle full name is recognised'
Assert-True ($null -eq (ConvertFrom-PackageFullName -FullName 'Deleted')) 'non-package folder is ignored'

# --- Host architecture under the 32-bit EC agent ------------------------------
Assert-Eq (Get-HostAppxArch -ProcArch 'x86' -ProcArchW6432 'AMD64') 'x64' '32-bit agent on 64-bit Windows is x64'
Assert-Eq (Get-HostAppxArch -ProcArch 'AMD64' -ProcArchW6432 '') 'x64' '64-bit process is x64'
Assert-Eq (Get-HostAppxArch -ProcArch 'ARM64' -ProcArchW6432 '') 'arm64' 'arm64'
Assert-Eq (Get-HostAppxArch -ProcArch 'x86' -ProcArchW6432 '' -Is64BitOS $false) 'x86' '32-bit Windows is x86'
Assert-Eq (Get-HostAppxArch -ProcArch '' -ProcArchW6432 '' -Is64BitOS $true) 'x64' 'unset variables on 64-bit Windows are x64, not x86'
Assert-True (Test-Needs64BitRelaunch -Is64BitOS $true -Is64BitProcess $false) '32-bit agent relaunches'
Assert-Eq ((Get-RelaunchArguments -ScriptPath 'C:\x.ps1' -Remove $true -DryRun $true) -join ' ') '-NoProfile -ExecutionPolicy Bypass -File C:\x.ps1 -Remove -DryRun' 'switches survive the relaunch'

# --- State from the inventory -------------------------------------------------
$user = [pscustomobject]@{ Sid = 'S-1-5-21-1-2-3-1001'; Name = 'COMPOSECURE\jdoe'; State = 'Installed' }
$old = [pscustomobject]@{ FullName = $tenableDir; Version = [version]'1.2.14.0'; Users = @($user) }
$s = Get-WebpState -Packages @($old) -ProvisionedNames @($tenableDir) -PayloadDirs @($tenableDir) -Fixed $fixed
Assert-Eq $s.Status 'Vulnerable' 'plugin 346896 host state is vulnerable'
Assert-Eq ($s.VulnerableDirs -join ',') $tenableDir 'the Tenable folder is the vulnerable one'
Assert-True (-not $s.FixedInstalled -and -not $s.FixedProvisioned) 'no fixed build yet'
Assert-Eq (Get-WebpOutcome -State $s -Mode 'update' -SystemStagedOnly $false).Exit 1 'nothing fixed installed: exit 1'

$newDir = 'Microsoft.WebpImageExtension_1.2.31.0_x64__8wekyb3d8bbwe'
$s = Get-WebpState -Packages @($old) -ProvisionedNames @($newDir) -PayloadDirs @($tenableDir, $newDir) -Fixed $fixed
Assert-True $s.FixedProvisioned 'fixed build provisioned'
Assert-Eq $s.Status 'Vulnerable' 'old registration still holds the old folder'
Assert-Eq (Get-WebpOutcome -State $s -Mode 'update' -SystemStagedOnly $false).Exit 3010 'fixed in place, old held: reboot and re-run'

$new = [pscustomobject]@{ FullName = $newDir; Version = [version]'1.2.31.0'; Users = @($user) }
$s = Get-WebpState -Packages @($new) -ProvisionedNames @($newDir) -PayloadDirs @($newDir) -Fixed $fixed
Assert-Eq $s.Status 'Fixed' 'only the fixed build left'
Assert-Eq (Get-WebpOutcome -State $s -Mode 'update' -SystemStagedOnly $false).Exit 0 'fixed: exit 0'
$s = Get-WebpState -Packages @($new) -ProvisionedNames @($tenableDir) -PayloadDirs @($newDir, $tenableDir) -Fixed $fixed
Assert-Eq ($s.VulnerableProvisioned -join ',') $tenableDir 'Store-updated host: old provisioned entry is what is left'
Assert-Eq (Get-WebpOutcome -State $s -Mode 'update' -SystemStagedOnly $false).Exit 3010 'Store-updated host with old provisioned entry is not clean'
$s = Get-WebpState -Packages @() -ProvisionedNames @() -PayloadDirs @($tenableDir) -Fixed $fixed
Assert-Eq $s.Status 'Vulnerable' 'an orphaned payload folder alone is still vulnerable'
$s = Get-WebpState -Packages @() -ProvisionedNames @() -PayloadDirs @() -Fixed $fixed
Assert-Eq $s.Status 'Absent' 'nothing on disk: absent'
Assert-Eq (Get-WebpOutcome -State $s -Mode 'remove' -SystemStagedOnly $false).Exit 0 'removed: exit 0'

$sysStaged = [pscustomobject]@{ FullName = $tenableDir; Version = [version]'1.2.14.0'; Users = @([pscustomobject]@{ Sid = 'S-1-5-18'; Name = 'NT AUTHORITY\SYSTEM'; State = 'Staged' }) }
Assert-True (Test-SystemStagedOnly -Packages @($sysStaged)) 'SYSTEM-staged remnant recognised'
Assert-True (-not (Test-SystemStagedOnly -Packages @($old))) 'a real user registration is not a staged remnant'
Assert-True (-not (Test-SystemStagedOnly -Packages @())) 'no registrations is not a staged remnant'
$s = Get-WebpState -Packages @($sysStaged) -ProvisionedNames @() -PayloadDirs @($tenableDir) -Fixed $fixed
Assert-Eq (Get-WebpOutcome -State $s -Mode 'remove' -SystemStagedOnly $true).Exit 3010 'removal queued behind a SYSTEM-staged remnant: 3010'
Assert-Eq (Get-WebpOutcome -State $s -Mode 'remove' -SystemStagedOnly $false).Exit 1 'removal that left a user registration: 1'

# --- Staged packages, read from the manifest inside the zip --------------------
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('webp_' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
function New-TestPackage {
    param([string]$Path, [string]$EntryName, [string]$Xml)
    $zip = [System.IO.Compression.ZipFile]::Open($Path, 'Create')
    try {
        $e = $zip.CreateEntry($EntryName)
        $w = New-Object System.IO.StreamWriter($e.Open())
        try { $w.Write($Xml) } finally { $w.Dispose() }
    } finally { $zip.Dispose() }
}
$q = [char]34
$ms = 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
function Get-AppxXml { param($Name, $Ver, $Arch, $Pub)
    '<?xml version=' + $q + '1.0' + $q + '?><Package xmlns=' + $q + 'http://schemas.microsoft.com/appx/manifest/foundation/windows10' + $q + '><Identity Name=' + $q + $Name + $q +
    ' Version=' + $q + $Ver + $q + ' ProcessorArchitecture=' + $q + $Arch + $q + ' Publisher=' + $q + $Pub + $q + ' /></Package>' }
try {
    $appx = Join-Path $tmp 'Microsoft.WebpImageExtension_1.2.31.0_x64__8wekyb3d8bbwe.Appx'
    New-TestPackage -Path $appx -EntryName 'AppxManifest.xml' -Xml (Get-AppxXml 'Microsoft.WebpImageExtension' '1.2.31.0' 'x64' $ms)
    $i = Get-PackageManifestInfo -Path $appx
    Assert-Eq ('' + $i.Name + '|' + $i.Version + '|' + ($i.Archs -join ',') + '|' + $i.IsBundle) 'Microsoft.WebpImageExtension|1.2.31.0|x64|False' 'appx manifest read'

    $bundle = Join-Path $tmp 'webp.msixbundle'
    $bx = '<?xml version=' + $q + '1.0' + $q + '?><Bundle xmlns=' + $q + 'http://schemas.microsoft.com/appx/2013/bundle' + $q + '><Identity Name=' + $q + 'Microsoft.WebpImageExtension' + $q +
        ' Version=' + $q + '2026.903.1.0' + $q + ' Publisher=' + $q + $ms + $q + ' /><Packages>' +
        '<Package Type=' + $q + 'application' + $q + ' Version=' + $q + '1.2.31.0' + $q + ' Architecture=' + $q + 'x64' + $q + ' FileName=' + $q + 'a.appx' + $q + ' />' +
        '<Package Type=' + $q + 'application' + $q + ' Version=' + $q + '1.2.31.0' + $q + ' Architecture=' + $q + 'arm64' + $q + ' FileName=' + $q + 'b.appx' + $q + ' />' +
        '<Package Type=' + $q + 'resource' + $q + ' Version=' + $q + '9.9.9.9' + $q + ' FileName=' + $q + 'r.appx' + $q + ' /></Packages></Bundle>'
    New-TestPackage -Path $bundle -EntryName 'AppxMetadata/AppxBundleManifest.xml' -Xml $bx
    $bi = Get-PackageManifestInfo -Path $bundle
    Assert-Eq ('' + $bi.Version + '|' + ($bi.Archs -join ',') + '|' + $bi.IsBundle) '1.2.31.0|arm64,x64|True' 'bundle: app package version, not the bundle date version'

    $vclibs = Join-Path $tmp 'Microsoft.VCLibs.140.00_14.0.33519.0_x64__8wekyb3d8bbwe.Appx'
    New-TestPackage -Path $vclibs -EntryName 'AppxManifest.xml' -Xml (Get-AppxXml 'Microsoft.VCLibs.140.00' '14.0.33519.0' 'x64' $ms)
    $vclibs86 = Join-Path $tmp 'Microsoft.VCLibs.140.00_14.0.33519.0_x86__8wekyb3d8bbwe.Appx'
    New-TestPackage -Path $vclibs86 -EntryName 'AppxManifest.xml' -Xml (Get-AppxXml 'Microsoft.VCLibs.140.00' '14.0.33519.0' 'x86' $ms)
    $old14 = Join-Path $tmp 'old.appx'
    New-TestPackage -Path $old14 -EntryName 'AppxManifest.xml' -Xml (Get-AppxXml 'Microsoft.WebpImageExtension' '1.2.14.0' 'x64' $ms)
    $fake = Join-Path $tmp 'fake.appx'
    New-TestPackage -Path $fake -EntryName 'AppxManifest.xml' -Xml (Get-AppxXml 'Microsoft.WebpImageExtension' '9.0.0.0' 'x64' 'CN=Contoso')
    $notzip = Join-Path $tmp 'blockpage.appx'
    Set-Content -LiteralPath $notzip -Value '<html>blocked</html>'
    $threw = $false
    try { Get-PackageManifestInfo -Path $notzip | Out-Null } catch { $threw = $true }
    Assert-True $threw 'a block page saved as .appx is not read as a package'

    $infos = @($appx, $vclibs, $vclibs86, $old14, $fake) | ForEach-Object { Get-PackageManifestInfo -Path $_ }
    $set = Select-StagedPackageSet -Infos $infos -PackageName 'Microsoft.WebpImageExtension' -Arch 'x64' -Fixed $fixed
    Assert-Eq $set.Main.Path $appx 'newest Microsoft-published x64 build is picked, not the Contoso 9.0'
    Assert-Eq (($set.Deps | ForEach-Object { $_.Path }) -join ',') $vclibs 'only the x64 VCLibs dependency'
    $set = Select-StagedPackageSet -Infos @(Get-PackageManifestInfo -Path $old14) -PackageName 'Microsoft.WebpImageExtension' -Arch 'x64' -Fixed $fixed
    Assert-True ($null -eq $set.Main) 'a staged 1.2.14.0 is refused'
    Assert-Eq $set.Reason 'the staged package is 1.2.14.0, below the fixed 1.2.31.0' 'and the log says why'
    $set = Select-StagedPackageSet -Infos @($infos[0]) -PackageName 'Microsoft.WebpImageExtension' -Arch 'arm64' -Fixed $fixed
    Assert-Eq $set.Reason 'no Microsoft.WebpImageExtension package for arm64 is staged' 'x64 package is not used on arm64'
    $set = Select-StagedPackageSet -Infos @($bi) -PackageName 'Microsoft.WebpImageExtension' -Arch 'arm64' -Fixed $fixed
    Assert-Eq $set.Main.Path $bundle 'a bundle covers each architecture it contains'
    $set = Select-StagedPackageSet -Infos @() -PackageName 'Microsoft.WebpImageExtension' -Arch 'x64' -Fixed $fixed
    Assert-Eq $set.Reason 'no Microsoft.WebpImageExtension package for x64 is staged' 'nothing staged'
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

# --- End to end: the whole script against shimmed AppX / DISM / Store ---------
# The shims keep a simulated machine in $global:webpSim and mirror its payload
# folders on disk, since the script reads those with Get-ChildItem.
$e2e = Join-Path ([System.IO.Path]::GetTempPath()) ('webpe2e_' + [guid]::NewGuid().ToString('N'))
$newDir = 'Microsoft.WebpImageExtension_1.2.31.0_x64__8wekyb3d8bbwe'
function Reset-Sim {
    param([bool]$StageFixed, [string]$StoreDelivers, [int]$StoreBudget = 900)
    Remove-Item -LiteralPath $e2e -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $e2e | Out-Null
    $copy = Join-Path $e2e 'Update-WebpImageExtension.ps1'
    (Get-Content -LiteralPath $scriptPath -Raw).Replace(([char]39 + 'C:\Logs\CompoSecure' + [char]39), ([char]39 + $e2e + '/logs' + [char]39)) |
        ForEach-Object { $_.Replace('$StoreWaitSeconds = 900', ('$StoreWaitSeconds = ' + $StoreBudget)) } |
        Set-Content -LiteralPath $copy
    $env:ProgramFiles = $e2e + '/pf'
    $global:webpApps = $env:ProgramFiles + '\WindowsApps'
    New-Item -ItemType Directory -Force -Path ($global:webpApps + '/' + $tenableDir) | Out-Null
    if ($StageFixed) {
        New-TestPackage -Path (Join-Path $e2e ($newDir + '.Appx')) -EntryName 'AppxManifest.xml' -Xml (Get-AppxXml 'Microsoft.WebpImageExtension' '1.2.31.0' 'x64' $ms)
    }
    $global:webpSim = @{
        Pkgs = @(@{ Full = $tenableDir; Ver = '1.2.14.0'; Sid = 'S-1-5-21-1-2-3-1001'; User = 'COMPOSECURE\jdoe' })
        Prov = @($tenableDir); StoreDelivers = $StoreDelivers; Calls = @()
    }
}
function Sync-SimDirs {
    $keep = @($global:webpSim.Pkgs | ForEach-Object { $_.Full }) + @($global:webpSim.Prov)
    foreach ($d in @(Get-ChildItem -LiteralPath $global:webpApps -Directory | ForEach-Object { $_.Name })) {
        if ($keep -notcontains $d) { Remove-Item -LiteralPath ($global:webpApps + '/' + $d) -Recurse -Force }
    }
    foreach ($k in $keep) { New-Item -ItemType Directory -Force -Path ($global:webpApps + '/' + $k) | Out-Null }
}
function Get-AppxPackage { param([switch]$AllUsers, $Name, $PackageTypeFilter)
    foreach ($p in $global:webpSim.Pkgs) {
        [pscustomobject]@{ PackageFullName = $p.Full; Version = $p.Ver
            PackageUserInformation = @([pscustomobject]@{ UserSecurityId = [pscustomobject]@{ Sid = $p.Sid; Username = $p.User }; InstallState = 'Installed' }) }
    }
}
function Get-AppxProvisionedPackage { param([switch]$Online)
    foreach ($n in $global:webpSim.Prov) { [pscustomobject]@{ DisplayName = 'Microsoft.WebpImageExtension'; PackageName = $n } }
}
function Add-AppxProvisionedPackage { param([switch]$Online, $PackagePath, $DependencyPackagePath, [switch]$SkipLicense)
    $global:webpSim.Calls += ('provision:' + (Get-InstallerLeaf $PackagePath))
    $global:webpSim.Prov = @($newDir); Sync-SimDirs
}
function Remove-AppxPackage { param($Package, [switch]$AllUsers)
    $global:webpSim.Calls += ('remove:' + $Package)
    $global:webpSim.Pkgs = @($global:webpSim.Pkgs | Where-Object { $_.Full -ne $Package }); Sync-SimDirs
}
function Remove-AppxProvisionedPackage { param([switch]$Online, $PackageName)
    $global:webpSim.Calls += ('deprovision:' + $PackageName)
    $global:webpSim.Prov = @($global:webpSim.Prov | Where-Object { $_ -ne $PackageName }); Sync-SimDirs
}
# The Store scan runs in its own powershell.exe; the shim decodes the command
# it was given and plays the Store: deliver (exit 0), refuse (exit 99), or
# still running at the deadline.
function Start-Process { param($FilePath, $ArgumentList, $WindowStyle, [switch]$PassThru)
    $cmd = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($ArgumentList[-1]))
    switch ($global:webpSim.StoreDelivers) {
        'yes'   {
            if ($cmd -match 'UpdateScanMethod') { $global:webpSim.Calls += 'store:UpdateScanMethod' }
            foreach ($p in $global:webpSim.Pkgs) { $p.Full = $newDir; $p.Ver = '1.2.31.0' }
            Sync-SimDirs
            return [pscustomobject]@{ HasExited = $true; ExitCode = 0; Handle = 1 }
        }
        'no'    { return [pscustomobject]@{ HasExited = $true; ExitCode = 99; Handle = 1 } }
        'never' { $global:webpSim.Calls += 'store:running'; return [pscustomobject]@{ HasExited = $false; ExitCode = $null; Handle = 1 } }
        default { throw ('Unhandled StoreDelivers ' + $global:webpSim.StoreDelivers) }
    }
}
function Get-Service { param($Name)
    foreach ($n in $Name) { [pscustomobject]@{ Name = $n; StartType = 'Manual'; Status = 'Stopped' } }
}
function Test-StoreHostReachable { param($HostName) '' }
function Start-Sleep { }
function Get-InstallerLeaf { param([string]$Path) ($Path -split '[\\/]')[-1] }
function Invoke-WebpScript { param([hashtable]$ScriptArgs)
    $env:WEBP_UPDATE_DOTSOURCE = ''
    Push-Location $e2e
    try { & (Join-Path $e2e 'Update-WebpImageExtension.ps1') @ScriptArgs *> (Join-Path $e2e 'run.log') } finally { Pop-Location }
    $env:WEBP_UPDATE_DOTSOURCE = '1'
    return $LASTEXITCODE
}
$savedPF = $env:ProgramFiles
try {
    Reset-Sim -StageFixed $true -StoreDelivers 'no'
    $rc = Invoke-WebpScript @{}
    Assert-Eq $rc 0 'e2e staged: exit 0'
    Assert-Eq ($global:webpSim.Calls -join ',') ('provision:' + $newDir + '.Appx,remove:' + $tenableDir) 'e2e staged: provision the fixed build, then remove the old registration'
    Assert-True (-not (Test-Path -LiteralPath ($global:webpApps + '/' + $tenableDir))) 'e2e staged: the Tenable folder is gone'

    Reset-Sim -StageFixed $false -StoreDelivers 'yes'
    $rc = Invoke-WebpScript @{}
    Assert-Eq $rc 0 'e2e Store: exit 0'
    Assert-Eq ($global:webpSim.Calls -join ',') ('store:UpdateScanMethod,deprovision:' + $tenableDir) 'e2e Store: scan, then drop the old provisioned entry'

    Reset-Sim -StageFixed $false -StoreDelivers 'no'
    $rc = Invoke-WebpScript @{}
    Assert-Eq $rc 1 'e2e nothing available: exit 1'
    Assert-Eq $global:webpSim.Calls.Count 0 'e2e nothing available: the old build is left in place'
    Assert-True ((Get-Content -LiteralPath (Join-Path $e2e 'run.log') -Raw) -match 'Stage the package, allow the Microsoft Store, or re-run with -Remove') 'e2e nothing available: log says what to do'

    Reset-Sim -StageFixed $false -StoreDelivers 'never' -StoreBudget 0
    $rc = Invoke-WebpScript @{}
    $log = Get-Content -LiteralPath (Join-Path $e2e 'run.log') -Raw
    Assert-Eq $rc 1 'e2e Store still running at the deadline: exit 1'
    Assert-Eq ($global:webpSim.Calls -join ',') 'store:running' 'e2e Store still running: the old build is left in place'
    Assert-True ($log -match 'still working through its update pass') 'e2e Store still running: log says the Store may deliver later'
    Assert-True ($log -match 'Store policy : nothing blocking') 'e2e: Store policy is logged before the scan'
    Assert-True ($log -match 'Reach 443    : storeedgefd\.dsx\.mp\.microsoft\.com ok') 'e2e: Store host reachability is logged'

    Reset-Sim -StageFixed $false -StoreDelivers 'no'
    $rc = Invoke-WebpScript @{ Remove = $true }
    Assert-Eq $rc 0 'e2e -Remove: exit 0'
    Assert-Eq ($global:webpSim.Calls -join ',') ('remove:' + $tenableDir + ',deprovision:' + $tenableDir) 'e2e -Remove: registration, then provisioning'

    Reset-Sim -StageFixed $true -StoreDelivers 'yes'
    $rc = Invoke-WebpScript @{ DryRun = $true }
    Assert-Eq $rc 0 'e2e -DryRun: exit 0'
    Assert-Eq $global:webpSim.Calls.Count 0 'e2e -DryRun: nothing changed'
} finally {
    $env:ProgramFiles = $savedPF
    foreach ($f in @('Get-AppxPackage', 'Get-AppxProvisionedPackage', 'Add-AppxProvisionedPackage', 'Remove-AppxPackage', 'Remove-AppxProvisionedPackage', 'Start-Process', 'Get-Service', 'Test-StoreHostReachable', 'Start-Sleep')) {
        Remove-Item -LiteralPath ('Function:\' + $f) -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $e2e -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Variable -Name webpSim, webpApps -Scope Global -ErrorAction SilentlyContinue
}

# --- Store path (CSLT-171 2026-11-23, CSLT-090 2026-11-24) ---------------------
# Both logged 'No usable staged package' and then, only after UpdateScanMethod
# returned, 'Store update scan started (ReturnValue 0).':
#   CSLT-171  10:05:20 -> 12:56:41 (blocked 2h51m), fixed build 208s later
#   CSLT-090  07:11:34 -> 07:19:10 (blocked 7.5 min), nothing in the next 480s
Assert-Eq (Get-ScanProcessState -HasExited $false -ExitCode $null) 'Running' 'scan process still in UpdateScanMethod is Running'
Assert-Eq (Get-ScanProcessState -HasExited $true -ExitCode 0) 'Completed' 'ReturnValue 0 is Completed'
Assert-Eq (Get-ScanProcessState -HasExited $true -ExitCode 99) 'Failed' 'exception in the scan process is Failed'
Assert-Eq (Get-ScanProcessState -HasExited $true -ExitCode 2147549183) 'Failed' 'nonzero ReturnValue is Failed'
Assert-Eq (Get-StoreWaitStep -FixedPresent $true -ScanState 'Running' -Elapsed 120 -Budget 900) 'Arrived' 'CSLT-171: fixed build seen while the scan is still running'
Assert-Eq (Get-StoreWaitStep -FixedPresent $false -ScanState 'Running' -Elapsed 10260 -Budget 900) 'TimedOut' 'CSLT-171: a 2h51m scan no longer holds the run past its budget'
Assert-Eq (Get-StoreWaitStep -FixedPresent $false -ScanState 'Completed' -Elapsed 456 -Budget 900) 'Wait' 'CSLT-090: scan done at 7.5 min, keep polling inside the budget'
Assert-Eq (Get-StoreWaitStep -FixedPresent $false -ScanState 'Failed' -Elapsed 30 -Budget 900) 'ScanFailed' 'failed scan stops the wait'
Assert-Eq (Get-StoreWaitStep -FixedPresent $true -ScanState 'Failed' -Elapsed 30 -Budget 900) 'Arrived' 'fixed build wins over a failed scan'
Assert-Eq $StoreWaitSeconds 900 'whole Store path budget is 15 minutes'

$cmd = Get-StoreScanCommand -ResultFile ('C:\Logs\CompoSecure\WebpStoreScan_20261124_071134.txt')
$cmdErrors = $null
$null = [System.Management.Automation.Language.Parser]::ParseInput($cmd, [ref]$null, [ref]$cmdErrors)
Assert-Eq @($cmdErrors).Count 0 'scan command parses'
Assert-True ($cmd -match 'UpdateScanMethod') 'scan command calls UpdateScanMethod'
Assert-True ($cmd -match 'exit 99') 'scan command exits 99 when the call throws'
Assert-True ($cmd -notmatch [char]34) 'scan command has no double quote'
$odd = Get-StoreScanCommand -ResultFile ('C:\Logs\O' + [char]39 + 'Neil\scan.txt')
$oddErrors = $null
$null = [System.Management.Automation.Language.Parser]::ParseInput($odd, [ref]$null, [ref]$oddErrors)
Assert-Eq @($oddErrors).Count 0 'single quote in the result path is escaped'

Assert-Eq (@(Get-StorePolicyFindings -Values @{}).Count) 0 'no Store policy, nothing blocking'
Assert-Eq (@(Get-StorePolicyFindings -Values @{ AutoDownload = 4 }).Count) 0 'AutoDownload 4 (always on) is fine'
Assert-Eq ((Get-StorePolicyFindings -Values @{ AutoDownload = 2 }) -join ';') 'AutoDownload = 2 (automatic Store app updates turned off by policy)' 'AutoDownload 2 is reported'
Assert-Eq (@(Get-StorePolicyFindings -Values @{ RemoveWindowsStore = 1; DisableStoreApps = 1; RequirePrivateStoreOnly = 1 }).Count) 3 'Store-off policies are each reported'
$svc = @(
    [pscustomobject]@{ Name = 'InstallService'; StartType = 'Manual' },
    [pscustomobject]@{ Name = 'wuauserv'; StartType = 'Disabled' }
)
Assert-Eq ((Get-StoreServiceFindings -Services $svc -Required @('InstallService', 'wuauserv', 'DoSvc')) -join ';') 'wuauserv is Disabled;DoSvc is not present' 'disabled or missing Store services are reported'


# --- Every Verb-Noun the script calls exists (or is Windows-only) --------------
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
Assert-Eq $parseErrors.Count 0 'script parses'
$defined = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name })
$called = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
    ForEach-Object { $_.GetCommandName() } | Where-Object { $_ -match '^[A-Za-z]+-[A-Za-z]+$' } | Sort-Object -Unique)
$windowsOnly = @('Get-AppxPackage', 'Remove-AppxPackage', 'Get-AppxProvisionedPackage', 'Add-AppxProvisionedPackage', 'Remove-AppxProvisionedPackage', 'Get-CimInstance', 'Invoke-CimMethod', 'Get-Service')
$unknown = @($called | Where-Object { $defined -notcontains $_ -and $windowsOnly -notcontains $_ -and -not (Get-Command $_ -ErrorAction SilentlyContinue) })
Assert-Eq ($unknown -join ',') '' 'every Verb-Noun command the script calls exists'
Assert-Eq (@($tokens | Where-Object { $_.Text -match [char]34 }).Count) 0 'no literal double quote in the script'

if ($failed -gt 0) {
    Write-Host ('')
    Write-Host ('' + $failed + ' test(s) failed')
    exit 1
}
Write-Host ''
Write-Host 'All tests passed'
exit 0
