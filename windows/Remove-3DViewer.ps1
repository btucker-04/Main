<#
.SYNOPSIS
    Removes Microsoft 3D Viewer (Store app) -- Nessus Plugin 141430 (v3.1).

.DESCRIPTION
    Removes the installed package for all users, the provisioned package,
    and (v2) handles the shared-machine case where registrations tied to
    ORPHANED SIDs (deleted accounts) block full removal:

      Remove-AppxPackage -AllUsers deregisters the app for existing users,
      but a registration owned by a deleted account cannot be deregistered,
      so the payload stays in WindowsApps and Tenable keeps flagging it
      (it keys on file presence).

    v2 verification lists exactly which users/SIDs still hold the package
    and their install state. With -CleanOrphanedProfiles, leftover profiles
    of DELETED accounts are removed (safe: the accounts no longer exist),
    which releases the registration, and removal is retried.

    v3: enumeration now uses -PackageTypeFilter All and removes BUNDLE
    packages before main packages. Staged AppxBundles (PackageFullName
    contains '_~_') are invisible to a default Get-AppxPackage call, and a
    main package that belongs to a staged bundle cannot actually be removed
    until the bundle registration goes -- Remove-AppxPackage reports success
    while removing nothing (observed on CSPRPC-110: package Staged for
    SYSTEM only, bundle 2026.2602.8012.0 holding the payload).

    v3.1: a SYSTEM-staged remnant whose payload persists after all removal
    paths is reported as REBOOT PENDING (exit 3010), not failure -- staged
    deregistration is queued and the AppX Deployment Service finalizes the
    payload deletion at the next restart. Re-run after reboot to verify.

.PARAMETER CleanOrphanedProfiles
    Remove on-disk profiles whose SID no longer resolves to an account,
    then retry package removal. Only unloaded, non-special profiles are
    touched.

.PARAMETER DryRun
    Report what would be removed without removing anything.

.NOTES
    Deploy via Endpoint Central (SYSTEM). Logs: C:\Logs\CompoSecure.
    Exit: 0 = fully removed or not present / 1 = still present / 3010 n/a
#>

[CmdletBinding()]
param(
    [switch]$CleanOrphanedProfiles,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$LogDir  = 'C:\Logs\CompoSecure'
$LogFile = Join-Path $LogDir ('Remove3DViewer_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

function Test-SidResolves {
    param([string]$Sid)
    try {
        $obj = New-Object System.Security.Principal.SecurityIdentifier($Sid)
        $null = $obj.Translate([System.Security.Principal.NTAccount])
        return $true
    } catch {
        return $false
    }
}

function Remove-3DViewerPackages {
    # Returns $true if a removal was attempted.
    # v3: -PackageTypeFilter All (bundles are invisible otherwise) and
    # bundles removed FIRST -- a main package inside a staged bundle
    # no-ops on removal until the bundle registration is gone.
    $attempted = $false
    $pkgs = Get-AppxPackage -AllUsers -Name $script:PkgName -PackageTypeFilter All -ErrorAction SilentlyContinue
    if (-not $pkgs) { Write-Log '  Not installed for any user.'; return $attempted }

    $ordered = @()
    $ordered += $pkgs | Where-Object { $_.PackageFullName -like '*_~_*' -or $_.IsBundle }
    $ordered += $pkgs | Where-Object { -not ($_.PackageFullName -like '*_~_*' -or $_.IsBundle) }

    foreach ($pkg in $ordered) {
        $kind = 'main'
        if ($pkg.PackageFullName -like '*_~_*' -or $pkg.IsBundle) { $kind = 'BUNDLE' }
        Write-Log ('  Found (' + $kind + '): ' + $pkg.PackageFullName)
        foreach ($ui in $pkg.PackageUserInformation) {
            $sidStr = $ui.UserSecurityId.Sid
            $uname  = $ui.UserSecurityId.Username
            $state  = $ui.InstallState
            if ([string]::IsNullOrWhiteSpace($uname)) { $uname = '(orphaned SID)' }
            Write-Log ('    ' + $uname + ' [' + $sidStr + '] state: ' + $state)
        }
        if ($DryRun) { Write-Log '    [DRYRUN] Would remove for all users.'; continue }
        $attempted = $true
        try {
            Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
            Write-Log '    Remove-AppxPackage -AllUsers completed.'
        } catch {
            Write-Log ('    Remove-AppxPackage error: ' + $_) -Level WARN
        }
    }
    return $attempted
}

$PkgName = 'Microsoft.Microsoft3DViewer'

Write-Log '=============================================='
Write-Log ' Microsoft 3D Viewer Removal -- Plugin 141430 (v3.1)'
Write-Log (' Host    : ' + $env:COMPUTERNAME)
Write-Log (' DryRun  : ' + $DryRun)
Write-Log (' Orphans : ' + $CleanOrphanedProfiles)
Write-Log '=============================================='

# ------------------------------------------------------------------
# 1. Installed packages (all user profiles)
# ------------------------------------------------------------------
Write-Log ''
Write-Log '[1/4] Installed packages (all users)...'
$null = Remove-3DViewerPackages

# ------------------------------------------------------------------
# 2. Provisioned package
# ------------------------------------------------------------------
Write-Log ''
Write-Log '[2/4] Provisioned package...'
$prov = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $PkgName }
if (-not $prov) {
    Write-Log '  Not provisioned.'
} else {
    foreach ($p in $prov) {
        Write-Log ('  Found provisioned: ' + $p.PackageName)
        if ($DryRun) { Write-Log '    [DRYRUN] Would deprovision.'; continue }
        try {
            Remove-AppxProvisionedPackage -Online -PackageName $p.PackageName -ErrorAction Stop | Out-Null
            Write-Log '    Deprovisioned.'
        } catch {
            Write-Log ('    Deprovision failed: ' + $_) -Level ERROR
        }
    }
}

# ------------------------------------------------------------------
# 3. Orphaned-SID handling (the shared-machine blocker)
# ------------------------------------------------------------------
Write-Log ''
Write-Log '[3/4] Checking for registrations held by orphaned SIDs...'
$remaining = Get-AppxPackage -AllUsers -Name $PkgName -PackageTypeFilter All -ErrorAction SilentlyContinue
if (-not $remaining) {
    Write-Log '  None -- package fully gone after step 1.'
} else {
    $orphanSids = @()
    foreach ($pkg in $remaining) {
        foreach ($ui in $pkg.PackageUserInformation) {
            $sidStr = $ui.UserSecurityId.Sid
            if (-not (Test-SidResolves $sidStr)) { $orphanSids += $sidStr }
        }
    }
    $orphanSids = $orphanSids | Sort-Object -Unique
    if ($orphanSids.Count -eq 0) {
        Write-Log '  Remaining registrations belong to EXISTING users -- see step 4 output.' -Level WARN
    } else {
        Write-Log ('  Orphaned SIDs holding the package: ' + ($orphanSids -join ', ')) -Level WARN
        if (-not $CleanOrphanedProfiles) {
            Write-Log '  These are deleted accounts whose leftover profiles block full removal.' -Level WARN
            Write-Log '  Re-run with -CleanOrphanedProfiles to remove those profiles and retry.' -Level WARN
        } elseif ($DryRun) {
            Write-Log '  [DRYRUN] Would remove these orphaned profiles and retry package removal.'
        } else {
            foreach ($sid in $orphanSids) {
                $profile = Get-CimInstance Win32_UserProfile -Filter ("SID='" + $sid + "'") -ErrorAction SilentlyContinue
                if (-not $profile) {
                    Write-Log ('  No Win32_UserProfile for ' + $sid + ' -- registration only; continuing.') -Level WARN
                    continue
                }
                if ($profile.Special) { Write-Log ('  Skipping special profile ' + $sid) -Level WARN; continue }
                if ($profile.Loaded)  { Write-Log ('  Profile ' + $sid + ' is LOADED -- skipping.') -Level WARN; continue }
                Write-Log ('  Removing orphaned profile: ' + $profile.LocalPath + ' [' + $sid + ']')
                try {
                    Remove-CimInstance -InputObject $profile -ErrorAction Stop
                    Write-Log '    Profile removed.'
                } catch {
                    Write-Log ('    Profile removal failed: ' + $_) -Level ERROR
                }
            }
            Write-Log '  Retrying package removal after orphan cleanup...'
            Start-Sleep -Seconds 3
            $null = Remove-3DViewerPackages
        }
    }
}

# ------------------------------------------------------------------
# 4. Verify (registration AND payload on disk)
# ------------------------------------------------------------------
Write-Log ''
Write-Log '[4/4] Verification...'
$Failed = $false
$RegistrationRemains = $false
$RebootPending = $false
if ($DryRun) {
    Write-Log '  [DRYRUN] Skipping verification.'
} else {
    $checkPkg  = Get-AppxPackage -AllUsers -Name $PkgName -PackageTypeFilter All -ErrorAction SilentlyContinue
    $checkProv = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $PkgName }
    $payload   = Get-ChildItem 'C:\Program Files\WindowsApps' -Directory -Filter ($PkgName + '_*') -ErrorAction SilentlyContinue

    if ($checkPkg) {
        Write-Log '  Package registration still present:' -Level WARN
        foreach ($pkg in $checkPkg) {
            foreach ($ui in $pkg.PackageUserInformation) {
                $uname = $ui.UserSecurityId.Username
                if ([string]::IsNullOrWhiteSpace($uname)) { $uname = '(orphaned SID)' }
                Write-Log ('    ' + $uname + ' [' + $ui.UserSecurityId.Sid + '] state: ' + $ui.InstallState) -Level WARN
            }
        }
        $RegistrationRemains = $true
    }
    if ($checkProv) { Write-Log '  Provisioned package still present!' -Level ERROR; $Failed = $true }
    if ($payload)   {
        foreach ($d in $payload) { Write-Log ('  Payload still on disk: ' + $d.FullName) -Level ERROR }
        Write-Log '  Tenable keys on file presence -- finding will NOT clear until this is gone.' -Level ERROR
        Write-Log '  Attempting DISM fallback for any matching provisioned package names...' -Level WARN
        $dismList = & dism.exe /Online /Get-ProvisionedAppxPackages 2>&1 | Out-String
        foreach ($d in $payload) {
            $dirName = $d.Name
            if ($dismList -match [regex]::Escape($dirName)) {
                Write-Log ('    DISM sees ' + $dirName + ' as provisioned -- removing...') -Level WARN
                $dOut = & dism.exe /Online /Remove-ProvisionedAppxPackage ('/PackageName:' + $dirName) 2>&1
                Write-Log ('    DISM exit: ' + $LASTEXITCODE)
            }
        }
        $payload2 = Get-ChildItem 'C:\Program Files\WindowsApps' -Directory -Filter ($PkgName + '_*') -ErrorAction SilentlyContinue
        if (-not $payload2) {
            Write-Log '  DISM fallback cleared the payload.'
        } else {
            # Is the ONLY remaining registration a SYSTEM-staged remnant?
            $sysStagedOnly = $true
            if ($checkPkg) {
                foreach ($pkg in $checkPkg) {
                    foreach ($ui in $pkg.PackageUserInformation) {
                        if ($ui.UserSecurityId.Sid -ne 'S-1-5-18' -or ($ui.InstallState -notmatch 'Staged')) { $sysStagedOnly = $false }
                    }
                }
            } else { $sysStagedOnly = $false }

            if ($sysStagedOnly) {
                Write-Log '  Remnant is SYSTEM-staged only. Deregistration is QUEUED --' -Level WARN
                Write-Log '  the payload is finalized/deleted at the next restart.' -Level WARN
                Write-Log '  REBOOT this machine, then re-run this script to verify.' -Level WARN
                $script:RebootPending = $true
            } else {
                Write-Log '  Payload persists after all removal paths. Remaining option is a' -Level ERROR
                Write-Log '  state-repository-level cleanup -- flag this machine for manual review' -Level ERROR
                Write-Log '  rather than ACL surgery on WindowsApps.' -Level ERROR
                $Failed = $true
            }
        }
    }
    if ($RegistrationRemains -and -not $RebootPending -and -not $Failed) {
        # Registration lingering without the queued-removal explanation = real failure
        $Failed = $true
    }
    if (-not $Failed -and -not $RebootPending) {
        Write-Log '  Confirmed: registration, provisioning, and payload all gone.'
    }
}

Write-Log ''
Write-Log '=============================================='
if ($Failed) {
    Write-Log ' Completed WITH ERRORS -- review log.' -Level ERROR
    Write-Log '=============================================='
    exit 1
}
if ($RebootPending) {
    Write-Log ' Removal QUEUED -- reboot required to finalize, then re-run to verify.' -Level WARN
    Write-Log '=============================================='
    exit 3010
}
Write-Log ' Done. Re-scan to confirm plugin 141430 clears.'
Write-Log '=============================================='
exit 0
