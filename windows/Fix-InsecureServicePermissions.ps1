<#
.SYNOPSIS
    Remediates insecure Windows service permissions (Nessus Plugin 65057) (v2)
    on the two SolidWorks service directories flagged on cslt-156.

.DESCRIPTION
    ** SCOPE: cslt-156 is a Pierce production workstation. Confirm change
    approval and run during a window where SolidWorks / the SWScheduler /
    Visualize queue service can restart. **

    The finding: the 'Users' group has write / full-control on the
    directories containing two SolidWorks service executables, allowing an
    unprivileged user to replace the binary and gain the service's
    privileges (LocalSystem) at next start.

    Surgical fix -- for each flagged directory this script:
      1. Backs up the current ACL (icacls /save) so the change is reversible.
      2. Removes WRITE/MODIFY/FULL-CONTROL for 'Users' (BUILTIN\Users,
         S-1-5-32-545) while LEAVING read & execute intact, so SolidWorks
         still launches and reads its files.
    It does NOT reset the whole ACL or strip Users entirely -- that would
    break SolidWorks components that legitimately read from these paths.

    Applies the ACL to the directory (with inheritance to child files), which
    is what actually closes the hole -- locking only the .exe still lets a
    user with directory-write delete-and-replace it.

    v2 (from the 2026-08-11 CSLT-156 run):
      * The risky ACE is INHERITED, not explicit. The saved ACL showed
        (A;OICIID;FA;;;BU) -- the ID flag means inherited -- coming down from
        the SOLIDWORKS Corp parent. 'icacls /remove:g' only removes EXPLICIT
        ACEs, so v1 stripped the explicit grants, added Read & Execute, and the
        inherited FullControl survived untouched. Verification caught it.
        v2 detects inheritance and calls 'icacls /inheritance:d' first, which
        converts inherited ACEs into explicit copies on this directory so the
        FullControl entry can actually be removed.
      * ACL backup now uses /T so children are captured too. v1 saved only the
        top-level directory while modifying recursively, so a rollback would
        have been incomplete.
      * Verification now distinguishes an inherited from an explicit leftover,
        because the remedies differ.
      * DELIBERATELY NOT FIXED: the parent 'SOLIDWORKS Corp' ACL that is the
        actual source. SolidWorks needs user write in parts of that tree
        (Toolbox data, templates, lang files), which is likely why the installer
        set FullControl. Stripping it tree-wide on a production CAD workstation
        risks breaking the application. Breaking inheritance on just the flagged
        service directories satisfies the finding without that risk. Raise the
        parent ACL with the CAD owner / SolidWorks rather than changing it here.

.PARAMETER DryRun
    Show current ACLs and what would change, without modifying anything.

.NOTES
    Deploy via Endpoint Central (SYSTEM). Logs + ACL backups:
    C:\Logs\CompoSecure. No reboot needed (change takes effect immediately;
    running service keeps its handle until next restart). Exit 0/1.
#>

[CmdletBinding()]
param([switch]$DryRun)

$ErrorActionPreference = 'Stop'
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

# The service-executable DIRECTORIES flagged by plugin 65057.
# We tighten the directory (inherits to files) rather than each .exe alone.
$TargetDirs = @(
    'C:\Program Files\SOLIDWORKS Corp\SOLIDWORKS Visualize',
    'C:\Program Files\SOLIDWORKS Corp\SOLIDWORKS\swScheduler'
)

# 'Users' well-known SID -- language-independent (do not hardcode the name).
$UsersSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')
$UsersAccount = $UsersSid.Translate([System.Security.Principal.NTAccount]).Value
Write-Log ('Users group resolves to: ' + $UsersAccount)

Write-Log '=============================================='
Write-Log ' Insecure Service Permissions Fix -- Plugin 65057'
Write-Log (' Host   : ' + $env:COMPUTERNAME)
Write-Log (' DryRun : ' + $DryRun)
Write-Log '=============================================='
Write-Log 'SCOPE: Pierce production workstation. Ensure SolidWorks can restart.'

$Failed = $false
$changed = 0

foreach ($dir in $TargetDirs) {
    Write-Log ''
    Write-Log ('--- ' + $dir + ' ---')
    if (-not (Test-Path $dir)) {
        Write-Log '  Not present on this machine. Skipping.'
        continue
    }

    # Show current Users ACEs
    $acl = Get-Acl $dir
    $usersAces = $acl.Access | Where-Object {
        $_.IdentityReference.Value -eq $UsersAccount -and
        $_.AccessControlType -eq 'Allow' -and
        ($_.FileSystemRights.ToString() -match 'Write|Modify|FullControl')
    }
    if (-not $usersAces) {
        Write-Log '  No write/modify/full-control ACE for Users. Already compliant.'
        continue
    }
    foreach ($ace in $usersAces) {
        Write-Log ('  Current risky ACE: Users = ' + $ace.FileSystemRights + ' (' + $ace.AccessControlType + ', inheritance: ' + $ace.InheritanceFlags + ')') -Level WARN
    }

    if ($DryRun) {
        Write-Log '  [DRYRUN] Would back up ACL, then remove Users write/modify/full-control'
        Write-Log '  [DRYRUN] (keeping read & execute) on this directory and inherited files.'
        continue
    }

    # 1. Back up current ACL for rollback
    $safeName = ($dir -replace '[:\\ ]', '_') + '.acl'
    $backupPath = Join-Path $AclBackupDir $safeName
    $parent = Split-Path -Parent $dir
    $leaf   = Split-Path -Leaf $dir
    $saveOut = & icacls "$dir" /save "$backupPath" /T /C 2>&1
    Write-Log ('  ACL backup: ' + $backupPath)

    # 2a. Is the risky ACE INHERITED? icacls /remove:g cannot touch inherited
    #     ACEs, so inheritance must be broken (converted to explicit) first.
    $inheritedRisky = $false
    foreach ($ace in $usersAces) {
        if ($ace.IsInherited) { $inheritedRisky = $true }
    }
    if ($inheritedRisky) {
        Write-Log '  The risky ACE is INHERITED from the parent directory.' -Level WARN
        Write-Log '  icacls /remove:g only affects EXPLICIT ACEs, so inheritance must be' -Level WARN
        Write-Log '  broken here first (/inheritance:d converts inherited ACEs into' -Level WARN
        Write-Log '  explicit copies on this directory, which can then be removed).' -Level WARN
        $inhOut = & icacls "$dir" /inheritance:d /T /C 2>&1
        Write-Log '  Inheritance disabled (inherited ACEs converted to explicit).'
    }

    # 2b. Remove Users' write-bearing rights, keep read+execute.
    #     Remove first so ACEs do not stack.
    $rmOut = & icacls "$dir" /remove:g "*S-1-5-32-545" /T /C 2>&1
    Write-Log ('  Removed Users grants (recursive).')
    $grantOut = & icacls "$dir" /grant:r "*S-1-5-32-545:(OI)(CI)(RX)" /T /C 2>&1
    Write-Log ('  Re-granted Users: Read & Execute only (OI)(CI)(RX).')

    # 3. Verify no write-bearing Users ACE remains on the directory
    $aclAfter = Get-Acl $dir
    $stillRisky = $aclAfter.Access | Where-Object {
        $_.IdentityReference.Value -eq $UsersAccount -and
        $_.AccessControlType -eq 'Allow' -and
        ($_.FileSystemRights.ToString() -match 'Write|Modify|FullControl')
    }
    if ($stillRisky) {
        $anyInherited = $false
        foreach ($ace in $stillRisky) {
            if ($ace.IsInherited) {
                $anyInherited = $true
                Write-Log ('  STILL PRESENT (INHERITED): Users = ' + $ace.FileSystemRights) -Level ERROR
            } else {
                Write-Log ('  STILL PRESENT (explicit): Users = ' + $ace.FileSystemRights) -Level ERROR
            }
        }
        if ($anyInherited) {
            Write-Log '  An INHERITED write ACE remains, so the parent directory still grants it.' -Level ERROR
            Write-Log '  Either /inheritance:d did not take, or the ACE was re-inherited. The' -Level ERROR
            Write-Log '  underlying source is the parent ACL -- see the note in this script''s' -Level ERROR
            Write-Log '  header about why that is not changed automatically.' -Level ERROR
        } else {
            Write-Log '  An EXPLICIT write ACE remains -- the remove/grant did not apply.' -Level ERROR
        }
        $Failed = $true
    } else {
        Write-Log '  Verified: Users now has read & execute only on this directory.'
        $changed++
    }
}

# Report the parent ACL, since that is the actual source of the loose permission.
$parentDir = 'C:\Program Files\SOLIDWORKS Corp'
if (Test-Path $parentDir) {
    Write-Log ''
    Write-Log ('--- Parent ACL for context: ' + $parentDir + ' ---')
    $pacl = Get-Acl $parentDir
    foreach ($ace in $pacl.Access) {
        if ($ace.IdentityReference.Value -eq $UsersAccount) {
            $inh = if ($ace.IsInherited) { 'inherited' } else { 'explicit' }
            Write-Log ('  Users = ' + $ace.FileSystemRights + '  (' + $ace.AccessControlType + ', ' + $inh + ')')
        }
    }
    Write-Log '  If Users has write here, every subfolder inherits it -- including any'
    Write-Log '  new service directory a future SolidWorks update creates. That is the'
    Write-Log '  durable fix, but it is a CAD-owner decision: SolidWorks needs user write'
    Write-Log '  in parts of this tree (Toolbox, templates, lang), so changing it here'
    Write-Log '  could break the application.'
}

Write-Log ''
Write-Log '=============================================='
if ($Failed) {
    Write-Log ' Completed WITH ERRORS -- review log. ACL backups in:' -Level ERROR
    Write-Log ('   ' + $AclBackupDir) -Level ERROR
    Write-Log ' Roll back a path with:  icacls "<parent dir>" /restore "<backup.acl>"'
    Write-Log '=============================================='
    exit 1
}
Write-Log (' Done. Directories tightened: ' + $changed)
Write-Log ' SolidWorks reads still work; a user can no longer replace the service exe.'
Write-Log ' ACL backups (for rollback) in: ' + $AclBackupDir
Write-Log ' Re-run a Nessus scan to confirm plugin 65057 clears.'
Write-Log '=============================================='
exit 0
