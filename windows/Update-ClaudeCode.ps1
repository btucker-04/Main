<#
.SYNOPSIS
    Remediates Anthropic Claude Code < 2.1.163 (Nessus Plugin 322792,
    CVE-2026-54316, data exfiltration) for PER-USER installs.

.DESCRIPTION
    Written for CSLT-202 (2026-08-27 Tenable group export):
      Path              : C:\Users\sbeatrice\.local
      Installed version : 2.1.156.0
      Fixed version     : 2.1.163

    THE CORE PROBLEM. Claude Code installs per-user under the user's own
    profile (%USERPROFILE%\.local), and this script runs as SYSTEM under
    Endpoint Central. SYSTEM cannot meaningfully run another user's per-user
    application updater: the updater writes into that profile and expects
    that user's environment. This is the same wall documented for Cursor in
    Update-ThirdPartyAppBundle.ps1 and for winget.exe in Update-WinGet.ps1 --
    per-user installs need USER-CONTEXT execution.

    HOW THIS INITIATES THE UPDATE REMOTELY ANYWAY. Rather than asking the user
    to act (the reason these findings stay open is that they do not), this
    stages the update INTO the user's own context via their per-user RunOnce
    key, under HKEY_USERS\<SID>\...\CurrentVersion\RunOnce. At that user's next
    logon Windows runs it AS THEM, once, and removes the entry itself. No
    credentials, no scheduled-task password, no cooperation required beyond
    them logging in to do their job.

    Deliberately NOT used here: creating a scheduled task with -RunLevel/-User
    for another account, which either needs that account's password or silently
    lands in a state that never runs. RunOnce is the mechanism that reliably
    executes in a specific user's context without their password.

    HONEST LIMITATION, stated rather than hidden: the update therefore does not
    happen NOW -- it happens at that user's next logon. This script's success
    means "staged correctly", not "version advanced". Verification is the next
    scan (or a re-run of this script, which reports the version it finds). If
    you need it done inside a maintenance window instead, the decisive option
    is -RemoveClaudeCode, which clears the finding immediately by removing the
    per-user install; that mirrors -RemoveCursor in
    Update-ThirdPartyAppBundle.ps1 and is appropriate when the tool is not
    sanctioned for that user.

.PARAMETER TargetVersion
    Minimum acceptable version. Default 2.1.163 (the fixed version for
    CVE-2026-54316).

.PARAMETER RemoveClaudeCode
    Remove the per-user Claude Code install(s) outright instead of staging an
    update. Immediate and verifiable, but destructive to that user's tool --
    use where Claude Code is not sanctioned for the account.

.PARAMETER NotifyUser
    Also send a console message to any logged-on user, so an update appearing
    at next logon is not a surprise.

.PARAMETER DryRun
    Report every install and intended action without changing anything.

.NOTES
    Deploy via Endpoint Central (SYSTEM), Repository mode, -File invocation,
    arguments as bare switches only. Logs: C:\Logs\CompoSecure.
    Exit codes: 0 = nothing vulnerable, or removed successfully
                2 = update STAGED for next logon (not yet verified), or a
                    version that could not be read -- deliberately not a
                    success code, because the finding has not cleared yet
                1 = failure (could not stage, or removal left files behind)
#>

[CmdletBinding()]
param(
    [string]$TargetVersion = '2.1.163',
    [switch]$RemoveClaudeCode,
    [switch]$NotifyUser,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$LogDir  = 'C:\Logs\CompoSecure'
$LogFile = Join-Path $LogDir ('ClaudeCodeUpdate_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

# '2.1.156.0' / 'claude 2.1.156' / '2.1.156 (Claude Code)' -> [version]
function Convert-ToVersion {
    param([string]$Text)
    if (-not $Text) { return $null }
    $m = [regex]::Match($Text, '\d+\.\d+\.\d+(\.\d+)?')
    if (-not $m.Success) { return $null }
    $parsed = $null
    try { $parsed = [version]$m.Value } catch { }
    return $parsed
}

# Resolve a profile directory to its SID via the ProfileList registry, which is
# authoritative -- do not guess from the folder name (it does not always match
# the account name).
function Get-ProfileSid {
    param([string]$ProfilePath)
    $base = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    foreach ($k in (Get-ChildItem $base -ErrorAction SilentlyContinue)) {
        $p = (Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
        if ($p -and ($p.TrimEnd('\') -eq $ProfilePath.TrimEnd('\'))) { return $k.PSChildName }
    }
    return $null
}

$Staged      = 0
$Removed     = 0
$Failed      = 0
$NeedsHuman  = 0
$targetVerObj = [version]$TargetVersion

Write-Log '=============================================='
Write-Log ' Claude Code Update -- Plugin 322792 (CVE-2026-54316)'
Write-Log (' Host       : ' + $env:COMPUTERNAME)
Write-Log (' Running as : ' + [Security.Principal.WindowsIdentity]::GetCurrent().Name)
Write-Log (' Target     : ' + $TargetVersion)
Write-Log (' Mode       : ' + $(if ($RemoveClaudeCode) { 'REMOVE per-user install' } else { 'STAGE update via per-user RunOnce' }))
Write-Log (' DryRun     : ' + $DryRun)
Write-Log '=============================================='

# ==============================================================
# 1. Enumerate per-user installs
# ==============================================================
Write-Log ''
Write-Log '[1/3] Locating per-user Claude Code installs (C:\Users\*\.local)...'

$candidates = @()
foreach ($profileDir in (Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
    $localDir = Join-Path $profileDir.FullName '.local'
    if (-not (Test-Path $localDir)) { continue }
    $exe = Get-ChildItem -Path $localDir -Filter 'claude*.exe' -File -Recurse -Depth 2 -ErrorAction SilentlyContinue |
           Select-Object -First 1
    $cmdShim = Join-Path $localDir 'bin\claude'
    if (-not $exe -and -not (Test-Path $cmdShim)) { continue }
    $candidates += [pscustomobject]@{
        User        = $profileDir.Name
        ProfilePath = $profileDir.FullName
        LocalDir    = $localDir
        Exe         = if ($exe) { $exe.FullName } else { $cmdShim }
    }
}

if ($candidates.Count -eq 0) {
    Write-Log '  No per-user Claude Code install found under C:\Users\*\.local.'
    Write-Log '  Nothing to remediate on this host.'
    Write-Log '=============================================='
    exit 0
}

foreach ($c in $candidates) {
    Write-Log ''
    Write-Log ('--- user: ' + $c.User + ' ---')
    Write-Log ('  Install : ' + $c.LocalDir)
    Write-Log ('  Binary  : ' + $c.Exe)

    # Version from the file itself. Running the binary as SYSTEM to ask it is
    # exactly the per-user-context problem this script exists to work around,
    # so read metadata instead.
    $ver = $null
    if ($c.Exe -match '\.exe$') {
        $vi = (Get-Item $c.Exe -ErrorAction SilentlyContinue).VersionInfo
        if ($vi) { $ver = Convert-ToVersion ('' + $vi.ProductVersion + ' ' + $vi.FileVersion) }
    }
    if (-not $ver) {
        # Fall back to a version-stamped directory name under .local
        $stamped = Get-ChildItem $c.LocalDir -Directory -Recurse -Depth 2 -ErrorAction SilentlyContinue |
                   Where-Object { $_.Name -match '^\d+\.\d+\.\d+' } |
                   Sort-Object Name -Descending | Select-Object -First 1
        if ($stamped) { $ver = Convert-ToVersion $stamped.Name }
    }

    if (-not $ver) {
        Write-Log '  Could not determine the installed version from file metadata.' -Level WARN
        Write-Log '  Tenable reads this from the user context; treat its reported version as' -Level WARN
        Write-Log '  authoritative and act on that host specifically.' -Level WARN
        $NeedsHuman = 1
    } else {
        Write-Log ('  Version : ' + $ver)
        if ($ver -ge $targetVerObj) {
            Write-Log '  Already at or above target. Nothing to do for this user.'
            continue
        }
        Write-Log ('  VULNERABLE (< ' + $TargetVersion + ').') -Level WARN
    }

    # ==============================================================
    # 2. Act: remove, or stage an update into the user's own context
    # ==============================================================
    if ($RemoveClaudeCode) {
        if ($DryRun) {
            Write-Log ('  [DRYRUN] Would remove ' + $c.LocalDir)
            continue
        }
        try {
            Remove-Item -Path $c.LocalDir -Recurse -Force -ErrorAction Stop
            Write-Log '  Removed the per-user install.'
            $Removed++
        } catch {
            Write-Log ('  Removal failed: ' + $_) -Level ERROR
            Write-Log '  Claude Code may be running for that user; retry when they are logged off.' -Level ERROR
            $Failed++
        }
        continue
    }

    $sid = Get-ProfileSid -ProfilePath $c.ProfilePath
    if (-not $sid) {
        Write-Log '  Could not resolve this profile to a SID via ProfileList -- cannot stage' -Level ERROR
        Write-Log '  a per-user RunOnce entry without it.' -Level ERROR
        $Failed++
        continue
    }
    Write-Log ('  SID     : ' + $sid)

    # 'claude update' must run as the user. RunOnce under their hive does that
    # at next logon, then Windows deletes the entry itself.
    $updateCmd = 'cmd.exe /c "' + $c.Exe + '" update'
    if ($DryRun) {
        Write-Log ('  [DRYRUN] Would set RunOnce for ' + $sid + ': ' + $updateCmd)
        continue
    }

    $hiveLoadedByUs = $false
    $hiveKey = 'HKU\' + $sid
    try {
        if (-not (Test-Path ('Registry::HKEY_USERS\' + $sid))) {
            # Profile not loaded (user not logged on) -- mount their NTUSER.DAT.
            $ntuser = Join-Path $c.ProfilePath 'NTUSER.DAT'
            if (-not (Test-Path $ntuser)) {
                Write-Log ('  Profile hive not loaded and NTUSER.DAT not found at ' + $ntuser) -Level ERROR
                $Failed++
                continue
            }
            Write-Log '  Profile not loaded; mounting NTUSER.DAT temporarily...'
            $regOut = & reg.exe load $hiveKey "$ntuser" 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Log ('  reg load failed: ' + ($regOut -join ' ')) -Level ERROR
                $Failed++
                continue
            }
            $hiveLoadedByUs = $true
        }

        $runOnce = 'Registry::HKEY_USERS\' + $sid + '\Software\Microsoft\Windows\CurrentVersion\RunOnce'
        if (-not (Test-Path $runOnce)) { New-Item -Path $runOnce -Force | Out-Null }
        Set-ItemProperty -Path $runOnce -Name 'CompoSecure_ClaudeCodeUpdate' -Value $updateCmd -ErrorAction Stop
        Write-Log '  Staged: RunOnce\CompoSecure_ClaudeCodeUpdate'
        Write-Log ('    ' + $updateCmd)
        Write-Log '  This runs AS THAT USER at their next logon, once, then Windows'
        Write-Log '  removes the entry. No password or user cooperation required.'
        $Staged++
    } catch {
        Write-Log ('  Failed to stage RunOnce entry: ' + $_) -Level ERROR
        $Failed++
    } finally {
        # Always unload a hive we mounted -- leaving it loaded blocks profile
        # operations for that user and is a genuinely disruptive footgun.
        if ($hiveLoadedByUs) {
            [gc]::Collect()
            $unload = & reg.exe unload $hiveKey 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Log ('  WARNING: reg unload failed: ' + ($unload -join ' ')) -Level WARN
                Write-Log ('  Verify with: reg query ' + $hiveKey) -Level WARN
            } else {
                Write-Log '  Unmounted the profile hive.'
            }
        }
    }
}

# ==============================================================
# 3. Notify + verdict
# ==============================================================
if ($NotifyUser -and -not $DryRun -and $Staged -gt 0) {
    Write-Log ''
    Write-Log '[3/3] Notifying logged-on user(s)...'
    try {
        & msg.exe * /TIME:120 'IT Security: a required Claude Code security update will install automatically the next time you sign in. No action needed beyond signing out and back in.' 2>$null
        Write-Log '  Message sent (best effort; no interactive session is not an error).'
    } catch {
        Write-Log '  Could not send a console message (no interactive session?).' -Level WARN
    }
}

Write-Log ''
Write-Log '=============================================='
if ($DryRun) {
    Write-Log ' DRYRUN -- nothing was changed.'
    Write-Log '=============================================='
    exit 0
}
if ($Failed -gt 0) {
    Write-Log (' Completed WITH FAILURES. Staged: ' + $Staged + '  Removed: ' + $Removed + '  Failed: ' + $Failed) -Level ERROR
    Write-Log '=============================================='
    exit 1
}
if ($Removed -gt 0) {
    Write-Log (' Removed ' + $Removed + ' per-user install(s). Re-scan to confirm 322792 clears.')
    Write-Log '=============================================='
    exit 0
}
if ($Staged -gt 0) {
    Write-Log (' Staged ' + $Staged + ' update(s) to run at the user''s next logon.') -Level WARN
    Write-Log ' The finding has NOT cleared yet -- it clears after that logon and a' -Level WARN
    Write-Log ' rescan. Exiting 2 so this is not recorded as done.' -Level WARN
    Write-Log '=============================================='
    exit 2
}
if ($NeedsHuman -gt 0) {
    Write-Log ' Nothing staged, but a version could not be read -- see the log.' -Level WARN
    Write-Log '=============================================='
    exit 2
}
Write-Log ' Nothing vulnerable found. Re-scan to confirm.'
Write-Log '=============================================='
exit 0
