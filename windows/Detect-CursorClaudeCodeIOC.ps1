<#
.SYNOPSIS
  READ-ONLY detection for the malicious Anthropic.claude-code 2.1.312 / 2.1.313 extension
  (Cursor VS Code Extension Marketplace incident, Oct 29, 2026) (v2).

.DESCRIPTION
  Advisory: https://cursor.com/blog/claude-code-extension-security-notice
  Malicious builds were published between about 2:27am and 1:35pm PT on Oct 29, 2026.

  The vendor one-liner checks $HOME. Under Endpoint Central that is
  C:\Windows\system32\config\systemprofile, so it reports not impacted on every machine.
  This script walks every user profile (ProfileList plus C:\Users) instead.

  Findings are graded:
    IMPACTED  backdoor or payload evidence: the svc-telemetry key, the dropped smt/stk
              files, the SysMon task or Startup script running them, a live tunnel or
              connection to the attacker, or the malicious extension.js still on disk.
              Isolate the host, then remediate (advisory steps 3-5).
    EXPOSED   2.1.312 / 2.1.313 was installed at some point (extension folder,
              extensions.json, .obsolete, Cursor logs, or the cached VSIX) but no backdoor
              artifact was found. Cursor deletes the old folder when the extension
              auto-updates, so these traces are often all that is left. The advisory still
              says to remove persistence and rotate credentials for these hosts.
    REVIEW    something an analyst must look at: a task named SysMon that does not
              reference the payload, or a location that could not be read.

  v2 (review of v1, Nov 2, 2026):
    * Exposure is detected even after the bad version was auto-updated away
      (extensions.json, .obsolete, CachedExtensionVSIXs, Cursor logs, VSIX hashes).
    * Attacker key matched by key material as well as the svc-telemetry comment.
    * Tunnel detection no longer requires -N directly after ssh; matches the
      advisory's -R *:0:localhost:22, ExitOnForwardFailure, tunnel@ and payload paths.
    * SysMon is matched by name in any task folder, and every task XML plus every
      Startup folder script is scanned for the payload strings, so a renamed task
      is still found. A SysMon task with no payload reference is REVIEW, not IMPACTED.
    * Also checks the machine-wide Startup folder and C:\Windows\Temp (elevated Cursor).
    * Relaunches in 64-bit PowerShell so System32\Tasks is not redirected.
    * Log is written as it goes, so a killed job still leaves output.
    * A location that could not be read becomes REVIEW instead of a clean result.

.NOTES
  Platform / Deploy : Windows, ManageEngine Endpoint Central, runs as SYSTEM. No arguments.
  EC command field  : powershell -ExecutionPolicy Bypass -File Detect-CursorClaudeCodeIOC.ps1
  This script makes NO changes. Remediation is a separate step (vendor remediate-windows.ps1).
  Log: C:\Logs\CompoSecure\CursorClaudeCodeIOC_<stamp>.log (+ _latest.log)

  Exit codes: 0 = no indicators found, 2 = IMPACTED / EXPOSED / REVIEW (needs attention),
  1 = script error. Leave EC success codes at 0 so exit 2 shows up as a failed target.
#>

$ErrorActionPreference = 'Continue'

# ---- IOCs from the advisory (updated Oct 30, 2026 11:30am PT) ----------------
$BadIP          = '134.209.82.225'
$BadKeyLabel    = 'svc-telemetry'
$BadKeyMaterial = 'AAAAC3NzaC1lZDI1NTE5AAAAIDdvylCEJ/k2TpezcTfedrkHyFSK9IZ3vmP6vhY4Ss0P'
$BadExtVersions = @('2.1.312', '2.1.313')
$BadPayloadSha  = 'ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15'
$BadVsixSha     = @(
    '3de1722901165769893bef57c72594e9a54459faa23f3091b136b79966edd081',  # 2.1.312 win32-x64
    '6786ec90cbd45949695bd7805c9fbb26cfc91bc5fc897de0183d9bcb9cb21731',  # 2.1.313 win32-x64
    'fcbb327e38e61c4fec795e0d0591f52cd1014b813d20a5912104953c3a17c364',  # 2.1.312 darwin-arm64
    '80402fdcad8799285fd93044976973ca000da7995fb93363f819bb8e4f84ee6c'   # 2.1.313 darwin-arm64
)
# Logs older than this cannot mention an install from the Oct 29 window.
$LogsSince      = [datetime]'2026-10-28'
$MaxScanBytes   = 200MB

# ---- helpers (dot-sourced by tests) -----------------------------------------

$script:Findings = New-Object System.Collections.ArrayList
$script:LogFile  = $null

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    if ($script:LogFile) { Add-Content -Path $script:LogFile -Value $line -ErrorAction SilentlyContinue }
}

function Add-Finding {
    param([ValidateSet('IMPACTED', 'EXPOSED', 'REVIEW')][string]$Kind, [string]$Msg)
    [void]$script:Findings.Add([pscustomobject]@{ Kind = $Kind; Msg = $Msg })
    Write-Log ($Kind + ': ' + $Msg) -Level 'IOC'
}

function Join-Parts {
    param([string[]]$Parts)
    return [IO.Path]::Combine([string[]]$Parts)
}

function Test-AttackerKeyText {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    return ($Text.Contains($BadKeyMaterial) -or $Text.Contains($BadKeyLabel))
}

function Get-BadVersionPattern {
    $alts = ($BadExtVersions | ForEach-Object { [regex]::Escape($_) }) -join '|'
    return ('(?i)anthropic\.claude-code[-@ ]v?(' + $alts + ')(?![0-9])')
}

function Test-BadVersionText {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    return ($Text -match (Get-BadVersionPattern))
}

function Get-ClaudeFolderVersion {
    param([string]$Name)
    if ($Name -match '^(?i)anthropic\.claude-code-([0-9]+\.[0-9]+\.[0-9]+)') { return $Matches[1] }
    return $null
}

function Test-PayloadText {
    # Strings that only the payload, its dropped scripts, or its task would contain.
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    if ($Text.Contains($BadIP)) { return $true }
    if ($Text.Contains($BadKeyLabel)) { return $true }
    if ($Text -match '(?i)tunnel@') { return $true }
    if ($Text -match '(?i)\.config[\\/](smt\.cmd|\.?smtk?)(?![\w.])') { return $true }
    if ($Text -match '(?i)\.stk_[0-9a-f]{10}') { return $true }
    return $false
}

function Test-SuspiciousCommandLine {
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $false }
    $c = $CommandLine
    if (Test-PayloadText -Text $c) { return $true }
    if ($c -match '(?i)\bautossh(\.exe)?\b.*\s-M\s*0\b') { return $true }
    if ($c -match '(?i)\bssh(\.exe)?\b' -and $c -match '\s-R\s') {
        if ($c -match '(?i):0:localhost:22\b') { return $true }
        if ($c -match '(?i)ExitOnForwardFailure=yes') { return $true }
    }
    return $false
}

function Test-StkArtifactName {
    param([string]$Name)
    return ($Name -match '^(?i)\.stk_[0-9a-f]{10}')
}

function Get-FileTextSafe {
    # Returns $null when unreadable; caller decides whether that is REVIEW.
    param([string]$Path)
    try {
        $fi = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($fi.Length -gt $MaxScanBytes) { return $null }
        return [IO.File]::ReadAllText($fi.FullName)
    } catch {
        return $null
    }
}

function Get-Sha256Lower {
    param([string]$Path)
    try { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() } catch { return $null }
}

function Test-ScriptFolderForPayload {
    # Startup folders: the named fallback file, or any script that runs the payload.
    param([string]$Folder)
    if (-not (Test-Path -LiteralPath $Folder)) { return }
    $sys = Join-Parts @($Folder, 'sysmon.cmd')
    if (Test-Path -LiteralPath $sys) { Add-Finding IMPACTED ('Startup persistence script: ' + $sys) }
    foreach ($f in @(Get-ChildItem -LiteralPath $Folder -File -Force -ErrorAction SilentlyContinue)) {
        if ($f.Name -ieq 'sysmon.cmd') { continue }
        if ($f.Extension -notmatch '^(?i)\.(cmd|bat|ps1|vbs|js|lnk)$') { continue }
        $t = Get-FileTextSafe -Path $f.FullName
        if ($f.Extension -ieq '.lnk' -and $t) { $t = $t -replace [char]0, '' }
        if (Test-PayloadText -Text $t) { Add-Finding IMPACTED ('Startup item runs the payload: ' + $f.FullName) }
    }
}

function Test-TempForStk {
    param([string]$Folder)
    if (-not (Test-Path -LiteralPath $Folder)) { return }
    foreach ($i in @(Get-ChildItem -LiteralPath $Folder -Force -Filter '.stk_*' -ErrorAction SilentlyContinue)) {
        if (Test-StkArtifactName -Name $i.Name) { Add-Finding IMPACTED ('Temp payload artifact: ' + $i.FullName) }
    }
}

function Invoke-ProfileScan {
    param([string]$ProfilePath)
    $h = $ProfilePath

    # 1. Attacker SSH key
    $ak = Join-Parts @($h, '.ssh', 'authorized_keys')
    if (Test-Path -LiteralPath $ak) {
        $t = Get-FileTextSafe -Path $ak
        if ($null -eq $t) { Add-Finding REVIEW ('Could not read ' + $ak) }
        elseif (Test-AttackerKeyText -Text $t) { Add-Finding IMPACTED ('Attacker svc-telemetry key in ' + $ak) }
        else { Write-Log ('  authorized_keys present, no attacker key: ' + $ak) }
    }

    # 2. Extension folders, manifests and the pending-delete list
    foreach ($root in @((Join-Parts @($h, '.cursor', 'extensions')), (Join-Parts @($h, '.vscode', 'extensions')), (Join-Parts @($h, '.vscode-insiders', 'extensions')))) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($d in @(Get-ChildItem -LiteralPath $root -Directory -Force -Filter 'anthropic.claude-code-*' -ErrorAction SilentlyContinue)) {
            $ver = Get-ClaudeFolderVersion -Name $d.Name
            Write-Log ('  Claude Code extension folder: ' + $d.FullName + '  (version ' + $ver + ')')
            if ($ver -and ($BadExtVersions -contains $ver)) {
                Add-Finding EXPOSED ('Affected extension version ' + $ver + ' on disk: ' + $d.FullName)
            }
            foreach ($js in @(Get-ChildItem -LiteralPath $d.FullName -Recurse -Depth 3 -File -Filter 'extension.js' -Force -ErrorAction SilentlyContinue)) {
                if ((Get-Sha256Lower -Path $js.FullName) -eq $BadPayloadSha) {
                    Add-Finding IMPACTED ('extension.js SHA-256 matches the malicious payload: ' + $js.FullName)
                    continue
                }
                $t = Get-FileTextSafe -Path $js.FullName
                if ($t -and ($t.Contains($BadIP) -or $t.Contains($BadKeyLabel))) {
                    Add-Finding IMPACTED ('extension.js contains the payload IOC strings: ' + $js.FullName)
                }
            }
        }
        foreach ($meta in @('extensions.json', '.obsolete')) {
            $mp = Join-Parts @($root, $meta)
            if (-not (Test-Path -LiteralPath $mp)) { continue }
            $t = Get-FileTextSafe -Path $mp
            if ($null -eq $t) { Add-Finding REVIEW ('Could not read ' + $mp) }
            elseif (Test-BadVersionText -Text $t) { Add-Finding EXPOSED ('Affected version listed in ' + $mp) }
        }
    }

    # 3. Downloaded packages: Cursor's VSIX cache and manually downloaded .vsix files
    $appData = Join-Parts @($h, 'AppData', 'Roaming')
    $cache = Join-Parts @($appData, 'Cursor', 'CachedExtensionVSIXs')
    if (Test-Path -LiteralPath $cache) {
        foreach ($f in @(Get-ChildItem -LiteralPath $cache -File -Force -ErrorAction SilentlyContinue)) {
            if ($f.Name -notmatch '^(?i)anthropic\.claude-code') { continue }
            if (Test-BadVersionText -Text $f.Name) {
                Add-Finding EXPOSED ('Affected VSIX in Cursor download cache: ' + $f.FullName)
            } elseif ($BadVsixSha -contains (Get-Sha256Lower -Path $f.FullName)) {
                Add-Finding EXPOSED ('Cached VSIX matches a malicious package hash: ' + $f.FullName)
            }
        }
    }
    $dl = Join-Parts @($h, 'Downloads')
    if (Test-Path -LiteralPath $dl) {
        foreach ($f in @(Get-ChildItem -LiteralPath $dl -File -Force -Filter '*.vsix' -ErrorAction SilentlyContinue)) {
            if ($f.Length -gt $MaxScanBytes) { continue }
            if ($BadVsixSha -contains (Get-Sha256Lower -Path $f.FullName)) {
                Add-Finding EXPOSED ('Downloaded VSIX matches a malicious package hash: ' + $f.FullName)
            }
        }
    }

    # 4. Cursor logs: install / activation lines that name the affected version
    $logs = Join-Parts @($appData, 'Cursor', 'logs')
    if (Test-Path -LiteralPath $logs) {
        $pattern = Get-BadVersionPattern
        $logHits = 0
        foreach ($lf in @(Get-ChildItem -LiteralPath $logs -Recurse -File -Filter '*.log' -Force -ErrorAction SilentlyContinue)) {
            if ($lf.LastWriteTime -lt $LogsSince -or $lf.Length -gt $MaxScanBytes) { continue }
            $m = Select-String -LiteralPath $lf.FullName -Pattern $pattern -List -ErrorAction SilentlyContinue
            if ($m) {
                $logHits++
                $sample = $m.Line.Trim()
                if ($sample.Length -gt 240) { $sample = $sample.Substring(0, 240) + '...' }
                Add-Finding EXPOSED ('Cursor log names the affected version: ' + $lf.FullName + ' :: ' + $sample)
                if ($logHits -ge 5) { Write-Log '  (stopping log scan for this profile after 5 matching files)'; break }
            }
        }
    }

    # 5. Dropped payload and persistence files
    foreach ($f in @((Join-Parts @($h, '.config', 'smt.cmd')), (Join-Parts @($h, '.config', 'smtk')), (Join-Parts @($h, '.config', '.smt')), (Join-Parts @($h, '.config', '.smtk')))) {
        if (Test-Path -LiteralPath $f) { Add-Finding IMPACTED ('Payload file: ' + $f) }
    }
    Test-ScriptFolderForPayload -Folder (Join-Parts @($appData, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'))
    Test-TempForStk -Folder (Join-Parts @($h, 'AppData', 'Local', 'Temp'))
}

function Get-ScanProfiles {
    $paths = New-Object System.Collections.ArrayList
    foreach ($k in @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue)) {
        if ($k.PSChildName -notmatch '^S-1-5-21-') { continue }
        $p = '' + (Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
        if ($p -and (Test-Path -LiteralPath $p) -and -not ($paths -contains $p)) { [void]$paths.Add($p) }
    }
    $skip = @('Public', 'Default', 'Default User', 'All Users')
    foreach ($d in @(Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue)) {
        if ($skip -contains $d.Name) { continue }
        if (-not ($paths -contains $d.FullName)) { [void]$paths.Add($d.FullName) }
    }
    return @($paths)
}

function Get-ResultSummary {
    param($Findings)
    $imp = @($Findings | Where-Object { $_.Kind -eq 'IMPACTED' }).Count
    $exp = @($Findings | Where-Object { $_.Kind -eq 'EXPOSED' }).Count
    $rev = @($Findings | Where-Object { $_.Kind -eq 'REVIEW' }).Count
    $counts = '(impacted ' + $imp + ', exposed ' + $exp + ', review ' + $rev + ')'
    if ($imp -gt 0) { return @{ Code = 2; Text = 'RESULT: IMPACTED ' + $counts + ' - isolate the host, remediate, rotate credentials (advisory steps 3-5)' } }
    if ($exp -gt 0) { return @{ Code = 2; Text = 'RESULT: EXPOSED ' + $counts + ' - affected version was installed; no backdoor artifact found. Run vendor remediation and rotate credentials.' } }
    if ($rev -gt 0) { return @{ Code = 2; Text = 'RESULT: REVIEW ' + $counts + ' - not proven clean; see REVIEW lines' } }
    return @{ Code = 0; Text = 'RESULT: CLEAN - no indicators found' }
}

function Test-Needs64BitRelaunch {
    param([bool]$Is64BitOS, [bool]$Is64BitProcess)
    return ($Is64BitOS -and -not $Is64BitProcess)
}

if ($env:CLAUDE_IOC_DOTSOURCE -eq '1') { return }

# ---- live run (Windows / Endpoint Central) ----------------------------------

if (Test-Needs64BitRelaunch -Is64BitOS ([Environment]::Is64BitOperatingSystem) -Is64BitProcess ([Environment]::Is64BitProcess)) {
    $ps64 = $env:WINDIR + '\Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $ps64) {
        & $ps64 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
        exit $LASTEXITCODE
    }
}

$LogDir = 'C:\Logs\CompoSecure'
$script:LogFile = $LogDir + '\CursorClaudeCodeIOC_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log'
$LatestFile = $LogDir + '\CursorClaudeCodeIOC_latest.log'
$code = 1

try {
    if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

    Write-Log '=============================================='
    Write-Log ' Cursor Claude Code extension IOC check (v2) - READ ONLY'
    Write-Log (' Host       : ' + $env:COMPUTERNAME)
    Write-Log (' Running as : ' + [Environment]::UserName + '  64-bit: ' + [Environment]::Is64BitProcess)
    Write-Log '=============================================='

    $profiles = @(Get-ScanProfiles)
    if ($profiles.Count -eq 0) { throw 'No user profiles found to scan' }
    Write-Log ('Profiles: ' + ($profiles -join ', '))

    foreach ($p in $profiles) {
        Write-Log ('--- ' + $p)
        try { Invoke-ProfileScan -ProfilePath $p }
        catch { Add-Finding REVIEW ('Profile scan failed for ' + $p + ': ' + $_.Exception.Message) }
    }

    Write-Log '--- Machine-wide'
    $adm = $env:ProgramData + '\ssh\administrators_authorized_keys'
    if (Test-Path -LiteralPath $adm) {
        $t = Get-FileTextSafe -Path $adm
        if ($null -eq $t) { Add-Finding REVIEW ('Could not read ' + $adm) }
        elseif (Test-AttackerKeyText -Text $t) { Add-Finding IMPACTED ('Attacker svc-telemetry key in ' + $adm) }
        else { Write-Log ('  ' + $adm + ' present, no attacker key') }
    }
    Test-ScriptFolderForPayload -Folder ($env:ProgramData + '\Microsoft\Windows\Start Menu\Programs\StartUp')
    Test-TempForStk -Folder ($env:WINDIR + '\Temp')

    # Scheduled tasks: by name in any folder, then any task XML that runs the payload.
    $sysmonTasks = @()
    try { $sysmonTasks = @(Get-ScheduledTask -TaskName 'SysMon' -ErrorAction Stop) } catch { $sysmonTasks = @() }
    $taskRoot = $env:WINDIR + '\System32\Tasks'
    $taskFiles = @(Get-ChildItem -LiteralPath $taskRoot -Recurse -File -Force -ErrorAction SilentlyContinue)
    if ($taskFiles.Count -eq 0) { Add-Finding REVIEW ('Could not list scheduled task files under ' + $taskRoot) }
    $payloadTaskFiles = @()
    foreach ($tf in $taskFiles) {
        $t = Get-FileTextSafe -Path $tf.FullName
        if (Test-PayloadText -Text $t) {
            $payloadTaskFiles += $tf.FullName
            Add-Finding IMPACTED ('Scheduled task runs the payload: ' + $tf.FullName.Substring($taskRoot.Length))
        }
    }
    foreach ($st in $sysmonTasks) {
        $actions = (@($st.Actions) | ForEach-Object { ('' + $_.Execute + ' ' + $_.Arguments).Trim() }) -join ' | '
        $desc = $st.TaskPath + $st.TaskName + ' (run-as ' + $st.Principal.UserId + ', action ' + $actions + ')'
        $file = $taskRoot + $st.TaskPath + $st.TaskName
        if ($payloadTaskFiles -contains $file) { continue }
        if (Test-PayloadText -Text $actions) { Add-Finding IMPACTED ('Scheduled task SysMon runs the payload: ' + $desc) }
        else { Add-Finding REVIEW ('Scheduled task named SysMon with no payload reference - confirm it is legitimate: ' + $desc) }
    }

    # Running tunnel / payload processes
    $procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
    if ($procs.Count -eq 0) { Add-Finding REVIEW 'Could not list processes (Win32_Process)' }
    foreach ($pr in $procs) {
        if ($pr.ProcessId -eq $PID) { continue }
        if (Test-SuspiciousCommandLine -CommandLine $pr.CommandLine) {
            Add-Finding IMPACTED ('Tunnel/payload process PID ' + $pr.ProcessId + ' (parent ' + $pr.ParentProcessId + '): ' + $pr.CommandLine)
        }
    }

    # Live or lingering connections to the attacker endpoint
    foreach ($c in @(Get-NetTCPConnection -RemoteAddress $BadIP -ErrorAction SilentlyContinue)) {
        Add-Finding IMPACTED ('TCP connection to ' + $BadIP + ':' + $c.RemotePort + ' state ' + $c.State + ' PID ' + $c.OwningProcess)
    }

    # Local SSH server (informational: the payload tries to enable it, which needs admin)
    $sshd = Get-Service sshd -ErrorAction SilentlyContinue
    if ($sshd) {
        $startType = '' + (Get-CimInstance Win32_Service -Filter 'Name=''sshd''' -ErrorAction SilentlyContinue).StartMode
        Write-Log ('INFO sshd present: status ' + $sshd.Status + ', start ' + $startType + ' (not an IOC alone; confirm it is expected on this host)')
    } else {
        Write-Log 'INFO sshd (OpenSSH Server) not installed'
    }

    $r = Get-ResultSummary -Findings $script:Findings
    Write-Log '=============================================='
    Write-Log $r.Text
    Write-Log '=============================================='
    $code = $r.Code
}
catch {
    Write-Log ('ERROR: ' + $_.Exception.Message) -Level ERROR
    Write-Log 'RESULT: ERROR - not verified'
    $code = 1
}

try { Copy-Item -LiteralPath $script:LogFile -Destination $LatestFile -Force -ErrorAction Stop } catch {}

exit $code
