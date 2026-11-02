<#
.SYNOPSIS
  Detection (default, read-only) and optional remediation for the malicious
  Anthropic.claude-code 2.1.312 / 2.1.313 extension (Cursor VS Code Extension
  Marketplace incident, Oct 29, 2026) (v3).

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
    * Files are read both BOM-decoded and byte-for-byte: the payload appends the key as
      UTF-8 even to a UTF-16 authorized_keys, which a plain decode garbles.

  v3 (Nov 2, 2026): -Remediate covers what the vendor's remediate-windows.ps1 removes,
  plus its gaps:
    * Removes only IMPACTED items: payload tasks (any folder), tunnel/payload processes,
      tampered extension folders (by content, as the vendor does), dropped smt/stk files,
      Startup scripts that run the payload, and the attacker key.
    * Also cleans C:\ProgramData\ssh\administrators_authorized_keys and
      C:\Windows\Temp\.stk_*, which the vendor script skips, and deletes the affected
      VSIX from Cursor's download cache so it cannot be reinstalled from there.
    * Every removed file, and every authorized_keys before it is edited, is copied to a
      quarantine folder under C:\Logs\CompoSecure readable only by SYSTEM and
      Administrators.
    * Key removal keeps the file's encoding. It handles the raw UTF-8 append the vendor
      describes, a key on the same line as a real key, and a fully UTF-16 file.
    * After acting it re-scans and grades on that second scan, not on what it tried.
    * A REVIEW item (a SysMon task with no payload reference) is never removed.
    * Exit 2 (not 0) when it removed a backdoor, so EC shows which hosts need
      credential rotation.

.PARAMETER Remediate
  Remove the IMPACTED items, then re-scan. Without it the script changes nothing.

.PARAMETER ForceCloseEditors
  With -Remediate: close Cursor (or VS Code) before deleting a tampered extension
  folder it has locked. Closes every instance on the machine; unsaved work can be lost.
  Without it a locked folder is reported and the result is REMEDIATION INCOMPLETE.

.PARAMETER DisableSshd
  With -Remediate: stop the OpenSSH Server service and set it to Disabled. The payload
  tries to enable it (that needs admin). Leave off on hosts that use sshd on purpose.

.NOTES
  Platform / Deploy : Windows, ManageEngine Endpoint Central, runs as SYSTEM.
  EC command field  : powershell -ExecutionPolicy Bypass -File Detect-CursorClaudeCodeIOC.ps1
  EC arguments      : none (detect), or -Remediate [-ForceCloseEditors] [-DisableSshd]
  Log: C:\Logs\CompoSecure\CursorClaudeCodeIOC_<stamp>.log (+ _latest.log)
  Quarantine (-Remediate): C:\Logs\CompoSecure\CursorClaudeCodeIOC_Quarantine_<stamp>

  Exit codes (leave EC success codes at 0 so anything else shows up as a failed target):
    0 = clean (nothing found)
    2 = needs attention: detect mode found IMPACTED / EXPOSED / REVIEW, or -Remediate
        removed a backdoor (rotate credentials), or only EXPOSED / REVIEW items exist
    3 = -Remediate ran but IMPACTED items remain (see the VERIFY section of the log)
    1 = script error
  EXPOSED traces (Cursor logs, extensions.json) are evidence, not payload, and are left
  in place, so a remediated host keeps reporting EXPOSED on later detect runs.
#>

[CmdletBinding()]
param(
    [switch]$Remediate,
    [switch]$ForceCloseEditors,
    [switch]$DisableSshd
)

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
    # Action/Target tell -Remediate what to do; findings without an Action are report-only.
    param(
        [ValidateSet('IMPACTED', 'EXPOSED', 'REVIEW')][string]$Kind,
        [string]$Msg,
        [ValidateSet('', 'RemoveTask', 'KillProcess', 'RemoveExtension', 'RemoveFile', 'CleanKey', 'RemovePackage')][string]$Action = '',
        [string]$Target = ''
    )
    [void]$script:Findings.Add([pscustomobject]@{ Kind = $Kind; Msg = $Msg; Action = $Action; Target = $Target })
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
    # Folder-style names (anthropic.claude-code-2.1.312-win32-x64, id@version) and the
    # extensions.json form, where id and version are separate fields of one entry.
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    if ($Text -match (Get-BadVersionPattern)) { return $true }
    $q = [char]34
    $alts = ($BadExtVersions | ForEach-Object { [regex]::Escape($_) }) -join '|'
    $json = '(?i)' + $q + 'anthropic\.claude-code' + $q + '(?:(?!' + $q + 'version' + $q + ').){0,300}' + $q + 'version' + $q + '\s*:\s*' + $q + '(' + $alts + ')' + $q
    return ($Text -match $json)
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
    if ($Text -match '(?i)\\Startup\\sysmon\.cmd') { return $true }
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

function ConvertFrom-FileBytes {
    # The payload appends UTF-8 bytes even when the file is UTF-16 (Windows PowerShell
    # 5.1 writes authorized_keys that way), so a BOM-aware decode alone garbles the key.
    # Latin-1 maps bytes 1:1 and keeps the raw UTF-8 run readable; return both views.
    param([byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return '' }
    $latin1 = [Text.Encoding]::GetEncoding(28591).GetString($Bytes)
    $ms = New-Object IO.MemoryStream (, $Bytes)
    $sr = New-Object IO.StreamReader ($ms, [Text.Encoding]::UTF8, $true)
    try { $decoded = $sr.ReadToEnd() } finally { $sr.Dispose() }
    return ($decoded + [char]10 + $latin1)
}

function Get-FileTextSafe {
    # Returns $null when unreadable; caller decides whether that is REVIEW.
    param([string]$Path)
    try {
        $fi = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($fi.Length -gt $MaxScanBytes) { return $null }
        return (ConvertFrom-FileBytes -Bytes ([IO.File]::ReadAllBytes($fi.FullName)))
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
    if (Test-Path -LiteralPath $sys) { Add-Finding IMPACTED ('Startup persistence script: ' + $sys) -Action RemoveFile -Target $sys }
    foreach ($f in @(Get-ChildItem -LiteralPath $Folder -File -Force -ErrorAction SilentlyContinue)) {
        if ($f.Name -ieq 'sysmon.cmd') { continue }
        if ($f.Extension -notmatch '^(?i)\.(cmd|bat|ps1|vbs|js|lnk)$') { continue }
        $t = Get-FileTextSafe -Path $f.FullName
        if ($t) { $t = $t -replace [char]0, '' }
        if (Test-PayloadText -Text $t) { Add-Finding IMPACTED ('Startup item runs the payload: ' + $f.FullName) -Action RemoveFile -Target $f.FullName }
    }
}

function Test-TempForStk {
    # Depth 1 also covers the per-session Temp\<n> folders on RDP hosts.
    param([string]$Folder)
    if (-not (Test-Path -LiteralPath $Folder)) { return }
    foreach ($i in @(Get-ChildItem -LiteralPath $Folder -Recurse -Depth 1 -Force -Filter '.stk_*' -ErrorAction SilentlyContinue)) {
        if (Test-StkArtifactName -Name $i.Name) { Add-Finding IMPACTED ('Temp payload artifact: ' + $i.FullName) -Action RemoveFile -Target $i.FullName }
    }
}

function Test-KeyFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $t = Get-FileTextSafe -Path $Path
    if ($null -eq $t) { Add-Finding REVIEW ('Could not read ' + $Path) }
    elseif (Test-AttackerKeyText -Text $t) { Add-Finding IMPACTED ('Attacker svc-telemetry key in ' + $Path) -Action CleanKey -Target $Path }
    else { Write-Log ('  ' + $Path + ' present, no attacker key') }
}

function Get-AttackerKeyPattern {
    return ('ssh-ed25519 ' + [regex]::Escape($BadKeyMaterial) + '(?: ' + [regex]::Escape($BadKeyLabel) + ')?')
}

function Remove-AttackerKeyFromBytes {
    # Returns @{ Changed; Bytes }. Edits in the file's own encoding so sshd still reads it.
    # The payload appends raw UTF-8 with no leading newline: Latin-1 round-trips those
    # bytes 1:1, and the \x00 lookbehind handles a UTF-16 newline (0A 00) before the key.
    param([byte[]]$Bytes)
    $keyRx = Get-AttackerKeyPattern
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return @{ Changed = $false; Bytes = $Bytes } }
    $latin1 = [Text.Encoding]::GetEncoding(28591)
    $text = $latin1.GetString($Bytes)
    if ($text -match $keyRx) {
        $new = ($text -replace ('(?m)(?<=^|\x00)' + $keyRx + '\r?\n'), '') -replace $keyRx, ''
        return @{ Changed = $true; Bytes = $latin1.GetBytes($new) }
    }
    foreach ($enc in @([Text.Encoding]::Unicode, [Text.Encoding]::BigEndianUnicode)) {
        $pre = $enc.GetPreamble()
        if ($Bytes.Length -lt $pre.Length) { continue }
        $hasBom = $true
        for ($i = 0; $i -lt $pre.Length; $i++) { if ($Bytes[$i] -ne $pre[$i]) { $hasBom = $false; break } }
        if (-not $hasBom) { continue }
        $body = $enc.GetString($Bytes, $pre.Length, $Bytes.Length - $pre.Length)
        if ($body -notmatch $keyRx) { continue }
        $new = ($body -replace ('(?m)^' + $keyRx + '\r?\n'), '') -replace $keyRx, ''
        return @{ Changed = $true; Bytes = [byte[]]($pre + $enc.GetBytes($new)) }
    }
    return @{ Changed = $false; Bytes = $Bytes }
}

function Get-EditorProcessName {
    # Which editor locks an extension folder, from the root it lives under.
    param([string]$ExtensionPath)
    if ($ExtensionPath -match '(?i)[\\/]\.cursor[\\/]extensions[\\/]') { return 'Cursor' }
    if ($ExtensionPath -match '(?i)[\\/]\.vscode-insiders[\\/]extensions[\\/]') { return 'Code - Insiders' }
    if ($ExtensionPath -match '(?i)[\\/]\.vscode[\\/]extensions[\\/]') { return 'Code' }
    return $null
}

function Get-RemediationPlan {
    # Unique actions in a safe order: stop what respawns the tunnel (tasks), stop the
    # tunnels, then delete files and the key. REVIEW / EXPOSED-only items have no Action
    # except RemovePackage (the cached malicious VSIX).
    param($Findings)
    $order = @('RemoveTask', 'KillProcess', 'RemoveExtension', 'RemoveFile', 'CleanKey', 'RemovePackage')
    $seen = @{}
    $plan = New-Object System.Collections.ArrayList
    foreach ($a in $order) {
        foreach ($f in @($Findings | Where-Object { $_.Action -eq $a })) {
            $k = ($a + '|' + $f.Target).ToLowerInvariant()
            if ($seen.ContainsKey($k)) { continue }
            $seen[$k] = $true
            [void]$plan.Add([pscustomobject]@{ Action = $a; Target = $f.Target })
        }
    }
    return @($plan)
}

function Get-QuarantineName {
    param([string]$Path)
    return (($Path -replace '^[A-Za-z]:', '') -replace '[\\/:]+', '_').TrimStart('_')
}

function Save-ToQuarantine {
    param([string]$Path)
    if (-not $script:QuarantineDir) { return $null }
    if (-not (Test-Path -LiteralPath $script:QuarantineDir)) {
        New-Item -ItemType Directory -Path $script:QuarantineDir -Force | Out-Null
        if ([Environment]::OSVersion.Platform -eq 'Win32NT') {
            $icacls = $env:WINDIR + '\System32\icacls.exe'
            $null = & $icacls $script:QuarantineDir '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' 2>&1
        }
    }
    $dest = Join-Parts @($script:QuarantineDir, (Get-QuarantineName -Path $Path))
    Copy-Item -LiteralPath $Path -Destination $dest -Recurse -Force -ErrorAction Stop
    return $dest
}

function Invoke-RemoveItemAction {
    param([string]$Path, [switch]$Quarantine)
    if (-not (Test-Path -LiteralPath $Path)) { Write-Log ('  already gone: ' + $Path); return $true }
    if ($Quarantine) {
        try { $q = Save-ToQuarantine -Path $Path; if ($q) { Write-Log ('  quarantined copy: ' + $q) } }
        catch { Write-Log ('  could not quarantine ' + $Path + ': ' + $_.Exception.Message + ' (removing anyway)') -Level WARN }
    }
    Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $Path) { Write-Log ('  could not remove ' + $Path) -Level ERROR; return $false }
    Write-Log ('  removed ' + $Path) -Level FIXED
    return $true
}

function Invoke-CleanKeyAction {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { Write-Log ('  already gone: ' + $Path); return $true }
    try {
        $q = Save-ToQuarantine -Path $Path
        if ($q) { Write-Log ('  backup before edit: ' + $q) }
        $r = Remove-AttackerKeyFromBytes -Bytes ([IO.File]::ReadAllBytes($Path))
        if ($r.Changed) { [IO.File]::WriteAllBytes($Path, [byte[]]$r.Bytes) }
    } catch {
        Write-Log ('  could not edit ' + $Path + ': ' + $_.Exception.Message) -Level ERROR
        return $false
    }
    if (Test-AttackerKeyText -Text (Get-FileTextSafe -Path $Path)) {
        Write-Log ('  attacker key still in ' + $Path + ' - remove the svc-telemetry line by hand') -Level ERROR
        return $false
    }
    Write-Log ('  removed attacker key from ' + $Path) -Level FIXED
    return $true
}

function Invoke-Remediation {
    # Returns @{ Done; Failed }. Windows-only actions (tasks, processes, editors) run only
    # when such findings exist, so the file actions can be exercised on any platform.
    param($Findings)
    $done = 0; $failed = 0
    $plan = @(Get-RemediationPlan -Findings $Findings)
    if ($plan.Count -eq 0) { Write-Log 'Nothing to remove.'; return @{ Done = 0; Failed = 0 } }
    $closed = @{}
    foreach ($p in $plan) {
        Write-Log ('[' + $p.Action + '] ' + $p.Target)
        $ok = $true
        switch ($p.Action) {
            'RemoveTask' {
                $schtasks = $env:WINDIR + '\System32\schtasks.exe'
                $null = & $schtasks '/End' '/TN' $p.Target 2>&1
                $out = & $schtasks '/Delete' '/TN' $p.Target '/F' 2>&1
                $rc = $LASTEXITCODE
                $null = & $schtasks '/Query' '/TN' $p.Target 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Log ('  task still registered (schtasks /Delete rc ' + $rc + '): ' + (($out | Out-String).Trim())) -Level ERROR
                    $ok = $false
                } else { Write-Log ('  removed task ' + $p.Target) -Level FIXED }
            }
            'KillProcess' {
                $procId = [int]$p.Target
                Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 500
                if (Get-Process -Id $procId -ErrorAction SilentlyContinue) { Write-Log ('  PID ' + $procId + ' still running') -Level ERROR; $ok = $false }
                else { Write-Log ('  stopped PID ' + $procId) -Level FIXED }
            }
            'RemoveExtension' {
                $editor = Get-EditorProcessName -ExtensionPath $p.Target
                if ($ForceCloseEditors -and $editor -and -not $closed.ContainsKey($editor)) {
                    $running = @(Get-Process -Name $editor -ErrorAction SilentlyContinue)
                    if ($running.Count -gt 0) {
                        Write-Log ('  closing ' + $running.Count + ' ' + $editor + ' process(es) (-ForceCloseEditors)') -Level WARN
                        $running | Stop-Process -Force -ErrorAction SilentlyContinue
                        Start-Sleep -Seconds 3
                    }
                    $closed[$editor] = $true
                }
                $js = Join-Parts @($p.Target, 'extension.js')
                if (Test-Path -LiteralPath $js) {
                    try { $q = Save-ToQuarantine -Path $js; if ($q) { Rename-Item -LiteralPath $q -NewName ((Split-Path -Leaf $q) + '.quarantine') -Force; Write-Log ('  quarantined extension.js as ' + $q + '.quarantine') } }
                    catch { Write-Log ('  could not quarantine extension.js: ' + $_.Exception.Message) -Level WARN }
                }
                $ok = Invoke-RemoveItemAction -Path $p.Target
                if (-not $ok -and $editor) {
                    Write-Log ('  ' + $editor + ' probably has it open. Close ' + $editor + ' and re-run, or add -ForceCloseEditors.') -Level ERROR
                }
            }
            'RemoveFile' { $ok = Invoke-RemoveItemAction -Path $p.Target -Quarantine }
            'CleanKey' { $ok = Invoke-CleanKeyAction -Path $p.Target }
            'RemovePackage' { $ok = Invoke-RemoveItemAction -Path $p.Target }
        }
        if ($ok) { $done++ } else { $failed++ }
    }
    return @{ Done = $done; Failed = $failed }
}

function Get-RemediationResult {
    param($Before, $After, [int]$Done, [int]$Failed)
    $impBefore = @($Before | Where-Object { $_.Kind -eq 'IMPACTED' }).Count
    $impAfter = @($After | Where-Object { $_.Kind -eq 'IMPACTED' }).Count
    $verify = Get-ResultSummary -Findings $After
    $tail = ' (actions ok ' + $Done + ', failed ' + $Failed + ')'
    if (@($Before).Count -eq 0) { return @{ Code = 0; Text = 'RESULT: CLEAN - no indicators found; nothing removed' } }
    if ($impAfter -gt 0) { return @{ Code = 3; Text = 'RESULT: REMEDIATION INCOMPLETE - ' + $impAfter + ' IMPACTED item(s) remain after re-scan' + $tail + '. See VERIFY lines.' } }
    if ($impBefore -gt 0) { return @{ Code = 2; Text = 'RESULT: REMEDIATED - backdoor removed and re-scan shows none left' + $tail + '. Rotate credentials for this host (advisory step 5). EXPOSED traces are kept as evidence.' } }
    $verifyText = $verify.Text -replace '^RESULT: ', ''
    return @{ Code = 2; Text = 'RESULT: NO BACKDOOR - ' + $verifyText + $tail }
}

function Invoke-ProfileScan {
    param([string]$ProfilePath)
    $h = $ProfilePath

    # 1. Attacker SSH key
    Test-KeyFile -Path (Join-Parts @($h, '.ssh', 'authorized_keys'))

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
                    Add-Finding IMPACTED ('extension.js SHA-256 matches the malicious payload: ' + $js.FullName) -Action RemoveExtension -Target $d.FullName
                    continue
                }
                $t = Get-FileTextSafe -Path $js.FullName
                if ($t -and ($t.Contains($BadIP) -or $t.Contains($BadKeyLabel))) {
                    Add-Finding IMPACTED ('extension.js contains the payload IOC strings: ' + $js.FullName) -Action RemoveExtension -Target $d.FullName
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
                Add-Finding EXPOSED ('Affected VSIX in Cursor download cache: ' + $f.FullName) -Action RemovePackage -Target $f.FullName
            } elseif ($BadVsixSha -contains (Get-Sha256Lower -Path $f.FullName)) {
                Add-Finding EXPOSED ('Cached VSIX matches a malicious package hash: ' + $f.FullName) -Action RemovePackage -Target $f.FullName
            }
        }
    }
    $dl = Join-Parts @($h, 'Downloads')
    if (Test-Path -LiteralPath $dl) {
        foreach ($f in @(Get-ChildItem -LiteralPath $dl -File -Force -Filter '*.vsix' -ErrorAction SilentlyContinue)) {
            if ($f.Length -gt $MaxScanBytes) { continue }
            if ($BadVsixSha -contains (Get-Sha256Lower -Path $f.FullName)) {
                Add-Finding EXPOSED ('Downloaded VSIX matches a malicious package hash: ' + $f.FullName) -Action RemovePackage -Target $f.FullName
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
        if (Test-Path -LiteralPath $f) { Add-Finding IMPACTED ('Payload file: ' + $f) -Action RemoveFile -Target $f }
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
    if ($imp -gt 0) { return @{ Code = 2; Text = 'RESULT: IMPACTED ' + $counts + ' - isolate the host, re-run with -Remediate, rotate credentials (advisory steps 3-5)' } }
    if ($exp -gt 0) { return @{ Code = 2; Text = 'RESULT: EXPOSED ' + $counts + ' - affected version was installed; no backdoor artifact found. Rotate credentials; -Remediate clears the cached VSIX.' } }
    if ($rev -gt 0) { return @{ Code = 2; Text = 'RESULT: REVIEW ' + $counts + ' - not proven clean; see REVIEW lines' } }
    return @{ Code = 0; Text = 'RESULT: CLEAN - no indicators found' }
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
        if ($v -is [System.Management.Automation.SwitchParameter] -and $v.IsPresent) { $a += ('-' + $k) }
    }
    return $a
}

function Invoke-MachineScan {
    Write-Log '--- Machine-wide'
    Test-KeyFile -Path ($env:ProgramData + '\ssh\administrators_authorized_keys')
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
            $tn = $tf.FullName.Substring($taskRoot.Length)
            Add-Finding IMPACTED ('Scheduled task runs the payload: ' + $tn) -Action RemoveTask -Target $tn
        }
    }
    foreach ($st in $sysmonTasks) {
        $actions = (@($st.Actions) | ForEach-Object { ('' + $_.Execute + ' ' + $_.Arguments).Trim() }) -join ' | '
        $desc = $st.TaskPath + $st.TaskName + ' (run-as ' + $st.Principal.UserId + ', action ' + $actions + ')'
        $file = $taskRoot + $st.TaskPath + $st.TaskName
        if ($payloadTaskFiles -contains $file) { continue }
        if (Test-PayloadText -Text $actions) { Add-Finding IMPACTED ('Scheduled task SysMon runs the payload: ' + $desc) -Action RemoveTask -Target ($st.TaskPath + $st.TaskName) }
        else { Add-Finding REVIEW ('Scheduled task named SysMon with no payload reference - confirm it is legitimate (never removed automatically): ' + $desc) }
    }

    # Running tunnel / payload processes
    $procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
    if ($procs.Count -eq 0) { Add-Finding REVIEW 'Could not list processes (Win32_Process)' }
    foreach ($pr in $procs) {
        if ($pr.ProcessId -eq $PID) { continue }
        if (Test-SuspiciousCommandLine -CommandLine $pr.CommandLine) {
            Add-Finding IMPACTED ('Tunnel/payload process PID ' + $pr.ProcessId + ' (parent ' + $pr.ParentProcessId + '): ' + $pr.CommandLine) -Action KillProcess -Target ('' + $pr.ProcessId)
        }
    }

    # Live or lingering connections to the attacker endpoint (the owning process is
    # stopped only if its command line matched above; it may be the editor itself)
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
}

function Invoke-FullScan {
    param([string[]]$Profiles)
    foreach ($p in $Profiles) {
        Write-Log ('--- ' + $p)
        try { Invoke-ProfileScan -ProfilePath $p }
        catch { Add-Finding REVIEW ('Profile scan failed for ' + $p + ': ' + $_.Exception.Message) }
    }
    Invoke-MachineScan
}

function Invoke-SshdDisable {
    $sshd = Get-Service sshd -ErrorAction SilentlyContinue
    if (-not $sshd) { Write-Log '[DisableSshd] sshd not installed; nothing to do'; return $true }
    Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
    Set-Service -Name sshd -StartupType Disabled -ErrorAction SilentlyContinue
    $mode = '' + (Get-CimInstance Win32_Service -Filter 'Name=''sshd''' -ErrorAction SilentlyContinue).StartMode
    $status = '' + (Get-Service sshd -ErrorAction SilentlyContinue).Status
    if ($status -eq 'Stopped' -and $mode -eq 'Disabled') { Write-Log '[DisableSshd] sshd stopped and disabled' -Level FIXED; return $true }
    Write-Log ('[DisableSshd] sshd is ' + $status + ' / ' + $mode + ' - could not disable') -Level ERROR
    return $false
}

if ($env:CLAUDE_IOC_DOTSOURCE -eq '1') { return }

# ---- live run (Windows / Endpoint Central) ----------------------------------

if (Test-Needs64BitRelaunch -Is64BitOS ([Environment]::Is64BitOperatingSystem) -Is64BitProcess ([Environment]::Is64BitProcess)) {
    $ps64 = $env:WINDIR + '\Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $ps64) {
        $relaunchArgs = Get-RelaunchArguments -ScriptPath $PSCommandPath -Bound $PSBoundParameters
        & $ps64 @relaunchArgs
        exit $LASTEXITCODE
    }
}

$LogDir = 'C:\Logs\CompoSecure'
$Stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$script:LogFile = $LogDir + '\CursorClaudeCodeIOC_' + $Stamp + '.log'
$script:QuarantineDir = $LogDir + '\CursorClaudeCodeIOC_Quarantine_' + $Stamp
$LatestFile = $LogDir + '\CursorClaudeCodeIOC_latest.log'
$code = 1

try {
    if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

    $mode = 'DETECT ONLY (no changes)'
    if ($Remediate) { $mode = 'REMEDIATE' + $(if ($ForceCloseEditors) { ' +ForceCloseEditors' } else { '' }) + $(if ($DisableSshd) { ' +DisableSshd' } else { '' }) }
    Write-Log '=============================================='
    Write-Log ' Cursor Claude Code extension IOC check (v3)'
    Write-Log (' Mode       : ' + $mode)
    Write-Log (' Host       : ' + $env:COMPUTERNAME)
    Write-Log (' Running as : ' + [Environment]::UserName + '  64-bit: ' + [Environment]::Is64BitProcess)
    Write-Log '=============================================='
    if (-not $Remediate -and ($ForceCloseEditors -or $DisableSshd)) {
        Write-Log '-ForceCloseEditors / -DisableSshd do nothing without -Remediate' -Level WARN
    }

    $profiles = @(Get-ScanProfiles)
    if ($profiles.Count -eq 0) { throw 'No user profiles found to scan' }
    Write-Log ('Profiles: ' + ($profiles -join ', '))

    Invoke-FullScan -Profiles $profiles
    $before = @($script:Findings)
    $r = Get-ResultSummary -Findings $before

    if ($Remediate) {
        Write-Log '=============================================='
        Write-Log ('Scan: ' + $r.Text)
        Write-Log '--- REMEDIATE'
        $res = Invoke-Remediation -Findings $before
        $done = $res.Done; $failed = $res.Failed
        if ($DisableSshd) { if (Invoke-SshdDisable) { $done++ } else { $failed++ } }

        Write-Log '--- VERIFY (re-scan after remediation)'
        $script:Findings.Clear()
        Invoke-FullScan -Profiles $profiles
        $after = @($script:Findings)

        $hadBackdoor = @($before | Where-Object { $_.Kind -eq 'IMPACTED' }).Count -gt 0
        if ($hadBackdoor -and -not $DisableSshd) {
            $listen = @(Get-NetTCPConnection -LocalPort 22 -State Listen -ErrorAction SilentlyContinue)
            if ($listen.Count -gt 0) { Write-Log 'Something listens on port 22 and the tunnel exposed it. Disable sshd unless this host needs it (-DisableSshd).' -Level WARN }
        }
        if (Test-Path -LiteralPath $script:QuarantineDir) { Write-Log ('Quarantine: ' + $script:QuarantineDir) }
        $r = Get-RemediationResult -Before $before -After $after -Done $done -Failed $failed
    }

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
