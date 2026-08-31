#requires -Version 5.1
<#
=====================================================================================
 SCRIPT   : Repair-ZscalerAgent.ps1
 AGENT    : Zscaler Client Connector (ZCC)
 TARGET OS: Windows 10 22H2 / Windows 11 / Windows Server 2019, 2022, 2025 (x64, ARM64)
 PURPOSE  : Diagnose + BOUNDED remediation for a Zscaler Client Connector that has
            stopped checking in ("not clean" in the fleet agent-status report --
            see agent-zscaler-not-clean-*.xlsx). Emits exactly ONE machine-parseable
            line per host to stdout so Endpoint Central (or any collector) can
            aggregate results across the fleet, PLUS a full evidence log per run
            under C:\Logs\CompoSecure for troubleshooting one specific host later --
            matching this repo's standard logging convention (see README.md).
            Never uninstalls, reinstalls, deletes binaries, or alters Zscaler policy.
 PRIVILEGE: SYSTEM or local Administrator (elevated). Script refuses to run otherwise.
 CONTEXT  : Non-interactive ONLY. Deployed per-endpoint via Endpoint Central. Never
            prompts, never blocks, and never emits multi-line output to the CONSOLE
            (the log file under C:\Logs\CompoSecure is where full per-host detail
            goes -- see .NOTES).
 PS PATHS : Detects $PSVersionTable.PSVersion.Major and executes either a Windows
            PowerShell 5.1-compatible path or a PowerShell 7+ path. One file, both.

 OUTPUT   : exactly one line to stdout (two with -IncludeHeader -Format Csv).
   -Format Kv   (default)  schema=1|agent=Zscaler|os=Win|host=...|status=...|code=...
   -Format Csv             RFC4180-quoted single row; -IncludeHeader adds a header row
   -Format Json            single-line compressed JSON object

 STATUS BANDS / EXIT CODES
   HEALTHY                0  installed, running, checking in; no action taken
   RECOVERED              0  was unhealthy; bounded remediation succeeded
   DEGRADED               1  partially working, or remediation blocked (tamper)
   REINSTALL_RECOMMENDED  2  safe remediation exhausted; see the log file for detail
   NOT_INSTALLED          3  agent not present on this host
   ERROR                  4  script could not complete its own checks

 IDEMPOTENT: yes. A healthy host is not modified and reports HEALTHY.
 EGRESS    : none.

 NOTES ON A REAL FLEET RUN (2026-08-31, agent-zscaler-not-clean-20260831.xlsx):
   25 hosts flagged, last-check-in age ranging from 4 to 151 days. 7 of the 25 were
   also flagged 'Not in Device Export' in the Zscaler admin console -- i.e. the
   CONSOLE has no device record at all for that host. That state cannot be fixed by
   anything running ON the endpoint (this script can only diagnose/repair the LOCAL
   agent); it needs console-side re-enrollment or device-record cleanup. Cross-
   reference this script's per-host verdict against that console flag before
   assuming a HEALTHY/RECOVERED result here means the host will start reporting --
   a locally-healthy agent talking to a device record the console can't find will
   still show as missing.

 VERSION  : 1.1.0  -  2026-08-31 (fixed a syntax error and a function-scope bug in
            an inline "quick local log" block that had been spliced into
            Invoke-Main's body in the 1.0.0 draft, which both prevented the script
            from parsing at all and, even if patched line-by-line, would have
            called four logging functions that only existed in Invoke-Main's own
            scope from two call sites outside it. Replaced with a single log file
            under C:\Logs\CompoSecure written once at the end of the run, matching
            this repo's standard convention, without touching the single-line
            stdout contract.)
=====================================================================================
#>

[CmdletBinding()]
param(
    # Output shape for the single result line.
    [ValidateSet('Kv', 'Csv', 'Json')]
    [string]$Format = 'Kv',

    # Emit a CSV header row before the data row. Ignored for Kv/Json. Leave OFF for
    # fleet runs - one header per host is noise; add it once at the collector.
    [switch]$IncludeHeader,

    # Seconds to wait for a service to reach Running after a start/restart.
    [ValidateRange(5, 300)]
    [int]$ServiceWaitSeconds = 45,

    # Minutes of ZCC log inactivity after which check-in is treated as STALE.
    [ValidateRange(5, 1440)]
    [int]$CheckInStaleMinutes = 60,

    # Truncation ceiling for free-text fields, so one chatty host cannot blow up a
    # fleet report row.
    [ValidateRange(40, 512)]
    [int]$TextFieldMaxLength = 160
)

# This variant is unconditionally non-interactive - see Test-Interactive below.

$ErrorActionPreference = 'Stop'
# StrictMode 1.0 (not 2.0) on purpose: uninstall-registry keys legitimately lack a
# DisplayName property, and 2.0 throws PropertyNotFoundException on absent members.
# 1.0 still catches uninitialised variables, which is the failure mode that matters here.
Set-StrictMode -Version 1.0

# ====================================================================================
# CONFIGURATION - environment-specific values
# ------------------------------------------------------------------------------------
# Any value left as an unsubstituted {{PLACEHOLDER}} is treated as "not configured"
# by Resolve-Config and falls back to the built-in default (or is skipped where no
# safe default exists). The script therefore RUNS as shipped, but every placeholder
# below should be substituted by your deployment tooling before production use.
# See the Manual Completion Checklist at the bottom of this file.
# ====================================================================================

$Cfg = @{
    # Root of the ZCC install. Default is correct for standard x64 installs.
    # ⚠️ [MANUAL: verify install root on a reference host - some ZCC builds and
    # ARM64 hosts place binaries under 'C:\Program Files (x86)\Zscaler'.]
    InstallRoot = '{{ZSCALER_INSTALL_ROOT}}'

    # Root of the ZCC log tree, used as the check-in freshness proxy.
    # ⚠️ [MANUAL: verify log root and that ZCC log level in your App Profile is
    # NOT set to 'Error' only - at Error-only verbosity logs go quiet on a perfectly
    # healthy host and freshness becomes meaningless. See CheckIn UNKNOWN handling.]
    LogRoot = '{{ZSCALER_LOG_ROOT}}'

    # Glob for log files considered evidence of recent agent activity.
    LogPattern = '{{ZSCALER_LOG_PATTERN}}'

    # Informational only - printed in the evidence block, never used for control flow.
    ExpectedCloud = 'zscalertwo'

    # Printed in the REINSTALL_RECOMMENDED handoff so the operator knows where to go.
    AdminPortalUrl = '{{ZCC_ADMIN_PORTAL_URL}}'

    # The reviewed, pinned ZCC installer version approved for this fleet. Printed in
    # the reinstall handoff. Deliberately NOT 'latest' - reinstall must use a known,
    # reviewed, stable release pulled from the internal package repository.
    ApprovedVersion = '{{ZCC_APPROVED_VERSION}}'

    # Internal package source for the approved installer.
    PackageSource = '{{INTERNAL_PACKAGE_REPO_PATH}}'

    # Escalation contact printed on DEGRADED / REINSTALL_RECOMMENDED.
    SupportContact = '{{SUPPORT_CONTACT}}'
}

# NOTE: There is deliberately NO variable for the ZCC uninstall/logout password.
# ZSACli.exe's documented verbs (logout, uninstall) are outside this script's
# remediation boundary, so the script never needs the secret and never handles it.

$DefaultInstallRoot = 'C:\Program Files\Zscaler'
$DefaultLogRoot     = 'C:\ProgramData\Zscaler'
$DefaultLogPattern  = '*.log'

# ------------------------------------------------------------------------------------
# Expected ZCC service set.
# ⚠️ [MANUAL: verify service short names against a reference host with
#   Get-Service -Name 'ZSA*' | Select-Object Name,DisplayName,Status,StartType
# ZSATunnel in particular is a standalone service on some ZCC builds and a child
# process of ZSAService on others. If it is not a service on your build, set
# Critical=$false for it - the ProcessName check below still covers the tunnel.]
# ------------------------------------------------------------------------------------
$ExpectedServices = @(
    [pscustomobject]@{ Name = 'ZSAService';     Display = 'Zscaler Service';      Critical = $true  }
    [pscustomobject]@{ Name = 'ZSATunnel';      Display = 'Zscaler Tunnel';       Critical = $true  }
    [pscustomobject]@{ Name = 'ZSAUpdater';     Display = 'Zscaler Updater';      Critical = $false }
    [pscustomobject]@{ Name = 'ZSATrayManager'; Display = 'Zscaler Tray Manager'; Critical = $false }
)

# Tunnel data-plane process. Presence is corroborating evidence for check-in.
$TunnelProcessName = 'ZSATunnel'

# Per-user tray UI. Runs ONLY inside an interactive user session. Its absence on a
# host with no logged-on user is EXPECTED and must never count as a fault - this is
# the single most common Zscaler health-check false positive.
$TrayProcessName = 'ZSATray'

# Uninstall-registry DisplayName pattern used for presence + version discovery.
$UninstallNamePattern = 'Zscaler'

# ====================================================================================
# SCRIPT STATE
# ====================================================================================

$script:PSMode       = 'Desktop51'
$script:ComputerName = $env:COMPUTERNAME
$script:Interactive  = $false

$script:Result = [pscustomobject]@{
    Status          = 'ERROR'
    ExitCode        = 4
    Installed       = $false
    Version         = 'UNKNOWN'
    InstallPath     = 'UNKNOWN'
    RunningState    = 'UNKNOWN'   # OK | PARTIAL | STOPPED | UNKNOWN
    CheckInState    = 'UNKNOWN'   # OK | STALE | UNKNOWN
    TamperBlocked   = $false
    Evidence        = New-Object System.Collections.ArrayList
    Actions         = New-Object System.Collections.ArrayList
    Reason          = ''
}

# ====================================================================================
# HELPERS - no CONSOLE output is emitted by the engine; Write-Verdict is the only
# function that ever calls Write-Output. Write-DiagnosticLog (below) writes the full
# evidence trail to disk ONLY -- it never touches stdout, so it cannot corrupt the
# single fleet-report line.
# ====================================================================================

$LogDir  = 'C:\Logs\CompoSecure'
$LogFile = Join-Path $LogDir ('ZscalerAgentRepair_' + $env:COMPUTERNAME + '_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')

function Write-DiagnosticLog {
    # Full per-host evidence/action trail, written once at the end of the run, for
    # troubleshooting a specific machine later -- this repo's standard logging
    # convention (see README.md: "Logs write to C:\Logs\CompoSecure\"). Best-effort
    # and silent on failure: a logging problem must never change the verdict or
    # touch the console.
    try {
        if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
        $r = $script:Result
        $lines = New-Object System.Collections.Generic.List[string]
        $lines.Add('==============================================')
        $lines.Add('[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] Zscaler agent check -- ' + $script:ComputerName)
        $lines.Add('==============================================')
        foreach ($e in $r.Evidence) { $lines.Add('  [' + $e.Level + '] ' + $e.Message) }
        foreach ($a in $r.Actions)  { $lines.Add('  [ACTION] ' + $a) }
        $lines.Add('')
        $lines.Add('VERDICT: ' + $r.Status + '  (exit ' + $r.ExitCode + ')')
        if ($r.Reason) { $lines.Add('REASON : ' + $r.Reason) }
        $lines.Add('==============================================')
        Add-Content -Path $LogFile -Value $lines -ErrorAction Stop
    }
    catch { }
}

function Resolve-Config {
    param(
        [AllowNull()][AllowEmptyString()][string]$Value,
        [AllowNull()][string]$Default = $null
    )
    if ([string]::IsNullOrWhiteSpace($Value))    { return $Default }
    if ($Value -match '^\s*\{\{.*\}\}\s*$')      { return $Default }
    return $Value
}

function Add-Evidence {
    param(
        [ValidateSet('OK', 'WARN', 'FAIL', 'INFO', 'SKIP')][string]$Level,
        [string]$Message
    )
    [void]$script:Result.Evidence.Add([pscustomobject]@{ Level = $Level; Message = $Message })
}

function Add-Action {
    param([string]$Message)
    [void]$script:Result.Actions.Add($Message)
}

function Set-Verdict {
    param(
        [ValidateSet('HEALTHY', 'RECOVERED', 'DEGRADED', 'REINSTALL_RECOMMENDED', 'NOT_INSTALLED', 'ERROR')]
        [string]$Status,
        [string]$Reason = ''
    )
    $map = @{
        'HEALTHY' = 0; 'RECOVERED' = 0; 'DEGRADED' = 1
        'REINSTALL_RECOMMENDED' = 2; 'NOT_INSTALLED' = 3; 'ERROR' = 4
    }
    $script:Result.Status   = $Status
    $script:Result.ExitCode = $map[$Status]
    if ($Reason) { $script:Result.Reason = $Reason }
}

function Test-Elevated {
    try {
        $ident   = [Security.Principal.WindowsIdentity]::GetCurrent()
        $princ   = New-Object Security.Principal.WindowsPrincipal($ident)
        $isAdmin = $princ.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        return [pscustomobject]@{
            Elevated = ($isAdmin -or $ident.IsSystem)
            IsSystem = $ident.IsSystem
            Account  = $ident.Name
        }
    }
    catch {
        return [pscustomobject]@{ Elevated = $false; IsSystem = $false; Account = 'UNKNOWN' }
    }
}

function Test-Interactive {
    # Hard-wired non-interactive. There is no code path in this script that prompts,
    # waits on input, or emits a multi-line console handoff, regardless of how or
    # where it is launched -- full detail goes to the log file (Write-DiagnosticLog),
    # never to an interactive prompt.
    return $false
}

function Test-AccessDenied {
    # Translate an SCM failure into "tamper protection / access denied" vs a real error.
    # These strings come from the Windows Service Control Manager, not from the agent.
    param($ErrorRecord)
    $probe = ''
    try { $probe = "$($ErrorRecord.Exception.Message) $($ErrorRecord.FullyQualifiedErrorId)" } catch { }
    $patterns = @(
        'Access is denied',
        'PermissionDenied',
        'Cannot open .* service on computer',
        'ServiceCommandException',
        'CouldNotStopService',
        'CouldNotStartService',
        'not authorized'
    )
    foreach ($p in $patterns) { if ($probe -match $p) { return $true } }
    return $false
}

function Get-ServiceInfoCompat {
    <#
      PS version branch point. Get-Service is present in both hosts, but the
      supplementary metadata path differs:
        7+     -> CIM only (Get-WmiObject does not exist in PowerShell 7).
        5.1    -> CIM first, WMI fallback for hosts where the CIM/WinRM stack is
                  broken or hardened off, which is common on the exact sick machines
                  this script is run against.
    #>
    param([Parameter(Mandatory)][string]$Name)

    $svc = $null
    try { $svc = Get-Service -Name $Name -ErrorAction Stop }
    catch { return $null }

    $startMode = 'UNKNOWN'; $procId = 0; $account = 'UNKNOWN'

    if ($script:PSMode -eq 'Core7') {
        try {
            $cim = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
            if ($cim) { $startMode = [string]$cim.StartMode; $procId = [int]$cim.ProcessId; $account = [string]$cim.StartName }
        }
        catch { }
    }
    else {
        try {
            $cim = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
            if ($cim) { $startMode = [string]$cim.StartMode; $procId = [int]$cim.ProcessId; $account = [string]$cim.StartName }
        }
        catch {
            try {
                $wmi = Get-WmiObject -Class Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
                if ($wmi) { $startMode = [string]$wmi.StartMode; $procId = [int]$wmi.ProcessId; $account = [string]$wmi.StartName }
            }
            catch { }
        }
    }

    return [pscustomobject]@{
        Name      = $svc.Name
        Display   = $svc.DisplayName
        Status    = [string]$svc.Status
        CanStop   = [bool]$svc.CanStop
        StartMode = $startMode
        ProcessId = $procId
        Account   = $account
        Controller= $svc
    }
}

function Test-UserSessionPresent {
    # explorer.exe running == an interactive desktop session exists, so ZSATray is
    # expected. No explorer == headless/locked-out host, tray absence is normal.
    try { return ([bool](Get-Process -Name 'explorer' -ErrorAction SilentlyContinue)) }
    catch { return $false }
}

function Get-ProcessPresent {
    param([Parameter(Mandatory)][string]$Name)
    try { return ([bool](Get-Process -Name $Name -ErrorAction SilentlyContinue)) }
    catch { return $false }
}

# ====================================================================================
# CONTRACT FUNCTION 1 - Test-Installed
# ====================================================================================
function Test-Installed {
    $installRoot = Resolve-Config -Value $Cfg.InstallRoot -Default $DefaultInstallRoot
    $found = $false

    # Evidence source A: uninstall registry (authoritative for presence + version).
    $version = 'UNKNOWN'
    $uninstallKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($key in $uninstallKeys) {
        try {
            $entries = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue |
                       Where-Object { $_.DisplayName -and $_.DisplayName -match $UninstallNamePattern }
            foreach ($e in $entries) {
                $found = $true
                if ($e.DisplayVersion) { $version = [string]$e.DisplayVersion }
            }
        }
        catch { }
    }
    if ($found) {
        Add-Evidence -Level OK -Message "Install receipt present in uninstall registry (DisplayName matches '$UninstallNamePattern')."
    }

    # Evidence source B: service registration.
    $registered = @()
    foreach ($s in $ExpectedServices) {
        $info = Get-ServiceInfoCompat -Name $s.Name
        if ($info) { $registered += $info.Name }
    }
    if ($registered.Count -gt 0) {
        $found = $true
        Add-Evidence -Level OK -Message ("Registered ZCC services: " + ($registered -join ', ') + '.')
    }

    # Surface any ZSA* service the expected set does not know about. This is how you
    # discover that a new ZCC build renamed or split a service.
    try {
        $discovered = Get-Service -Name 'ZSA*' -ErrorAction SilentlyContinue |
                      Where-Object { $ExpectedServices.Name -notcontains $_.Name }
        if ($discovered) {
            Add-Evidence -Level WARN -Message ("Unexpected ZSA* services present (verify expected-service list): " +
                (($discovered | ForEach-Object { $_.Name }) -join ', ') + '.')
        }
    }
    catch { }

    # Evidence source C: install directory / binary path.
    if ($installRoot -and (Test-Path -LiteralPath $installRoot)) {
        $found = $true
        $script:Result.InstallPath = $installRoot
        Add-Evidence -Level OK -Message "Install directory present: $installRoot"
        if ($version -eq 'UNKNOWN') {
            # Fall back to the tray binary's file version.
            try {
                $bin = Get-ChildItem -Path $installRoot -Filter 'ZSATray.exe' -Recurse -ErrorAction SilentlyContinue |
                       Select-Object -First 1
                if ($bin) { $version = [string]$bin.VersionInfo.FileVersion }
            }
            catch { }
        }
    }
    else {
        Add-Evidence -Level WARN -Message "Install directory not found at '$installRoot' (verify install root)."
    }

    $script:Result.Installed = $found
    $script:Result.Version   = $version

    if ($found) {
        Add-Evidence -Level INFO -Message "Detected ZCC version: $version"
        $cloud = Resolve-Config -Value $Cfg.ExpectedCloud
        if ($cloud) { Add-Evidence -Level INFO -Message "Expected Zscaler cloud (informational): $cloud" }
    }
    return $found
}

# ====================================================================================
# CONTRACT FUNCTION 2 - Test-Running
# ====================================================================================
function Test-Running {
    $criticalTotal = 0; $criticalUp = 0
    $nonCriticalDown = @()
    $anyCanStopFalse = $false

    foreach ($s in $ExpectedServices) {
        $info = Get-ServiceInfoCompat -Name $s.Name
        if (-not $info) {
            if ($s.Critical) {
                $criticalTotal++
                Add-Evidence -Level FAIL -Message "Critical service '$($s.Name)' ($($s.Display)) is not registered on this host."
            }
            else {
                Add-Evidence -Level SKIP -Message "Optional service '$($s.Name)' not registered (may not exist on this ZCC build)."
            }
            continue
        }

        if ($s.Critical) { $criticalTotal++ }

        if ($info.Status -eq 'Running') {
            if ($s.Critical) { $criticalUp++ }
            Add-Evidence -Level OK -Message "Service '$($info.Name)' Running (start mode: $($info.StartMode))."
        }
        else {
            if ($s.Critical) {
                Add-Evidence -Level FAIL -Message "Service '$($info.Name)' is $($info.Status) (start mode: $($info.StartMode))."
            }
            else {
                $nonCriticalDown += $info.Name
                Add-Evidence -Level WARN -Message "Optional service '$($info.Name)' is $($info.Status)."
            }
        }

        # A protected security service commonly reports CanStop=False when ZCC
        # tamper protection is enforced by policy. Record it as a tamper hint.
        if ($info.Status -eq 'Running' -and -not $info.CanStop) {
            $anyCanStopFalse = $true
        }
    }

    if ($anyCanStopFalse) {
        Add-Evidence -Level INFO -Message "At least one ZCC service reports CanStop=False - tamper protection is likely enforced by policy."
    }

    # Tunnel data-plane process.
    if (Get-ProcessPresent -Name $TunnelProcessName) {
        Add-Evidence -Level OK -Message "Tunnel process '$TunnelProcessName' is running."
    }
    else {
        Add-Evidence -Level FAIL -Message "Tunnel process '$TunnelProcessName' is not running."
    }

    # Tray UI - only meaningful when an interactive desktop session exists.
    if (Test-UserSessionPresent) {
        if (Get-ProcessPresent -Name $TrayProcessName) {
            Add-Evidence -Level OK -Message "Tray process '$TrayProcessName' running in the active user session."
        }
        else {
            Add-Evidence -Level WARN -Message "Tray process '$TrayProcessName' absent despite an active user session - user may see no ZCC UI."
        }
    }
    else {
        Add-Evidence -Level SKIP -Message "No interactive session (explorer.exe absent) - '$TrayProcessName' absence is expected, not a fault."
    }

    if ($criticalTotal -eq 0) {
        $script:Result.RunningState = 'UNKNOWN'
    }
    elseif ($criticalUp -eq $criticalTotal) {
        $script:Result.RunningState = 'OK'
    }
    elseif ($criticalUp -eq 0) {
        $script:Result.RunningState = 'STOPPED'
    }
    else {
        $script:Result.RunningState = 'PARTIAL'
    }

    return ($script:Result.RunningState -eq 'OK')
}

# ====================================================================================
# CONTRACT FUNCTION 3 - Test-CheckIn
# ====================================================================================
function Test-CheckIn {
    <#
      ZCC on Windows exposes no supported, documented status CLI that reports
      console connectivity. ZSACli.exe exists but its documented verbs (logout,
      uninstall) are outside this script's remediation boundary, so it is DETECTED
      and never invoked. Check-in is therefore inferred from the agent's own
      facilities: service state plus log-write freshness.

      Three-state on purpose:
        OK      - fresh log activity within the staleness window
        STALE   - logs exist but are older than the window  -> restart is justified
        UNKNOWN - no readable logs at all -> insufficient evidence. UNKNOWN must
                  never escalate to REINSTALL_RECOMMENDED; a missing log trail is
                  a telemetry gap, not proof the agent is broken.

      ⚠️ [MANUAL: validate the staleness window against your App Profile log
      level. At 'Error'-only verbosity a healthy agent writes nothing for hours and
      this check will read STALE, causing needless restarts. Either raise the log
      level for managed hosts or raise -CheckInStaleMinutes.]
    #>
    $logRoot    = Resolve-Config -Value $Cfg.LogRoot    -Default $DefaultLogRoot
    $logPattern = Resolve-Config -Value $Cfg.LogPattern -Default $DefaultLogPattern

    # ZSACli presence detection only - never executed.
    try {
        $installRoot = Resolve-Config -Value $Cfg.InstallRoot -Default $DefaultInstallRoot
        if ($installRoot -and (Test-Path -LiteralPath $installRoot)) {
            $cli = Get-ChildItem -Path $installRoot -Filter 'ZSACli.exe' -Recurse -ErrorAction SilentlyContinue |
                   Select-Object -First 1
            if ($cli) {
                Add-Evidence -Level INFO -Message "ZSACli.exe present at '$($cli.FullName)' - detected only; not invoked (its verbs are out of remediation scope)."
            }
        }
    }
    catch { }

    if (-not $logRoot -or -not (Test-Path -LiteralPath $logRoot)) {
        Add-Evidence -Level WARN -Message "Log root '$logRoot' not found - check-in freshness cannot be evaluated."
        $script:Result.CheckInState = 'UNKNOWN'
        return $false
    }

    $newest = $null
    try {
        $newest = Get-ChildItem -Path $logRoot -Filter $logPattern -Recurse -File -ErrorAction SilentlyContinue |
                  Sort-Object LastWriteTime -Descending | Select-Object -First 1
    }
    catch {
        Add-Evidence -Level WARN -Message "Could not enumerate '$logRoot' (permissions or path). Check-in freshness unavailable."
        $script:Result.CheckInState = 'UNKNOWN'
        return $false
    }

    if (-not $newest) {
        Add-Evidence -Level WARN -Message "No files matching '$logPattern' under '$logRoot' - check-in freshness unavailable."
        $script:Result.CheckInState = 'UNKNOWN'
        return $false
    }

    $ageMin = [math]::Round(((Get-Date) - $newest.LastWriteTime).TotalMinutes, 1)
    if ($ageMin -le $CheckInStaleMinutes) {
        Add-Evidence -Level OK -Message "Most recent agent log write $ageMin min ago (threshold $CheckInStaleMinutes min): $($newest.Name)"
        $script:Result.CheckInState = 'OK'
        return $true
    }

    Add-Evidence -Level FAIL -Message "Most recent agent log write $ageMin min ago exceeds the $CheckInStaleMinutes min threshold: $($newest.Name)"
    $script:Result.CheckInState = 'STALE'
    return $false
}

# ====================================================================================
# CONTRACT FUNCTION 4 - Invoke-Remediation
# ====================================================================================
function Invoke-Remediation {
    <#
      BOUNDED. Permitted: start a stopped service, restart a running-but-stale
      service. Forbidden and not implemented anywhere in this script: uninstall,
      reinstall, binary deletion, driver removal, posture/quarantine/policy edits,
      disabling any security feature, ZSACli logout (forces end-user reauth and can
      drop the tunnel), registry surgery.
    #>
    param(
        [ValidateSet('Start', 'Restart')][string]$Mode
    )

    $targets = $ExpectedServices | Where-Object { $_.Critical }
    $blocked = $false
    $acted   = $false

    foreach ($s in $targets) {
        $info = Get-ServiceInfoCompat -Name $s.Name
        if (-not $info) { continue }

        if ($Mode -eq 'Start' -and $info.Status -eq 'Running') { continue }

        try {
            if ($Mode -eq 'Start') {
                Add-Action "Starting service '$($info.Name)'."
                Start-Service -Name $info.Name -ErrorAction Stop
            }
            else {
                Add-Action "Restarting service '$($info.Name)' to force re-check-in."
                # Restart-Service -Force handles dependent services; ZSAService has them.
                Restart-Service -Name $info.Name -Force -ErrorAction Stop
            }
            $acted = $true

            $span = New-Object System.TimeSpan(0, 0, $ServiceWaitSeconds)
            try {
                $info.Controller.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, $span)
                Add-Evidence -Level OK -Message "Service '$($info.Name)' reached Running after $Mode."
            }
            catch {
                Add-Evidence -Level WARN -Message "Service '$($info.Name)' did not reach Running within $ServiceWaitSeconds s after $Mode."
            }
        }
        catch {
            if (Test-AccessDenied -ErrorRecord $_) {
                $blocked = $true
                $script:Result.TamperBlocked = $true
                Add-Evidence -Level FAIL -Message "Service '$($info.Name)': $Mode blocked by access denial - consistent with ZCC tamper protection."
            }
            else {
                $msg = ''
                try { $msg = $_.Exception.Message } catch { }
                Add-Evidence -Level FAIL -Message "Service '$($info.Name)': $Mode failed - $msg"
            }
        }
    }

    if (-not $acted -and -not $blocked) {
        Add-Evidence -Level SKIP -Message "No service required a $Mode action."
    }

    # Rung 4 of the ladder - supported re-register / re-establish-comms command.
    # ZCC exposes no vendor-documented, non-destructive re-registration verb on
    # Windows. Re-enrollment requires ZSACli logout (end-user reauth) or a device
    # removal in the admin portal - both outside the automation boundary. Recorded
    # explicitly so the ladder's stop point is auditable rather than silently skipped.
    if ($Mode -eq 'Restart') {
        Add-Evidence -Level SKIP -Message "Rung 4 (forced re-registration): no supported non-destructive ZCC verb exists on Windows - console-side or manual action only."
    }

    return (-not $blocked)
}

# ====================================================================================
# CONTRACT FUNCTION 5 - Write-Verdict  (BULK emitter - exactly one line)
# ====================================================================================
function Format-Field {
    <#
      Collapse any free-text value into something a fleet collector can parse safely.
      Agent- and OS-emitted strings are treated as untrusted text here: they are
      sanitised and length-capped, never interpreted, and never used for control flow.
    #>
    param(
        [AllowNull()][AllowEmptyString()][string]$Text,
        [int]$MaxLength = 160
    )
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $s = $Text
    $s = $s -replace '[\r\n\t]', ' '      # no line breaks - one row per host
    $s = $s -replace '\|', '/'            # protect the Kv delimiter
    $s = $s -replace '\s{2,}', ' '
    $s = $s.Trim()
    if ($s.Length -gt $MaxLength) { $s = $s.Substring(0, [math]::Max(1, $MaxLength - 3)) + '...' }
    return $s
}

function Format-CsvValue {
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ($null -eq $Text) { $Text = '' }
    return '"' + ($Text -replace '"', '""') + '"'
}

function Write-Verdict {
    $r = $script:Result

    # Roll the evidence list up into counters plus the first hard failure, which is
    # the single most useful triage field in a fleet report.
    $failCount = 0
    $warnCount = 0
    $firstFail = ''
    foreach ($e in $r.Evidence) {
        if ($e.Level -eq 'FAIL') {
            $failCount++
            if (-not $firstFail) { $firstFail = $e.Message }
        }
        elseif ($e.Level -eq 'WARN') {
            $warnCount++
        }
    }

    $lastAction = ''
    if ($r.Actions.Count -gt 0) { $lastAction = $r.Actions[$r.Actions.Count - 1] }

    $fields = [ordered]@{
        schema      = '1'
        agent       = 'Zscaler'
        os          = 'Win'
        host        = $script:ComputerName
        status      = $r.Status
        code        = [string]$r.ExitCode
        installed   = $(if ($r.Installed) { '1' } else { '0' })
        version     = (Format-Field -Text $r.Version -MaxLength 48)
        services    = $r.RunningState
        checkin     = $r.CheckInState
        tamper      = $(if ($r.TamperBlocked) { '1' } else { '0' })
        remediated  = $(if ($r.Actions.Count -gt 0) { '1' } else { '0' })
        actions     = [string]$r.Actions.Count
        fails       = [string]$failCount
        warns       = [string]$warnCount
        lastaction  = (Format-Field -Text $lastAction -MaxLength $TextFieldMaxLength)
        firstfail   = (Format-Field -Text $firstFail  -MaxLength $TextFieldMaxLength)
        reason      = (Format-Field -Text $r.Reason   -MaxLength $TextFieldMaxLength)
        psver       = [string]$PSVersionTable.PSVersion
        psmode      = $script:PSMode
        ts          = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
    }

    # This switch is the ONLY place this script ever calls Write-Output. Do not
    # add another Write-Host/Write-Output anywhere else in the engine -- it will
    # corrupt every row a fleet collector reads from stdout.
    switch ($Format) {

        'Json' {
            try {
                Write-Output ([string](ConvertTo-Json -InputObject $fields -Compress -Depth 3))
            }
            catch {
                Write-Output ('{"schema":"1","agent":"Zscaler","os":"Win","host":"' + $script:ComputerName + '","status":"ERROR","code":"4"}')
            }
        }

        'Csv' {
            if ($IncludeHeader) {
                Write-Output (($fields.Keys | ForEach-Object { Format-CsvValue -Text $_ }) -join ',')
            }
            Write-Output (($fields.Keys | ForEach-Object { Format-CsvValue -Text ([string]$fields[$_]) }) -join ',')
        }

        default {
            # Kv - pipe-delimited key=value, the friendliest shape for Endpoint
            # Central's script-output column and for a quick grep across a sweep.
            $pairs = @()
            foreach ($k in $fields.Keys) { $pairs += ('{0}={1}' -f $k, [string]$fields[$k]) }
            Write-Output ($pairs -join '|')
        }
    }
}

# ====================================================================================
# MAIN
# ====================================================================================
function Invoke-Main {

    # --- PowerShell version branch -------------------------------------------------
    $major = 0
    try { $major = [int]$PSVersionTable.PSVersion.Major } catch { $major = 0 }
    if ($major -ge 7)      { $script:PSMode = 'Core7' }
    elseif ($major -eq 5)  { $script:PSMode = 'Desktop51' }
    else {
        $script:PSMode = 'Desktop51'
        Add-Evidence -Level FAIL -Message "Unsupported PowerShell major version '$major'. Requires Windows PowerShell 5.1 or PowerShell 7+."
        Set-Verdict -Status ERROR -Reason 'Unsupported PowerShell version.'
        return
    }
    Add-Evidence -Level INFO -Message "PowerShell $($PSVersionTable.PSVersion) detected - executing the $($script:PSMode) code path."

    # --- Elevation check (must be first privileged gate) ---------------------------
    $elev = Test-Elevated
    if (-not $elev.Elevated) {
        Add-Evidence -Level FAIL -Message "Running as '$($elev.Account)', which is not elevated. No privileged action attempted."
        Set-Verdict -Status ERROR -Reason 'Not elevated. Re-run as SYSTEM or as an elevated Administrator.'
        return
    }
    Add-Evidence -Level OK -Message ("Elevation confirmed: {0}{1}." -f $elev.Account, $(if ($elev.IsSystem) { ' (SYSTEM)' } else { ' (elevated Administrator)' }))

    # --- Interactivity detection ---------------------------------------------------
    $script:Interactive = Test-Interactive
    Add-Evidence -Level INFO -Message ("Interactivity: {0}." -f $(if ($script:Interactive) { 'interactive - reinstall handoff may prompt' } else { 'non-interactive - will never prompt or block' }))

    # --- Rung 1: Installed? --------------------------------------------------------
    if (-not (Test-Installed)) {
        Set-Verdict -Status NOT_INSTALLED -Reason 'No install receipt, registered service, or install directory found.'
        return
    }

    # --- Rung 2: Running? ----------------------------------------------------------
    $running = Test-Running
    if (-not $running) {
        if ($script:Result.RunningState -eq 'UNKNOWN') {
            Set-Verdict -Status DEGRADED -Reason 'Agent is installed but no critical service is registered - cannot evaluate or remediate service state.'
            return
        }
        $ok = Invoke-Remediation -Mode Start
        $running = Test-Running
        if (-not $ok -and -not $running) {
            Set-Verdict -Status DEGRADED -Reason 'Service start was blocked (tamper protection or access denial). Console-side action required.'
            return
        }
        if (-not $running) {
            Set-Verdict -Status REINSTALL_RECOMMENDED -Reason 'Critical services will not start and no safe remediation remains.'
            return
        }
        # Services recovered - fall through to the check-in rung before verdicting.
    }

    # --- Rung 3: Checking in? ------------------------------------------------------
    $checkedIn = Test-CheckIn
    if (-not $checkedIn -and $script:Result.CheckInState -eq 'STALE') {
        $ok = Invoke-Remediation -Mode Restart
        $running   = Test-Running
        $checkedIn = Test-CheckIn
        if (-not $ok) {
            Set-Verdict -Status DEGRADED -Reason 'Check-in is stale and the corrective restart was blocked (tamper protection or access denial). Console-side action required.'
            return
        }
        if ($running -and $checkedIn) {
            Set-Verdict -Status RECOVERED -Reason 'Stale check-in cleared by a service restart; agent is now running and reporting.'
            return
        }
        if ($running) {
            Set-Verdict -Status REINSTALL_RECOMMENDED -Reason 'Services run but check-in remains stale after restart; no supported non-destructive re-registration path exists.'
            return
        }
        Set-Verdict -Status REINSTALL_RECOMMENDED -Reason 'Agent did not return to a running, reporting state after restart.'
        return
    }

    # --- Rung 5: Verdict ----------------------------------------------------------
    if ($script:Result.Actions.Count -gt 0) {
        if ($running -and $script:Result.CheckInState -eq 'OK') {
            Set-Verdict -Status RECOVERED -Reason 'Agent was unhealthy; bounded remediation restored it to a running, reporting state.'
        }
        elseif ($running) {
            Set-Verdict -Status DEGRADED -Reason 'Services are running after remediation but check-in could not be confirmed (no usable log evidence).'
        }
        else {
            Set-Verdict -Status DEGRADED -Reason 'Remediation ran but the agent is not fully healthy.'
        }
        return
    }

    if ($running -and $script:Result.CheckInState -eq 'OK') {
        Set-Verdict -Status HEALTHY -Reason 'Installed, all critical services running, recent check-in confirmed. No action taken.'
        return
    }

    if ($running -and $script:Result.CheckInState -eq 'UNKNOWN') {
        # Deliberately NOT a reinstall trigger: absent logs are a telemetry gap.
        Set-Verdict -Status DEGRADED -Reason 'All critical services are running, but check-in could not be verified (no readable agent logs). Telemetry gap, not proof of failure - verify this device in the admin portal.'
        return
    }

    Set-Verdict -Status DEGRADED -Reason 'Agent state could not be fully confirmed. Review the evidence above.'
}

# ------------------------------------------------------------------------------------
# Entry point. Nothing risky escapes to the console; all failures become status bands.
# ------------------------------------------------------------------------------------
try {
    Invoke-Main
}
catch {
    $msg = 'unknown failure'
    try { $msg = $_.Exception.Message } catch { }
    Add-Evidence -Level FAIL -Message "Unhandled script fault: $msg"
    Set-Verdict -Status ERROR -Reason 'The health check itself failed. No remediation was attempted.'
}
finally {
    try { Write-Verdict }
    catch { Write-Output ('schema=1|agent=Zscaler|os=Win|host={0}|status=ERROR|code=4|reason=verdict rendering failed' -f $env:COMPUTERNAME) }
    Write-DiagnosticLog
}

exit $script:Result.ExitCode

<#
=====================================================================================
 MANUAL COMPLETION CHECKLIST - complete every item before production deployment
=====================================================================================

 This is a single-file engine: the same detection/remediation ladder produces both
 the one-line fleet-report row (stdout) and the full evidence log
 (C:\Logs\CompoSecure\ZscalerAgentRepair_<host>_<timestamp>.log). There is no
 separate SINGLE-host variant to keep in sync -- for full detail on one host,
 read that host's log file rather than re-running a different script.

 VARIABLES TO SUBSTITUTE (in the $Cfg block near the top)
 ---------------------------------------------------------
 [ ] {{ZSCALER_INSTALL_ROOT}}        Install root. Default fallback: C:\Program Files\Zscaler
 [ ] {{ZSCALER_LOG_ROOT}}            Log root.     Default fallback: C:\ProgramData\Zscaler
 [ ] {{ZSCALER_LOG_PATTERN}}         Log glob.     Default fallback: *.log
 [ ] zscalertwo          Cloud name - informational only, printed in the log's evidence
 [ ] {{ZCC_ADMIN_PORTAL_URL}}        Not currently emitted; kept for future use
 [ ] {{ZCC_APPROVED_VERSION}}        Pinned, reviewed ZCC build approved for this fleet - never "latest"
 [ ] {{INTERNAL_PACKAGE_REPO_PATH}}  Internal source for the approved installer
 [ ] {{SUPPORT_CONTACT}}             Escalation contact

 NOT a variable, on purpose: the ZCC uninstall/logout password. This script never
 invokes ZSACli and therefore never needs the secret. Do not add it.

 MANUAL VERIFICATION MARKERS
 ----------------------------
 [ ] Install root       - confirm on a reference host; ARM64 / x86 builds may differ
 [ ] Log root + pattern - confirm files are actually written there on a healthy host
 [ ] Log verbosity      - if the App Profile log level is Error-only, a healthy agent
                          writes nothing for hours and check-in will read STALE.
                          Raise verbosity for managed hosts or raise -CheckInStaleMinutes.
                          Validate this BEFORE a fleet run or you will mass-restart
                          healthy agents
 [ ] Service short names- run: Get-Service -Name 'ZSA*' | Select Name,DisplayName,Status,StartType
                          and reconcile against $ExpectedServices
 [ ] ZSATunnel          - confirm whether it is a service or a child process on your
                          build; if it is not a service, set Critical=$false for it
 [ ] Tamper policy      - if your App Profile blocks local service control, expect a
                          fleet-wide band of DEGRADED with tamper=1. That is correct
                          behaviour, not a script fault - fix it console-side
 [ ] Field set          - confirm the emitted field list matches what your collector
                          or Endpoint Central report expects before wide rollout

 OUTPUT / COLLECTOR NOTES
 ------------------------
 [ ] Exactly one stdout line per host (two with -Format Csv -IncludeHeader). Do not
     add Write-Host or Write-Output anywhere in the engine except inside Write-Verdict's
     format switch - it will corrupt every row
 [ ] Kv rows are pipe-delimited; the '|' character is stripped from free text by
     Format-Field, so a naive split on '|' is safe
 [ ] Csv rows are fully quoted with doubled internal quotes (RFC4180). Add the header
     once at the collector rather than per host
 [ ] Json rows are single-line and compressed; safe to append straight to a .jsonl file
 [ ] Triage priority for a sweep: status=ERROR first, then tamper=1, then
     status=REINSTALL_RECOMMENDED, then DEGRADED with checkin=UNKNOWN (telemetry gap)
 [ ] For any host that comes back DEGRADED or REINSTALL_RECOMMENDED, read
     C:\Logs\CompoSecure\ZscalerAgentRepair_<host>_*.log on that host for the full
     evidence trail (every check performed, in order, with OK/WARN/FAIL/INFO/SKIP)
 [ ] Cross-reference against the Zscaler admin console's device export. A host this
     script reports HEALTHY or RECOVERED but that is flagged 'Not in Device Export'
     will still show as missing fleet-wide -- that half of the problem is console-side
     and this script cannot see or fix it

 DEPLOYMENT NOTES
 ----------------
 [ ] Save this file as UTF-8 WITH BOM. Windows PowerShell 5.1 misparses non-ASCII
     comment characters in a BOM-less UTF-8 file
 [ ] Endpoint Central: run as SYSTEM, PowerShell, no user interaction. Map exit codes
     0=success, 1=DEGRADED, 2=REINSTALL_RECOMMENDED, 3=NOT_INSTALLED, 4=ERROR
 [ ] Stagger the fleet run. Rung 3 can restart ZSAService, which briefly drops the
     tunnel; a simultaneous fleet-wide restart is a self-inflicted outage. Ring the
     rollout (pilot -> IT -> department -> fleet)
 [ ] If your MDM cannot consume exit codes and requires stdout only, delete the final
     'exit $script:Result.ExitCode' line; the result line remains parseable
=====================================================================================
#>
