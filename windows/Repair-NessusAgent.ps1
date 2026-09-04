<#
.SYNOPSIS
    Nessus Agent link repair (v5). Checks the agent's actual state and only
    fixes what is broken -- healthy linked agents are left untouched.

.DESCRIPTION
    Decision flow:
      Agent installed?
        NO  -> install agent via Tenable bootstrap script (-type agent --
               the v1 script said 'scanner', which installs the wrong product)
               -> bootstrap failed to produce nessuscli.exe? fall back to a
                  staged MSI (see v4 below)
        YES -> ensure service is running (either service name)
               -> already linked to the right host? exit 0, touch nothing
               -> not linked / wrong host? link (unlink first only if needed)

    v5 (from the CSPRPC-76 run, 2026-09-03): the link failed with
    'Link fail: Connection to sensor.cloud.tenable.com:443 failed.' and the
    script fell through to the generic 'Agent still not linked after repair
    attempt' -- naming no cause and implying a retry might help. Two problems
    with that:
      * It conflated two genuinely different failures. 'empty response from
        controller' (the only link error v4 recognised) means the connection
        DID come up and the reply was mangled -- the TLS-inspection signature.
        'Connection to ...:443 failed' means nothing was ever established, so
        the egress path is the suspect instead. Same symptom, different owner.
      * It threw away the fact that this agent had NEVER connected
        ('Last connect: Never', 'Plugin set: (null)'). That is not a
        regression to repair; egress from that host to Tenable had never
        worked at all, so relinking could never fix it.
    Now:
      * New Test-ManagerReachability probes DNS, then TCP 443, then the TLS
        certificate ISSUER, and reports where the path actually breaks. The
        issuer check is the only one that PROVES interception rather than
        suspecting it -- an inspection proxy presents its own CA, so a
        non-vendor issuer is hard evidence for a bypass request. Uses raw
        .NET rather than Test-NetConnection, which lives in a module whose
        availability under EC's SYSTEM context is not guaranteed and which
        cannot report the issuer anyway.
      * A connection-level failure now gets its own branch, is explicitly
        contrasted with the 'empty response' case, and says so when the agent
        has never connected.
      * The generic final failure path also probes, so no run ends on a bare
        "it did not work" with nothing to hand the network team.

    v4 (from the CSLT-168 run, 2026-08-28): the bootstrap install has no
    fallback -- if ms-install-script.ps1 fails for ANY reason (download
    blocked, block page instead of the script, or the embedded msiexec
    itself failing) the script just aborted. CSLT-168's bootstrap
    downloaded fine but its own msiexec died with 1603, and the only
    remedy at the time was to run NessusAgent_CleanReinstall.ps1 (a
    separate, more destructive script) with a staged MSI.
      * This script now falls back to a staged MSI install when the
        bootstrap route does not produce nessuscli.exe, for ANY reason
        (download failure, block page, or a failed install inside the
        bootstrap). No new switch needed -- Endpoint Central's per-script
        Repository option is not "install software," it is "run a script,"
        and per the repo-wide EC-argument convention (README.md) a MSI path
        should not be passed as a script argument anyway (quoted paths get
        mangled). Stage the MSI as this Custom Script configuration's
        Dependency File instead: EC extracts Dependency Files into the SAME
        folder the script itself runs from, which PowerShell exposes as
        $PSScriptRoot, so no path needs to be configured by hand.
      * Get-StagedNessusMsi checks $PSScriptRoot first (same as
        NessusAgent_CleanReinstall.ps1 v4.2), then C:\ as a
        manual-staging fallback, and prefers a filename matching this
        host's architecture (x64/win32/arm64).
      * Invoke-Msi (ported from NessusAgent_CleanReinstall.ps1) runs
        msiexec by FULL PATH with -NoNewWindow -- a bare 'msiexec.exe'
        goes through ShellExecute and fails under EC's SYSTEM context --
        and retries 1618/1601 (installer busy) with backoff instead of
        treating them as fatal.
      * -MsiPath still accepts an explicit override for local/manual
        testing; auto-discovery via $PSScriptRoot is what a normal EC
        deployment relies on.

    v3 (from the 2026-08-07 CSLT-171 / CSLT-243 runs):
      * GROUP RESOLUTION. v2 linked with no group unless -LinkGroups was passed
        by hand, then declared SUCCESS -- CSLT-243 came out linked into no group,
        which means no scan policy, no plugins, no results, and a finding that
        never clears. Groups now resolve from the same prefix-rule + override
        table as NessusAgent_CleanReinstall.ps1, and a host that ends up with no
        group exits 2 rather than 0.
      * NATIVE STDERR NO LONGER KILLS THE SCRIPT. nessuscli writes informational
        JSON to stderr; under $ErrorActionPreference='Stop' PowerShell promotes
        that to a terminating NativeCommandError. CSLT-171 died at the first
        'agent status' call over a line whose own severity was "INFO". All
        nessuscli calls now go through Invoke-NessusCli, which drops to Continue
        for the duration and stringifies the output.
      * Detects and reports the FIPS module integrity failure explicitly.

.PARAMETER LinkKey
    Tenable linking key. Defaults to the CompoSecure group key.

.PARAMETER LinkHost
    Manager host. Default sensor.cloud.tenable.com.

.PARAMETER LinkGroups
    Agent group(s) to join, e.g. 'Workstations'. SET THIS -- an agent linked
    with no group is not targeted by any scans.

.PARAMETER ForceRelink
    Unlink and relink even if the agent reports healthy. Use only when an
    agent is misbehaving despite showing linked.

.PARAMETER MsiPath
    Explicit path to a staged Nessus Agent MSI, used only if the Tenable
    bootstrap install fails. If omitted (the normal EC deployment case),
    the script searches $PSScriptRoot (where EC extracts this Custom
    Script configuration's Dependency Files) then C:\ for
    NessusAgent-*.msi, preferring a filename matching this host's
    architecture. Do not pass a quoted path as an EC script argument --
    see README.md on EC argument mangling; stage the MSI as a Dependency
    File instead and leave this empty.

.NOTES
    Deploy via Endpoint Central (SYSTEM). Exit: 0 ok / 3010 ok, reboot
    recommended (configure EC's "Specify exit code(s)" as 0,3010) / 1
    failure / 2 linked but needs human attention (no group / FIPS warning).
    Zscaler: 'empty response from controller' on link = SSL inspection of
    sensor.cloud.tenable.com; add a bypass and re-run.
#>

[CmdletBinding()]
param(
    [string]$LinkKey    = '4f858e2b28a33a5927c7805eab8b8533ecb35c983417b392c5b570b5a6a96fba',
    [string]$LinkHost   = 'sensor.cloud.tenable.com',
    [string]$LinkGroups = '',
    [switch]$ForceRelink,
    # Manual override only. Leave empty for a normal EC deployment -- see
    # .PARAMETER MsiPath above.
    [string]$MsiPath    = ''
)

$ErrorActionPreference = 'Stop'
$NoGroup      = $false
$FipsWarning  = $false
$RebootNeeded = $false
$LogDir  = 'C:\Logs\CompoSecure'
$LogFile = Join-Path $LogDir ('NessusAgentRepair_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

# Exact-hostname overrides -- checked FIRST, win over any prefix rule.
$GroupOverride = @{
    'CS-MCALPHA-01' = 'CIS Windows Server 2019'
    'CS-VCID01' = 'Critical Assets,Windows Servers'
    'CSPRLT-13' = 'CIS Windows 10 Benchmark,Laptops'
    'CV-MBPC02' = 'MacBook'
    'CX-DCPR01' = 'CIS Windows Server 2019'
}

# Prefix rules. LONGEST matching prefix wins, so more specific entries
# (CS-MEM-JUMP) correctly beat broader ones (CS-).
$GroupPrefix = @(
    @{ P = 'C02V'; G = 'Securitas Physical Security' }
    @{ P = 'ACCESS-CLIENT'; G = 'Securitas Physical Security' }
    @{ P = 'MIMAKI'; G = 'Shop Floor Equip' }
    @{ P = 'SWISSQ'; G = 'Shop Floor Equip' }
    @{ P = 'SHRB'; G = 'Shop Floor Equip' }
    @{ P = 'SHOPPR'; G = 'Shop Floor Equip' }
    @{ P = 'LCELO'; G = 'Shop Floor Equip' }
    @{ P = 'CSMB'; G = 'MacBook' }
    @{ P = 'CSPRMB'; G = 'MacBook' }
    @{ P = 'CSPRIM'; G = 'MacBook' }
    @{ P = 'CSIM'; G = 'MacBook' }
    @{ P = 'CSMS'; G = 'MacBook' }
    @{ P = 'ARMB'; G = 'MacBook' }
    @{ P = 'JRIEGEL-MAC'; G = 'MacBook' }
    @{ P = 'CSPC'; G = 'Desktop PC' }
    @{ P = 'CSMEPC'; G = 'Desktop PC' }
    @{ P = 'CSDVPC'; G = 'Desktop PC' }
    @{ P = 'CSPSPC'; G = 'Desktop PC' }
    @{ P = 'CSPRPC'; G = 'Desktop PC' }
    @{ P = 'CSLD'; G = 'Desktop PC' }
    @{ P = 'CSLT'; G = 'Laptops' }
    @{ P = 'CSPRLT'; G = 'Laptops' }
    @{ P = 'CSMELT'; G = 'Laptops' }
    @{ P = 'CSDVLT'; G = 'Laptops' }
    @{ P = 'CSXPS'; G = 'Laptops' }
    @{ P = 'CSPRXPS'; G = 'Laptops' }
    @{ P = 'CSRZ'; G = 'Laptops' }
    @{ P = 'CSPRRZ'; G = 'Laptops' }
    @{ P = 'CSSB'; G = 'Laptops' }
    @{ P = 'CSLV'; G = 'Laptops' }
    @{ P = 'CS-APG-JUMP'; G = 'DMZ Servers' }
    @{ P = 'CS-DVN-JUMP'; G = 'DMZ Servers' }
    @{ P = 'CS-MEM-JUMP'; G = 'DMZ Servers' }
    @{ P = 'CS-PRC-JUMP'; G = 'DMZ Servers' }
    @{ P = 'CS-RSV-JUMP'; G = 'DMZ Servers' }
    @{ P = 'CS-EA'; G = 'DMZ Servers' }
    @{ P = 'CS-'; G = 'Windows Servers' }
    @{ P = 'CX-'; G = 'Windows Servers' }
    @{ P = 'CV-'; G = 'Windows Servers' }
    @{ P = 'TENABLE-'; G = 'Windows Servers' }
)

function Resolve-AgentGroups {
    param([string]$HostName)
    $h = $HostName.ToUpper()
    if ($GroupOverride.ContainsKey($h)) { return $GroupOverride[$h] }
    $bestPrefix = ''
    $bestGroups = ''
    foreach ($rule in $GroupPrefix) {
        if ($h.StartsWith($rule.P) -and ($rule.P.Length -gt $bestPrefix.Length)) {
            $bestPrefix = $rule.P
            $bestGroups = $rule.G
        }
    }
    return $bestGroups
}

$Cli = 'C:\Program Files\Tenable\Nessus Agent\nessuscli.exe'

function Invoke-NessusCli {
    # nessuscli writes informational JSON to stderr. Under
    # $ErrorActionPreference='Stop' that becomes a terminating NativeCommandError,
    # which killed v2 on CSLT-171. Drop to Continue for the call and stringify.
    param([string[]]$CliArgs)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $raw = & $Cli @CliArgs 2>&1
        $lines = @()
        foreach ($item in $raw) { $lines += ($item | Out-String).TrimEnd() }
        return ($lines -join "`n")
    } finally {
        $ErrorActionPreference = $prev
    }
}

function Test-FipsFailure {
    param([string]$Text)
    return ($Text -match 'FIPS module .*Integrity.*FAIL' -or $Text -match 'Module_Integrity HMAC test\s+FAIL')
}

function Test-ManagerReachability {
    # v5: turn a link failure into EVIDENCE instead of a guess, by finding out
    # WHERE the path to the manager breaks. Three checks, because the three
    # real-world causes are distinguishable and need different owners:
    #   DNS fails            -> name resolution / split-DNS problem
    #   TCP 443 never opens  -> egress blocked or filtered, or a proxy is required
    #   TLS cert is not the vendor's -> traffic is being intercepted (SSL
    #                                   inspection), which needs a bypass
    #
    # Raw .NET rather than Test-NetConnection: that cmdlet lives in the NetTCPIP
    # module, whose availability under EC's SYSTEM context is not guaranteed,
    # and it cannot report the certificate issuer -- which is the only check
    # here that actually PROVES interception rather than suspecting it.
    #
    # NOTE the parameter is $TargetHost, not $Host -- $Host is a reserved
    # PowerShell automatic variable and binding it breaks the host UI.
    param([string]$TargetHost, [int]$Port = 443, [int]$TimeoutMs = 10000)

    Write-Log ('  Probing ' + $TargetHost + ':' + $Port + ' from this host...')

    try {
        $addrs = @([System.Net.Dns]::GetHostAddresses($TargetHost) | ForEach-Object { $_.IPAddressToString })
        Write-Log ('  DNS      : resolves to ' + ($addrs -join ', '))
    } catch {
        Write-Log ('  DNS      : FAILED to resolve -- ' + $_.Exception.Message) -Level ERROR
        Write-Log '  DNS is the first thing to fix; nothing else here can succeed without it.' -Level ERROR
        return
    }

    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $tcp.BeginConnect($TargetHost, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            Write-Log ('  TCP ' + $Port + '  : TIMED OUT after ' + [int]($TimeoutMs / 1000) + 's.') -Level ERROR
            Write-Log '  Egress to the manager is blocked or silently dropped. This is a network' -Level ERROR
            Write-Log '  path problem, not an agent problem -- the agent cannot fix it by relinking.' -Level ERROR
            $tcp.Close()
            return
        }
        $tcp.EndConnect($iar)
        Write-Log ('  TCP ' + $Port + '  : connected')
    } catch {
        Write-Log ('  TCP ' + $Port + '  : FAILED -- ' + $_.Exception.Message) -Level ERROR
        Write-Log '  Egress to the manager is refused. Network path problem, not an agent one.' -Level ERROR
        $tcp.Close()
        return
    }

    # Accept ANY certificate on purpose: the point is to LOOK at what is being
    # presented, including an intercepting one that normal validation rejects.
    try {
        $noValidation = [System.Net.Security.RemoteCertificateValidationCallback] { $true }
        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $noValidation)
        $ssl.AuthenticateAsClient($TargetHost)
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]$ssl.RemoteCertificate
        Write-Log ('  TLS cert : subject ' + $cert.Subject)
        Write-Log ('  TLS cert : issuer  ' + $cert.Issuer)
        if ($cert.Issuer -match 'Zscaler|Proxy|Forcepoint|Netskope|Palo Alto|Blue Coat|Fortinet') {
            Write-Log '  *** The certificate presented for this host is issued by an INSPECTION' -Level ERROR
            Write-Log '  *** PROXY, not the vendor CA. TLS to the manager is being intercepted.' -Level ERROR
            Write-Log ('  *** Add a TLS-inspection BYPASS for ' + $TargetHost + ' and re-run.') -Level ERROR
        } else {
            Write-Log '  TLS cert : issuer does not look like an inspection proxy.'
        }
        $ssl.Dispose()
    } catch {
        Write-Log ('  TLS      : handshake FAILED -- ' + $_.Exception.Message) -Level WARN
        Write-Log '  The port is open but TLS did not complete. Something is terminating or' -Level WARN
        Write-Log '  rewriting the session (inspection proxy, or a TLS version/cipher mismatch).' -Level WARN
    }
    $tcp.Close()
}

function Get-StagedNessusMsi {
    # Same search + architecture-matching logic as NessusAgent_CleanReinstall.ps1's
    # MSI resolution. $PSScriptRoot -- not $MyInvocation.MyCommand.Path, which
    # inside a function refers to the function's own invocation, not the
    # script's -- is where Endpoint Central extracts this Custom Script
    # configuration's Dependency Files before running the script.
    $osArch = $env:PROCESSOR_ARCHITEW6432
    if ([string]::IsNullOrWhiteSpace($osArch)) { $osArch = $env:PROCESSOR_ARCHITECTURE }
    $archToken = switch ($osArch) {
        'ARM64'  { 'arm64' }
        'AMD64'  { 'x64' }
        'x86'    { 'win32' }
        default  { '' }
    }
    Write-Log ('  OS architecture : ' + $osArch + '  (expecting MSI token: ' + $archToken + ')')

    $searchDirs = @()
    if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) { $searchDirs += $PSScriptRoot }
    $searchDirs += 'C:\'

    $candidates = @()
    foreach ($dir in $searchDirs) {
        foreach ($f in (Get-ChildItem -Path $dir -Filter 'NessusAgent-*.msi' -File -ErrorAction SilentlyContinue)) {
            $candidates += $f
            Write-Log ('  Found staged MSI : ' + $f.FullName + '  (' + [math]::Round($f.Length/1MB,1) + ' MB)')
        }
    }
    if ($candidates.Count -eq 0) { return $null }

    $archMatch = @($candidates | Where-Object { $archToken -and ($_.Name -like ('*' + $archToken + '*')) })
    if ($archMatch.Count -gt 0) {
        $pick = ($archMatch | Sort-Object Name -Descending | Select-Object -First 1)
        Write-Log ('  Architecture match: ' + $pick.Name)
        return $pick.FullName
    }
    $pick = ($candidates | Sort-Object Name -Descending | Select-Object -First 1)
    Write-Log ('  WARNING: no staged MSI matches architecture ' + $archToken + '.') -Level WARN
    Write-Log ('  Falling back to ' + $pick.Name + ' -- verify this is correct for this host.') -Level WARN
    return $pick.FullName
}

function Invoke-Msi {
    # Full path + -NoNewWindow: a bare 'msiexec.exe' goes through ShellExecute
    # and fails under EC's SYSTEM context ("No application is associated with
    # the specified file for this operation") -- same fix already applied in
    # NessusAgent_CleanReinstall.ps1. 1618/1601 are transient installer-busy
    # codes, retried with backoff rather than treated as fatal.
    param([string]$Arguments, [int]$Retries = 4)
    $msiexec = Join-Path $env:SystemRoot 'System32\msiexec.exe'
    if (-not (Test-Path $msiexec)) { $msiexec = 'msiexec.exe' }
    $attempt = 0
    while ($true) {
        $attempt++
        $p = Start-Process -FilePath $msiexec -ArgumentList $Arguments -Wait -PassThru -NoNewWindow
        $code = $p.ExitCode
        if ($code -ne 1618 -and $code -ne 1601) { return $code }
        if ($attempt -ge $Retries) {
            Write-Log ('    Still ' + $code + ' after ' + $attempt + ' attempts.') -Level ERROR
            return $code
        }
        $wait = 30 * $attempt
        Write-Log ('    ' + $code + ' = installer busy. Waiting ' + $wait + 's, retry ' + $attempt + '/' + $Retries + '...') -Level WARN
        Start-Sleep -Seconds $wait
    }
}

Write-Log '=== Nessus Agent Repair (v5) ==='
Write-Log ('Host: ' + $env:COMPUTERNAME)

# ------------------------------------------------------------------
# Branch 1: agent not installed -> install it (as an AGENT, not scanner)
# ------------------------------------------------------------------
if (-not (Test-Path $Cli)) {
    Write-Log 'Agent not installed. Installing via Tenable bootstrap...' -Level WARN
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $bootstrap = Join-Path $env:TEMP 'ms-install-script.ps1'
    $bootstrapOk = $true
    try {
        Invoke-WebRequest -Uri 'https://sensor.cloud.tenable.com/install/agent/installer/ms-install-script.ps1' -OutFile $bootstrap -UseBasicParsing
    } catch {
        Write-Log ('Bootstrap download failed: ' + $_) -Level WARN
        $bootstrapOk = $false
    }
    if ($bootstrapOk) {
        # Sanity: should be a PowerShell script, not an HTML block page
        $head = (Get-Content $bootstrap -TotalCount 5) -join ' '
        if ($head -match '<html|<!DOCTYPE') {
            Write-Log 'Downloaded bootstrap is an HTML block page, not the install script' -Level WARN
            Write-Log '(likely Zscaler SSL inspection of sensor.cloud.tenable.com).' -Level WARN
            Remove-Item $bootstrap -Force -ErrorAction SilentlyContinue
            $bootstrapOk = $false
        }
    }
    if ($bootstrapOk) {
        try {
            & $bootstrap -key $LinkKey -type 'agent'
        } catch {
            Write-Log ('Bootstrap script threw: ' + $_) -Level WARN
        } finally {
            Remove-Item $bootstrap -Force -ErrorAction SilentlyContinue
        }
        Start-Sleep -Seconds 10
    }

    # v4: bootstrap failing for ANY reason (blocked download, block page, or
    # the bootstrap's own embedded msiexec failing -- CSLT-168, 2026-08-28,
    # exit 1603) used to be a dead end here. Fall back to a staged MSI
    # instead of aborting.
    if (-not (Test-Path $Cli)) {
        if ($bootstrapOk) {
            Write-Log 'Bootstrap ran but did not produce nessuscli.exe.' -Level WARN
        }
        Write-Log 'Falling back to a staged MSI install...' -Level WARN
        $msi = $MsiPath
        if ([string]::IsNullOrWhiteSpace($msi)) { $msi = Get-StagedNessusMsi }
        if ([string]::IsNullOrWhiteSpace($msi) -or -not (Test-Path $msi)) {
            Write-Log 'No staged NessusAgent-*.msi found in this Custom Script''s Dependency' -Level ERROR
            Write-Log 'Files (extracted beside this script) or in C:\, and no -MsiPath given.' -Level ERROR
            Write-Log 'Upload the MSI as a Dependency File on this EC configuration and re-run --' -Level ERROR
            Write-Log 'no script argument needed, it is found automatically. Aborting.' -Level ERROR
            exit 1
        }
        Write-Log ('  Installing staged MSI: ' + $msi)
        $installLog = Join-Path $LogDir ('msi_install_nessusagent_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')
        $code = Invoke-Msi ('/i "' + $msi + '" /qn /norestart /l*v "' + $installLog + '"')
        Write-Log ('  msiexec exit code: ' + $code)
        if ($code -eq 3010) {
            Write-Log '  Install succeeded but reports a reboot is required.' -Level WARN
            $script:RebootNeeded = $true
        } elseif ($code -ne 0) {
            Write-Log ('  MSI install failed. See ' + $installLog) -Level ERROR
            if ($code -eq 1603) {
                Write-Log '  1603 is a fatal/rollback error. Search the MSI log for "Error 0x" and' -Level ERROR
                Write-Log '  "Rolling back". Common causes: a pending reboot, a locked file from a' -Level ERROR
                Write-Log '  running Nessus process, or a damaged prior install -- try' -Level ERROR
                Write-Log '  NessusAgent_CleanReinstall.ps1 instead, which tears down stale' -Level ERROR
                Write-Log '  registrations before installing.' -Level ERROR
            }
            exit 1
        }
        Start-Sleep -Seconds 5
        if (-not (Test-Path $Cli)) {
            Write-Log 'Install did not produce nessuscli.exe via bootstrap OR staged MSI.' -Level ERROR
            Write-Log 'Aborting.' -Level ERROR
            exit 1
        }
    }
    Write-Log 'Agent installed.'
}

# ------------------------------------------------------------------
# Ensure the service is running (either name) before nessuscli calls
# ------------------------------------------------------------------
$svc = Get-Service | Where-Object { $_.Name -like '*Nessus Agent*' } | Select-Object -First 1
if (-not $svc) {
    Write-Log 'nessuscli.exe present but no agent service registered -- broken install.' -Level ERROR
    Write-Log 'Use NessusAgent_CleanReinstall.ps1 for this machine.' -Level ERROR
    exit 1
}
if ($svc.Status -ne 'Running') {
    Write-Log ('Service ' + $svc.Name + ' is ' + $svc.Status + ' -- starting...')
    Start-Service $svc.Name -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5
}
Write-Log ('Service: ' + $svc.Name + ' (' + (Get-Service $svc.Name).Status + ')')

# ------------------------------------------------------------------
# Check current link state -- do nothing if already healthy
# ------------------------------------------------------------------
$statusOut = Invoke-NessusCli @('agent','status')
foreach ($line in ($statusOut -split "`n")) { Write-Log ('  ' + $line) }
if (Test-FipsFailure $statusOut) {
    Write-Log '  FIPS MODULE INTEGRITY FAILURE reported by nessuscli.' -Level WARN
    Write-Log '  The agent OpenSSL FIPS provider failed its self-check. If the agent also' -Level WARN
    Write-Log '  cannot connect, treat this as a corrupted install and run' -Level WARN
    Write-Log '  NessusAgent_CleanReinstall.ps1 rather than repairing the link.' -Level WARN
    $script:FipsWarning = $true
}

$linkedOk = ($statusOut -match 'Linked to:\s*\S') -and ($statusOut -notmatch 'Linked to:\s*None') -and ($statusOut -match [regex]::Escape($LinkHost))

# v5: has this agent EVER talked to the controller? 'Last connect: Never' with a
# null plugin set means it has not -- so this is a host whose egress to Tenable
# has never worked, not a working agent that regressed. Different problem and a
# different owner: nothing on the agent side was ever "lost", so relinking
# cannot help until the network path is opened (CSPRPC-76, 2026-09-03).
$NeverConnected = ($statusOut -match 'Last connect:\s*Never')

if ($linkedOk -and -not $ForceRelink) {
    Write-Log ('Agent already linked to ' + $LinkHost + '. Nothing to repair.')
    exit 0
}

# ------------------------------------------------------------------
# (Re)link -- unlink first only if some link state exists
# ------------------------------------------------------------------
if ($statusOut -notmatch 'Linked to:\s*None') {
    Write-Log 'Existing link state present -- unlinking first...' -Level WARN
    $unlinkOut = Invoke-NessusCli @('agent','unlink','--force')
    foreach ($line in $unlinkOut) { Write-Log ('  ' + $line) }
}

Write-Log ('Linking to ' + $LinkHost + '...')
$hostKey = $env:COMPUTERNAME.ToUpper()
$groups  = $LinkGroups
if ($groups) {
    Write-Log ('Using -LinkGroups override: ' + $groups)
} else {
    $groups = Resolve-AgentGroups $hostKey
    if ($groups) {
        Write-Log ('Resolved groups for ' + $hostKey + ': ' + $groups)
    } else {
        Write-Log ($hostKey + ' matches no prefix rule and has no override.') -Level WARN
        Write-Log 'Linking with NO GROUP means no scan policy, no plugins, no results --' -Level WARN
        Write-Log 'Tenable would keep reporting the old state indefinitely.' -Level WARN
        Write-Log 'Pass -LinkGroups, add a rule/override, or assign the group in Tenable.' -Level WARN
        $script:NoGroup = $true
    }
}
$linkArgs = @('agent', 'link', ('--key=' + $LinkKey), ('--host=' + $LinkHost), '--port=443')
if ($groups) { $linkArgs += ('--groups=' + $groups) }

$linkOut = Invoke-NessusCli $linkArgs
foreach ($line in ($linkOut -split "`n")) { Write-Log ('  ' + $line) }

if ($linkOut -match 'empty response') {
    Write-Log 'Link failed: empty response from controller.' -Level ERROR
    Write-Log ('Likely Zscaler SSL inspection of ' + $LinkHost + ' -- add a bypass and re-run.') -Level ERROR
    Write-Log 'Confirming with a direct probe rather than assuming:' -Level ERROR
    Test-ManagerReachability -TargetHost $LinkHost
    exit 1
}

# v5: the connection never came up at all. This is a DIFFERENT failure from
# 'empty response' above and must not be diagnosed as the same thing:
#   'empty response'          -> the connection DID come up, but the reply was
#                                mangled. Classic TLS-inspection signature.
#   'Connection to ... failed' -> nothing was ever established. The egress path
#                                itself is the suspect (blocked/filtered egress,
#                                a required proxy, or DNS).
# CSPRPC-76 (2026-09-03) hit the second and fell through to the generic "still
# not linked" error, which named no cause and implied a retry might help.
if ($linkOut -match 'Connection to .*failed' -or $linkOut -match 'Failed to connect' -or $linkOut -match 'Could not connect') {
    Write-Log 'Link failed: could not establish a connection to the manager at all.' -Level ERROR
    Write-Log 'This is NOT the "empty response" signature -- that one means the connection' -Level ERROR
    Write-Log 'succeeded and the reply was mangled. Here nothing was established, so the' -Level ERROR
    Write-Log 'egress path is the suspect rather than TLS inspection specifically.' -Level ERROR
    if ($NeverConnected) {
        Write-Log '' -Level ERROR
        Write-Log 'This agent has NEVER connected ("Last connect: Never"). It is not a' -Level ERROR
        Write-Log 'regression -- egress from this host to the manager has never worked, so' -Level ERROR
        Write-Log 'no amount of relinking will fix it. Treat it as a provisioning/network' -Level ERROR
        Write-Log 'gap for this host and hand the evidence below to whoever owns egress.' -Level ERROR
    }
    Write-Log '' -Level ERROR
    Test-ManagerReachability -TargetHost $LinkHost
    exit 1
}

# ------------------------------------------------------------------
# Verify
# ------------------------------------------------------------------
Start-Sleep -Seconds 5
$finalStatus = Invoke-NessusCli @('agent','status')
foreach ($line in ($finalStatus -split "`n")) { Write-Log ('  ' + $line) }

if (($finalStatus -match 'Linked to:\s*\S') -and ($finalStatus -notmatch 'Linked to:\s*None')) {
    Write-Log 'Agent is linked.'
    if ($NoGroup) {
        Write-Log 'ATTENTION: linked with NO GROUP -- it will not scan or report until a' -Level WARN
        Write-Log 'group is assigned. Exiting 2 so this is not recorded as done.' -Level WARN
        exit 2
    }
    if ($FipsWarning) {
        Write-Log 'ATTENTION: a FIPS integrity failure was reported earlier; verify the agent' -Level WARN
        Write-Log 'actually connects before considering this host healthy.' -Level WARN
        exit 2
    }
    Write-Log 'SUCCESS: agent linked and grouped.'
    if ($RebootNeeded) { exit 3010 }
    exit 0
}
Write-Log 'Agent still not linked after repair attempt.' -Level ERROR
# v5: never end on a bare "it did not work". Probe the path so the log carries
# evidence of WHERE it broke, even for a link error this script has no specific
# branch for yet.
Write-Log 'Link error was not one this script recognises specifically. Probing the' -Level ERROR
Write-Log 'path to the manager so the log at least shows where it breaks:' -Level ERROR
Test-ManagerReachability -TargetHost $LinkHost
exit 1
