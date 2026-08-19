<#
.SYNOPSIS
    Nessus Agent link repair (v3). Checks the agent's actual state and only
    fixes what is broken -- healthy linked agents are left untouched.

.DESCRIPTION
    Decision flow:
      Agent installed?
        NO  -> install agent via Tenable bootstrap script (-type agent --
               the v1 script said 'scanner', which installs the wrong product)
        YES -> ensure service is running (either service name)
               -> already linked to the right host? exit 0, touch nothing
               -> not linked / wrong host? link (unlink first only if needed)

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

.NOTES
    Deploy via Endpoint Central (SYSTEM). Exit: 0 ok / 1 failure.
    Zscaler: 'empty response from controller' on link = SSL inspection of
    sensor.cloud.tenable.com; add a bypass and re-run.
#>

[CmdletBinding()]
param(
    [string]$LinkKey    = '4f858e2b28a33a5927c7805eab8b8533ecb35c983417b392c5b570b5a6a96fba',
    [string]$LinkHost   = 'sensor.cloud.tenable.com',
    [string]$LinkGroups = '',
    [switch]$ForceRelink
)

$ErrorActionPreference = 'Stop'
$NoGroup     = $false
$FipsWarning = $false
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

Write-Log '=== Nessus Agent Repair (v3) ==='
Write-Log ('Host: ' + $env:COMPUTERNAME)

# ------------------------------------------------------------------
# Branch 1: agent not installed -> install it (as an AGENT, not scanner)
# ------------------------------------------------------------------
if (-not (Test-Path $Cli)) {
    Write-Log 'Agent not installed. Installing via Tenable bootstrap...' -Level WARN
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $bootstrap = Join-Path $env:TEMP 'ms-install-script.ps1'
    try {
        Invoke-WebRequest -Uri 'https://sensor.cloud.tenable.com/install/agent/installer/ms-install-script.ps1' -OutFile $bootstrap -UseBasicParsing
    } catch {
        Write-Log ('Bootstrap download failed: ' + $_) -Level ERROR
        Write-Log 'If Zscaler blocks this, stage the agent MSI and use the CleanReinstall script instead.' -Level ERROR
        exit 1
    }
    # Sanity: should be a PowerShell script, not an HTML block page
    $head = (Get-Content $bootstrap -TotalCount 5) -join ' '
    if ($head -match '<html|<!DOCTYPE') {
        Write-Log 'Downloaded file is an HTML block page, not the install script. Aborting.' -Level ERROR
        Remove-Item $bootstrap -Force -ErrorAction SilentlyContinue
        exit 1
    }
    try {
        & $bootstrap -key $LinkKey -type 'agent'
    } finally {
        Remove-Item $bootstrap -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 10
    if (-not (Test-Path $Cli)) {
        Write-Log 'Install did not produce nessuscli.exe. Aborting.' -Level ERROR
        exit 1
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
    exit 0
}
Write-Log 'Agent still not linked after repair attempt.' -Level ERROR
exit 1
