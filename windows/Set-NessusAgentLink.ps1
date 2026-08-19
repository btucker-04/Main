<#
.SYNOPSIS
    Relink Nessus Agent with per-host group preservation (Windows).
    Regenerated from the full Tenable agents export 2026-08-04: 496 Windows
    hosts across all groups (was 178 from the 07-13 snapshot).

.DESCRIPTION
    Looks up this machine's Tenable agent group membership in an embedded
    map and relinks with EXACTLY those groups -- because 'nessuscli agent
    link --groups' REPLACES membership, a relink without the full list
    silently drops machines from overlapping groups (Critical Assets,
    Ad Hoc groups, etc.).

    Hosts not in the map are relinked with -FallbackGroups if provided,
    otherwise the script exits without touching the link (exit 2).

.NOTES
    Deploy via Endpoint Central (SYSTEM). Exit: 0 ok / 1 failure / 2 skipped.
    Regenerate the map when group memberships change.
#>

[CmdletBinding()]
param(
    [string]$LinkKey        = '4f858e2b28a33a5927c7805eab8b8533ecb35c983417b392c5b570b5a6a96fba',
    [string]$LinkHost       = 'sensor.cloud.tenable.com',
    [string]$FallbackGroups = ''
)

$ErrorActionPreference = 'Stop'
$LogDir  = 'C:\Logs\CompoSecure'
$LogFile = Join-Path $LogDir ('NessusRelink_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

# ==============================================================
# Tenable agent-group resolution -- PREFIX RULES + EXACT OVERRIDES
# Derived from the cleaned agents export 2026-08-04 (593 hosts).
# Verified: 592/593 hosts resolve exactly; the only unresolved host is
# SYS76-01, which genuinely has no group in Tenable and must be
# assigned one by a human.
#
# Why prefix rules instead of a per-host map: a 496-line hostname map
# went stale the moment a machine was imaged, and any host missing from
# it linked with NO GROUP -- which means no scan policy, no plugins, no
# results, and a finding that never clears (cost us CSLT-173/-178/-205/
# -210 and CSPC-079). Prefix rules cover new machines automatically.
#
# MAINTENANCE: add a prefix rule when a new naming convention appears;
# add an override only when a single host legitimately differs from its
# prefix. Note 'nessuscli agent link --groups' REPLACES membership, so
# multi-group hosts must list every group.
# ==============================================================

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
$HostKey = $env:COMPUTERNAME.ToUpper()

Write-Log '=== Nessus Agent Relink (group-preserving) ==='
Write-Log ('Host: ' + $HostKey)

if (-not (Test-Path $Cli)) {
    Write-Log 'nessuscli.exe not found -- agent not installed. Use CleanReinstall instead.' -Level ERROR
    exit 1
}

$svc = Get-Service | Where-Object { $_.Name -like '*Nessus Agent*' } | Select-Object -First 1
if (-not $svc) { Write-Log 'No agent service registered -- broken install; use CleanReinstall.' -Level ERROR; exit 1 }
if ($svc.Status -ne 'Running') { Start-Service $svc.Name -ErrorAction SilentlyContinue; Start-Sleep -Seconds 5 }

$groups = Resolve-AgentGroups $HostKey
if (-not $groups) {
    if ($FallbackGroups) {
        $groups = $FallbackGroups
        Write-Log ('Host not in map -- using fallback groups: ' + $groups) -Level WARN
    } else {
        Write-Log 'Host not in the group map and no -FallbackGroups given. Skipping relink' -Level WARN
        Write-Log 'to avoid wiping unknown group membership. Exit 2.' -Level WARN
        exit 2
    }
} else {
    Write-Log ('Mapped groups: ' + $groups)
}

$statusOut = (& $Cli agent status 2>&1) -join "`n"
if ($statusOut -notmatch 'Linked to:\s*None') {
    Write-Log 'Unlinking existing state...'
    & $Cli agent unlink --force 2>&1 | ForEach-Object { Write-Log ('  ' + $_) }
}

Write-Log ('Linking to ' + $LinkHost + ' with groups [' + $groups + ']...')
$linkOut = (& $Cli agent link ('--key=' + $LinkKey) ('--host=' + $LinkHost) '--port=443' ('--groups=' + $groups) 2>&1) -join "`n"
foreach ($line in ($linkOut -split "`n")) { Write-Log ('  ' + $line) }

if ($linkOut -match 'empty response') {
    Write-Log ('Link failed: empty response -- Zscaler SSL inspection of ' + $LinkHost + '?') -Level ERROR
    exit 1
}

Start-Sleep -Seconds 5
$final = (& $Cli agent status 2>&1) -join "`n"
foreach ($line in ($final -split "`n")) { Write-Log ('  ' + $line) }
if (($final -match 'Linked to:\s*\S') -and ($final -notmatch 'Linked to:\s*None')) {
    Write-Log 'SUCCESS: relinked.'
    exit 0
}
Write-Log 'Still not linked after relink attempt.' -Level ERROR
exit 1
