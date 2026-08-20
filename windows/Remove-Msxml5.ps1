<#
.SYNOPSIS
    Remediation: MS13-002 MSXML5 (Nessus Plugin 63420)
    Removes the orphaned, EOL Msxml5.dll from the Office11 Common Files path.

.DESCRIPTION
    Msxml5.dll under Common Files\Microsoft Shared\Office11 shipped with
    Office 2003 / Word Viewer / Office Compatibility Pack. The MS13-002 fix
    (KB2760574) only applies when Office 2003 SP3 is installed -- which it
    will not be on a modern endpoint. MSXML5 is EOL; the correct remediation
    for a leftover DLL is removal, not patching.

    Safety:
      - Scans ARP for any product that might still use MSXML5
        (Office 2003 / 11.0, Word Viewer, Office Compatibility Pack).
        If found, the script STOPS and reports instead of removing.
      - Unregisters the DLL, then MOVES it (plus msxml5r.dll) to a
        quarantine folder for 30-day rollback rather than deleting.
      - -WhatIf supported.

.NOTES
    Deploy via Endpoint Central (SYSTEM). EC-safe concatenated strings.
    Exit codes: 0 = success/nothing to do, 2 = blocked by legacy product, 1 = failure
#>

[CmdletBinding(SupportsShouldProcess)]
param()

$ErrorActionPreference = 'Stop'

$LogDir     = 'C:\Logs\CompoSecure'
$LogFile    = Join-Path $LogDir ('MSXML5_Remediation_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')
$Quarantine = Join-Path $LogDir 'Quarantine\MSXML5'

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

Write-Log '=============================================='
Write-Log ' MSXML5 Removal -- Plugin 63420 / MS13-002'
Write-Log (' Host   : ' + $env:COMPUTERNAME)
Write-Log (' WhatIf : ' + $WhatIfPreference)
Write-Log '=============================================='

# ------------------------------------------------------------------
# 1. Locate Msxml5.dll in both possible Common Files locations
# ------------------------------------------------------------------
Write-Log '[1/4] Locating MSXML5 files...'

$candidates = @(
    'C:\Program Files (x86)\Common Files\Microsoft Shared\Office11\Msxml5.dll',
    'C:\Program Files (x86)\Common Files\Microsoft Shared\Office11\msxml5r.dll',
    'C:\Program Files\Common Files\Microsoft Shared\Office11\Msxml5.dll',
    'C:\Program Files\Common Files\Microsoft Shared\Office11\msxml5r.dll'
)

$found = @()
foreach ($f in $candidates) {
    if (Test-Path $f) {
        $ver = (Get-Item $f).VersionInfo.FileVersion
        Write-Log ('  Found: ' + $f + '  (version ' + $ver + ')')
        $found += $f
    }
}

if ($found.Count -eq 0) {
    Write-Log '  No MSXML5 files present. Nothing to remediate.'
    exit 0
}

# ------------------------------------------------------------------
# 2. Guard: is anything installed that still legitimately uses MSXML5?
# ------------------------------------------------------------------
Write-Log '[2/4] Checking for legacy products that may depend on MSXML5...'

$legacy = Get-ItemProperty `
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' `
    -ErrorAction SilentlyContinue |
    Where-Object {
        $_.DisplayName -like '*Office 2003*' -or
        $_.DisplayName -like '*Office Compatibility Pack*' -or
        $_.DisplayName -like '*Word Viewer*' -or
        $_.DisplayName -like '*Excel Viewer*' -or
        ($_.DisplayName -like '*Microsoft Office*' -and $_.DisplayVersion -like '11.*')
    }

if ($legacy) {
    Write-Log '  BLOCKED: legacy product(s) still installed that may use MSXML5:' -Level WARN
    foreach ($l in $legacy) {
        Write-Log ('    ' + $l.DisplayName + ' ' + $l.DisplayVersion) -Level WARN
    }
    Write-Log '  Not removing the DLL. Either uninstall the legacy product first,' -Level WARN
    Write-Log '  or apply KB2760574 from the Microsoft Update Catalog to patch in place.' -Level WARN
    exit 2
}
Write-Log '  No Office 2003-era products found. DLL is orphaned -- safe to remove.'

# ------------------------------------------------------------------
# 3. Unregister and quarantine
# ------------------------------------------------------------------
Write-Log '[3/4] Unregistering and quarantining MSXML5 files...'

if (-not (Test-Path $Quarantine)) { New-Item -ItemType Directory -Path $Quarantine -Force | Out-Null }

$moved = 0
foreach ($f in $found) {
    if ($PSCmdlet.ShouldProcess($f, 'Unregister and quarantine')) {
        # Unregister (only msxml5.dll is registered; msxml5r.dll is a resource DLL)
        if ($f -like '*Msxml5.dll') {
            $r = Start-Process regsvr32.exe -ArgumentList ('/u /s "' + $f + '"') -Wait -PassThru
            Write-Log ('  regsvr32 /u exit ' + $r.ExitCode + ' for ' + $f)
        }

        # Move to quarantine with a name encoding the original path
        $safeName = ($f -replace '[:\\]', '_')
        $dest = Join-Path $Quarantine $safeName
        Move-Item -Path $f -Destination $dest -Force
        Write-Log ('  Quarantined: ' + $f)
        Write-Log ('           -> ' + $dest)
        $moved++
    } else {
        Write-Log ('  [WHATIF] Would unregister and quarantine: ' + $f)
    }
}

# ------------------------------------------------------------------
# 4. Verify + rollback instructions
# ------------------------------------------------------------------
Write-Log '[4/4] Verifying...'
$remaining = @()
foreach ($f in $found) { if (Test-Path $f) { $remaining += $f } }

if ($WhatIfPreference) {
    Write-Log '  [WHATIF] No changes made.'
    exit 0
}

if ($remaining.Count -gt 0) {
    foreach ($r in $remaining) { Write-Log ('  STILL PRESENT: ' + $r) -Level ERROR }
    Write-Log '  Removal incomplete -- file may be locked. Investigate.' -Level ERROR
    exit 1
}

Write-Log ('  All MSXML5 files removed (' + $moved + ' quarantined).')
Write-Log ''
Write-Log ('  Rollback: move files back from ' + $Quarantine + ' and regsvr32 Msxml5.dll.')
Write-Log '  If nothing breaks within 30 days, delete the quarantine folder.'
Write-Log '  Re-run a Nessus scan to confirm plugin 63420 clears.'
Write-Log '=============================================='
exit 0
