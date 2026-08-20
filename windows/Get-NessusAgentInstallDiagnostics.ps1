<#
.SYNOPSIS
    Diagnostic: Nessus Agent MSI Installation Failure (v3)
    Collects everything needed to root-cause a 1603/1612 on a machine where
    the agent install or upgrade fails.

.NOTES
    v3 improvements:
      - Checks BOTH service names (Nessus Agent / Tenable Nessus Agent 11.2+)
      - NEW Section 4: Installer-DB orphan classification (ARP + cached MSI
        cross-check) -- identifies the 1612 orphan state directly
      - Event log query uses FilterHashtable (was ~50s, now ~1s)
      - MSI log search includes C:\Logs\CompoSecure and only greps
        Nessus-related logs (no more Defender MpSigStub noise)
#>

$ErrorActionPreference = 'SilentlyContinue'

$LogDir  = 'C:\Logs\CompoSecure'
$OutFile = Join-Path $LogDir ('NessusAgent_Diag_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $OutFile -Value $line
}
function Write-Section {
    param([string]$Title)
    Write-Log ''
    Write-Log '----------------------------------------------'
    Write-Log (' ' + $Title)
    Write-Log '----------------------------------------------'
}
function Convert-CompressedGuid {
    param([string]$Compressed)
    if ($Compressed.Length -ne 32) { return $null }
    $s = $Compressed.ToUpper()
    $p1 = -join ($s.Substring(0,8).ToCharArray()[7..0])
    $p2 = -join ($s.Substring(8,4).ToCharArray()[3..0])
    $p3 = -join ($s.Substring(12,4).ToCharArray()[3..0])
    $p4 = ''
    foreach ($i in 0..1) { $pair = $s.Substring(16 + $i*2, 2); $p4 += $pair[1] + $pair[0] }
    $p5 = ''
    foreach ($i in 0..5) { $pair = $s.Substring(20 + $i*2, 2); $p5 += $pair[1] + $pair[0] }
    return '{' + $p1 + '-' + $p2 + '-' + $p3 + '-' + $p4 + '-' + $p5 + '}'
}

Write-Log '=============================================='
Write-Log ' Nessus Agent Install Diagnostic (v3)'
Write-Log (' Host : ' + $env:COMPUTERNAME)
Write-Log (' Date : ' + (Get-Date))
Write-Log '=============================================='

# ------------------------------------------------------------------
# 1. Service state (both names)
# ------------------------------------------------------------------
Write-Section '1. Nessus Agent Service State'
$svcs = Get-Service | Where-Object { $_.Name -like '*Nessus Agent*' -or $_.DisplayName -like '*Nessus Agent*' }
if ($svcs) {
    foreach ($svc in $svcs) {
        Write-Log ('Name: ' + $svc.Name + ' | DisplayName: ' + $svc.DisplayName + ' | Status: ' + $svc.Status + ' | StartType: ' + $svc.StartType)
    }
} else {
    Write-Log 'No Nessus Agent service registered (checked both old and new names).' -Level WARN
}

# ------------------------------------------------------------------
# 2. Running processes
# ------------------------------------------------------------------
Write-Section '2. Running Nessus Processes'
$nessusProcs = Get-Process -Name 'nessusagent','nessusd','nessus-service' -ErrorAction SilentlyContinue
if ($nessusProcs) {
    foreach ($p in $nessusProcs) {
        Write-Log ('PID ' + $p.Id + '  Name: ' + $p.Name + '  Path: ' + $p.Path) -Level WARN
    }
    if (-not $svcs) {
        Write-Log 'ORPHANED PROCESSES: running with no service registration.' -Level WARN
        Write-Log 'These hold DB locks and cause file-in-use 1603s. OrphanFix kills them first.' -Level WARN
    }
} else {
    Write-Log 'No Nessus processes currently running.'
}

# ------------------------------------------------------------------
# 3. Installed version (registry + ARP)
# ------------------------------------------------------------------
Write-Section '3. Installed Version (Registry)'
foreach ($rp in @('HKLM:\SOFTWARE\Tenable\Nessus Agent', 'HKLM:\SOFTWARE\WOW6432Node\Tenable\Nessus Agent')) {
    if (Test-Path $rp) {
        $props = Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue
        Write-Log ('Path    : ' + $rp)
        Write-Log ('Version : ' + $props.VERSION)
    }
}
$arpGuids = @()
$arp = Get-ItemProperty `
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' `
    -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like '*Nessus*' }
foreach ($entry in $arp) {
    $arpGuids += $entry.PSChildName.ToUpper()
    Write-Log ('ARP: ' + $entry.DisplayName + ' ' + $entry.DisplayVersion + ' ' + $entry.PSChildName)
}
if (-not $arp) { Write-Log 'No Nessus entries in ARP.' -Level WARN }

# ------------------------------------------------------------------
# 4. Installer-DB orphan classification  ** the 1612 detector **
# ------------------------------------------------------------------
Write-Section '4. Installer Database Orphan Check'
$foundReg = 0
Get-ChildItem 'HKLM:\SOFTWARE\Classes\Installer\Products' -ErrorAction SilentlyContinue | ForEach-Object {
    $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    if ($props.ProductName -notlike '*Nessus*') { return }
    $foundReg++
    $c    = $_.PSChildName
    $guid = Convert-CompressedGuid $c
    $lp   = (Get-ItemProperty ('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\' + $c + '\InstallProperties') -ErrorAction SilentlyContinue).LocalPackage
    $hasArp   = $guid -and ($arpGuids -contains $guid.ToUpper())
    $hasCache = $lp -and (Test-Path $lp)
    Write-Log ('Registration : ' + $props.ProductName + '  ' + $guid)
    Write-Log ('  ARP entry    : ' + $hasArp)
    Write-Log ('  Cached MSI   : ' + $hasCache + '  (' + $lp + ')')
    if ($hasArp -and $hasCache) {
        Write-Log '  VERDICT: HEALTHY -- normal msiexec /x should work once processes are stopped.'
    } else {
        Write-Log '  VERDICT: ORPHANED -- upgrades will fail with 1612/1603 at RemoveExistingProducts.' -Level WARN
        Write-Log '  Remediation: NessusAgent_OrphanFix_Reinstall.ps1' -Level WARN
    }
}
if ($foundReg -eq 0) { Write-Log 'No Nessus registrations in the Installer database.' }

# ------------------------------------------------------------------
# 5. MSI logs (incl. C:\Logs\CompoSecure), Nessus-related only
# ------------------------------------------------------------------
Write-Section '5. Nessus MSI Logs + Fatal Error Excerpts'
$logDirs = @($env:TEMP, ($env:SystemRoot + '\Temp'), 'C:\Windows\Temp', 'C:\Logs\CompoSecure')
$seen = @{}
foreach ($dir in $logDirs) {
    $logs = Get-ChildItem -Path $dir -Filter '*.log' -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match 'nessus|msi_nessus' } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 5
    foreach ($l in $logs) {
        if ($seen.ContainsKey($l.FullName)) { continue }
        $seen[$l.FullName] = $true
        Write-Log ('Log: ' + $l.FullName + '  (' + [math]::Round($l.Length/1KB,1) + ' KB, ' + $l.LastWriteTime + ')')
        $hits = Select-String -Path $l.FullName -Pattern 'Return value 3','value 1603','error code 16','1714','RemoveExistingProducts' -ErrorAction SilentlyContinue |
                Select-Object -Last 10
        foreach ($h in $hits) { Write-Log ('  ' + $h.Line.Trim()) }
    }
}
if ($seen.Count -eq 0) { Write-Log 'No Nessus-related MSI logs found in temp dirs or C:\Logs\CompoSecure.' }

# ------------------------------------------------------------------
# 6. MsiInstaller event log (fast filtered query)
# ------------------------------------------------------------------
Write-Section '6. Windows Installer Event Log (last 20 warnings/errors)'
$msiEvents = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'MsiInstaller'; Level = 2,3 } -MaxEvents 20 -ErrorAction SilentlyContinue
foreach ($evt in $msiEvents) {
    Write-Log ('[' + $evt.TimeCreated + '] ID ' + $evt.Id + ' -- ' + ($evt.Message -replace '\s+', ' '))
}
if (-not $msiEvents) { Write-Log 'No recent MsiInstaller warnings/errors.' }

# ------------------------------------------------------------------
# 7. Pending file renames
# ------------------------------------------------------------------
Write-Section '7. Pending File Rename Operations'
$pfro = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
if ($pfro) {
    $nr = $pfro | Where-Object { $_ -like '*Nessus*' -or $_ -like '*Tenable*' }
    if ($nr) {
        Write-Log 'Nessus/Tenable pending renames found -- reboot before install:' -Level WARN
        $nr | ForEach-Object { Write-Log ('  ' + $_) -Level WARN }
    } else { Write-Log 'No Nessus/Tenable entries in PendingFileRenameOperations.' }
} else { Write-Log 'No pending file rename operations.' }

# ------------------------------------------------------------------
# 8. Data directory lock check
# ------------------------------------------------------------------
Write-Section '8. Nessus Data Directory'
$dataDir = 'C:\ProgramData\Tenable\Nessus Agent'
if (Test-Path $dataDir) {
    $dbFiles = Get-ChildItem -Path $dataDir -Recurse -Filter '*.db' -ErrorAction SilentlyContinue
    Write-Log ('Database files found: ' + $dbFiles.Count)
    $lockedCount = 0
    foreach ($db in $dbFiles) {
        try {
            $fs = [System.IO.File]::Open($db.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            $fs.Close(); $fs.Dispose()
            Write-Log ('  [UNLOCKED] ' + $db.FullName)
        } catch {
            $lockedCount++
            Write-Log ('  [LOCKED]   ' + $db.FullName) -Level WARN
        }
    }
    if ($lockedCount -gt 0 -and $nessusProcs) {
        Write-Log ('Locks are held by the running Nessus PIDs listed in Section 2.') -Level WARN
    }
} else {
    Write-Log ('Data directory not found: ' + $dataDir)
}

Write-Log ''
Write-Log '=============================================='
Write-Log ' Diagnostic complete.'
Write-Log (' Review output at: ' + $OutFile)
Write-Log '=============================================='
Write-Host ('Full diagnostic saved to: ' + $OutFile)
