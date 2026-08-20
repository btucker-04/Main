<#
.SYNOPSIS
    Dumps the tail of the most recent Visual Studio installer logs so the
    real cause of a failed VS update can be seen (network/proxy vs pending
    reboot vs lock). Read-only.

.NOTES
    Run: powershell -ExecutionPolicy Bypass -File .\Get-VSInstallerLogs.ps1
    Also writes a copy to C:\Logs\CompoSecure for collection.
#>

$LogDir = 'C:\Logs\CompoSecure'
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$outFile = Join-Path $LogDir ('VSInstallerLogs_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.txt')

function Emit { param([string]$s); Write-Host $s; Add-Content -Path $outFile -Value $s }

Emit ('=== VS installer log capture -- ' + $env:COMPUTERNAME + ' -- ' + (Get-Date) + ' ===')

# VS setup logs land in %TEMP% as dd_*.log (bootstrapper, installer, setup).
# When run as SYSTEM via EC, TEMP is under C:\Windows\Temp; interactively it is
# the user's temp. Search both plus common locations.
$dirs = @(
    $env:TEMP,
    'C:\Windows\Temp',
    ('C:\Users\' + $env:USERNAME + '\AppData\Local\Temp')
) | Sort-Object -Unique

$logs = @()
foreach ($d in $dirs) {
    if (Test-Path $d) {
        $logs += Get-ChildItem -Path $d -Filter 'dd_*.log' -ErrorAction SilentlyContinue
    }
}

if (-not $logs) {
    Emit 'No dd_*.log files found in TEMP locations.'
    Emit 'Checked:'
    foreach ($d in $dirs) { Emit ('  ' + $d) }
    Emit ''
    Emit 'If the update ran as SYSTEM via EC, also check C:\Windows\Temp specifically,'
    Emit 'and %ProgramData%\Microsoft\VisualStudio\Packages\_Instances for instance state.'
    Add-Content -Path $outFile -Value ''
    Write-Host ('Saved: ' + $outFile)
    exit 0
}

$recent = $logs | Sort-Object LastWriteTime -Descending | Select-Object -First 5
foreach ($l in $recent) {
    Emit ''
    Emit ('========== ' + $l.FullName + '  (' + $l.LastWriteTime + ', ' + [math]::Round($l.Length/1KB,1) + ' KB) ==========')
    $tail = Get-Content $l.FullName -Tail 40 -ErrorAction SilentlyContinue
    foreach ($line in $tail) { Emit ('  ' + $line) }
}

# Also surface any obvious error/failure lines across all recent logs
Emit ''
Emit '========== Error/failure lines across recent logs =========='
foreach ($l in $recent) {
    $hits = Select-String -Path $l.FullName -Pattern 'error|fail|denied|forbidden|proxy|timeout|0 bytes|reboot|1618|5007|cannot|unable' -ErrorAction SilentlyContinue |
            Select-Object -Last 8
    foreach ($h in $hits) { Emit ('  [' + $l.Name + '] ' + $h.Line.Trim()) }
}

Emit ''
Write-Host ('Saved: ' + $outFile)
