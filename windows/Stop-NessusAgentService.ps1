<#
.SYNOPSIS
    Pre-install: Stop Nessus Agent service before MSI upgrade
    Deploy via Endpoint Central as a pre-install script on the
    Nessus Agent software deployment task.

.DESCRIPTION
    Endpoint Central's MSI installer cannot replace Nessus Agent
    files while the service is running. This script gracefully
    stops the service and waits for full termination before EC
    executes the upgrade package.
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'

$LogDir  = 'C:\Logs\CompoSecure'
$LogFile = Join-Path $LogDir ("NessusAgent_PreInstall_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

function Write-Log {
    param(
        [string]$Msg,
        [ValidateSet('INFO','WARN','ERROR','OK')]
        [string]$Level = 'INFO'
    )
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

# Nessus Agent service name as registered in Windows
$ServiceName    = 'Nessus Agent'
$StopTimeoutSec = 60

# ==============================================================
# Setup
# ==============================================================
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

Write-Log "=============================================="
Write-Log " Nessus Agent Pre-Install — Service Stop"
Write-Log " Host : $env:COMPUTERNAME"
Write-Log " Date : $(Get-Date)"
Write-Log "=============================================="

# ==============================================================
# Check service exists
# ==============================================================
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

if (-not $svc) {
    Write-Log "Service '$ServiceName' not found on this machine." -Level WARN
    Write-Log "Nothing to stop — EC will proceed with a fresh install." -Level WARN
    exit 0
}

Write-Log "Service found  : $($svc.DisplayName)"
Write-Log "Current status : $($svc.Status)"

# ==============================================================
# Stop the service if running
# ==============================================================
if ($svc.Status -eq 'Stopped') {
    Write-Log "Service is already stopped. Nothing to do." -Level OK
    exit 0
}

Write-Log "Sending stop signal to '$ServiceName'..."

try {
    Stop-Service -Name $ServiceName -Force -ErrorAction Stop
} catch {
    Write-Log "Stop-Service call failed: $_" -Level ERROR
    # Don't exit yet — the service may still wind down. Fall through to the wait loop.
}

# ==============================================================
# Wait for the service to fully reach Stopped state
# ==============================================================
$elapsed = 0
$interval = 3

Write-Log "Waiting for service to reach Stopped state (timeout: ${StopTimeoutSec}s)..."

while ($elapsed -lt $StopTimeoutSec) {
    Start-Sleep -Seconds $interval
    $elapsed += $interval

    $svc.Refresh()

    if ($svc.Status -eq 'Stopped') {
        Write-Log "Service stopped successfully after ${elapsed}s." -Level OK
        exit 0
    }

    Write-Log "  ...still $($svc.Status) (${elapsed}s elapsed)"
}

# ==============================================================
# Timeout — try a hard kill via the PID before giving up
# ==============================================================
Write-Log "Service did not stop within ${StopTimeoutSec}s. Attempting process kill..." -Level WARN

try {
    $proc = Get-WmiObject Win32_Service -Filter "Name='$ServiceName'" |
            Select-Object -ExpandProperty ProcessId

    if ($proc -and $proc -gt 0) {
        Write-Log "Killing PID $proc..."
        Stop-Process -Id $proc -Force -ErrorAction Stop
        Start-Sleep -Seconds 3
        $svc.Refresh()

        if ($svc.Status -eq 'Stopped') {
            Write-Log "Process killed. Service now stopped." -Level OK
            exit 0
        }
    }
} catch {
    Write-Log "Process kill attempt failed: $_" -Level ERROR
}

# If we reach here the service is still running — fail so EC doesn't
# proceed with the MSI and leave the agent in a broken state.
Write-Log "Could not stop '$ServiceName' within timeout. Aborting upgrade." -Level ERROR
Write-Log "Check for held locks or a hung NessusAgent.exe process manually." -Level ERROR
exit 1
