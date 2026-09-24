# Unit tests for NessusAgent_CleanReinstall.ps1 pre-flight helpers.
# Run: pwsh -NoProfile -File windows/tests/NessusAgent_CleanReinstall.Tests.ps1
#
# Covers CSLT-192 (2026-09-24): the pre-flight refused to start because
# Global\_MSIExecute could be OPENED. The mutex object lives as long as any
# process holds a handle to it, so an idle msiexec service process is enough
# to make an existence check report "install in progress" forever. Ownership
# is the real signal: if the mutex can be acquired, nothing is executing.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path (Split-Path -Parent $here) 'NessusAgent_CleanReinstall.ps1'
$env:NESSUS_CLEANREINSTALL_DOTSOURCE = '1'
. $scriptPath
$failed = 0
function Assert-True {
    param([bool]$Cond, [string]$Name)
    if (-not $Cond) {
        Write-Host "FAIL $Name"
        $script:failed++
    } else {
        Write-Host "OK   $Name"
    }
}

$mutexName = 'cs_msi_test_' + [guid]::NewGuid().ToString('N')

# --- Nothing has created the mutex ------------------------------------------
Assert-True (-not (Test-MsiInProgress -MutexName $mutexName)) 'absent mutex is not an install in progress'

# --- The object exists but no one owns it (the CSLT-192 false positive) -----
$idle = New-Object System.Threading.Mutex($false, $mutexName)
try {
    Assert-True (-not (Test-MsiInProgress -MutexName $mutexName)) 'unowned mutex is not an install in progress'
    Assert-True (Wait-MsiAvailable -TimeoutMinutes 0 -MutexName $mutexName) 'Wait-MsiAvailable returns immediately when free'
} finally {
    $idle.Dispose()
}

# --- Genuinely held by another process --------------------------------------
$holderScript = @'
param($Name)
$m = New-Object System.Threading.Mutex($false, $Name)
[void]$m.WaitOne()
Start-Sleep -Seconds 30
'@
$holderFile = Join-Path ([System.IO.Path]::GetTempPath()) ('holder_' + [guid]::NewGuid().ToString('N') + '.ps1')
Set-Content -Path $holderFile -Value $holderScript -Encoding utf8
$heldName = 'cs_msi_test_' + [guid]::NewGuid().ToString('N')
$holder = Start-Process -FilePath (Get-Process -Id $PID).Path `
    -ArgumentList @('-NoProfile', '-File', $holderFile, $heldName) -PassThru
try {
    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline -and -not (Test-MsiInProgress -MutexName $heldName)) {
        Start-Sleep -Milliseconds 200
    }
    Assert-True (Test-MsiInProgress -MutexName $heldName) 'mutex held by another process IS an install in progress'

    $waitStart = Get-Date
    $freed = Wait-MsiAvailable -TimeoutMinutes 0.05 -PollSeconds 1 -MutexName $heldName
    $waited = ((Get-Date) - $waitStart).TotalSeconds
    Assert-True (-not $freed) 'Wait-MsiAvailable gives up when the installer never finishes'
    Assert-True ($waited -ge 2 -and $waited -lt 30) 'Wait-MsiAvailable honours its timeout instead of blocking'
} finally {
    Stop-Process -Id $holder.Id -Force -ErrorAction SilentlyContinue
    Remove-Item $holderFile -Force -ErrorAction SilentlyContinue
}

# --- The wait clears as soon as the other installer exits -------------------
$freeingName = 'cs_msi_test_' + [guid]::NewGuid().ToString('N')
$freeingFile = Join-Path ([System.IO.Path]::GetTempPath()) ('holder_' + [guid]::NewGuid().ToString('N') + '.ps1')
Set-Content -Path $freeingFile -Value @'
param($Name)
$m = New-Object System.Threading.Mutex($false, $Name)
[void]$m.WaitOne()
Start-Sleep -Seconds 3
$m.ReleaseMutex()
'@ -Encoding utf8
$freeing = Start-Process -FilePath (Get-Process -Id $PID).Path `
    -ArgumentList @('-NoProfile', '-File', $freeingFile, $freeingName) -PassThru
try {
    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline -and -not (Test-MsiInProgress -MutexName $freeingName)) {
        Start-Sleep -Milliseconds 200
    }
    Assert-True (Wait-MsiAvailable -TimeoutMinutes 1 -PollSeconds 1 -MutexName $freeingName) `
        'Wait-MsiAvailable proceeds once the other installer releases the mutex'
} finally {
    Stop-Process -Id $freeing.Id -Force -ErrorAction SilentlyContinue
    Remove-Item $freeingFile -Force -ErrorAction SilentlyContinue
}

if ($failed -gt 0) {
    Write-Host "`n$failed test(s) failed"
    exit 1
}
Write-Host "`nAll tests passed"
exit 0
