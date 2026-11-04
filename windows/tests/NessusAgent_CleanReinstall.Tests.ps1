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

# --- CSPRPC-76 (2026-11-04): installed fine, link never connected ------------
$csprpc76Link = '[error] [agent] Link fail: Connection to sensor.cloud.tenable.com:443 failed.'
$csprpc76Status = @'
Running: Yes
Linked to: None
Link status: Not linked to a manager
Proxy: None
Last connect: Never
Last connection attempt: Never
'@
Assert-True ((Get-LinkFailureKind $csprpc76Link) -eq 'NoConnection') 'CSPRPC-76 link error is a connection failure'
Assert-True (-not (Test-AgentLinked $csprpc76Status)) 'CSPRPC-76 status is NOT linked'
Assert-True ((Get-LinkFailureKind 'Link fail: empty response from controller') -eq 'EmptyResponse') 'empty response is its own signature'
Assert-True ((Get-LinkFailureKind '[error] [agent] Link fail: [409] Agent with different token already exists') -eq 'DuplicateIdentity') '409 is duplicate identity, not network'
Assert-True ((Get-LinkFailureKind '[info] [agent] Successfully linked to sensor.cloud.tenable.com:443') -eq 'None') 'successful link output is not a failure'
Assert-True ((Get-LinkFailureKind '') -eq 'None') 'empty link output is not a failure'
Assert-True (Test-AgentLinked "Running: Yes`nLinked to: sensor.cloud.tenable.com:443`nLink status: Connected") 'linked status is linked'
Assert-True (-not (Test-AgentLinked '')) 'no status output is not linked'

$v = Get-LinkVerdict -FailureKind 'NoConnection' -Probe 'TcpTimeout' -TargetHost 'sensor.cloud.tenable.com'
Assert-True ($v -match 'silently dropped' -and $v -match 'relinking cannot fix') 'TCP timeout verdict names egress, not the agent'
$v = Get-LinkVerdict -FailureKind 'NoConnection' -Probe 'Intercepted' -TargetHost 'sensor.cloud.tenable.com'
Assert-True ($v -match 'bypass') 'intercepted TLS verdict asks for an inspection bypass'
$v = Get-LinkVerdict -FailureKind 'DuplicateIdentity' -Probe '' -TargetHost 'sensor.cloud.tenable.com'
Assert-True ($v -match '409' -and $v -match 'ResetTenableTag') '409 verdict points at the duplicate record'
$v = Get-LinkVerdict -FailureKind 'NoConnection' -Probe 'Ok' -TargetHost 'sensor.cloud.tenable.com'
Assert-True ($v -match 'probes clean NOW') 'clean probe verdict says the path works now'
$v = Get-LinkVerdict -FailureKind 'NoConnection' -Probe 'DNS' -TargetHost 'sensor.cloud.tenable.com'
Assert-True ($v -match 'DNS') 'DNS verdict names DNS'

# Probe against a local port nothing listens on: must report a TCP failure, not throw.
$listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
$listener.Start(); $freePort = $listener.LocalEndpoint.Port; $listener.Stop()
$probe = Test-ManagerReachability -TargetHost '127.0.0.1' -Port $freePort -TimeoutMs 3000
Assert-True ($probe -eq 'TcpRefused' -or $probe -eq 'TcpTimeout') ('closed port probes as a TCP failure (got ' + $probe + ')')
$probe = Test-ManagerReachability -TargetHost 'no-such-host.invalid' -TimeoutMs 3000
Assert-True ($probe -eq 'DNS') ('unresolvable host probes as DNS (got ' + $probe + ')')

if ($failed -gt 0) {
    Write-Host "`n$failed test(s) failed"
    exit 1
}
Write-Host "`nAll tests passed"
exit 0
