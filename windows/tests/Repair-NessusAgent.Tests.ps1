# Unit tests for Repair-NessusAgent.ps1 link-error classification.
# Run: pwsh -NoProfile -File windows/tests/Repair-NessusAgent.Tests.ps1
#
# Covers CSPRLT-124 (2026-09-24): link failed with HTTP 409 "another agent in
# container ... with different token already exists", then v5 fell through to
# the generic "not one this script recognises" path and probed DNS/TCP/TLS.
# The probe succeeded (Cloudflare IPs, Google Trust Services cert), which
# looks like a network diagnosis. 409 is a duplicate host-identity rejection
# and has nothing to do with the path to the manager.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path (Split-Path -Parent $here) 'Repair-NessusAgent.ps1'
$env:NESSUS_REPAIR_DOTSOURCE = '1'
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

# Verbatim line from the CSPRLT-124 log.
$csprlt124 = '[error] [agent] Link fail: [409] Agent with uuid agentUuid=5a27d89a-0677-4587-9ff8-39544f0d5875 attempt to link, but another agent in container containerUuid=e681ad28-ac2b-4041-98e0-6c59a6382fbb with different token already exists.. Request UUID: 808c3a8c62882d999da52a29d12024bb'

Assert-True (Test-LinkDuplicateIdentity -Text $csprlt124) 'CSPRLT-124 409 is recognised as duplicate identity'
Assert-True (Test-LinkDuplicateIdentity -Text 'with different token already exists') 'token-collision wording without [409] still matches'
Assert-True (-not (Test-LinkDuplicateIdentity -Text 'Link fail: empty response from controller')) 'empty-response is not a 409'
Assert-True (-not (Test-LinkDuplicateIdentity -Text 'Link fail: Connection to sensor.cloud.tenable.com:443 failed.')) 'connect-failed is not a 409'
Assert-True (-not (Test-LinkDuplicateIdentity -Text '')) 'empty output is not a 409'
Assert-True (-not (Test-LinkDuplicateIdentity -Text $null)) 'null output is not a 409'

if ($failed -gt 0) {
    Write-Host "`n$failed test(s) failed"
    exit 1
}
Write-Host "`nAll tests passed"
exit 0
