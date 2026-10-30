# Unit tests for Update-OracleJava8.ps1 version helpers.
# Run: pwsh -NoProfile -File windows/tests/Update-OracleJava8.Tests.ps1
#
# Covers plugin 371349 (CVE-2026-91403 Security Alert, 2026-10-30): the fix is
# the 8u511 b32 BPR, which installs into the same jre1.8.0_511 folder as the
# vulnerable 8u511 GA build, so the folder name alone cannot tell them apart.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path (Split-Path -Parent $here) 'Update-OracleJava8.ps1'
$env:ORACLEJAVA8_DOTSOURCE = '1'
. $scriptPath
$failed = 0
function Assert-Eq {
    param($Actual, $Expected, [string]$Name)
    if ("$Actual" -ne "$Expected") {
        Write-Host "FAIL $Name : got '$Actual' expected '$Expected'"
        $script:failed++
    } else {
        Write-Host "OK   $Name"
    }
}
function Assert-True {
    param([bool]$Cond, [string]$Name)
    if (-not $Cond) { Write-Host "FAIL $Name"; $script:failed++ } else { Write-Host "OK   $Name" }
}
function Fmt { param($v) if ($null -eq $v) { return 'null' } return ('' + $v.Update + 'b' + $v.Build) }

# --- Version parsing ---------------------------------------------------------
Assert-Eq (Fmt (ConvertTo-JavaVersion -Text '8.0.5030.1')) '503b1' 'java.exe FileVersion 8.0.5030.1 is 8u503 b1'
Assert-Eq (Fmt (ConvertTo-JavaVersion -Text '8.0.5110.32')) '511b32' 'BPR FileVersion 8.0.5110.32 is 8u511 b32'
Assert-Eq (Fmt (ConvertTo-JavaVersion -Text '8.0.501.8')) '501b8' 'Tenable-style 8.0.501.8 is 8u501 b8'
Assert-Eq (Fmt (ConvertTo-JavaVersion -Text '8.0.4910.10 (build 1.8.0_491-b10)')) '491b10' 'trailing text ignored'
Assert-Eq (Fmt (ConvertTo-JavaVersion -Text '')) 'null' 'empty version is unknown'
Assert-Eq (Fmt (ConvertTo-JavaVersion -Text '21.0.13.0')) 'null' 'non-8 major is not a Java 8 version'

# --- Target comparison -------------------------------------------------------
$t = { param($u, $b) Test-JavaAtTarget -Version ([pscustomobject]@{ Update = $u; Build = $b }) -TargetUpdate 511 -TargetBuild 32 }
Assert-True (-not (& $t 503 1)) '8u503 is vulnerable'
Assert-True (-not (& $t 511 7)) '8u511 GA (b7) is vulnerable'
Assert-True (& $t 511 32) '8u511 b32 BPR is fixed'
Assert-True (& $t 521 1) 'a later update is fixed'
Assert-True (-not (& $t 511 $null)) '8u511 with unknown build is treated as vulnerable'
Assert-True (-not (Test-JavaAtTarget -Version $null -TargetUpdate 511 -TargetBuild 32)) 'unknown version is vulnerable'

# --- Inventory ---------------------------------------------------------------
# java.exe on Linux has no version resource, so the reader is mocked.
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('jre8_' + [guid]::NewGuid().ToString('N'))
try {
    $root = Join-Path $tmp 'Java'
    foreach ($n in @('jre1.8.0_503', 'jre1.8.0_511', 'jdk-17', 'jre1.8.0_491')) {
        New-Item -ItemType Directory -Force -Path (Join-Path $root $n) | Out-Null
    }
    $fileVersions = @{ 'jre1.8.0_503' = '8.0.5030.1'; 'jre1.8.0_511' = '8.0.5110.7' }
    function Get-JavaExeVersion { param([string]$JreDir) return $fileVersions[(Split-Path -Leaf $JreDir)] }

    $inv = @(Get-JreInventory -Root $root | Sort-Object Name)
    Assert-Eq $inv.Count 3 'only jre1.8.0_* folders are inventoried'
    Assert-Eq (($inv | ForEach-Object { $_.Name + '=' + (Fmt $_) }) -join ',') 'jre1.8.0_491=491b,jre1.8.0_503=503b1,jre1.8.0_511=511b7' `
        'versions come from java.exe, folder name only when java.exe is unreadable'
    Assert-Eq (($inv | Where-Object { -not (Test-JavaAtTarget -Version $_ -TargetUpdate 511 -TargetBuild 32) }).Count) 3 `
        'all three, including the 8u511 GA folder, are vulnerable'
    Assert-Eq @(Get-JreInventory -Root (Join-Path $tmp 'missing')).Count 0 'missing root yields nothing'
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failed -gt 0) {
    Write-Host "`n$failed test(s) failed"
    exit 1
}
Write-Host "`nAll tests passed"
exit 0
