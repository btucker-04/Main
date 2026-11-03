# Unit tests for Update-OracleJava8.ps1 version helpers.
# Run: pwsh -NoProfile -File windows/tests/Update-OracleJava8.Tests.ps1
#
# Covers plugins 371349 (CVE-2026-91403, fixed in 8u511 b32) and 372933
# (CVE-2026-114820, fixed in 8u511 b33). Every 8u511 build installs into the
# same jre1.8.0_511 folder, so the folder name alone cannot tell them apart.
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
$t = { param($u, $b) Test-JavaAtTarget -Version ([pscustomobject]@{ Update = $u; Build = $b }) -TargetUpdate 511 -TargetBuild 33 }
Assert-True (-not (& $t 503 1)) '8u503 is vulnerable'
Assert-True (-not (& $t 511 7)) '8u511 GA (b7) is vulnerable'
Assert-True (-not (& $t 511 32)) '8u511 b32 is vulnerable to CVE-2026-114820 (plugin 372933)'
Assert-True (& $t 511 33) 'CSLT-136: 8u511 b33 is the fix; it is not downgraded'
Assert-True (& $t 511 40) 'a later 8u511 build is fixed'
Assert-True (& $t 521 1) 'a later update is fixed'
Assert-True (-not (& $t 511 $null)) '8u511 with unknown build is treated as vulnerable'
Assert-True (-not (Test-JavaAtTarget -Version $null -TargetUpdate 511 -TargetBuild 33)) 'unknown version is vulnerable'
Assert-Eq (Fmt (ConvertTo-JavaVersion -Text '8.0.511.33')) '511b33' 'Tenable output 8.0.511.33 (CSLT-136) is 8u511 b33'

# --- Same-update replacement ---------------------------------------------------
$n = { param($u, $b) Test-NeedsSameUpdateRemoval -Version ([pscustomobject]@{ Update = $u; Build = $b }) -TargetUpdate 511 -TargetBuild 33 }
Assert-True (-not (& $n 511 33)) 'CSLT-136: 8u511 b33 is left alone'
Assert-True (& $n 511 32) '8u511 b32 must be uninstalled before b33 can install'
Assert-True (& $n 511 7) '8u511 GA must be uninstalled before b33 can install'
Assert-True (& $n 511 $null) '8u511 with unknown build must be uninstalled first'
Assert-True (-not (& $n 503 1)) '8u503 upgrades in place (different folder and product code)'
Assert-True (-not (& $n 521 1)) 'a later update is left alone'

# --- Add/Remove Programs entry for a JRE folder -----------------------------------
$arp = @(
    [pscustomobject]@{ DisplayName = 'Java 8 Update 511'; InstallLocation = 'C:\Program Files (x86)\Java\jre1.8.0_511\'; ProductCode = '{26A24AE4-039D-4CA4-87B4-2F32180511F0}' },
    [pscustomobject]@{ DisplayName = 'Java 8 Update 511 (64-bit)'; InstallLocation = 'C:\Program Files\Java\jre1.8.0_511\'; ProductCode = '{26A24AE4-039D-4CA4-87B4-2F64180511F0}' },
    [pscustomobject]@{ DisplayName = 'Java Auto Updater'; InstallLocation = ''; ProductCode = '{4A03706F-666A-4037-7777-5F2748764D10}' }
)
Assert-Eq (Select-JavaArpEntry -Entries $arp -JrePath 'C:\Program Files\Java\jre1.8.0_511' -Update 511 -Arch 'x64').ProductCode '{26A24AE4-039D-4CA4-87B4-2F64180511F0}' 'x64 folder maps to the 64-bit entry by InstallLocation'
Assert-Eq (Select-JavaArpEntry -Entries $arp -JrePath 'C:\Program Files (x86)\Java\jre1.8.0_511' -Update 511 -Arch 'x86').ProductCode '{26A24AE4-039D-4CA4-87B4-2F32180511F0}' 'x86 folder maps to the 32-bit entry'
$noLoc = @(
    [pscustomobject]@{ DisplayName = 'Java 8 Update 511'; InstallLocation = ''; ProductCode = '{26A24AE4-039D-4CA4-87B4-2F32180511F0}' },
    [pscustomobject]@{ DisplayName = 'Java 8 Update 511 (64-bit)'; InstallLocation = ''; ProductCode = '{26A24AE4-039D-4CA4-87B4-2F64180511F0}' }
)
Assert-Eq (Select-JavaArpEntry -Entries $noLoc -JrePath 'C:\Program Files\Java\jre1.8.0_511' -Update 511 -Arch 'x64').ProductCode '{26A24AE4-039D-4CA4-87B4-2F64180511F0}' 'blank InstallLocation falls back to name + (64-bit)'
$other = @([pscustomobject]@{ DisplayName = 'Java 8 Update 5111 (64-bit)'; InstallLocation = ''; ProductCode = '{26A24AE4-039D-4CA4-87B4-2F64185111F0}' })
Assert-True ($null -eq (Select-JavaArpEntry -Entries $other -JrePath 'C:\Program Files\Java\jre1.8.0_511' -Update 511 -Arch 'x64')) 'Update 511 does not match an Update 5111 entry'
Assert-True ($null -eq (Select-JavaArpEntry -Entries @() -JrePath 'C:\Program Files\Java\jre1.8.0_511' -Update 511 -Arch 'x64')) 'no entry means no product code (script stops before uninstalling)'

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
    Assert-Eq (($inv | Where-Object { -not (Test-JavaAtTarget -Version $_ -TargetUpdate 511 -TargetBuild 33) }).Count) 3 `
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
