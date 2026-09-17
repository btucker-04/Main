# Unit tests for Test-ScriptIntegrity.ps1.
# Run: pwsh -NoProfile -File windows/tests/Test-ScriptIntegrity.Tests.ps1
#
# Covers the CSPC-004 deployment fault (2026-09-17): the copy under
# ...\UEMS_Agent\Computer\startup\94531\ had the script's header comment
# 1751 lines down the file, so PowerShell parsed the prose as code
# ("Unexpected token 'Installs'"). The committed file parses cleanly, so the
# corruption was introduced between the repository and the agent.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$windowsDir = Split-Path -Parent $here
$scriptPath = Join-Path $windowsDir 'Test-ScriptIntegrity.ps1'
$env:SCRIPT_INTEGRITY_DOTSOURCE = '1'
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
    if (-not $Cond) {
        Write-Host "FAIL $Name"
        $script:failed++
    } else {
        Write-Host "OK   $Name"
    }
}

$clean = @'
<#
.SYNOPSIS
    Example.
#>
[CmdletBinding()]
param([switch]$DryRun)
Write-Host 'hello'
'@

# --- A healthy script ------------------------------------------------------
$r = Get-ScriptIntegrityReport -Content $clean -Name 'clean.ps1'
Assert-True $r.Ok 'clean script passes'
Assert-Eq $r.Problems.Count 0 'clean script has no problems'
Assert-Eq $r.OpenComments 1 'clean script has one <#'
Assert-Eq $r.CloseComments 1 'clean script has one #>'
Assert-Eq $r.SynopsisCount 1 'clean script has one .SYNOPSIS'
Assert-Eq $r.CmdletBindingCount 1 'clean script has one [CmdletBinding'

# --- The CSPC-004 shape: the whole file appended to itself ------------------
$dupe = $clean + "`n" + $clean
$r = Get-ScriptIntegrityReport -Content $dupe -Name 'dupe.ps1'
Assert-True (-not $r.Ok) 'duplicate-append is rejected'
Assert-Eq $r.SynopsisCount 2 'duplicate-append has two .SYNOPSIS'
Assert-Eq $r.CmdletBindingCount 2 'duplicate-append has two [CmdletBinding'
Assert-True ([bool]($r.Problems -match 'DUPLICATE')) 'duplicate-append reports DUPLICATE'

# --- A lost comment opener leaves prose to be parsed as code ---------------
$noOpener = $clean -replace '(?m)^<#\r?\n', ''
$r = Get-ScriptIntegrityReport -Content $noOpener -Name 'noopener.ps1'
Assert-True (-not $r.Ok) 'missing <# is rejected'
Assert-True ([bool]($r.Problems -match 'UNBALANCED')) 'missing <# reports UNBALANCED'

# --- A lost closer swallows the rest of the file ---------------------------
$noCloser = $clean -replace '(?m)^#>\r?\n', ''
$r = Get-ScriptIntegrityReport -Content $noCloser -Name 'nocloser.ps1'
Assert-True (-not $r.Ok) 'missing #> is rejected'
Assert-True ([bool]($r.Problems -match 'UNBALANCED')) 'missing #> reports UNBALANCED'

# --- Syntax errors are surfaced separately ---------------------------------
$r = Get-ScriptIntegrityReport -Content "if (`$true) { 'x'" -Name 'broken.ps1'
Assert-True (-not $r.Ok) 'unterminated block is rejected'
Assert-True ([bool]($r.Problems -match 'PARSE')) 'syntax error reports PARSE'

Assert-True (Get-ScriptIntegrityReport -Content '' -Name 'empty.ps1').Ok 'empty file is not a failure'

# --- Every committed Windows script must pass ------------------------------
$repoProblems = @()
foreach ($f in (Get-ChildItem -LiteralPath $windowsDir -Filter '*.ps1' -File | Sort-Object Name)) {
    $rep = Get-ScriptIntegrityReport -Content (Get-Content -LiteralPath $f.FullName -Raw) -Name $f.Name
    if (-not $rep.Ok) { $repoProblems += ($f.Name + ': ' + ($rep.Problems -join '; ')) }
}
if ($repoProblems.Count -gt 0) {
    foreach ($p in $repoProblems) { Write-Host ('     ' + $p) }
}
Assert-Eq $repoProblems.Count 0 'every committed windows/*.ps1 passes integrity'

# --- The real Update-DotNetRuntimes.ps1, doubled, is caught ----------------
$realPath = Join-Path $windowsDir 'Update-DotNetRuntimes.ps1'
$real = Get-Content -LiteralPath $realPath -Raw
Assert-True (Get-ScriptIntegrityReport -Content $real -Name 'real').Ok 'real script passes as committed'
$realDoubled = Get-ScriptIntegrityReport -Content ($real + $real) -Name 'real-doubled'
Assert-True (-not $realDoubled.Ok) 'real script doubled is caught'
Assert-True ([bool]($realDoubled.Problems -match 'DUPLICATE')) 'real doubled reports DUPLICATE'

if ($failed -gt 0) {
    Write-Host "`n$failed test(s) failed"
    exit 1
}
Write-Host "`nAll tests passed"
exit 0
