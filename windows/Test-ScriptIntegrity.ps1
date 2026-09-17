<#
.SYNOPSIS
    Read-only: verifies a PowerShell script file is intact and parseable.
    Point it at the Endpoint Central agent's cached copy when a deployed
    script fails with parse errors that the repository copy does not have.

.DESCRIPTION
    CSPC-004 (2026-09-17) failed before it ran a single line:

      ...\UEMS_Agent\Computer\startup\94531\Update-DotNetRuntimes.ps1:1759
      +       1. Installs the latest patch of each installed flavor via aka.m ...
      +          ~~~~~~~~
      Unexpected token 'Installs' in expression or statement.

    That text is the script's own header documentation, which lives at line 8
    of the committed file inside a block comment. PowerShell only reports it
    as code if that block comment is not in effect. Every reported error line
    sat exactly 1751 lines below its position in the repository copy, which
    means roughly 1751 lines of content preceded the header in the deployed
    file -- the file had been assembled with an extra copy of itself in front
    of the real one. The committed file has exactly one block-comment opener,
    one closer, one .SYNOPSIS and one CmdletBinding attribute, and parses
    cleanly.

    This script detects that class of corruption:
      PARSE       the PowerShell parser rejects the file
      UNBALANCED  block-comment opener and closer counts differ
      DUPLICATE   more than one .SYNOPSIS or CmdletBinding attribute -- the
                  signature of a file appended to itself, as happened here

    A truncated or blocked transfer is not a separate check: it fails PARSE.

    Note: a block comment cannot contain the closing marker, so this file
    deliberately never writes those two characters inside its own header.

    Changes nothing. Reads only.

.PARAMETER Path
    File or directory to check. Defaults to the folder holding this script.
    For a suspect deployment, pass the agent's cached folder, for example
    the UEMS_Agent Computer\startup\<id> directory that EC extracts into.

.PARAMETER Recurse
    Recurse into subdirectories when Path is a directory.

.NOTES
    Run: powershell -ExecutionPolicy Bypass -File .\Test-ScriptIntegrity.ps1
    Exit: 0 = all files intact / 1 = at least one problem
#>

[CmdletBinding()]
param(
    [string]$Path = '',
    [switch]$Recurse
)

$ErrorActionPreference = 'Stop'

function Get-ScriptIntegrityReport {
    param([string]$Content, [string]$Name)

    $problems = @()
    $text = if ($null -eq $Content) { '' } else { $Content }

    $open  = ([regex]::Matches($text, '<#')).Count
    $close = ([regex]::Matches($text, '#>')).Count
    # (?m) so ^ anchors per line: these markers are only meaningful at the
    # start of a line in this repository's scripts.
    $synopsis = ([regex]::Matches($text, '(?m)^\s*\.SYNOPSIS\s*$')).Count
    $binding  = ([regex]::Matches($text, '(?m)^\s*\[CmdletBinding')).Count

    if ($text.Trim().Length -gt 0) {
        $parseErrors = $null
        $tokens = $null
        [void][System.Management.Automation.Language.Parser]::ParseInput(
            $text, [ref]$tokens, [ref]$parseErrors)
        if ($parseErrors -and $parseErrors.Count -gt 0) {
            $first = $parseErrors[0]
            $problems += ('PARSE: ' + $parseErrors.Count + ' error(s); first at line ' +
                          $first.Extent.StartLineNumber + ': ' + $first.Message)
        }

        if ($open -ne $close) {
            $problems += ('UNBALANCED: ' + $open + ' "<#" vs ' + $close + ' "#>" -- a lost block-comment delimiter leaves documentation to be parsed as code')
        }
        if ($synopsis -gt 1) {
            $problems += ('DUPLICATE: ' + $synopsis + ' .SYNOPSIS blocks -- the file appears to contain more than one copy of itself')
        }
        if ($binding -gt 1) {
            $problems += ('DUPLICATE: ' + $binding + ' [CmdletBinding] blocks -- the file appears to contain more than one copy of itself')
        }
    }

    return [pscustomobject]@{
        Name               = $Name
        Ok                 = ($problems.Count -eq 0)
        Problems           = $problems
        OpenComments       = $open
        CloseComments      = $close
        SynopsisCount      = $synopsis
        CmdletBindingCount = $binding
        Bytes              = $text.Length
    }
}

if ($env:SCRIPT_INTEGRITY_DOTSOURCE -eq '1') { return }

# ---- live run --------------------------------------------------------------

$target = $Path
if ([string]::IsNullOrWhiteSpace($target)) {
    $target = Split-Path -Parent $MyInvocation.MyCommand.Path
}

if (-not (Test-Path -LiteralPath $target)) {
    Write-Host ('ERROR: path not found: ' + $target)
    exit 1
}

$files = @()
if (Test-Path -LiteralPath $target -PathType Container) {
    $gciArgs = @{ LiteralPath = $target; Filter = '*.ps1'; File = $true }
    if ($Recurse) { $gciArgs['Recurse'] = $true }
    $files = @(Get-ChildItem @gciArgs | Sort-Object FullName)
} else {
    $files = @(Get-Item -LiteralPath $target)
}

Write-Host '=============================================='
Write-Host ' PowerShell script integrity check (read-only)'
Write-Host (' Target : ' + $target)
Write-Host (' Files  : ' + $files.Count)
Write-Host '=============================================='

$bad = 0
foreach ($f in $files) {
    $content = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction SilentlyContinue
    $report = Get-ScriptIntegrityReport -Content $content -Name $f.Name
    if ($report.Ok) {
        Write-Host ('  OK   ' + $f.Name)
        continue
    }
    $bad++
    Write-Host ('  BAD  ' + $f.Name)
    Write-Host ('       <#=' + $report.OpenComments + '  #>=' + $report.CloseComments +
                '  .SYNOPSIS=' + $report.SynopsisCount +
                '  [CmdletBinding]=' + $report.CmdletBindingCount +
                '  bytes=' + $report.Bytes)
    foreach ($p in $report.Problems) { Write-Host ('       ' + $p) }
}

Write-Host '=============================================='
if ($bad -gt 0) {
    Write-Host (' Problem file(s): ' + $bad)
    Write-Host ' A DUPLICATE or UNBALANCED result on a DEPLOYED copy while the repository'
    Write-Host ' copy is clean means the file was corrupted in transfer or packaging.'
    Write-Host ' Re-deploy it: delete the agent''s cached startup folder for this script'
    Write-Host ' and let it download again, then re-run this check before the script.'
    Write-Host '=============================================='
    exit 1
}
Write-Host ' All files intact.'
Write-Host '=============================================='
exit 0
