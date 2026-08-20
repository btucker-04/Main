<#
.SYNOPSIS
    Diagnostic: list MSI dependency providers holding references on old
    .NET runtime versions, with each dependent resolved to a product name.
    Explains why exit-0 uninstalls leave version folders on disk
    (cspc-099 / cspc-100 pattern).

.PARAMETER VersionMatch
    Version string to match in provider key names. Default '10.0.3'.

.NOTES
    Read-only -- changes nothing. Deploy via EC as a script, or run
    locally: powershell -ExecutionPolicy Bypass -File .\Get-DotNetDependencyRefs.ps1
    Output: console + C:\Logs\CompoSecure\DotNetDepRefs_<timestamp>.log
#>

[CmdletBinding()]
param([string]$VersionMatch = '10.0.3')

$LogDir  = 'C:\Logs\CompoSecure'
$LogFile = Join-Path $LogDir ('DotNetDepRefs_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Msg)
    Write-Host $Msg
    Add-Content -Path $LogFile -Value $Msg -ErrorAction SilentlyContinue
}

Write-Log ('=== .NET dependency reference check -- ' + $env:COMPUTERNAME + ' -- match: ' + $VersionMatch + ' ===')

$depRoot = 'HKLM:\SOFTWARE\Classes\Installer\Dependencies'
$verEsc  = [regex]::Escape($VersionMatch)
$hits    = 0

Get-ChildItem $depRoot -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match $verEsc } | ForEach-Object {
    $hits++
    Write-Log ''
    Write-Log ('Provider: ' + $_.PSChildName)
    $depPath = Join-Path $_.PSPath 'Dependents'
    if (-not (Test-Path $depPath)) {
        Write-Log '  (no Dependents subkey -- ORPHANED provider registration;'
        Write-Log '   safe to delete this provider key, then re-run the update script)'
        return
    }
    $deps = Get-ChildItem $depPath -ErrorAction SilentlyContinue
    if (-not $deps) {
        Write-Log '  (Dependents subkey empty -- effectively orphaned)'
        return
    }
    foreach ($d in $deps) {
        $guid = $d.PSChildName
        $displayName = '(not found in ARP -- dependent product itself may be gone)'
        foreach ($hive in @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\'
        )) {
            $prop = Get-ItemProperty ($hive + $guid) -ErrorAction SilentlyContinue
            if ($prop -and $prop.DisplayName) {
                $displayName = $prop.DisplayName + '  [' + $prop.DisplayVersion + ']'
                break
            }
        }
        Write-Log ('  Dependent: ' + $guid + '  ' + $displayName)
    }
}

if ($hits -eq 0) {
    Write-Log ''
    Write-Log ('No provider keys matching "' + $VersionMatch + '" found.')
    Write-Log 'If old version folders persist anyway, the hold is not a Windows Installer'
    Write-Log 'dependency -- check for open file handles or antivirus interference instead.'
}

Write-Log ''
Write-Log ('Log: ' + $LogFile)
