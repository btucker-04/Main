<#
.SYNOPSIS
    Remediation: Windows Unquoted Service Path Enumeration
    Nessus Plugin ID : 63155

.DESCRIPTION
    Enumerates all Windows services whose ImagePath registry value
    contains spaces but is not wrapped in double quotes, then quotes
    them in place. Covers all findings on this machine, including:
      - GlideXNearService   (cslt-243)
      - GlideXRemoteService (cslt-243)
      - KDService           (cspc-037 / csmelt-10)

    Deploy via Endpoint Central (runs as SYSTEM).

.PARAMETER WhatIf
    Preview changes without writing to the registry.
#>

#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess)]
param()

$ErrorActionPreference = 'Stop'

$LogDir  = 'C:\Logs\CompoSecure'
$LogFile = Join-Path $LogDir ("UnquotedSvcPath_63155_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

# ---- Logging ----
function Write-Log {
    param(
        [string]$Msg,
        [ValidateSet('INFO','WARN','ERROR','FIXED','OK','SKIP')]
        [string]$Level = 'INFO'
    )
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

# ---- Wrap an ImagePath in quotes if it needs it ----
# Handles paths that may have trailing arguments after the .exe
function Get-QuotedImagePath {
    param([string]$ImagePath)

    $trimmed = $ImagePath.TrimStart()

    # Already quoted — no change needed
    if ($trimmed -match '^"') { return $null }

    # Kernel/driver paths starting with \SystemRoot or \?? — skip
    if ($trimmed -match '^\\') { return $null }

    # Split on .exe boundary to isolate executable from arguments
    if ($trimmed -match '^(?i)(.*?\.exe)((\s+.*)?)$') {
        $exePath = $matches[1].Trim()
        $trailing = $matches[2].Trim()

        # Only quote if the exe path actually has a space
        if ($exePath -match '\s') {
            if ($trailing) {
                return '"{0}" {1}' -f $exePath, $trailing
            } else {
                return '"{0}"' -f $exePath
            }
        }
    }

    return $null  # No change needed
}

# ==============================================================
# Setup
# ==============================================================
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

Write-Log "=============================================="
Write-Log " Unquoted Service Path Remediation"
Write-Log " Plugin ID  : 63155"
Write-Log " Host       : $env:COMPUTERNAME"
Write-Log " Date       : $(Get-Date)"
Write-Log " WhatIf     : $($WhatIfPreference)"
Write-Log "=============================================="
Write-Log ""

$ServicesKey = 'HKLM:\SYSTEM\CurrentControlSet\Services'
$allKeys     = Get-ChildItem -Path $ServicesKey -ErrorAction SilentlyContinue

$countFixed   = 0
$countClean   = 0
$countSkipped = 0
$countErrors  = 0

# ==============================================================
# Main loop — check every service's ImagePath
# ==============================================================
foreach ($svcKey in $allKeys) {
    try {
        $imagePath = $svcKey.GetValue('ImagePath')

        if ([string]::IsNullOrWhiteSpace($imagePath)) {
            $countSkipped++
            continue
        }

        $newPath = Get-QuotedImagePath -ImagePath $imagePath

        if ($null -eq $newPath) {
            $countClean++
            continue
        }

        $svcName = $svcKey.PSChildName
        Write-Log "[$svcName] Unquoted path detected:" -Level WARN
        Write-Log "  Before : $imagePath"
        Write-Log "  After  : $newPath"

        if ($WhatIfPreference) {
            Write-Log "  [WHATIF] Registry write skipped." -Level SKIP
            $countSkipped++
        } else {
            Set-ItemProperty -Path $svcKey.PSPath -Name 'ImagePath' -Value $newPath
            Write-Log "  Registry updated successfully." -Level FIXED
            $countFixed++
        }

    } catch {
        $countErrors++
        Write-Log "[$($svcKey.PSChildName)] ERROR: $_" -Level ERROR
    }
}

# ==============================================================
# Summary
# ==============================================================
Write-Log ""
Write-Log "=============================================="
Write-Log " Summary"
Write-Log " Fixed         : $countFixed service(s)"
Write-Log " Already clean : $countClean"
Write-Log " Skipped       : $countSkipped (no ImagePath or WhatIf)"
Write-Log " Errors        : $countErrors"
Write-Log " Log           : $LogFile"
Write-Log "=============================================="
Write-Log ""
Write-Log "IMPORTANT: Services use the ImagePath value at START time."
Write-Log "A reboot (or individual service restart) is required before"
Write-Log "Nessus will see the fix. Re-scan after the next reboot."
Write-Log ""

# Exit codes consistent with Endpoint Central conventions
if ($countErrors -gt 0)  { exit 1    }   # Failure
if ($countFixed  -gt 0)  { exit 3010 }   # Success, reboot recommended
exit 0                                    # No changes needed / already clean
