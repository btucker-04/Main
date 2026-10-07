# Unit tests for Update-NodeJS.ps1 target resolution.
# Run: pwsh -NoProfile -File windows/tests/Update-NodeJS.Tests.ps1
#
# CSRZ-002 (2026-10-07): a stale fixed-version map read 22.x -> 22.23.0, so a
# host on 22.23.0 was "already at target" while Tenable wanted 22.23.2. The
# target now comes from nodejs.org/dist/index.json at run time.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path (Split-Path -Parent $here) 'Update-NodeJS.ps1'
$env:NODEJS_UPDATE_DOTSOURCE = '1'
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

$index = @'
[
  {"version":"v26.10.0","files":["win-x64-msi","win-arm64-zip"],"lts":false},
  {"version":"v24.21.0","files":["win-x64-msi","win-arm64-zip"],"lts":"Krypton"},
  {"version":"v24.20.0","files":["win-x64-msi"],"lts":"Krypton"},
  {"version":"v23.11.1","files":["win-x64-msi"],"lts":false},
  {"version":"v22.23.3","files":["win-x64-msi"],"lts":"Jod"},
  {"version":"v22.23.2","files":["win-x64-msi","win-arm64-zip"],"lts":"Jod"},
  {"version":"v22.9.0","files":["win-x64-msi"],"lts":"Jod"},
  {"version":"v22.24.0-rc.1","files":["win-x64-msi"],"lts":false},
  {"version":"v20.20.2","files":["win-x64-msi"],"lts":"Iron"}
]
'@

Assert-Eq (Get-LatestNodeRelease -IndexJson $index -Major '22' -Arch 'x64') '22.23.3' 'CSRZ-002: 22.x resolves to the newest 22 release'
Assert-Eq (Get-LatestNodeRelease -IndexJson $index -Major '24' -Arch 'x64') '24.21.0' '24.x resolves to 24.21.0'
Assert-Eq (Get-LatestNodeRelease -IndexJson $index -Major '26' -Arch 'x64') '26.10.0' '26.x resolves to 26.10.0'
Assert-Eq (Get-LatestNodeRelease -IndexJson $index -Major '22' -Arch 'arm64') '22.23.2' 'arm64 skips releases without an arm64 build'
Assert-Eq (Get-LatestNodeRelease -IndexJson $index -Major '2' -Arch 'x64') '' 'major 2 does not match 22/24/26'
Assert-Eq (Get-LatestNodeRelease -IndexJson $index -Major '18' -Arch 'x64') '' 'a line with no releases resolves to empty'
Assert-Eq (Get-LatestNodeRelease -IndexJson $index -Major '23' -Arch 'x64') '23.11.1' 'odd line still resolves within itself'
Assert-Eq (Get-LatestNodeRelease -IndexJson '[{"version":"v22.23.3","files":["win-x64-msi"]}]' -Major '22' -Arch 'arm64') '' 'index entry with no arm64 build is skipped for arm64'
Assert-Eq ([version](Get-LatestNodeRelease -IndexJson $index -Major '22' -Arch 'x64') -gt [version]'22.23.0') 'True' '22.23.0 is now behind the target'
Assert-Eq ([version](Get-LatestNodeRelease -IndexJson $index -Major '22' -Arch 'x64') -gt [version]'22.9.0') 'True' 'versions compare numerically, not as text'

$staged = @('node-v22.23.2-x64.msi', 'node-v22.9.0-x64.msi', 'node-v24.21.0-x64.msi', 'node-v22.23.3-arm64.msi', 'readme.txt')
Assert-Eq (Select-StagedNodeMsi -Names $staged -Major '22' -Arch 'x64') 'node-v22.23.2-x64.msi' 'newest staged MSI for the line and arch'
Assert-Eq (Select-StagedNodeMsi -Names $staged -Major '24' -Arch 'x64') 'node-v24.21.0-x64.msi' 'staged MSI on another line'
Assert-Eq (Select-StagedNodeMsi -Names $staged -Major '26' -Arch 'x64') '' 'no staged MSI for the line'
Assert-Eq (Select-StagedNodeMsi -Names @() -Major '22' -Arch 'x64') '' 'empty staging dir'

if ($failed -gt 0) { Write-Host "$failed test(s) failed"; exit 1 }
Write-Host 'All tests passed'
exit 0
