# Unit tests for Update-NotepadPlusPlus.ps1 helpers.
# Run: pwsh -NoProfile -File windows/tests/Update-NotepadPlusPlus.Tests.ps1
#
# swissqp-02 (2026-10-21): plugins 327203 (< 8.9.7), 318684 (< 8.9.6.1) and
# 299664 (< 8.9.2) RESURFACED because Update-ThirdPartyAppBundle.ps1 pins
# 8.9.6.1. The target now comes from the latest GitHub release at run time.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path (Split-Path -Parent $here) 'Update-NotepadPlusPlus.ps1'
$env:NOTEPADPP_UPDATE_DOTSOURCE = '1'
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

# Versions
Assert-Eq (ConvertTo-NppVersion '8.9.6.1') '8.9.6.1' 'four-part version'
Assert-Eq (ConvertTo-NppVersion 'v8.9.7') '8.9.7.0' 'tag form padded to four parts'
Assert-Eq (ConvertTo-NppVersion '8.9') '8.9.0.0' 'two-part tag'
Assert-Eq ($null -eq (ConvertTo-NppVersion '8.981x')) 'True' 'garbage is not a version'
Assert-Eq ((ConvertTo-NppVersion '8.9.7') -eq (ConvertTo-NppVersion '8.9.7.0')) 'True' '8.9.7 equals 8.9.7.0'
Assert-Eq ((ConvertTo-NppVersion '8.9.6.1') -lt (ConvertTo-NppVersion '8.9.7')) 'True' 'swissqp-02: 8.9.6.1 is below 327203 fix 8.9.7'
Assert-Eq ((ConvertTo-NppVersion '8.9.8.1') -ge (ConvertTo-NppVersion '8.9.7')) 'True' '8.9.8.1 clears 327203'
Assert-Eq ((ConvertTo-NppVersion '8.10') -gt (ConvertTo-NppVersion '8.9.8.1')) 'True' 'numeric, not text: 8.10 > 8.9.8.1'

# Target from the releases/latest redirect
Assert-Eq (Get-VersionFromReleaseUrl 'https://github.com/notepad-plus-plus/notepad-plus-plus/releases/tag/v8.9.8.1') '8.9.8.1' 'version from the redirect Location'
Assert-Eq (Get-VersionFromReleaseUrl 'https://github.com/notepad-plus-plus/notepad-plus-plus/releases/tag/v8.9') '8.9' 'two-part tag kept as published'
Assert-Eq (Get-VersionFromReleaseUrl 'https://github.com/notepad-plus-plus/notepad-plus-plus/releases') '' 'no tag in the url'
Assert-Eq (Get-VersionFromReleaseUrl 'https://login.zscaler.net/block?url=releases/tag/v8.9.8.1x') '' 'block page url is not a version'

# Asset names (as published on the v8.9.8.1 release)
Assert-Eq (Get-NppAssetName -Version '8.9.8.1' -Arch 'x64') 'npp.8.9.8.1.Installer.x64.exe' 'x64 asset'
Assert-Eq (Get-NppAssetName -Version '8.9.8.1' -Arch 'x86') 'npp.8.9.8.1.Installer.exe' 'x86 asset'
Assert-Eq (Get-NppAssetName -Version '8.9.8.1' -Arch 'arm64') 'npp.8.9.8.1.Installer.arm64.exe' 'arm64 asset'
Assert-Eq (Get-NppAssetName -Version '8.9.8.1' -Arch 'x64' -Kind 'msi') 'npp.8.9.8.1.Installer.x64.msi' 'x64 msi asset'

# PE machine
function New-PeBytes { param([int]$Machine)
    $b = New-Object byte[] 512
    $b[0] = 0x4D; $b[1] = 0x5A; $b[0x3C] = 0x80
    $b[0x80] = 0x50; $b[0x81] = 0x45
    $b[0x84] = [byte]($Machine -band 0xFF); $b[0x85] = [byte](($Machine -shr 8) -band 0xFF)
    return ,$b
}
Assert-Eq (ConvertFrom-PeMachine (Get-PeMachine (New-PeBytes 0x8664))) 'x64' 'x64 PE header'
Assert-Eq (ConvertFrom-PeMachine (Get-PeMachine (New-PeBytes 0x014C))) 'x86' 'x86 PE header'
Assert-Eq (ConvertFrom-PeMachine (Get-PeMachine (New-PeBytes 0xAA64))) 'arm64' 'arm64 PE header'
$html = [System.Text.Encoding]::ASCII.GetBytes(('<html>' + (' ' * 200)))
Assert-Eq (Get-PeMachine $html) '-1' 'block page is not a PE file'
Assert-Eq (ConvertFrom-PeMachine 0x1234) '' 'unknown machine'

# Checksum file (verbatim lines from npp.8.9.8.1.checksums.sha256)
$sums = @'
a53c5116b55ac93fedd7808e71096badecbf10a55f2be9b28b741591b8917a73  npp.8.9.8.1.Installer.arm64.exe
ee848aa54df153921678b343857a83861da81ce0c9dbb217b6f55a8780e60f5e  npp.8.9.8.1.Installer.exe
26f3bcced788fadbac4e7e577b430ea2ce6060cf3bcad993ef4612ecd7d743da  npp.8.9.8.1.Installer.x64.exe
0c4f4fe82babd7688f5c1431b1357392491563af6ffedf4e37f5de0bd71babb4  npp.8.9.8.1.Installer.x64.msi
'@
Assert-Eq (Get-ChecksumForAsset $sums 'npp.8.9.8.1.Installer.x64.exe') '26f3bcced788fadbac4e7e577b430ea2ce6060cf3bcad993ef4612ecd7d743da' 'x64 exe checksum'
Assert-Eq (Get-ChecksumForAsset $sums 'npp.8.9.8.1.Installer.exe') 'ee848aa54df153921678b343857a83861da81ce0c9dbb217b6f55a8780e60f5e' 'x86 checksum is not the x64 one'
Assert-Eq (Get-ChecksumForAsset ($sums -replace "`n", "`r`n") 'npp.8.9.8.1.Installer.x64.msi') '0c4f4fe82babd7688f5c1431b1357392491563af6ffedf4e37f5de0bd71babb4' 'CRLF checksum file'
Assert-Eq (Get-ChecksumForAsset $sums 'npp.8.9.7.Installer.x64.exe') '' 'asset not listed'
Assert-Eq (Get-ChecksumForAsset '' 'npp.8.9.8.1.Installer.x64.exe') '' 'no checksum file'
$sumBytes = [System.Text.Encoding]::UTF8.GetBytes($sums)
Assert-Eq (Get-ChecksumForAsset (ConvertTo-ResponseText $sumBytes) 'npp.8.9.8.1.Installer.x64.exe') '26f3bcced788fadbac4e7e577b430ea2ce6060cf3bcad993ef4612ecd7d743da' 'checksum file served as bytes (octet-stream)'
Assert-Eq (ConvertTo-ResponseText 'text') 'text' 'string content passes through'

# Signer (Windows SignerCertificate.Subject form of the v8.9.8.1 installer's cert)
Assert-Eq (Test-NppSigner 'E=don.h@free.fr, CN=NOTEPAD++, O=NOTEPAD++, L=Paris, S=Ile-de-France, C=FR') 'True' 'Notepad++ signer accepted'
Assert-Eq (Test-NppSigner 'CN=Notepad++, O=Notepad++, C=FR') 'True' 'case-insensitive'
Assert-Eq (Test-NppSigner 'CN=NOTEPAD++ Fan Club, O=Evil, C=XX') 'False' 'look-alike CN refused'
Assert-Eq (Test-NppSigner 'CN=Evil, O=NOTEPAD++') 'False' 'O= alone is not enough'
Assert-Eq (Test-NppSigner '') 'False' 'unsigned refused'

# Staged installers
$staged = @('npp.8.9.6.1.Installer.x64.exe', 'npp.8.9.8.1.Installer.x64.exe', 'npp.8.9.10.Installer.exe',
            'npp.8.9.8.1.Installer.x64.msi', 'npp.8.9.8.1.portable.x64.zip', 'readme.txt')
Assert-Eq ((Select-StagedNppInstaller -Names $staged -Arch 'x64') -join '|') 'npp.8.9.8.1.Installer.x64.exe|8.9.8.1' 'newest x64 exe'
Assert-Eq ((Select-StagedNppInstaller -Names $staged -Arch 'x86') -join '|') 'npp.8.9.10.Installer.exe|8.9.10' 'x86 never picks an x64 file'
Assert-Eq ((Select-StagedNppInstaller -Names $staged -Arch 'x64' -Kind 'msi') -join '|') 'npp.8.9.8.1.Installer.x64.msi|8.9.8.1' 'msi only for MSI installs'
Assert-Eq ($null -eq (Select-StagedNppInstaller -Names $staged -Arch 'arm64')) 'True' 'no arm64 staged'
Assert-Eq ($null -eq (Select-StagedNppInstaller -Names @() -Arch 'x64')) 'True' 'empty staging dir'

if ($failed -gt 0) { Write-Host "$failed test(s) failed"; exit 1 }
Write-Host 'All tests passed'
exit 0
