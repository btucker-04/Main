<#
.SYNOPSIS
    Read-only drive and storage inventory (v2): total, used and free for every
    volume, plus enough context to explain why a drive reports no size.

.DESCRIPTION
    Written to diagnose Endpoint Central's file manager showing
    "NaN KB free of NaN KB" for a drive (CSPC-071: E: and F:). EC renders NaN
    when the size/free values it gets back are null or zero, so the useful
    question is not "how big is the drive" but "why is there no number".

    Reports from four independent layers, because each sees something different:
      1. Win32_LogicalDisk  -- drive letters, DriveType, Size/FreeSpace.
                               A NULL Size here is the direct cause of NaN.
      2. Win32_Volume       -- includes volumes with NO drive letter, and
                               reports Capacity separately from LogicalDisk.
      3. Get-Disk / Get-Partition -- the physical layer: offline or
                               uninitialised disks, and partitions with no
                               filesystem.
      4. BitLocker status   -- a LOCKED volume reports no capacity until
                               unlocked, which looks identical to empty media.

    Then it prints a per-drive VERDICT naming the most likely reason a drive
    has no size: removable/optical with no media inserted, BitLocker-locked,
    RAW/unformatted, offline disk, or a network mapping invisible to SYSTEM.

    NOTE ON CONTEXT: run from EC this executes as SYSTEM, which CANNOT see the
    logged-on user's mapped network drives. If E:/F: are user drive mappings
    they will be absent here entirely -- itself a diagnosis, and the script
    says so.

    v2: adds PHYSICAL DEVICE IDENTIFICATION (section 3b). A drive letter with no
    media is usually an empty slot, but it can also be an attached device
    presenting virtual media. CSPC-071 (2026-08-17) showed two disks named
    "Linux File-CD Gadget" -- the Linux USB mass-storage gadget driver, i.e. a
    Linux-based device exposing itself as removable media. That is common for
    cameras, encoders, access-control panels and KVM/console appliances in
    configuration mode, and also matches a BadUSB-class implant, so the vendor
    should be named rather than assumed. Section 3b reports Model,
    InterfaceType, USB VID/PID and the PnP manufacturer for every disk and
    optical device, which identifies the hardware outright.

    Changes nothing.

.NOTES
    Deploy via Endpoint Central: powershell -ExecutionPolicy Bypass -File <path>
    Log: C:\Logs\CompoSecure\DriveInventory_<timestamp>.log  (+ CSV for rollup)
    Exit: 0 = every lettered volume reported a size / 2 = at least one did not
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'SilentlyContinue'

$LogDir  = 'C:\Logs\CompoSecure'
$LogFile = Join-Path $LogDir ('DriveInventory_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log')
$CsvFile = Join-Path $LogDir 'DriveInventory.csv'
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}
function FmtBytes {
    param($Bytes)
    if ($null -eq $Bytes) { return 'null' }
    if ($Bytes -eq 0)     { return '0' }
    $gb = [math]::Round(($Bytes / 1GB), 2)
    if ($gb -lt 1) { return ([math]::Round(($Bytes / 1MB), 1).ToString() + ' MB') }
    return ($gb.ToString() + ' GB')
}
$DriveTypeName = @{
    0 = 'Unknown'; 1 = 'No Root Directory'; 2 = 'Removable'; 3 = 'Local Disk'
    4 = 'Network'; 5 = 'Optical (CD/DVD)'; 6 = 'RAM Disk'
}

Write-Log '=============================================='
Write-Log ' Drive & Storage Inventory (read-only)'
Write-Log (' Host    : ' + $env:COMPUTERNAME)
Write-Log (' Running as : ' + [Security.Principal.WindowsIdentity]::GetCurrent().Name)
Write-Log '=============================================='

# ------------------------------------------------------------------
# 1. Logical disks -- the layer EC reads
# ------------------------------------------------------------------
Write-Log ''
Write-Log '[1] Win32_LogicalDisk (drive letters -- this is what EC reports on)'
$logical = Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction SilentlyContinue
if (-not $logical) { $logical = Get-WmiObject -Class Win32_LogicalDisk -ErrorAction SilentlyContinue }

$noSize = @()
if (-not $logical) {
    Write-Log '  No logical disks returned at all -- WMI/CIM problem on this host.' -Level ERROR
} else {
    Write-Log ''
    Write-Log ('  {0,-6} {1,-18} {2,-10} {3,>12} {4,>12} {5,>12} {6,>6}' -f 'Drive','Type','FileSys','Total','Used','Free','Used%')
    Write-Log ('  ' + ('-' * 84))
    foreach ($d in ($logical | Sort-Object DeviceID)) {
        $tname = $DriveTypeName[[int]$d.DriveType]
        if (-not $tname) { $tname = ('Type ' + $d.DriveType) }
        $size = $d.Size; $free = $d.FreeSpace
        if ($null -ne $size -and $size -gt 0) {
            $used = $size - $free
            $pct  = [math]::Round((($used / $size) * 100), 1)
            Write-Log ('  {0,-6} {1,-18} {2,-10} {3,>12} {4,>12} {5,>12} {6,>5}%' -f `
                $d.DeviceID, $tname, ('' + $d.FileSystem), (FmtBytes $size), (FmtBytes $used), (FmtBytes $free), $pct)
        } else {
            Write-Log ('  {0,-6} {1,-18} {2,-10} {3,>12} {4,>12} {5,>12} {6,>6}' -f `
                $d.DeviceID, $tname, ('' + $d.FileSystem), (FmtBytes $size), '-', (FmtBytes $free), '-') -Level WARN
            $noSize += $d
        }
    }
}

# ------------------------------------------------------------------
# 2. Volumes -- catches volumes with no letter, and a second capacity source
# ------------------------------------------------------------------
Write-Log ''
Write-Log '[2] Win32_Volume (includes volumes with no drive letter)'
$vols = Get-CimInstance -ClassName Win32_Volume -ErrorAction SilentlyContinue
if (-not $vols) { $vols = Get-WmiObject -Class Win32_Volume -ErrorAction SilentlyContinue }
if ($vols) {
    foreach ($v in $vols) {
        $letter = if ($v.DriveLetter) { $v.DriveLetter } else { '(no letter)' }
        Write-Log ('  ' + $letter.PadRight(12) + ' fs=' + ('' + $v.FileSystem).PadRight(8) +
                   ' label=' + ('' + $v.Label).PadRight(16) +
                   ' capacity=' + (FmtBytes $v.Capacity) + '  free=' + (FmtBytes $v.FreeSpace))
    }
} else {
    Write-Log '  (no Win32_Volume data)'
}

# ------------------------------------------------------------------
# 3. Physical layer -- offline / uninitialised / RAW
# ------------------------------------------------------------------
Write-Log ''
Write-Log '[3] Physical disks and partitions'
if (Get-Command Get-Disk -ErrorAction SilentlyContinue) {
    foreach ($disk in (Get-Disk | Sort-Object Number)) {
        Write-Log ('  Disk ' + $disk.Number + ': ' + $disk.FriendlyName +
                   '  size=' + (FmtBytes $disk.Size) +
                   '  partitionStyle=' + $disk.PartitionStyle +
                   '  operationalStatus=' + $disk.OperationalStatus +
                   '  healthStatus=' + $disk.HealthStatus)
        if ($disk.OperationalStatus -ne 'Online') {
            Write-Log '    Disk is NOT online -- its volumes cannot report size.' -Level WARN
        }
        foreach ($p in (Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue)) {
            $pl = if ($p.DriveLetter) { $p.DriveLetter + ':' } else { '(none)' }
            Write-Log ('    Partition ' + $p.PartitionNumber + '  letter=' + $pl +
                       '  size=' + (FmtBytes $p.Size) + '  type=' + $p.Type)
        }
    }
} else {
    Write-Log '  Storage cmdlets unavailable on this host (older OS / missing module).'
}

# ------------------------------------------------------------------
# 3b. Physical device identity -- what IS that drive, really?
# ------------------------------------------------------------------
Write-Log ''
Write-Log '[3b] Device identity for disks and optical drives (USB VID/PID)'
Write-Log '     A no-media drive letter may be an empty slot OR an attached device'
Write-Log '     presenting virtual media. The VID/PID names the manufacturer.'

function Get-VidPid {
    param([string]$PnpId)
    if ($PnpId -match 'VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})') {
        return ('VID_' + $matches[1].ToUpper() + ' PID_' + $matches[2].ToUpper())
    }
    if ($PnpId -match 'VEN_([^&\\]+)&PROD_([^&\\]+)') {
        return ('VEN_' + $matches[1] + ' PROD_' + $matches[2])
    }
    return ''
}
function Get-PnpManufacturer {
    param([string]$PnpId)
    if (-not (Get-Command Get-PnpDevice -ErrorAction SilentlyContinue)) { return '' }
    $dev = Get-PnpDevice -InstanceId $PnpId -ErrorAction SilentlyContinue
    if ($dev) { return ('' + $dev.Manufacturer) }
    return ''
}

$diskDrives = Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction SilentlyContinue
if (-not $diskDrives) { $diskDrives = Get-WmiObject -Class Win32_DiskDrive -ErrorAction SilentlyContinue }
foreach ($dd in ($diskDrives | Sort-Object Index)) {
    Write-Log ''
    Write-Log ('  Disk ' + $dd.Index + ': ' + $dd.Model)
    Write-Log ('    interface   : ' + $dd.InterfaceType + '   mediaType: ' + ('' + $dd.MediaType))
    Write-Log ('    size        : ' + (FmtBytes $dd.Size) + '   partitions: ' + $dd.Partitions)
    Write-Log ('    PNPDeviceID : ' + $dd.PNPDeviceID)
    $vp = Get-VidPid $dd.PNPDeviceID
    if ($vp) { Write-Log ('    identifiers : ' + $vp) }
    $mf = Get-PnpManufacturer $dd.PNPDeviceID
    if ($mf) { Write-Log ('    manufacturer: ' + $mf) }
    # letters served by this physical disk
    $letters = @()
    $parts = Get-CimInstance -Query ('ASSOCIATORS OF {Win32_DiskDrive.DeviceID="' + ($dd.DeviceID -replace '\\','\\\\') + '"} WHERE AssocClass=Win32_DiskDriveToDiskPartition') -ErrorAction SilentlyContinue
    foreach ($pt in $parts) {
        $lds = Get-CimInstance -Query ('ASSOCIATORS OF {Win32_DiskPartition.DeviceID="' + $pt.DeviceID + '"} WHERE AssocClass=Win32_LogicalDiskToPartition') -ErrorAction SilentlyContinue
        foreach ($ld in $lds) { $letters += $ld.DeviceID }
    }
    if ($letters.Count -gt 0) { Write-Log ('    drive letters: ' + ($letters -join ', ')) }
    else { Write-Log '    drive letters: (none mapped -- no media, or unformatted)' }
    if ('' + $dd.Model -match 'Gadget|Linux|UMS|Virtual|Composite') {
        Write-Log '    NOTE: the model name indicates a device presenting VIRTUAL media rather' -Level WARN
        Write-Log '    than a storage slot. Identify it from the VID/PID above before assuming' -Level WARN
        Write-Log '    it is benign. On a physical-security or lab workstation this is commonly' -Level WARN
        Write-Log '    a camera, encoder, access-control panel or KVM/console appliance in' -Level WARN
        Write-Log '    configuration mode -- but the same profile matches a BadUSB implant.' -Level WARN
    }
}

$cdroms = Get-CimInstance -ClassName Win32_CDROMDrive -ErrorAction SilentlyContinue
if (-not $cdroms) { $cdroms = Get-WmiObject -Class Win32_CDROMDrive -ErrorAction SilentlyContinue }
foreach ($cd in $cdroms) {
    Write-Log ''
    Write-Log ('  Optical ' + ('' + $cd.Drive) + ': ' + $cd.Caption)
    Write-Log ('    PNPDeviceID : ' + $cd.PNPDeviceID)
    $vp = Get-VidPid $cd.PNPDeviceID
    if ($vp) { Write-Log ('    identifiers : ' + $vp) }
    $mf = Get-PnpManufacturer $cd.PNPDeviceID
    if ($mf) { Write-Log ('    manufacturer: ' + $mf) }
    if ('' + $cd.PNPDeviceID -match '^USB') {
        Write-Log '    NOTE: a USB-attached optical device. If no physical drive is plugged in,' -Level WARN
        Write-Log '    this is virtual media presented by an attached appliance.' -Level WARN
    }
}

# Any currently-connected USB mass-storage devices, for cross-reference
if (Get-Command Get-PnpDevice -ErrorAction SilentlyContinue) {
    Write-Log ''
    Write-Log '  USB mass-storage / disk devices currently present:'
    $usb = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
           Where-Object { $_.Class -in @('DiskDrive','CDROM','USB','SCSIAdapter') -and ('' + $_.InstanceId) -match '^USB' }
    if ($usb) {
        foreach ($u in ($usb | Sort-Object Class, FriendlyName)) {
            Write-Log ('    [' + $u.Class + '] ' + ('' + $u.FriendlyName))
            Write-Log ('        ' + $u.InstanceId + '   status=' + $u.Status)
        }
    } else {
        Write-Log '    (none reported)'
    }
}

# ------------------------------------------------------------------
# 4. BitLocker -- a locked volume reports no capacity
# ------------------------------------------------------------------
Write-Log ''
Write-Log '[4] BitLocker status'
if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
    $bl = Get-BitLockerVolume -ErrorAction SilentlyContinue
    if ($bl) {
        foreach ($b in $bl) {
            Write-Log ('  ' + ('' + $b.MountPoint).PadRight(6) +
                       ' protection=' + ('' + $b.ProtectionStatus).PadRight(10) +
                       ' lockStatus=' + ('' + $b.LockStatus).PadRight(10) +
                       ' encryption=' + ('' + $b.VolumeStatus))
            if ('' + $b.LockStatus -eq 'Locked') {
                Write-Log '    LOCKED -- this volume will report no size until unlocked.' -Level WARN
            }
        }
    } else { Write-Log '  (no BitLocker volumes reported)' }
} else {
    Write-Log '  Get-BitLockerVolume unavailable; falling back to manage-bde.'
    $mb = & manage-bde -status 2>&1 | Select-String -Pattern 'Volume|Conversion|Lock Status|Protection Status'
    foreach ($l in $mb) { Write-Log ('  ' + $l.Line.Trim()) }
}

# ------------------------------------------------------------------
# 5. Verdicts for anything with no size
# ------------------------------------------------------------------
Write-Log ''
Write-Log '=============================================='
Write-Log ' VERDICTS'
Write-Log '=============================================='
if ($noSize.Count -eq 0) {
    Write-Log ' Every lettered volume reported a size. If EC still shows NaN for a'
    Write-Log ' drive, the drive is likely a USER mapped network drive: EC runs this'
    Write-Log ' as SYSTEM, which has its own (empty) set of mappings, so a user drive'
    Write-Log ' is invisible here and unreadable there.'
} else {
    foreach ($d in $noSize) {
        $t = [int]$d.DriveType
        Write-Log ''
        Write-Log (' ' + $d.DeviceID + '  (' + $DriveTypeName[$t] + ') reports no size -- this is what EC renders as NaN.')
        switch ($t) {
            2 { Write-Log '   Removable drive with NO MEDIA inserted (card reader, USB slot,'
                Write-Log '   floppy-class device), OR an attached device presenting virtual'
                Write-Log '   media. Check section 3b: if the model names a gadget/virtual'
                Write-Log '   device, identify the vendor from its VID/PID before treating this'
                Write-Log '   as an empty slot.' }
            5 { Write-Log '   Optical drive with no disc inserted -- normal and expected IF a'
                Write-Log '   physical drive exists. If section 3b shows it is USB-attached with'
                Write-Log '   no real drive present, it is virtual media from an appliance.' }
            4 { Write-Log '   Network drive. Under SYSTEM the share is usually unreachable or'
                Write-Log '   unauthenticated, so no size is returned. Check it as the user.' }
            3 { Write-Log '   LOCAL disk with no size -- this one is worth investigating. Check'
                Write-Log '   section 4 for a BitLocker Locked status, and section 3 for a RAW'
                Write-Log '   partition or a disk that is not Online.' }
            1 { Write-Log '   Drive letter assigned with no root directory -- typically a stale'
                Write-Log '   mapping or an ejected device that kept its letter.' }
            default { Write-Log '   Unrecognised drive type; see sections 2 and 3 for context.' }
        }
    }
}

# CSV for fleet rollup
if (-not (Test-Path $CsvFile)) {
    Add-Content -Path $CsvFile -Value 'Timestamp,Host,Drive,Type,FileSystem,TotalBytes,UsedBytes,FreeBytes' -ErrorAction SilentlyContinue
}
foreach ($d in $logical) {
    $size = if ($null -eq $d.Size) { '' } else { $d.Size }
    $free = if ($null -eq $d.FreeSpace) { '' } else { $d.FreeSpace }
    $used = if ($null -ne $d.Size -and $null -ne $d.FreeSpace) { $d.Size - $d.FreeSpace } else { '' }
    Add-Content -Path $CsvFile -Value ((Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ',' + $env:COMPUTERNAME + ',' +
        $d.DeviceID + ',' + $DriveTypeName[[int]$d.DriveType] + ',' + ('' + $d.FileSystem) + ',' +
        $size + ',' + $used + ',' + $free) -ErrorAction SilentlyContinue
}

Write-Log ''
Write-Log (' Log: ' + $LogFile)
Write-Log (' CSV: ' + $CsvFile)
Write-Log '=============================================='
if ($noSize.Count -gt 0) { exit 2 }
exit 0
