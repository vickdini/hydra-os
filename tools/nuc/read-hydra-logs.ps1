# Reads Hydra's boot logs off the Hydra USB stick into a folder and a zip file on the Desktop.
# READ ONLY: the stick is opened for reading; nothing on it is changed.
#
# Windows hides the stick's EFI partition (where Hydra writes \logs), so this script reads it
# directly: it finds the stick by its layout (partition 1 an EFI partition, partition 2 a Hydra
# pool partition), reads the FAT32 file system itself and copies the folder "logs" with its
# subfolders.
#
# Use: right-click "read-hydra-logs.cmd" > "Run as administrator" (or, in an administrator
# PowerShell: powershell -ExecutionPolicy Bypass -File read-hydra-logs.ps1)
# For developers: -Image FILE reads an image file instead (an EFI partition image, or a whole
# stick image with -Offset 1048576), -Out FOLDER writes there instead of the Desktop.
param([string]$Image, [int64]$Offset = 0, [string]$Out)
$ErrorActionPreference = 'Stop'

$EspType  = '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
$PoolType = '{7685a0b8-df41-47eb-af4f-02ce6fb01879}'

function Find-HydraStick {
    $found = @()
    foreach ($d in Get-Disk) {
        if ($d.PartitionStyle -ne 'GPT') { continue }
        $parts = @(Get-Partition -DiskNumber $d.Number -ErrorAction SilentlyContinue)
        $p1 = $parts | Where-Object { $_.PartitionNumber -eq 1 }
        $p2 = $parts | Where-Object { $_.PartitionNumber -eq 2 }
        if ($p1 -and $p2 -and $p1.GptType -eq $EspType -and $p2.GptType -eq $PoolType -and $p1.Size -le 1GB) {
            $found += [pscustomobject]@{ Disk = $d; Esp = $p1 }
        }
    }
    return $found
}

if ($Image) {
    $dev = [System.IO.FileStream]::new((Resolve-Path $Image).Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    $base = $Offset
} else {
$sticks = @(Find-HydraStick)
if ($sticks.Count -eq 0) { throw "No Hydra stick found. Plug it in (and close Rufus), then run this again." }
if ($sticks.Count -gt 1) { Write-Host "More than one Hydra disk found; using the first USB one." }
$stick = ($sticks | Where-Object { $_.Disk.BusType -eq 'USB' } | Select-Object -First 1)
if (-not $stick) { $stick = $sticks[0] }
$disk = $stick.Disk; $esp = $stick.Esp
Write-Host ("Hydra stick: disk {0} ({1}), EFI partition {2} MB" -f $disk.Number, $disk.FriendlyName, [math]::Round($esp.Size / 1MB))

$dev = [System.IO.FileStream]::new("\\.\PhysicalDrive$($disk.Number)", [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
$base = [int64]$esp.Offset
}

# Reads $count bytes at byte $off of the partition (whole sectors: raw disks need them)
function Read-Bytes([int64]$off, [int]$count) {
    $start = [int64]([math]::Floor($off / 512) * 512)
    $len = [int]([math]::Ceiling(($off + $count - $start) / 512) * 512)
    $buf = New-Object byte[] $len
    $dev.Seek($base + $start, [System.IO.SeekOrigin]::Begin) | Out-Null
    $got = 0
    while ($got -lt $len) {
        $n = $dev.Read($buf, $got, $len - $got)
        if ($n -le 0) { throw "Read error on the stick." }
        $got += $n
    }
    $out = New-Object byte[] $count
    [Array]::Copy($buf, [int]($off - $start), $out, 0, $count)
    return ,$out
}

try {
    $bs = Read-Bytes 0 512
    if ($bs[510] -ne 0x55 -or $bs[511] -ne 0xAA) { throw "The EFI partition has no FAT boot sector." }
    $bps = [BitConverter]::ToUInt16($bs, 11); $spc = $bs[13]; $rsv = [BitConverter]::ToUInt16($bs, 14)
    $nfat = $bs[16]; $fatsz = [BitConverter]::ToUInt32($bs, 36); $rootclus = [BitConverter]::ToUInt32($bs, 44)
    if ($bps -eq 0 -or $spc -eq 0 -or $fatsz -eq 0) { throw "The EFI partition is not FAT32." }
    $clusBytes = [int]($bps * $spc)
    $fatOff = [int64]$rsv * $bps
    $dataOff = ([int64]$rsv + [int64]$nfat * $fatsz) * $bps

    function Get-Chain([uint32]$first) {
        $chain = New-Object System.Collections.Generic.List[uint32]
        $c = $first
        while ($c -ge 2 -and $c -lt 0x0FFFFFF8 -and $chain.Count -lt 1000000) {
            $chain.Add($c)
            $e = Read-Bytes ($fatOff + [int64]$c * 4) 4
            $c = [BitConverter]::ToUInt32($e, 0) -band 0x0FFFFFFF
        }
        return ,$chain
    }
    function Read-Chain([uint32]$first, [int64]$size) {
        $ms = New-Object System.IO.MemoryStream
        foreach ($c in (Get-Chain $first)) {
            $b = Read-Bytes ($dataOff + ([int64]$c - 2) * $clusBytes) $clusBytes
            $ms.Write($b, 0, $b.Length)
            if ($size -ge 0 -and $ms.Length -ge $size) { break }
        }
        $all = $ms.ToArray()
        if ($size -ge 0 -and $all.Length -gt $size) { $all = $all[0..([int]$size - 1)] }
        return ,$all
    }
    # The entries of the directory at cluster $first: name, directory?, first cluster, size
    function Get-Entries([uint32]$first) {
        $data = Read-Chain $first -1
        $list = @()
        for ($i = 0; $i + 32 -le $data.Length; $i += 32) {
            $b0 = $data[$i]
            if ($b0 -eq 0) { break }
            if ($b0 -eq 0xE5) { continue }
            $attr = $data[$i + 11]
            if (($attr -band 0x0F) -eq 0x0F -or ($attr -band 0x08)) { continue }
            $nm = [System.Text.Encoding]::ASCII.GetString($data, $i, 8).TrimEnd()
            $ex = [System.Text.Encoding]::ASCII.GetString($data, $i + 8, 3).TrimEnd()
            if ($data[$i + 12] -band 0x08) { $nm = $nm.ToLower() }
            if ($data[$i + 12] -band 0x10) { $ex = $ex.ToLower() }
            $name = if ($ex) { "$nm.$ex" } else { $nm }
            if ($name -eq '.' -or $name -eq '..') { continue }
            $clus = ([uint32][BitConverter]::ToUInt16($data, $i + 20) -shl 16) -bor [BitConverter]::ToUInt16($data, $i + 26)
            $list += [pscustomobject]@{ Name = $name; Dir = [bool]($attr -band 0x10); Cluster = [uint32]$clus; Size = [BitConverter]::ToUInt32($data, $i + 28) }
        }
        return $list
    }
    function Copy-Dir([uint32]$cluster, [string]$to) {
        New-Item -ItemType Directory -Force -Path $to | Out-Null
        foreach ($e in (Get-Entries $cluster)) {
            $target = Join-Path $to $e.Name
            if ($e.Dir) { Copy-Dir $e.Cluster $target }
            elseif ($e.Size -gt 0) { [System.IO.File]::WriteAllBytes($target, (Read-Chain $e.Cluster ([int64]$e.Size))); Write-Host "  $target" }
        }
    }

    $logs = Get-Entries $rootclus | Where-Object { $_.Dir -and $_.Name -ieq 'logs' } | Select-Object -First 1
    if (-not $logs) { throw "The stick has no logs folder yet (Hydra never got far enough to write one)." }
    $desk = if ($Out) { $Out } else { [Environment]::GetFolderPath('Desktop') }
    $out = Join-Path $desk ("hydra-logs-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
    Write-Host "Copying the logs to $out"
    Copy-Dir $logs.Cluster $out
    $zip = "$out.zip"
    Compress-Archive -Path (Join-Path $out '*') -DestinationPath $zip -Force
    Write-Host ""
    Write-Host "Done. Please send this file back: $zip"
} finally {
    $dev.Close()
}
if (-not $Image) { Read-Host "Press Enter to close" }
