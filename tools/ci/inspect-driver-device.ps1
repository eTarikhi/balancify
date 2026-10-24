[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$devicePath = '\\.\Balancify'
$ioctlGetStats = 0x00126004
$statsSize = 48

if (-not ('BalanciFyDriverNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class BalanciFyDriverNative
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    public static extern SafeFileHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DeviceIoControl(
        SafeFileHandle device,
        uint controlCode,
        IntPtr inputBuffer,
        uint inputBufferLength,
        [Out] byte[] outputBuffer,
        uint outputBufferLength,
        out uint bytesReturned,
        IntPtr overlapped);
}
'@
}

# The control-device DACL allows SYSTEM and Administrators only. This script
# opens with read access and issues GET_STATS only; it never injects or dequeues.
$handle = [BalanciFyDriverNative]::CreateFileW(
    $devicePath,
    [uint32]0x80000000, # GENERIC_READ
    [uint32]0,
    [IntPtr]::Zero,
    [uint32]3, # OPEN_EXISTING
    [uint32]0x80, # FILE_ATTRIBUTE_NORMAL
    [IntPtr]::Zero
)
if ($handle.IsInvalid) {
    $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if ($errorCode -eq 2 -or $errorCode -eq 3) {
        throw "BalanciFy control device '$devicePath' is not present. Install and start the test driver first."
    }
    if ($errorCode -eq 5) {
        throw 'Access denied. Open an elevated Administrator PowerShell; the driver DACL intentionally excludes unprivileged desktop users.'
    }
    if ($errorCode -eq 32) {
        throw 'The control device is already open exclusively. Stop the BalanciFy service process, then rerun this read-only preflight.'
    }
    throw [System.ComponentModel.Win32Exception]::new($errorCode, "Could not open $devicePath")
}

try {
    [byte[]]$buffer = [byte[]]::new($statsSize)
    [uint32]$bytesReturned = 0
    $ok = [BalanciFyDriverNative]::DeviceIoControl(
        $handle,
        [uint32]$ioctlGetStats,
        [IntPtr]::Zero,
        [uint32]0,
        $buffer,
        [uint32]$buffer.Length,
        [ref]$bytesReturned,
        [IntPtr]::Zero
    )
    if (-not $ok) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw [System.ComponentModel.Win32Exception]::new($errorCode, 'GET_STATS failed')
    }
    if ($bytesReturned -ne $statsSize) {
        throw "GET_STATS returned $bytesReturned bytes; expected $statsSize."
    }

    $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
    $evidence = [ordered]@{
        timestamp_utc = [DateTime]::UtcNow.ToString('o')
        computer_name = $env:COMPUTERNAME
        windows_caption = $operatingSystem.Caption
        windows_version = $operatingSystem.Version
        device_path = $devicePath
        operation = 'GET_STATS (read-only)'
        driver_stats = [ordered]@{
            tx_packets = [BitConverter]::ToUInt64($buffer, 0)
            rx_packets = [BitConverter]::ToUInt64($buffer, 8)
            tx_errors = [BitConverter]::ToUInt64($buffer, 16)
            tx_bytes = [BitConverter]::ToUInt64($buffer, 24)
            rx_bytes = [BitConverter]::ToUInt64($buffer, 32)
            mtu = [BitConverter]::ToUInt32($buffer, 40)
            paused = ($buffer[44] -ne 0)
        }
        scope = 'Device-open and GET_STATS smoke check only; no packet was injected or dequeued.'
    }

    $outputDirectory = Join-Path $repoRoot 'target\local-wdk\runtime-checks'
    New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
    $stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
    $outputPath = Join-Path $outputDirectory "driver-device-$stamp.json"
    $json = $evidence | ConvertTo-Json -Depth 5
    Set-Content -LiteralPath $outputPath -Value $json -Encoding utf8

    Write-Host "BalanciFy read-only driver-device check passed."
    Write-Host "MTU=$($evidence.driver_stats.mtu) Paused=$($evidence.driver_stats.paused) TxErrors=$($evidence.driver_stats.tx_errors)"
    Write-Host "Evidence: $outputPath"
    Write-Host 'This does not validate packet-path operation, signing, Driver Verifier, or HVCI.'
}
finally {
    $handle.Dispose()
}
