[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot

if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    throw 'MSVC cl.exe was not found. Open an x64 Developer PowerShell from Visual Studio 2022.'
}
if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw 'The Python launcher (py -3) is required for the OID contract test.'
}

$outputDirectory = Join-Path $repoRoot 'target\local-ci-windows\driver-tests'
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
$testSources = @(
    'driver\tests\test_ip_packet_validation.c',
    'driver\tests\test_mtu_config.c',
    'driver\tests\test_rx_pause_state.c',
    'driver\tests\test_tx_packet_queue.c'
)

foreach ($source in $testSources) {
    $name = [IO.Path]::GetFileNameWithoutExtension($source)
    $executable = Join-Path $outputDirectory "$name.exe"
    $objectFile = Join-Path $outputDirectory "$name.obj"
    Write-Host "Compile portable C contract test with MSVC: $source"
    $arguments = @('/nologo', '/W4', '/WX', '/std:c11', '/TC', "/Fo$objectFile", "/Fe$executable", $source)
    & cl.exe @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "MSVC failed to compile $source (exit $LASTEXITCODE)."
    }

    Write-Host "Run $name.exe"
    & $executable
    if ($LASTEXITCODE -ne 0) {
        throw "$name.exe failed (exit $LASTEXITCODE)."
    }
}

Write-Host 'Run Python OID/INF source contract test'
& py -3 driver\tests\test_oid_contract.py
if ($LASTEXITCODE -ne 0) {
    throw "OID/INF contract tests failed (exit $LASTEXITCODE)."
}

Write-Host 'Windows portable driver packet/OID contract tests passed (MSVC strict warnings; no ASan/UBSan instrumentation).'
