#Requires -Version 5.1
<#
.SYNOPSIS
    Build Disk Arcana client MSI from WiX scaffold (Windows host only).

.DESCRIPTION
    Scaffold only — requires WiX Toolset (candle.exe + light.exe) on PATH.
    Cannot run on Linux DEVS. Operator executes on a Windows build VM.

.PARAMETER Binary
    Path to built disk.exe

.PARAMETER Version
    MSI product version (x.x.x.x)

.PARAMETER OutDir
    Output directory for .msi
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Binary,
    [string]$Version = "0.1.0.0",
    [string]$OutDir = "dist"
)

$ErrorActionPreference = "Stop"

if ($PSVersionTable.PSVersion.Major -lt 5) {
    throw "PowerShell 5.1+ required"
}

if (-not (Test-Path -LiteralPath $Binary)) {
    throw "Binary not found: $Binary"
}

$candle = Get-Command candle.exe -ErrorAction SilentlyContinue
$light = Get-Command light.exe -ErrorAction SilentlyContinue
if (-not $candle -or -not $light) {
    throw @"
WiX Toolset not found on PATH (candle.exe, light.exe).
Install WiX v3.14+ from https://wixtoolset.org/ or use portable zip instead.
This script is intentionally NOT run in CI — MSI build is operator-gated.
"@
}

$RepoRoot = Split-Path -Parent $PSScriptRoot
$WixDir = Join-Path $RepoRoot "deploy\windows\wix"
$ProductWxs = Join-Path $WixDir "Product.wxs"
if (-not (Test-Path -LiteralPath $ProductWxs)) {
    throw "Missing WiX source: $ProductWxs"
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Stage = Join-Path $env:TEMP "disk-wix-$PID"
if (Test-Path -LiteralPath $Stage) {
    Remove-Item -LiteralPath $Stage -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $Stage | Out-Null

Copy-Item -LiteralPath $ProductWxs -Destination (Join-Path $Stage "Product.wxs")
Copy-Item -LiteralPath $Binary -Destination (Join-Path $Stage "disk.exe")

# Patch version in staged wxs (simple replace — scaffold only)
$wxs = Get-Content -LiteralPath (Join-Path $Stage "Product.wxs") -Raw
$wxs = $wxs -replace 'Version="0\.1\.0\.0"', "Version=""$Version"""
Set-Content -LiteralPath (Join-Path $Stage "Product.wxs") -Value $wxs -Encoding UTF8

Push-Location $Stage
try {
    & candle.exe Product.wxs -out Product.wixobj
    if ($LASTEXITCODE -ne 0) { throw "candle failed" }
    $msiName = "DiskArcana-client-$Version-x64.msi"
    & light.exe Product.wixobj -out (Join-Path (Resolve-Path $OutDir) $msiName)
    if ($LASTEXITCODE -ne 0) { throw "light failed" }
    Write-Host "Created $(Join-Path $OutDir $msiName)"
} finally {
    Pop-Location
    Remove-Item -LiteralPath $Stage -Recurse -Force -ErrorAction SilentlyContinue
}
