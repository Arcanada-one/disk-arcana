#Requires -Version 5.1
<#
.SYNOPSIS
    Build a portable Windows zip for Disk Arcana (DISK-0013 Phase 3).

.PARAMETER Binary
    Path to the built disk.exe (release).

.PARAMETER OutDir
    Directory that will receive disk-arcana-windows-x86_64.zip

.PARAMETER Version
    Optional version label embedded in the archive root folder name.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Binary,
    [string]$OutDir = "dist",
    [string]$Version = "dev"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $Binary)) {
    throw "Binary not found: $Binary"
}

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$StageName = "disk-arcana-windows-x86_64-$Version"
$StageDir = Join-Path ([System.IO.Path]::GetTempPath()) $StageName
$ZipPath = Join-Path $OutDir "disk-arcana-windows-x86_64.zip"

if (Test-Path -LiteralPath $StageDir) {
    Remove-Item -LiteralPath $StageDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $StageDir, $OutDir | Out-Null

Copy-Item -LiteralPath $Binary -Destination (Join-Path $StageDir "disk.exe")
Copy-Item -LiteralPath (Join-Path $RepoRoot "disk.toml.example") -Destination (Join-Path $StageDir "disk.toml.example")
Copy-Item -LiteralPath (Join-Path $RepoRoot "scripts\install-windows.ps1") -Destination (Join-Path $StageDir "install-windows.ps1")

@"
Disk Arcana — Windows portable bundle
=====================================

1. Extract this folder anywhere.
2. Edit disk.toml.example -> C:\ProgramData\disk-arcana\disk.toml (or run install-windows.ps1 as Administrator).
3. Run: .\disk.exe config validate --file disk.toml.example
4. For a managed install + Windows service: open PowerShell as Administrator and run .\install-windows.ps1 -Binary .\disk.exe

Loopback status (when daemon is running): http://127.0.0.1:9444/status
"@ | Set-Content -Path (Join-Path $StageDir "README-windows.txt") -Encoding UTF8

if (Test-Path -LiteralPath $ZipPath) {
    Remove-Item -LiteralPath $ZipPath -Force
}
Compress-Archive -Path (Join-Path $StageDir "*") -DestinationPath $ZipPath -Force
Remove-Item -LiteralPath $StageDir -Recurse -Force

Write-Host "Created $ZipPath"
Get-Item -LiteralPath $ZipPath | Format-List Name, Length, LastWriteTime
