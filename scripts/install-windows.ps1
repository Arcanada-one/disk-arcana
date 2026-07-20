#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Install the Disk Arcana client daemon as a Windows service (DISK-0013 Phase 3).

.DESCRIPTION
    - Copies disk.exe to "C:\Program Files\Disk Arcana\"
    - Provisions C:\ProgramData\disk-arcana\ (config, state, logs)
    - Registers the DiskArcana Windows service (auto-start)
    - Starts the service and waits for the loopback REST listener

.PARAMETER Binary
    Path to the release disk.exe (defaults to .\disk.exe in the current directory).

.PARAMETER SkipStart
    Register files + service but do not start the service (useful for CI dry-runs).
#>
[CmdletBinding()]
param(
    [string]$Binary = ".\disk.exe",
    [switch]$SkipStart
)

$ErrorActionPreference = "Stop"

$InstallDir = "C:\Program Files\Disk Arcana"
$ConfigDir  = "C:\ProgramData\disk-arcana"
$ConfigFile = Join-Path $ConfigDir "disk.toml"
$StateDir   = Join-Path $ConfigDir "state"
$LogDir     = Join-Path $ConfigDir "logs"
$ServiceName = "DiskArcana"
$RepoRoot   = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

if (-not (Test-Path -LiteralPath $Binary)) {
    throw "Binary not found or not executable: $Binary"
}

Write-Host "==> installing $Binary to $InstallDir\disk.exe"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -LiteralPath $Binary -Destination (Join-Path $InstallDir "disk.exe") -Force

Write-Host "==> provisioning $ConfigDir"
New-Item -ItemType Directory -Force -Path $ConfigDir, $StateDir, $LogDir | Out-Null

if (-not (Test-Path -LiteralPath $ConfigFile)) {
    $Example = Join-Path $RepoRoot "disk.toml.example"
    if (Test-Path -LiteralPath $Example) {
        Copy-Item -LiteralPath $Example -Destination $ConfigFile
        Write-Host "    seeded $ConfigFile from disk.toml.example (edit before production use)"
    } else {
        Write-Warning "disk.toml.example missing — create $ConfigFile before starting the service"
    }
}

$DaemonExe = Join-Path $InstallDir "disk.exe"
$BinPath = "`"$DaemonExe`" daemon start --foreground --config `"$ConfigFile`" --state-dir `"$StateDir`""

$Existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($Existing) {
    Write-Host "==> stopping and removing existing $ServiceName service"
    if ($Existing.Status -eq "Running") {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    }
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

Write-Host "==> registering Windows service $ServiceName"
sc.exe create $ServiceName binPath= $BinPath start= auto DisplayName= "Disk Arcana Client" | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "sc.exe create failed with exit code $LASTEXITCODE"
}
sc.exe description $ServiceName "Disk Arcana client daemon (gRPC sync + loopback REST :9444)" | Out-Null

if ($SkipStart) {
    Write-Host "==> SkipStart set — service registered but not started"
    exit 0
}

Write-Host "==> starting $ServiceName"
Start-Service -Name $ServiceName

Write-Host "==> waiting for loopback REST listener on 127.0.0.1:9444"
for ($i = 1; $i -le 30; $i++) {
    try {
        $resp = Invoke-WebRequest -Uri "http://127.0.0.1:9444/status" -UseBasicParsing -TimeoutSec 2
        if ($resp.StatusCode -eq 200) {
            Write-Host "    OK — daemon is up (HTTP $($resp.StatusCode))"
            Write-Host ""
            Write-Host "Done. Operator next steps:"
            Write-Host "  1. Edit $ConfigFile and run: Restart-Service $ServiceName"
            Write-Host "  2. Verify: Invoke-WebRequest http://127.0.0.1:9444/status"
            Write-Host "  3. Logs: Get-EventLog -LogName Application -Source $ServiceName (if configured)"
            exit 0
        }
    } catch {
        # Service may still be booting.
    }
    Start-Sleep -Seconds 1
}

Write-Host "warn: service did not answer /status within 30 s" -ForegroundColor Yellow
Get-Service -Name $ServiceName | Format-List *
exit 1
