#Requires -Version 5.1
<#
.SYNOPSIS
    Non-admin Windows smoke test for Disk Arcana (DISK-0013 Phase 4).

.DESCRIPTION
    Exercises CLI validate + foreground daemon REST /status on windows-latest CI
    without registering a Windows Service (no elevation required).

    NOT covered here (documented gap — requires operator Windows VM):
    - install-windows.ps1 service registration
    - enroll + gRPC sync against a live server

.PARAMETER Binary
    Path to disk.exe (release build).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Binary
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $Binary)) {
    throw "Binary not found: $Binary"
}

Write-Host "==> smoke: disk --help"
& $Binary --help | Out-Null

$Root = Join-Path $env:TEMP "disk-smoke-$PID"
$ShareDir = Join-Path $Root "share"
$StateDir = Join-Path $Root "state"
$ConfigFile = Join-Path $Root "disk.toml"
$StdoutLog = Join-Path $Root "daemon.stdout.log"
$StderrLog = Join-Path $Root "daemon.stderr.log"

if (Test-Path -LiteralPath $Root) {
    Remove-Item -LiteralPath $Root -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $ShareDir, $StateDir | Out-Null
Set-Content -Path (Join-Path $ShareDir "note.md") -Value "smoke" -Encoding UTF8

$sharePath = $ShareDir.Replace('\', '\\')
$config = @"
[node]
id = "windows-smoke"
[node.default]
intended_direction = "bidirectional"

[server]
address = "127.0.0.1:1"
client_cert = "C:\\ProgramData\\disk-arcana\\client.crt"
client_key  = "C:\\ProgramData\\disk-arcana\\client.key"

[[share]]
name = "wiki"
path = "$sharePath"
"@
Set-Content -Path $ConfigFile -Value $config -Encoding UTF8

Write-Host "==> smoke: disk config validate"
& $Binary config validate --file $ConfigFile
if ($LASTEXITCODE -ne 0) {
    throw "disk config validate failed with exit code $LASTEXITCODE"
}

Write-Host "==> smoke: daemon foreground + GET /status"
$daemon = Start-Process -FilePath $Binary -ArgumentList @(
    "daemon", "start", "--foreground",
    "--status-bind", "127.0.0.1:0",
    "--config", $ConfigFile,
    "--state-dir", $StateDir
) -PassThru -RedirectStandardOutput $StdoutLog -RedirectStandardError $StderrLog -NoNewWindow

$port = $null
for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep -Milliseconds 500
    if (Test-Path -LiteralPath $StdoutLog) {
        $lines = Get-Content -LiteralPath $StdoutLog -ErrorAction SilentlyContinue
        foreach ($line in $lines) {
            if ($line -match 'listening on 127\.0\.0\.1:(\d+)') {
                $port = [int]$Matches[1]
                break
            }
        }
    }
    if ($null -ne $port) { break }
    if ($daemon.HasExited) { break }
}

if ($null -eq $port) {
    if (Test-Path -LiteralPath $StderrLog) {
        Write-Host "--- daemon stderr ---"
        Get-Content -LiteralPath $StderrLog
    }
    if (Test-Path -LiteralPath $StdoutLog) {
        Write-Host "--- daemon stdout ---"
        Get-Content -LiteralPath $StdoutLog
    }
    throw "daemon did not print listening port within 30s (exit=$($daemon.ExitCode))"
}

$statusUrl = "http://127.0.0.1:$port/status"
$resp = Invoke-WebRequest -Uri $statusUrl -UseBasicParsing -TimeoutSec 10
if ($resp.StatusCode -ne 200) {
    throw "GET /status returned HTTP $($resp.StatusCode)"
}
if ($resp.Content -notmatch 'windows-smoke') {
    throw "status JSON missing node id windows-smoke: $($resp.Content)"
}

Write-Host "    OK — $statusUrl returned node windows-smoke"

if (-not $daemon.HasExited) {
    Stop-Process -Id $daemon.Id -Force -ErrorAction SilentlyContinue
    Wait-Process -Id $daemon.Id -ErrorAction SilentlyContinue
}

Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "==> smoke PASSED"
