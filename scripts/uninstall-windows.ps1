#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Remove Disk Arcana Windows service and install paths (DISK-0013).

.DESCRIPTION
    Stops and deletes the DiskArcana service, removes the Program Files binary,
    and optionally removes ProgramData (config/state). Default keeps ProgramData
    so operators can re-install without re-enrolling.

.PARAMETER PurgeConfig
    Also remove C:\ProgramData\disk-arcana\ (destructive — includes meta.db).
#>
[CmdletBinding()]
param(
    [switch]$PurgeConfig
)

$ErrorActionPreference = "Stop"

$InstallDir = "C:\Program Files\Disk Arcana"
$ConfigDir  = "C:\ProgramData\disk-arcana"
$ServiceName = "DiskArcana"

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "==> stopping $ServiceName"
    if ($svc.Status -eq "Running") {
        Stop-Service -Name $ServiceName -Force
    }
    Write-Host "==> deleting service $ServiceName"
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

if (Test-Path -LiteralPath $InstallDir) {
    Write-Host "==> removing $InstallDir"
    Remove-Item -LiteralPath $InstallDir -Recurse -Force
}

if ($PurgeConfig) {
    if (Test-Path -LiteralPath $ConfigDir) {
        Write-Host "==> purging $ConfigDir"
        Remove-Item -LiteralPath $ConfigDir -Recurse -Force
    }
} else {
    Write-Host "==> keeping $ConfigDir (re-run with -PurgeConfig to delete)"
}

Write-Host "==> uninstall complete"
