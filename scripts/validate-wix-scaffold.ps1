#Requires -Version 5.1
<#
.SYNOPSIS
    Validate WiX scaffold XML is well-formed (runs on windows-latest CI, no WiX build).
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$ProductWxs = Join-Path $RepoRoot "deploy\windows\wix\Product.wxs"

if (-not (Test-Path -LiteralPath $ProductWxs)) {
    throw "Missing $ProductWxs"
}

[xml]$null = Get-Content -LiteralPath $ProductWxs
Write-Host "WiX scaffold XML is well-formed: $ProductWxs"
