# Windows deploy assets (DISK-0013)

## Supported install paths

| Method | Script | Operator gate |
|--------|--------|---------------|
| Portable zip | `scripts/bundle-windows.ps1` | None (CI builds zip) |
| Service install | `scripts/install-windows.ps1` | Admin PowerShell on Windows host |
| MSI (scaffold) | `deploy/windows/wix/` + `scripts/build-msi.ps1` | **Windows host + WiX Toolset** — not built in CI yet |

Default paths match `crates/disk-cli/src/paths.rs`:

- Binary: `C:\Program Files\Disk Arcana\disk.exe`
- Config: `C:\ProgramData\disk-arcana\disk.toml`
- State: `C:\ProgramData\disk-arcana\state\`
- Service name: `DiskArcana`

## MSI scaffold (Phase 5 — not production-ready)

The WiX sources under `wix/` are a **template** for future `cargo-wix` or
WiX Toolset builds. Building an `.msi` requires:

1. Windows host (cannot link MSI on Linux DEVS)
2. [WiX Toolset v3.14+](https://wixtoolset.org/) (`candle.exe`, `light.exe`) **or**
   `cargo install cargo-wix` on Windows

```powershell
# On a Windows build machine, after cargo build --release -p disk-cli:
.\scripts\build-msi.ps1 -Binary .\target\x86_64-pc-windows-msvc\release\disk.exe -Version 0.1.0
```

Output: `dist\DiskArcana-client-<version>-x64.msi` (when WiX is installed).

**Operator gate:** signing the MSI for SmartScreen / enterprise deployment is
out of scope for DISK-0013; use portable zip until signed MSI is requested.

## VM validation

See `docs/runbooks/DISK-RB-008-windows-vm-e2e.md`.
