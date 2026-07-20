# Windows platform notes (DISK-0013)

Engineering decisions and CI coverage for the Disk Arcana **client** on
`x86_64-pc-windows-msvc`. Parent: `datarim/plans/DISK-0013-plan.md` /
DISK-0001 §Phase 12.

## Phase 12 traceability (DISK-0001-plan)

| DISK-0001 §12 item | Implementation | Verified on |
|--------------------|----------------|-------------|
| Cross-compile `x86_64-pc-windows-msvc` | `.github/workflows/windows.yml` | `windows-latest` CI |
| File watcher (`notify` / `ReadDirectoryChangesW`) | `disk-client::watcher::FsWatcher` | `it_watcher_debounce.rs` on `windows-latest` |
| Rename identity (`FILE_ID_INFO`) | `file-id` crate → `platform::inode_from_path` | `scanner_e2e` `#[cfg(windows)]` rename IT |
| Long paths (`\\?\`) + UTF-16 | `disk-core::platform::normalize_path` | Unit tests + Windows IT fixtures |
| Installer (portable zip + MSI scaffold) | `bundle-windows.ps1`, WiX under `deploy/windows/` | CI zip artifact; WiX XML validated in CI |
| Windows Service | `install-windows.ps1` via `sc.exe` | Operator VM (DISK-RB-008); not in CI (admin) |
| CI `windows-latest` matrix | `windows.yml` | Every PR touching branch |
| Full sync cycle on Windows VM | DISK-RB-008 playbook | **Operator-gated** |

## Service hosting: `sc.exe` vs `windows-service` crate

**Decision (Phase 5):** keep `sc.exe` + foreground `disk daemon start --foreground`
for DISK-0013. Rationale:

- Matches Linux/macOS pattern (external supervisor owns lifecycle).
- No extra native crate dependency or SCM callback wiring in the binary.
- Portable zip + install script already document the operator path.

**Deferred:** embedding `windows-service` for in-process SCM integration — revisit
when MSI becomes the primary distribution channel or graceful shutdown hooks need
SCM stop signals. WiX scaffold already registers the same `binPath=` as
`install-windows.ps1`.

## Filesystem watcher

`notify::RecommendedWatcher` on Windows uses `ReadDirectoryChangesW` (notify 8.x).
Integration tests in `crates/disk-client/tests/it_watcher_debounce.rs` run on
`windows-latest` and assert create + debounce behaviour. No Windows-specific
watcher code path is required beyond canonical path handling in tests
(`canonicalize()` — same pattern as macOS `/private/var` symlinks).

## Paths and MetaDB

- CLI defaults: `crates/disk-cli/src/paths.rs` → `C:\ProgramData\disk-arcana\`.
- Stored relative paths use forward slashes (`5017b6d`) so lookups stay consistent
  across `strip_prefix` on Windows.

## Operator-only steps

| Step | Script / doc |
|------|----------------|
| Non-admin smoke | `scripts/test-windows-smoke.ps1` (CI) |
| Service install | `scripts/install-windows.ps1` (admin) |
| Uninstall | `scripts/uninstall-windows.ps1` |
| Full VM e2e | `docs/runbooks/DISK-RB-008-windows-vm-e2e.md` |
| MSI build | `scripts/build-msi.ps1` (WiX on Windows host) |
