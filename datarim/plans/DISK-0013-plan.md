---
taskId: DISK-0013
title: Windows Support (v2.0 prep)
status: in_progress
created: 2026-07-20
complexity: L2
prefix: DISK
parent: DISK-0001
phase: implementation
---

# DISK-0013 — Windows Support Implementation Plan

**Goal:** Ship a Windows-capable Disk Arcana **client** (`disk` CLI + daemon) with CI
coverage, stable rename identity, operator install path, portable release artifact,
and documented gaps for live VM sync e2e.

**Parent:** `DISK-0001` §Phase 12 (Windows Support). **Branch:**
`DISK-0013-phase1`. **PR:** #39 (do not merge until operator lifts hard-gate).

**Out of scope (this task):** MSI (`cargo-wix`), in-process `windows-service`
crate, full client↔server sync cycle on a dedicated Windows VM, Obsidian desktop
validation on Windows.

---

## Phase map

| Phase | Scope | Status | Anchor commit |
|-------|--------|--------|---------------|
| **1** | `windows-latest` CI matrix; `platform.rs` groundwork; `\\?\` path normalize; Windows IT fixture paths | **Done** | `5017b6d` |
| **2** | `FILE_ID_INFO` rename identity via `file-id` crate; scanner wired; Windows rename IT | **Done** | `7a5bb5e` |
| **3** | `paths.rs` ProgramData defaults; `install-windows.ps1`; `bundle-windows.ps1`; CI portable zip artifact | **Done** | `f7e5111` |
| **4** | `test-windows-smoke.ps1` in CI; Windows client job on tag release; formalize this plan; document VM e2e gap | **Done** | `1bddd8f` |

---

## Phase 1 — CI + path groundwork (done)

1. Add `.github/workflows/windows.yml` (`x86_64-pc-windows-msvc`: fmt, clippy, test, build).
2. Add `disk-core::platform` with extended-length path normalization.
3. Fix integration/unit tests that embedded Unix-only `disk.toml` paths.

**Deliverable:** Green Windows workflow on every PR.

---

## Phase 2 — FILE_ID_INFO identity (done)

1. Depend on `file-id` crate (`#![forbid(unsafe_code)]` safe).
2. `platform::inode_from_path` + `encode_file_id` → `FileMeta.inode` wire field.
3. Scanner (`walk.rs`) calls platform helper instead of `creation_time` fallback.
4. `#[cfg(windows)]` rename regression in `scanner_e2e.rs`.

**Deliverable:** Rename detection uses stable Windows file IDs, not creation time.

---

## Phase 3 — Install + portable bundle (done)

1. `crates/disk-cli/src/paths.rs` — defaults under `C:\ProgramData\disk-arcana\`.
2. `scripts/install-windows.ps1` — copies binary, provisions ProgramData, registers
   `DiskArcana` service via `sc.exe`, smoke-checks `http://127.0.0.1:9444/status`.
3. `scripts/bundle-windows.ps1` — portable zip for manual install.
4. Windows CI uploads `disk-windows-portable-x86_64-pc-windows-msvc` artifact.

**Deliverable:** Operator can install from zip or run install script on a Windows host.

---

## Phase 4 — E2E smoke prep + release (this phase)

### 4.1 CI smoke (`scripts/test-windows-smoke.ps1`)

Runs on `windows-latest` **without** admin / Windows Service:

1. `disk --help`
2. Write temp `disk.toml` with Windows-absolute share + cert paths
3. `disk config validate --file …`
4. Spawn `disk daemon start --foreground --status-bind 127.0.0.1:0`, parse
   listening port from stdout, `GET /status`, assert node id in JSON
5. Stop daemon process

Wired into `.github/workflows/windows.yml` after release build.

### 4.2 Release workflow Windows job

Add `build-windows-client` job to `.github/workflows/release-deploy.yml` on
`refs/tags/v*.*.*`:

- Build `disk` release binary on `windows-latest`
- Run `bundle-windows.ps1` with tag version label
- Attach `disk-arcana-windows-x86_64.zip` to GitHub Release (alongside Linux server binary)

**Note:** Linux server build remains on self-hosted runner; Windows client build uses
GitHub-hosted `windows-latest` (no cross-compile from DEVS required).

### 4.3 Documentation / gaps

| Gap | Reason | Follow-up |
|-----|--------|-----------|
| Live Windows VM full sync e2e | No managed Windows VM on DEVS fleet; `windows-latest` covers compile + smoke only | Operator-run on vika-pc or dedicated VM; extend smoke to enrolled node |
| `install-windows.ps1` in CI | Requires elevation (`#Requires -RunAsAdministrator`) | Manual / operator VM checklist in plan |
| MSI installer | Deferred; portable zip satisfies v2.0 prep | Optional DISK-0013-FU or Phase 5 |
| `windows-service` in-process | External `sc.exe` matches Linux systemd / macOS launchd pattern | Revisit only if service control needs Rust API |

---

## Verification matrix

| Check | Where | Phase |
|-------|-------|-------|
| `cargo test --target x86_64-pc-windows-msvc` | windows.yml | 1+ |
| `scan_preserves_file_id_across_rename` | windows.yml test | 2 |
| Portable zip artifact | windows.yml upload | 3 |
| `test-windows-smoke.ps1` | windows.yml | 4 |
| Release zip on tag | release-deploy.yml | 4 |
| VM install + sync cycle | **Manual / blocked** | — |

---

## Operator checklist (post-merge, on Windows host)

1. Download `disk-arcana-windows-x86_64.zip` from Release or CI artifact.
2. `.\disk.exe config validate --file disk.toml.example` (after editing paths).
3. Admin PowerShell: `.\install-windows.ps1 -Binary .\disk.exe`
4. `Invoke-WebRequest http://127.0.0.1:9444/status`
5. Enroll + share init per `DISK-RB-001`; verify sync against dev server (manual).

---

## References

- Parent plan: `datarim/plans/DISK-0001-plan.md` §Phase 12
- PRD: `datarim/prd/PRD-DISK-0001-disk-arcana.md`
- Linux install parity: `scripts/install-linux.sh`, `deploy/linux/disk-arcana.service`
