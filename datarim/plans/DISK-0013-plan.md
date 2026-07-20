---
taskId: DISK-0013
title: Windows Support (v2.0 prep)
status: pending_operator_gates
created: 2026-07-20
complexity: L2
prefix: DISK
parent: DISK-0001
phase: implementation
---

# DISK-0013 — Windows Support Implementation Plan

**Goal:** Ship a Windows-capable Disk Arcana **client** (`disk` CLI + daemon) with CI
coverage, stable rename identity, operator install path, portable release artifact,
documented VM validation playbook, and MSI scaffold for a future signed release.

**Parent:** `DISK-0001` §Phase 12 (Windows Support). **Branch:**
`DISK-0013-phase1`. **PR:** #39 (do not merge until operator lifts hard-gate).

**Agent-autonomous work complete through Phase 5.** Remaining items require operator:
merge PR, tag release, Windows VM e2e (DISK-RB-008), MSI build/sign on Windows host.

---

## Phase map

| Phase | Scope | Status | Anchor commit |
|-------|--------|--------|---------------|
| **1** | `windows-latest` CI matrix; `platform.rs` groundwork; `\\?\` path normalize; Windows IT fixture paths | **Done** | `5017b6d` |
| **2** | `FILE_ID_INFO` rename identity via `file-id` crate; scanner wired; Windows rename IT | **Done** | `7a5bb5e` |
| **3** | `paths.rs` ProgramData defaults; `install-windows.ps1`; `bundle-windows.ps1`; CI portable zip artifact | **Done** | `f7e5111` |
| **4** | `test-windows-smoke.ps1` in CI; Windows client job on tag release; formalize this plan; document VM e2e gap | **Done** | `1bddd8f` |
| **5** | VM e2e playbook (DISK-RB-008); MSI WiX scaffold; `uninstall-windows.ps1`; plan status | **Done** | `4662cfd` |

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

## Phase 4 — E2E smoke prep + release (done)

### 4.1 CI smoke (`scripts/test-windows-smoke.ps1`)

Runs on `windows-latest` **without** admin / Windows Service.

### 4.2 Release workflow Windows job

`build-windows-client` in `release-deploy.yml` on tag `v*.*.*`.

---

## Phase 5 — Docs + MSI scaffold (done, no operator)

### 5.1 VM e2e playbook

`docs/runbooks/DISK-RB-008-windows-vm-e2e.md` — operator checklist for install,
enroll, share, sync, rename validation on a Windows VM. **Not executed on DEVS.**

### 5.2 MSI scaffold (build deferred)

| Asset | Purpose |
|-------|---------|
| `deploy/windows/wix/Product.wxs` | WiX template (service custom action stub) |
| `scripts/build-msi.ps1` | Build on Windows when WiX Toolset installed |
| `scripts/validate-wix-scaffold.ps1` | XML well-formed check in CI (no WiX required) |
| `deploy/windows/README.md` | Operator notes |

### 5.3 Uninstall helper

`scripts/uninstall-windows.ps1` — stop/delete service, remove Program Files;
optional `-PurgeConfig` for ProgramData.

---

## Operator gates (STOP — agent cannot proceed)

| Gate | Action | Owner |
|------|--------|-------|
| **Merge PR #39** | Land Windows work to `main` | Operator |
| **Merge PR #38** | Queue integration (separate) | Operator |
| **Tag `v*.*.*`** | Trigger release zip attach | Operator |
| **DISK-RB-008 VM e2e** | Full enroll + sync on Windows host | Operator |
| **MSI build + sign** | Run `build-msi.ps1` on Windows + code signing | Operator |

---

## Verification matrix

| Check | Where | Phase |
|-------|-------|-------|
| `cargo test --target x86_64-pc-windows-msvc` | windows.yml | 1+ |
| `scan_preserves_file_id_across_rename` | windows.yml test | 2 |
| Portable zip artifact | windows.yml upload | 3 |
| `test-windows-smoke.ps1` | windows.yml | 4 |
| `validate-wix-scaffold.ps1` | windows.yml | 5 |
| Release zip on tag | release-deploy.yml | 4 |
| VM install + sync cycle | **DISK-RB-008 (operator)** | 5 |
| MSI `.msi` artifact | **Windows host (operator)** | 5 scaffold |

---

## Operator checklist (post-merge)

1. Merge PR #39 (after review).
2. Download zip from CI artifact or post-tag Release.
3. Follow **DISK-RB-008** on a Windows VM.
4. Optional: build MSI via `scripts/build-msi.ps1` when WiX is available.

---

## References

- Parent plan: `datarim/plans/DISK-0001-plan.md` §Phase 12
- VM playbook: `docs/runbooks/DISK-RB-008-windows-vm-e2e.md`
- Linux install parity: `scripts/install-linux.sh`, `deploy/linux/disk-arcana.service`
