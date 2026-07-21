---
taskId: DISK-0009
title: Archive Folders — compression, index, restore
status: done
created: 2026-07-21
merged: 2026-07-21
merge_commit: 4b7ff10
pr: 47
complexity: L2
prefix: DISK
parent: DISK-0001
branch: DISK-0009-archive
---

# DISK-0009 — Archive Folders Plan

**Parent:** DISK-0001. **Goal:** Compress folder trees into indexed `.disk-archive`
snapshots with safe restore.

## Phase map

| Phase | Scope | Status |
|-------|--------|--------|
| **1** | `disk_core::archive` create/index/restore | Done (PR #38) |
| **2** | Hardcoded `.disk-archive` scanner deny | Done |
| **3** | `disk archive` CLI (create/list/restore) | Done (this branch) |
| **4** | Docs + traversal test | Done |
| **5** | Daemon auto-archive on share | Deferred |

## Deliverables

| Item | Location |
|------|----------|
| Core library | `crates/disk-core/src/archive.rs` |
| CLI | `crates/disk-cli/src/archive_cmd.rs` |
| Operator doc | `docs/archive-folders.md` |

## Deferred

- Daemon-triggered archival when `[archive] enabled = true`
- Obsidian / GUI surfacing

## References

- Prior archive note: `documentation/archive/disk/archive-DISK-0009.md` (KB)
