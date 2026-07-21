---
taskId: DISK-0011
title: Agent Dreamer Integration
status: done
created: 2026-07-21
merged: 2026-07-21
merge_commit: ddab6d9
pr: 44
complexity: L2
prefix: DISK
parent: DISK-0001
phase: implementation
branch: DISK-0011-dreamer
---

# DISK-0011 — Agent Dreamer Integration Plan

**Parent:** DISK-0001 §Phase 10. **Goal:** `wiki/` synced via Disk Arcana; Dreamer reads server copy.

## Phase map

| Phase | Scope | Status | Owner |
|-------|--------|--------|-------|
| **1** | Hardcoded `.dreamer` deny; example `disk.toml`; RB-009 playbook | **Done (agent)** | DEVS |
| **2** | Prod server wiki share + ACL | **Operator** | Ops |
| **3** | macOS + DEVS enroll + collaborate share | **Operator** | Ops |
| **4** | Dreamer `AGENT-0062` path → server wiki | **Operator** | Ops |
| **5** | E2E smoke (_raw_ → Dreamer → sync back) | **Operator** | Ops |
| **6** | Retire Google Drive docs | **Operator** | Ops |

## Agent deliverables (this branch)

- `crates/disk-core/src/filter.rs` — `.dreamer` in `HARDCODED_DENY_SEGMENTS`
- `deploy/examples/dreamer-wiki.disk.toml`
- `docs/runbooks/DISK-RB-009-dreamer-wiki-sync.md`

## Operator gates

- Live sync / prod deploy / Dreamer env change
- WWW rsync (DISK-0010) — see `deploy/www/README.md`

## References

- ADR-0001 workflow exclusions
- Prior Hermes MVP archive: `documentation/archive/disk/archive-DISK-0011.md` (KB)
- AGENT-0062 Dreamer server migration (backlog)
