---
title: DISK-RB-009 — Dreamer wiki sync via Disk Arcana
created: 2026-07-21
task: DISK-0011
status: draft
operator_gate: true
---

# DISK-RB-009 — Dreamer wiki sync via Disk Arcana

Operator playbook to replace Google Drive / interim rsync for the Arcanada KB
`wiki/` tree with Disk Arcana bidirectional sync, so **Agent Dreamer** ingests
from the server-side copy (`/var/lib/disk-arcana/wiki/` or equivalent).

**Agent-deliverable on DEVS:** hardcoded `.dreamer` deny, example config, this
runbook. **Live prod cutover** remains operator-gated (server install, ACL, e2e).

## Goals (DISK-0001 §Phase 10)

| # | Criterion |
|---|-----------|
| 1 | `wiki/` syncs macOS ↔ server via Disk Arcana (not Google Drive) |
| 2 | Dreamer reads server-side `wiki/` only |
| 3 | Workflow dirs excluded: `.dreamer/`, `node_modules/`, `.git` |
| 4 | New file in `_raw_/` on Mac → server ≤10s → Dreamer ingest ≤1 min → page visible on Mac |

## Preconditions

- Disk Arcana server running on prod (DISK-0005) with ACL for both nodes
- macOS node enrolled (DISK-RB-001)
- DEVS node enrolled if bi-directional KB editing from arcana-dev is required
- Tailscale / firewall: `:9443` mTLS between nodes and server

## Ignore policy

| Path | Mechanism |
|------|-----------|
| `.git` | Hardcoded deny (`disk-core` scanner) |
| `.disk-archive` | Hardcoded deny |
| `.dreamer` | Hardcoded deny (DISK-0011) |
| `node_modules/` | `share.filter.exclude` in `disk.toml` |
| `.meta/`, `.claude/` | `share.filter.exclude` (recommended) |

Example: `deploy/examples/dreamer-wiki.disk.toml`

## Procedure

### 1. Declare wiki share (each node)

```bash
disk share init --preset collaborate --name wiki \
  --path /home/dev/arcanada/wiki \
  --config /etc/disk-arcana/disk.toml
```

On macOS operator laptop, use the Mac vault path (e.g. `/Users/ug/arcanada/wiki`).

Merge `[share.filter]` block from the example TOML; restart daemon.

### 2. Server ACL

Provision `disk-acl.yaml` rows for `wiki` share on both node certificates
(DISK-RB-001 §4). Directions: mac bidirectional, server vault receive+send as designed.

### 3. Cutover from Google Drive / rsync

1. Stop Google Drive File Stream sync for `wiki/` (operator).
2. Ensure single writer — no parallel Syncthing/rsync on same tree.
3. One-shot baseline: `disk import-state --from-rsync …` if migrating from Hermes MVP (optional).
4. Start Disk Arcana daemons; verify `/status` shows `wiki` share `idle` or `syncing`.

### 4. Point Dreamer at server wiki

Dreamer ingest root MUST be the server path (e.g. `/var/lib/disk-arcana/wiki/`), not
Google Drive mount. Update Agent Dreamer env / `AGENT-0062` migration config on
arcana-ai per operator runbook (out of repo scope).

### 5. E2E validation

1. Create `wiki/_raw_/smoke-disk-0011.md` on macOS with unique marker.
2. Within 10s: file visible on server under wiki share root.
3. Within 1 min: Dreamer processes → structured page appears under `wiki/`.
4. Within next sync cycle: page visible back on macOS.

### 6. Rollback

Re-enable previous sync channel only after stopping Disk Arcana share (avoid dual-writer).
See DISK-RB-003 cutover notes for rsync MVP rollback.

## WWW / landing gap

DISK-0010 `deploy/www/` rsync to `disk.arcanada.ai` is documented in
`deploy/www/README.md` — not automated without WWW SSH (operator).

## Related

- ADR-0001 File Sync Policy — workflow state exclusions
- DISK-RB-001 Enroll, DISK-RB-003 Cutover
- `deploy/examples/dreamer-wiki.disk.toml`
- Parent: `datarim/plans/DISK-0011-plan.md`
