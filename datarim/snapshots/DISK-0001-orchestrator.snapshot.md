# DISK-0001 orchestrator snapshot

**Date:** 2026-07-22  
**Repo:** `Arcanada-one/disk-arcana` @ main (post DISK-0028 slice 4)

## Closed this sprint (verified on main)

| ID | Summary | Evidence |
|----|---------|----------|
| DISK-0044 | Enrollment bootstrap audit + RB-011 | `0a8e881`; dual listener DISK-0037 |
| DISK-0059 | Dev-flag lint skips comment lines | `90f2d05`; CI wired |
| DISK-0061 | Enrollment `tls_domain` | PR #109 `3cd6edc` |
| DISK-0053 | Multi-share conflict REST/CLI | PR #51 `c85d8d0` |
| DISK-0062 | Daemon pull `x-disk-share` | PR #25 `0c79c65` |
| DISK-0063 | Server `DISK_SYNC_ROOT` create_dir_all | PR #27 |
| DISK-0064 | Upload error swallow twin | PR #26 |
| DISK-0015 | E2EE slices 1–5 (download decrypt) | PR #110 `37d67db` |
| DISK-0028 | AI Agents API slice 4 — gRPC `sync.file_*` webhooks | this pass |

## Backlog audit DISK-0008..0032 (2026-07-22)

KB `datarim/backlog.md` reconciled against `main`. All DISK-0016..0030 product scaffolds are **shipped on main** (slices per design docs). Stale `pending` rows corrected.

| ID | KB status | Notes |
|----|-----------|-------|
| 0008–0013, 0015, 0032 | done | unchanged |
| 0014 | skip | mobile v2.0 |
| 0016–0017, 0019–0030 | done | code on main; 0019/0021 do not rebuild |
| 0018 | skip | billing deferred per orchestrator |
| 0028 | done | slice 4 closes gRPC hook gap |

## In-flight (this orchestrator pass)

**DISK-0028 slice 4** — wire `AgentWebhookDispatcher` into `SyncServiceImpl`; dispatch `sync.file_changed` on `DeltaUpload`, `sync.file_deleted` on DeleteLocal tombstone.

## Operator gates (defer — not code)

- **Prod `:9445`** — timeout from DEVS; RB-011 sign-off; may be firewall or `DISK_CA_MODE=offline`
- **DISK-0006 R13** — hermes-artefacts cutover (DISK-RB-003), Mac operator
- **DISK-0057 P5-R** — live mesh KB sync rollout

## Skip list

DISK-0018 (billing), DISK-0014 (mobile), DISK-0055 (P3 GUI tech-debt), DISK-0015 slice 6+ (escrow)

## Next execute (orchestrator pick)

1. **DISK-0018** billing Stripe live mode (P0) — only unblocked MVP product gap; operator-gated secrets
2. Operator: R13 cutover when Mac available; RB-011 prod enroll
