# DISK-0001 orchestrator snapshot

**Date:** 2026-08-04  
**State:** **PARKED** — DISK-0070/0071 closed; orchestrator idle

## Fleet status

| Host / lane | Verdict |
|-------------|---------|
| arcana-agents `:9543` mesh | **PASS** (PID 3993652, shares=2 watchers) |
| Mac R13 consumer | **PASS** (both shares syncing, Mach-O arm64) |
| DISK-0070 | **done** 2026-08-04 |
| DISK-0071 | **done** 2026-08-04 |
| DISK-0067–0069 | **done** |

RB-011 **not opened**.

## DISK-0070 closure evidence

- `DISK_SHARE_ROOTS` includes `datarim-kb` + `hermes-artefacts`; startup log `shares=2`
- Probe `reports/DISK-0070-replication-probe-20260804T1145Z.txt` indexed `deleted=0` within 4s

## DISK-0071 closure evidence

- 19 tombstoned rows with bytes on disk revived via index upsert (touch)
- 376 tombstoned rows remain where file absent (legitimate deletes)
- Rename-over-target fix in main (#151); server running `disk0071` build

## Mac (operator 2026-08-04)

- `datarim-kb` + `hermes-artefacts`: **syncing**, no `server_unreachable`
- Native arm64 `~/.local/bin/disk` only

## Track B research

`datarim/research/DISK-company-drive-azure-blob-2026-08-04.md` — **NO-GO** full Nextcloud replacement; **PILOT** for bounded PoC.

## Next (operator gates only)

- `release-deploy.yml` arcana-agents job (RB-012) for reproducible server updates
- DISK-0057 long-run / INFRA rsync migration — backlog, not orchestrator-active
