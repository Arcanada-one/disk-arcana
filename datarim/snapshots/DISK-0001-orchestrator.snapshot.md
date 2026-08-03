# DISK-0001 orchestrator snapshot

**Date:** 2026-08-03  
**State:** **ACTIVE** — unparked; CTA drain in progress

## Fleet status

| Host / lane | Verdict |
|-------------|---------|
| arcana-prod `:9443` | **PASS** |
| arcana-agents `:9543` mesh | **PASS** (user unit PID 2292321, redeployed 2026-08-03) |
| Mac R13 consumer | **PASS** (last verified 2026-08-02; kickstart after F4 if needed) |
| DISK-0067–0069 | **done** |
| DISK-0062 | **done** (shipped 2026-06-24 PR #25) |

RB-011 **not opened**.

## CTA progress (2026-08-03 unpark)

| # | Item | Status |
|---|------|--------|
| 1 | Mac native arm64 from `main` | brief: repo `datarim/orchestration/DISK-0001/mac-arm64-deploy-2026-08-03.md` (KB) |
| 2 | PR #137 docs snapshot | this PR |
| 3 | DISK-0062 x-disk-share | **done** (in `main` since `0c79c65`) |
| 4 | F4 agents mesh redeploy | **done** — probes PASS 2026-08-03 |

## Mac reference (2026-08-02)

- `datarim-kb`: idle, last_ok `2026-08-02T15:07:05Z`
- `hermes-artefacts`: syncing, last_ok `2026-08-02T15:07:01Z`
- `~/.local/bin/disk` Mach-O arm64 (never Linux ELF from DEVS)

## Code on main

- PR #136 `3e54b7b` — mesh client recovery (2026-08-02)
- PR #25 `0c79c65` — DISK-0062 x-disk-share (2026-06-24)
- Probe scripts: `mesh-auth-probe.sh`, `mesh-hermes-probe.sh`, `mac-mesh-recover.sh`

## Remaining

1. Merge this PR (#137)
2. Mac: native `cargo install` per deploy brief if not already on patched arm64
