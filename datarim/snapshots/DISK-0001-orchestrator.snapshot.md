# DISK-0001 orchestrator snapshot

**Date:** 2026-07-28  
**Repo:** `Arcanada-one/disk-arcana` @ `main` (PR #125 merged)  
**State:** **ACTIVE** — POST-R13 mesh green; hydrate fix landed in git

## Execution summary (2026-07-28)

| Item | Result | Evidence |
|------|--------|----------|
| R13 Mac consumer cutover | **DONE** | hermes receive_only `last_ok`; do not redo |
| PR #124 share_index + CI | **MERGED** | `4ed3e8d`: `DISK_SHARE_ROOTS` watcher, `ci-ensure-cc.sh` in CI |
| Linux share_index server | **LIVE** | arcana-agents mesh `:9543`; watcher armed for hermes-artefacts |
| AuthStore hydrate fix | **MERGED** | PR #125 → `main`: boot hydrates api_key hashes from MetaDb nodes |
| RB-012 RegisterNodeMode | **CLOSED** | `DISK_REGISTER_NODE_MODE=enrolled`; Mac api_key survives restart |
| Mesh sync | **GREEN** | `datarim-kb` + `hermes-artefacts` `last_ok` |
| Dual-port plan | **DOCUMENTED** | `docs/design/DISK-0001-dual-port-retirement.md` — plan-only, no stop |
| CI runner gcc | **DONE** | `ci-ensure-cc.sh` persists PATH; `bootstrap-runner-gcc.sh` for host install |

## Skip / do-not-rebuild (honoured)

- Mesh cutover — **do not redo**
- DISK-0016–0030 / DISK-0019 / DISK-0021 — not rebuilt
- `:9543` stop / dual-port collapse — **blocked** until consilium + operator safe window

## Operator gates (document only — human action required)

| Gate | Status | Notes |
|------|--------|-------|
| DISK-0006 **R13** | **DONE** | Mac consumer cutover complete |
| DISK-0044 **RB-011** | **HARD-GATED** | Prod WAN `:9445` firewall / `DISK_CA_MODE=offline` sign-off |
| DISK-0057 **P5-R** | **DONE** | Live mesh KB sync (`datarim-kb` + hermes green) |

## Next

1. Rebuild/redeploy server on arcana-agents from `main` when operator schedules (hydrate fix now in git).
2. Run `scripts/bootstrap-runner-gcc.sh` on cc-less self-hosted runners (optional host hardening).
3. RB-011 remains operator-only — no autonomous WAN `:9445` changes.
