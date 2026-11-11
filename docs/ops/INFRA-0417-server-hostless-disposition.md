# INFRA-0417 — Disk Arcana server hostless disposition

Muneral task: `00f3c8e2-5471-4843-9feb-3b2a9181efb3`  
Measured: 2026-11-11T01:42Z (UTC)  
Product decision: **not retired** — hostless / deploy-path broken until Root-authorized restore.

## Decision

Keep Disk Arcana as a live product whose KB delivery path stays masked until
`DISK-0098` (see workspace `ADR-0001` and `spaces/arcanada/space.yml` →
`disk_arcana_delivery: disabled-pending-DISK-0098`).

Do **not** treat the gRPC server as retired. Record it as **hostless after
INFRA-0417**: no surviving host currently runs `disk-arcana-server`, and the
dedicated deploy labels have zero org runners.

Redeploy on a live host (candidate: `arcana-prd`) requires Root/authority for:

1. new TLS material (prior arcana-prod keys wiped in INFRA-0417);
2. a dedicated runner carrying `disk-arcana-prod` (and, for staging,
   `disk-arcana-stage` / group `disk-arcana-stage`);
3. lifting or satisfying the `DISK-0098` delivery mask when KB delivery is
   intended.

This leaf does **not** Deploy, issue keys, or mutate runner labels.

## Remeasured evidence (2026-11-11)

| Surface | Result | Evidence |
|---|---|---|
| `arcana-prd` unit `/etc/systemd/system/disk-arcana-server.service` | absent | Deploy probe run `42940843284` on label `arcana-prd-host` — Verdict: `FAIL unit file absent` |
| `arcana-prd` service state | inactive / not-found | same run — `is-active=inactive`, `is-enabled=not-found` |
| `arcana-prd` health `127.0.0.1:9446` | unreachable | same run — `health 9446 = false` |
| `arcana-devs` unit + health | absent / unreachable | local probe on hostname `arcana-devs` at 2026-11-11T01:42Z |
| Org runners with label `disk-arcana-prod` | **NONE** (32 runners) | `GET /orgs/Arcanada-one/actions/runners` |
| Org runners with label `disk-arcana-stage` | **NONE** (32 runners) | same inventory |
| Label `arcana-prd-host` | held by online runner `arcana-prd` | same inventory; used by read-only `deploy-probe.yml` (PR #233) |
| Prior green probe | 2026-08-11 on retired arcana-prod path | run `31444643689` |
| Canon | delivery disabled pending DISK-0098 | workspace ADR-0001; `space.yml` |

Historical red probe named in the Muneral description: run `36698828886`
(2026-09-30, then still labeled `arcana-prod` input). Remeasure above uses the
host-unique `arcana-prd-host` label after PR #233.

## Source wiring change in this repository

`.github/workflows/release-deploy.yml` keeps the stage/prod job definitions for
restore, but adds an explicit `false &&` circuit-breaker on every job that
targets `disk-arcana-stage` or `disk-arcana-prod`. Without the breaker those
jobs queue forever on a missing label. `build-only` (and other non-dedicated
deploy targets) stay schedulable.

`reverse_if` (remove the `false &&` conjuncts only when **all** hold):

1. A Root-authorized host runs `disk-arcana-server` with health on `:9446`.
2. An online org runner carries the exact label each restored job selects
   (`disk-arcana-stage` / `disk-arcana-prod`) and the repository is on the
   runner group's allowlist.
3. TLS / broker / sudo grant material for that host is reissued under Root
   (key lifecycle is Root-only; this leaf must not call issue/revoke routes).
4. Any KB delivery use still respects `DISK-0098` / ADR-0001 (separate gate).

## Related

- `.github/retired-workflows/README.md` — `deploy-arcana-agents-share.yml`
  already cites this Muneral card.
- Read-only probe: `.github/workflows/deploy-probe.yml` (targets
  `arcana-prd-host` / `arcana-devs`).
