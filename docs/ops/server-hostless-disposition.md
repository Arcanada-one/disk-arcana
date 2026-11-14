# Disk Arcana server: hostless disposition

Measured: 2026-11-11T01:42Z (UTC)
Product decision: **not retired** — hostless / deploy path broken until an authorized restore.

## Decision

Keep Disk Arcana as a live product whose knowledge-base delivery path stays
masked (delivery disabled) until the tracked delivery task is done.

Do **not** treat the gRPC server as retired. Record it as **hostless after the
decommissioning of the old server hosts**: no surviving host currently runs
`disk-arcana-server`, and the dedicated deploy labels have zero org runners.

Redeploy on a live host requires the repository owner's authorization for:

1. new TLS material (the keys of the decommissioned production host were wiped);
2. a dedicated runner carrying `disk-arcana-prod` (and, for staging,
   `disk-arcana-stage` / group `disk-arcana-stage`);
3. lifting or satisfying the delivery mask when knowledge-base delivery is
   intended.

This change does **not** deploy, issue keys, or mutate runner labels.

## Remeasured evidence (2026-11-11)

| Surface | Result | Evidence |
|---|---|---|
| Production host: unit `/etc/systemd/system/disk-arcana-server.service` | absent | Deploy probe run `42940843284` on the host-unique probe label — Verdict: `FAIL unit file absent` |
| Production host: service state | inactive / not-found | same run — `is-active=inactive`, `is-enabled=not-found` |
| Production host: health `127.0.0.1:9446` | unreachable | same run — `health 9446 = false` |
| Development host: unit + health | absent / unreachable | local probe at 2026-11-11T01:42Z |
| Org runners with label `disk-arcana-prod` | **NONE** (32 runners) | `GET /orgs/Arcanada-one/actions/runners` |
| Org runners with label `disk-arcana-stage` | **NONE** (32 runners) | same inventory |
| Host-unique probe label | held by one online runner | same inventory; used by read-only `deploy-probe.yml` (PR #233) |
| Prior green probe | 2026-08-11 on the since-retired production path | run `31444643689` |
| Canon | delivery disabled pending the delivery task | file-sync ADR |

An earlier red probe (run `36698828886`, 2026-09-30) still used the old
production label input. The remeasure above uses the host-unique probe label
introduced by PR #233.

## Source wiring change in this repository

`.github/workflows/release-deploy.yml` keeps the stage/prod job definitions for
restore, but adds an explicit `false &&` circuit-breaker on every job that
targets `disk-arcana-stage` or `disk-arcana-prod`. Without the breaker those
jobs queue forever on a missing label. `build-only` (and other non-dedicated
deploy targets) stay schedulable.

`reverse_if` (remove the `false &&` conjuncts only when **all** hold):

1. An authorized host runs `disk-arcana-server` with health on `:9446`.
2. An online org runner carries the exact label each restored job selects
   (`disk-arcana-stage` / `disk-arcana-prod`) and the repository is on the
   runner group's allowlist.
3. TLS / broker / sudo grant material for that host is reissued by its owner
   (key lifecycle is owner-only; this change must not call issue/revoke routes).
4. Any knowledge-base delivery use still respects the delivery mask and the
   file-sync ADR (separate gate).

## Related

- `.github/retired-workflows/README.md` — the retired share-deploy workflow
  row points here.
- Read-only probe: `.github/workflows/deploy-probe.yml`.
