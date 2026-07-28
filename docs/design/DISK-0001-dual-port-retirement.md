# Dual-port retirement plan — :9443 (system) vs :9543 (user mesh)

**Status:** plan-only (POST-R13). No port changes without consilium + operator safe window.

## Context

Disk Arcana currently runs two distinct gRPC listeners in the ecosystem:

| Port | Role | Typical host | Audience |
|------|------|--------------|----------|
| **:9443** | Production **system** mTLS sync plane | `disk.arcanada.ai` (Arcana-PROD) | Enrolled fleet nodes, public product surface |
| **:9543** | Dev/mesh **user** sync plane | `arcana-agents` (mesh) | KB canon, Hermes artefacts, Mac consumer cutover (R13) |

`:9445` (enrollment, TLS-only) is orthogonal — see `docs/design/DISK-0044-enrollment-bootstrap.md`.

## Why two ports exist

1. **:9443** — hardened prod listener with full mTLS, ACL, billing hooks, WAN exposure policy (RB-011 deferred for `:9445` only).
2. **:9543** — mesh-local listener for operator/dev KB sync without mixing Hermes cache paths into `DISK_SYNC_ROOT` (R13 `DISK_SHARE_ROOTS`).

Collapsing them prematurely would either expose mesh ACL laxity to WAN or force prod traffic through a non-standard port.

## Retirement criteria (all required)

1. Mac R13 consumer cutover **DONE** and soak ≥7 days green (`datarim-kb` + `hermes-artefacts` `last_ok`).
2. `DISK_SHARE_ROOTS` + server `share_index` watcher deployed on mesh **and** prod if Hermes path is ever promoted.
3. Fleet ACL signed for prod `:9443` with no `open` RegisterNode drift.
4. Consilium pass with blast-radius ≥3 (network + ACL + client config).
5. Operator safe window announced (no parallel bash MVP).

## Safe sequence (when criteria met)

1. **Document** client `disk.toml` target migration (mesh nodes only) — no auto-push.
2. **Freeze** new enrollments on `:9543` (`DISK_REGISTER_NODE_MODE=enrolled` on mesh).
3. **Drain** active sessions (watch `exchange_state` concurrency / Ops Bot audit).
4. **Stop** mesh listener (`DISK_BIND_ADDR` change or unit drop) during maintenance window.
5. **Verify** all nodes on `:9443` mTLS; rollback = re-bind `:9543` from snapshot env.

## Explicit non-goals (this plan)

- Do **not** stop `:9543` in POST-R13 autonomous cycle.
- Do **not** change prod `:9443` firewall without RB-011 / operator gate.
- Do **not** merge Hermes into `DISK_SYNC_ROOT` (rejected in R13 consilium).

## References

- `datarim/creative/creative-DISK-0001-r13-hermes-mesh.md`
- `deploy/linux/provision-hermes-share.sh`
- `documentation/runbooks/disk-arcana/DISK-RB-001-enroll.md`
