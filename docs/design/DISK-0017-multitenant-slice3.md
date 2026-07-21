# DISK-0017 — Multi-tenant (slice 3)

**Status:** slice 3 on DEVS — per-tenant DB isolation for reconcile path.  
**Parent:** DISK-0017 slice 2 (merged #65).

## Scope

| Area | Change |
|------|--------|
| `TenantScope` | `tenant_id` + `vault_id` helper in `disk-core::tenant` |
| `exchange_state` | `list_files_scoped`, scoped baselines, scoped tombstone/conflict writes |
| `node_baselines` | `load/upsert_node_baselines_scoped` filter/bind `tenant_id` |
| `conflicts` | `create_conflict_scoped` |
| Migration `009` | Index `node_baselines(tenant_id, node_id, vault_id)` |
| Migration `010` | Rebuild `node_baselines` PK → `(tenant_key, node_id, vault_id, path)` |

## Isolation contract

Server reconcile (`ExchangeState`) never reads or writes another tenant's rows:

- Server index: `(tenant_id, x-disk-share)` not global `list_all_files`
- Baselines: `tenant_id` column on load/upsert
- Tombstones + conflict rows: tenant from resolved session

Legacy single-tenant (`tenant_id = NULL`) unchanged.

## Tests

- `crates/disk-core/src/meta_db/node_baseline.rs` — baseline tenant isolation
- `crates/disk-server/tests/tenant_exchange_isolation.rs` — exchange_state IT
