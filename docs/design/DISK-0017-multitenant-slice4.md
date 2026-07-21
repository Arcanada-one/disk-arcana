# DISK-0017 — Multi-tenant (slice 4)

**Status:** slice 4 on DEVS — separate SQLite files per tenant.  
**Parent:** DISK-0017 slice 3 (merged #66).

## Scope

| Area | Change |
|------|--------|
| `TenantMetaRouter` | Control DB + optional `{DISK_TENANT_DB_DIR}/{tenant}/meta.sqlite` shards |
| `DISK_TENANT_DB_DIR` | Env var enabling split mode (unset = legacy single DB) |
| `SyncServiceImpl` | Routes file/baseline/conflict ops through `tenant_data()` |
| `QuotaEnforcer` | Billing on control DB; storage sums on tenant shard |

## Layout

```
DISK_DB_PATH          → control.sqlite (nodes, ACL, billing, tenant_vaults)
DISK_TENANT_DB_DIR/   → per-tenant data (when set)
  acme/meta.sqlite    → files, baselines, conflicts, tombstones
  beta/meta.sqlite
  _legacy/meta.sqlite → NULL tenant_id (legacy single-tenant)
```

## Isolation contract

- Physical blast-radius: tenant A cannot read tenant B rows — separate files + slice 3 scoped queries.
- Legacy self-hosted: omit `DISK_TENANT_DB_DIR`; behaviour unchanged from slice 3.

## Tests

- `crates/disk-core/src/tenant_db.rs` — shard path + file isolation unit tests
- `crates/disk-server/tests/tenant_db_file_isolation.rs` — upload + exchange_state IT
