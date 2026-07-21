# DISK-0017 — Multi-tenant (slice 1)

**Status:** slice 1 on DEVS — wire `tenant_id` through nodes/files.  
**Parent:** DISK-0001 SaaS track.  
**Tracking:** DISK-0017 in Datarim backlog.

## Scope

| Slice | In scope | Out of scope |
|-------|----------|--------------|
| 1 (merged #64) | `resolve_tenant_id`, scoped MetaDb CRUD, `nodes.tenant_id` on RegisterNode, `files` upsert via `x-disk-tenant` + `x-disk-share` | Per-tenant DB isolation, session tenant binding, quotas per tenant row in nodes |
| 2 (merged) | Session tenant validation, client daemon tenant header, enrollment tenant | Per-tenant DB isolation |
| 3 (this PR) | Scoped `exchange_state` MetaDb path, baselines + conflicts tenant bind | Separate DB files per tenant |

## Tenant resolution

Priority: gRPC metadata `x-disk-tenant` → proto `tenant_id` field → `NULL` (legacy single-tenant).

## Storage keys

| Table | Scope key |
|-------|-----------|
| `files` | `(tenant_id, vault_id, path)` — `vault_id` = `x-disk-share` (default `default`) |
| `nodes` | `node_id` + `tenant_id` column on RegisterNode |
| Billing tables | Already keyed by `tenant_id` (DISK-0018) |

## API

```rust
disk_core::resolve_tenant_id(header, proto_field)
MetaDb::upsert_file_scoped(tenant_id, vault_id, meta)
MetaDb::get_file_scoped(tenant_id, vault_id, path)
MetaDb::upsert_node_tenant(node_id, tenant_id, api_key_hash, ...)
```

## Tests

- `crates/disk-core/src/tenant.rs` — resolution unit tests
- `crates/disk-core/src/meta_db/files.rs` — tenant isolation
- `crates/disk-server/tests/tenant_upload_isolation.rs` — upload IT
