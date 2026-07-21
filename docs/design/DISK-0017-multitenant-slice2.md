# DISK-0017 — Multi-tenant (slice 2)

**Status:** slice 2 on DEVS — session validation, client header, enrollment binding.  
**Parent:** DISK-0017 slice 1 (merged #64).

## Scope

| Slice | In scope |
|-------|----------|
| 2 (this PR) | `enforce_node_tenant`, sync RPC validation, `disk.toml` `[node].tenant_id`, `DiskClient` `x-disk-tenant`, enrollment token `tenant_id` + migration 008 |

## Session validation

After bearer auth, `SyncServiceImpl::resolve_session_tenant`:

1. Read `x-disk-tenant` header (optional).
2. Load node binding from `AuthStore` or `MetaDb.nodes`.
3. `disk_core::enforce_node_tenant` — bound nodes reject mismatched headers; missing header inherits binding.

## Client

```toml
[node]
id = "laptop-1"
tenant_id = "acme-corp"
```

Propagated as `x-disk-tenant` on `register_node`, `exchange_state`, `delta_upload`, `delta_download`.

## Enrollment

`EnrollmentTokenRequest.tenant_id` (proto field 3) + `x-disk-tenant` admin header → `pending_enrollments.tenant_id` → `nodes.tenant_id` on `Enroll`.

CLI: `disk admin pending-token --hostname HOST --tenant acme-corp`.

## Tests

- `crates/disk-core/src/tenant.rs` — `enforce_node_tenant`
- `crates/disk-server/tests/tenant_session_validation.rs` — mismatch + inherit IT
- `crates/disk-server/src/enrollment/mod.rs` — `enroll_binds_tenant_from_token`
