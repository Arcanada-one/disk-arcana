# DISK-0021 — Compliance (ToS, Privacy, GDPR, DPA, data export)

**Status:** slice 2 on DEVS — account deletion / right-to-erasure.  
**Parent:** DISK-0001 commercial / SaaS track.  
**Tracking:** DISK-0021 in Datarim backlog.

## Scope

| Slice | In scope | Out of scope |
|-------|----------|--------------|
| 1 (merged #76) | Static legal pages (`deploy/www/legal/`), `GET /compliance/export`, dashboard export button + signup ToS notice | Account deletion API, signed enterprise DPA workflow, cookie banner |
| 2 (this PR) | `POST /compliance/delete-account`, tenant metadata purge when last user leaves, dashboard delete UI | Blob storage erasure, Auth Arcana IdP account deletion, cookie banner |
| 3+ | Sub-processor registry page, consent audit trail | Legal Arcana CMS integration |

## HTTP API

| Method | Path | Auth | Body | Response |
|--------|------|------|------|----------|
| GET | `/compliance/export` | Bearer JWT | — | JSON export bundle |
| POST | `/compliance/delete-account` | Bearer JWT | `{ "confirm_email": "..." }` | `{ deleted, user_id, tenant_purged }` |

Mounted on the health HTTP listener when `DISK_AUTH_MODE=enforce` (same router as `/dashboard/*`).

### Delete account behaviour

1. `confirm_email` must match the authenticated user's normalized email.
2. Deletes the `user_accounts` row.
3. If no users remain for the tenant, purges tenant metadata: `conflicts`, `node_baselines`, `tombstones`, `files`, `nodes`, `tenant_vaults`, `tenant_billing`, `pending_enrollments`.
4. On-disk blob payloads are **not** deleted in this slice (metadata-only erasure).

### Export JSON shape (format_version 1)

```json
{
  "exported_at": 1710000000,
  "format_version": 1,
  "user": {
    "user_id", "email", "tenant_id", "email_verified",
    "oauth_provider", "created_at", "updated_at"
  },
  "tenant": {
    "tenant_id", "plan_tier",
    "vaults": [{ "vault_id", "created_at" }],
    "devices": [{ "node_id", "display_name", "platform", "registered_at", "last_seen" }]
  }
}
```

## Static pages

- `deploy/www/legal/` — Terms, Privacy, DPA summary (slice 1)

## Tests

- `crates/disk-core/src/meta_db/compliance.rs` — purge unit test
- `crates/disk-server/src/compliance/routes.rs` — `integration_tests` HTTP round-trips

## References

- `docs/design/DISK-0019-web-dashboard.md`
- `deploy/www/dashboard/index.html` — export + delete account UI
