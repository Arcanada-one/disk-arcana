# DISK-0030 — Team / Org Workspaces

**Status:** slice 2 on DEVS — dashboard org panel + persisted active-org context.  
**Parent:** DISK-0001 commercial / SaaS track.  
**Tracking:** DISK-0030 in Datarim backlog.

## Problem

Personal tenants (`tenant_id` derived from signup email) work for solo users. Teams need a shared organizational boundary: multiple users, one `tenant_id`, shared vaults synced under the org slug.

## Scope

| Slice | In scope | Out of scope |
|-------|----------|--------------|
| 1 (merged #106) | `organizations` + `organization_members` tables; `POST/GET /orgs`; `GET/POST /orgs/members` | Dashboard org switcher, JWT tenant override, billing per org, `disk org` CLI |
| 2 (this PR) | Dashboard org panel + workspace switcher; `GET/PUT /orgs/context` persisted active org | SSO group sync, SCIM |
| 3 (planned) | `disk org` CLI + sync `x-disk-tenant` org context | Cross-org vault federation |

## Data model

### `organizations`

| Column | Type | Notes |
|--------|------|-------|
| `id` | TEXT PK | `org_<hex>` |
| `slug` | TEXT UNIQUE | URL-safe identifier; also used as `tenant_id` |
| `name` | TEXT | Display name |
| `tenant_id` | TEXT UNIQUE | Vault routing key for org shares (`x-disk-tenant`) |
| `created_by` | TEXT FK | `user_accounts.id` |
| `created_at` / `updated_at` | INTEGER | Unix seconds |

### `organization_members`

| Column | Type | Notes |
|--------|------|-------|
| `org_id` | TEXT FK | |
| `user_id` | TEXT FK | |
| `role` | TEXT | `owner` \| `admin` \| `member` |
| `created_at` | INTEGER | |

Roles:
- **owner** — full control; assigned to org creator
- **admin** — add members (`admin`/`member` roles)
- **member** — use org vaults (enforcement deferred to slice 2+)

## HTTP API (slice 1)

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| POST | `/orgs` | Bearer JWT | Body: `{ name, slug }` → creator becomes `owner`; `tenant_id = slug` |
| GET | `/orgs` | Bearer JWT | List orgs for current user with role |
| GET | `/orgs/members?org_id=` | Bearer JWT (member+) | List members |
| POST | `/orgs/members` | Bearer JWT (admin+) | Body: `{ org_id, email, role: admin\|member }` — target must be existing user |

Mounted on the health HTTP listener when `DISK_AUTH_MODE=enforce`.

## Active workspace context (slice 2)

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| GET | `/orgs/context` | Bearer JWT | `{ mode, active_org_id?, active_tenant_id, personal_tenant_id, organization? }` |
| PUT | `/orgs/context` | Bearer JWT | Body: `{ org_id: null \| "<id>" }` — must be org member when setting |

Persisted in `user_org_context`. Stale org membership auto-clears to personal on read.

## Dashboard (slice 2)

- Workspace switcher (personal vs organization) in tenant dashboard header
- Organizations panel: create org, list memberships, add members (admin+)
- Active tenant label reflects selected workspace context

## Tests

- `crates/disk-core/src/meta_db/orgs.rs` — create + member list + context unit tests
- `crates/disk-core/tests/schema_smoke.rs` — migration 022/023 tables exist
- `crates/disk-server/src/orgs/routes.rs` — HTTP round-trip (create + add member + context switch)
- `deploy/www/dashboard/index.html` — org panel + workspace switcher UI

## References

- `docs/design/DISK-0017-multitenant-slice1.md` — tenant_id wire-through
- `docs/design/DISK-0022-sharing.md` — external collaborator RBAC (orthogonal to org membership)
- `crates/disk-core/migrations/007_tenant_vaults.sql` — vault registry per tenant
