# DISK-0020 — File Versioning and History

**Status:** slice 2 on DEVS — version history UI polish + list/restore API pagination.  
**Parent:** DISK-0001 commercial / SaaS track.  
**Tracking:** DISK-0020 in Datarim backlog.

## Scope

| Slice | In scope | Out of scope |
|-------|----------|--------------|
| 1 (merged #79) | `file_versions` table, versioned upsert on sync upload, content blob archive, `GET /versions`, `POST /versions/restore`, tier retention (Free/Pro/Team), dashboard UI scaffold | Client-side version picker, billing-gated restore limits beyond retention, cross-vault moves |
| 2 (this PR) | API polish: `current` snapshot, pagination (`offset`/`limit`), `plan_tier` + retention hints, restore guards (`version is already current`, matching content), dashboard table UI, vault select, paging controls | gRPC/proto wire fill, CLI `disk versions` |
| 3+ | gRPC/proto version fields populated on exchange, CLI `disk versions` | Point-in-time vault snapshots |

## Retention by tier

| Tier | Max versions / path | Max age |
|------|---------------------|---------|
| Free | 5 | 7 days |
| Pro | 30 | 90 days |
| Team | 100 | 365 days |

Pruned after each versioned write (`prune_file_versions`).

## HTTP API

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| GET | `/versions?path=&vault_id=&limit=&offset=` | Bearer JWT | Lists historical revisions (newest first) plus `current` live snapshot |
| POST | `/versions/restore` | Bearer JWT | Body: `{ path, vault_id, version_id }` — writes blob back to sync root, bumps version |

### List response (slice 2)

```json
{
  "path": "notes.md",
  "vault_id": "default",
  "plan_tier": "free",
  "file_exists": true,
  "file_deleted": false,
  "current_version_id": 3,
  "retention": { "max_versions": 5, "max_age_secs": 604800, "max_age_days": 7 },
  "pagination": { "limit": 20, "offset": 0, "total_historical": 2, "has_more": false },
  "current": { "version_id": 3, "is_current": true, "blob_available": true, ... },
  "versions": [ { "version_id": 2, "is_current": false, ... } ]
}
```

Restore returns `{ restored, new_version_id, message, ... }`. Errors: `409` when version is already current or blob missing; `404` when version row absent.

Mounted on the health HTTP listener when `DISK_AUTH_MODE=enforce`.

## Storage

- **Metadata:** `file_versions` (migration 014) + `files.version_id` / `parent_version_id`
- **Blobs:** `{sync_root}/.version-blobs/{hh}/{hash}` content-addressed store (`ContentBlobStore`)
- **Sync path:** before overwrite on `DeltaUpload`, prior bytes archived; upsert uses `upsert_file_scoped_versioned`

## Dashboard UI (slice 2)

- `deploy/www/dashboard/index.html` — version table (size, hash prefix, author), retention banner, vault `<select>`, pagination, restore success line
- Deep link: `?version_path=docs/a.md&version_vault=default`

## Tests

- `crates/disk-core/src/meta_db/versions.rs` — versioned upsert unit test
- `crates/disk-core/tests/schema_smoke.rs` — migration 014
- `crates/disk-server/src/versions/routes.rs` — list + restore HTTP round-trip, restore rejects current version

## References

- `proto/disk.proto` — forward-compat `version_id` / `parent_version_id` fields (wire fill in slice 3)
- `docs/design/DISK-0018-billing-scaffold.md` — tier source for retention
- `deploy/www/dashboard/index.html` — version history panel
