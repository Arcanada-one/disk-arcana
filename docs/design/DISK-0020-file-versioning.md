# DISK-0020 — File Versioning and History

**Status:** slice 1 on DEVS — version history, tier retention, restore API.  
**Parent:** DISK-0001 commercial / SaaS track.  
**Tracking:** DISK-0020 in Datarim backlog.

## Scope

| Slice | In scope | Out of scope |
|-------|----------|--------------|
| 1 (this PR) | `file_versions` table, versioned upsert on sync upload, content blob archive, `GET /versions`, `POST /versions/restore`, tier retention (Free/Pro/Team), dashboard UI | Client-side version picker, billing-gated restore limits beyond retention, cross-vault moves |
| 2+ | gRPC/proto version fields populated on exchange, CLI `disk versions` | Point-in-time vault snapshots |

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
| GET | `/versions?path=&vault_id=&limit=` | Bearer JWT | Lists historical revisions (newest first) |
| POST | `/versions/restore` | Bearer JWT | Body: `{ path, vault_id, version_id }` — writes blob back to sync root, bumps version |

Mounted on the health HTTP listener when `DISK_AUTH_MODE=enforce`.

## Storage

- **Metadata:** `file_versions` (migration 014) + `files.version_id` / `parent_version_id`
- **Blobs:** `{sync_root}/.version-blobs/{hh}/{hash}` content-addressed store (`ContentBlobStore`)
- **Sync path:** before overwrite on `DeltaUpload`, prior bytes archived; upsert uses `upsert_file_scoped_versioned`

## Tests

- `crates/disk-core/src/meta_db/versions.rs` — versioned upsert unit test
- `crates/disk-core/tests/schema_smoke.rs` — migration 014
- `crates/disk-server/src/versions/routes.rs` — list + restore HTTP round-trip

## References

- `proto/disk.proto` — forward-compat `version_id` / `parent_version_id` fields (wire fill in slice 2)
- `docs/design/DISK-0018-billing-scaffold.md` — tier source for retention
- `deploy/www/dashboard/index.html` — version history panel
