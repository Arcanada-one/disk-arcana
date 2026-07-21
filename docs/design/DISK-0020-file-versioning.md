# DISK-0020 — File Versioning and History

**Status:** slice 3 on DEVS — gRPC `version_id` wire fill + `disk versions` CLI.  
**Parent:** DISK-0001 commercial / SaaS track.  
**Tracking:** DISK-0020 in Datarim backlog.

## Scope

| Slice | In scope | Out of scope |
|-------|----------|--------------|
| 1 (merged #79) | `file_versions` table, versioned upsert on sync upload, content blob archive, `GET /versions`, `POST /versions/restore`, tier retention (Free/Pro/Team), dashboard UI scaffold | Client-side version picker, billing-gated restore limits beyond retention, cross-vault moves |
| 2 (merged #80) | API polish: `current` snapshot, pagination, retention hints, restore guards, dashboard table UI | gRPC/proto wire fill, CLI `disk versions` |
| 3 (this PR) | Populate `FileMetadata.version_id` / `parent_version_id` on gRPC exchange (server + client), MetaDb overlay on client scan, `disk versions list|restore` CLI | Point-in-time vault snapshots |
| 4+ | Point-in-time vault snapshots | — |

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

Mounted on the health HTTP listener when `DISK_AUTH_MODE=enforce`.

## gRPC wire (slice 3)

`proto/disk.proto` fields 14–15 on `FileMetadata`:

- `version_id` — monotonic revision for the path (0 = unset on wire)
- `parent_version_id` — prior revision (0 = root)

Server `exchange_state` / delta paths populate these via `file_meta_to_proto` when MetaDb rows carry version counters. Client scan overlays version ids from local MetaDb before upload; download baselines preserve ids from `to_download` metadata.

## CLI (slice 3)

```bash
# List versions (health API — defaults to http://127.0.0.1:9446)
disk versions list --path notes/a.md --vault default \
  --api https://disk.arcanada.ai --token "$DISK_ACCESS_TOKEN"

# Restore a historical revision
disk versions restore --path notes/a.md --version-id 2 --vault default
```

Env: `DISK_API_BASE`, `DISK_ACCESS_TOKEN`.

## Storage

- **Metadata:** `file_versions` (migration 014) + `files.version_id` / `parent_version_id`
- **Blobs:** `{sync_root}/.version-blobs/{hh}/{hash}` content-addressed store (`ContentBlobStore`)
- **Sync path:** before overwrite on `DeltaUpload`, prior bytes archived; upsert uses `upsert_file_scoped_versioned`

## Tests

- `crates/disk-server/src/services/sync.rs` — proto version_id round-trip
- `crates/disk-client/src/sync_loop/wire.rs` — client `file_meta_to_proto` / `proto_to_file_meta`
- `crates/disk-cli/src/main.rs` — `disk versions` clap parse tests

## References

- `docs/design/DISK-0018-billing-scaffold.md` — tier source for retention
- `deploy/www/dashboard/index.html` — version history panel
