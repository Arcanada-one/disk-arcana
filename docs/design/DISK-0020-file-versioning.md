# DISK-0020 — File Versioning and History

**Status:** slice 4 on DEVS — point-in-time vault snapshots.  
**Parent:** DISK-0001 commercial / SaaS track.  
**Tracking:** DISK-0020 in Datarim backlog.

## Scope

| Slice | In scope | Out of scope |
|-------|----------|--------------|
| 1 (merged #79) | `file_versions` table, versioned upsert on sync upload, content blob archive, `GET /versions`, `POST /versions/restore`, tier retention (Free/Pro/Team), dashboard UI scaffold | Client-side version picker, billing-gated restore limits beyond retention, cross-vault moves |
| 2 (merged #80) | API polish: `current` snapshot, pagination, retention hints, restore guards, dashboard table UI | gRPC/proto wire fill, CLI `disk versions` |
| 3 (merged #81) | gRPC `version_id` wire fill, `disk versions list\|restore` CLI | Point-in-time vault snapshots |
| 4 (this PR) | `vault_snapshots` + `vault_snapshot_files` tables, snapshot create/list/show/restore HTTP API, tier snapshot retention, `disk snapshots` CLI | Cross-vault snapshot clone, scheduled snapshots |

## Retention by tier

### Per-file version history

| Tier | Max versions / path | Max age |
|------|---------------------|---------|
| Free | 5 | 7 days |
| Pro | 30 | 90 days |
| Team | 100 | 365 days |

### Vault snapshots (slice 4)

| Tier | Max snapshots / vault | Max age |
|------|----------------------|---------|
| Free | 2 | 7 days |
| Pro | 20 | 90 days |
| Team | 100 | 365 days |

Pruned after each snapshot create (`prune_vault_snapshots`).

## HTTP API

### Per-file versions

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| GET | `/versions?path=&vault_id=&limit=&offset=` | Bearer JWT | Lists historical revisions plus `current` |
| POST | `/versions/restore` | Bearer JWT | Body: `{ path, vault_id, version_id }` |

### Vault snapshots (slice 4)

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| POST | `/snapshots` | Bearer JWT | Body: `{ vault_id, label? }` — capture current vault index |
| GET | `/snapshots?vault_id=&limit=&offset=` | Bearer JWT | List snapshots (newest first) |
| GET | `/snapshots/:id?vault_id=` | Bearer JWT | Snapshot detail + frozen file index |
| POST | `/snapshots/:id/restore` | Bearer JWT | Body: `{ vault_id }` — restore live files from snapshot |

Restore skips tombstoned (`deleted`) entries in the snapshot index; reports `files_restored`, `files_skipped`, `files_failed`.

Mounted on the health HTTP listener when `DISK_AUTH_MODE=enforce`.

## CLI

```bash
disk snapshots create --vault default --label "pre-migration"
disk snapshots list --vault default
disk snapshots show --id 1 --vault default
disk snapshots restore --id 1 --vault default

disk versions list --path notes/a.md   # slice 3
```

Env: `DISK_API_BASE`, `DISK_ACCESS_TOKEN`.

## Storage

- **Metadata:** `file_versions` (014), `vault_snapshots` + `vault_snapshot_files` (015)
- **Blobs:** `{sync_root}/.version-blobs/{hh}/{hash}` — snapshots reference existing content hashes (no duplicate blob copy)

## Tests

- `crates/disk-core/src/meta_db/snapshots.rs` — create/list unit test
- `crates/disk-core/tests/schema_smoke.rs` — migration 015
- `crates/disk-server/src/snapshots/routes.rs` — HTTP create/list/restore round-trip
- `crates/disk-cli/src/main.rs` — `disk snapshots` clap parse test

## References

- `docs/design/DISK-0018-billing-scaffold.md` — tier source for retention
- `deploy/www/dashboard/index.html` — per-file version history panel (dashboard snapshot UI deferred)
