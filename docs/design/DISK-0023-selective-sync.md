# DISK-0023 — Selective Sync

**Status:** slice 3 on DEVS — gRPC selective-sync enforcement.  
**Parent:** DISK-0001 commercial / SaaS track.  
**Tracking:** DISK-0023 in Datarim backlog.

## Scope

| Slice | In scope | Out of scope |
|-------|----------|--------------|
| 1 (merged #90) | `device_sync_includes` table, GET/PUT `/selective-sync`, `disk selective-sync` CLI, path prefix normalization + matcher | gRPC SyncState/Delta enforcement, dashboard folder picker UI |
| 2 (merged #91) | Dashboard selective-sync panel: vault + device picker, folder prefix textarea, load/save/clear; Devices table "Folders" shortcut | Client daemon auto-apply on sync |
| 3 (this PR) | Enforce includes on gRPC sync paths: `exchange_state` filters `to_download`/`to_upload`/`to_delete`; `DeltaDownload`/`DeltaUpload` reject excluded paths | Client daemon auto-prune of local excluded folders |

## Model

Each authenticated user may configure folder **include prefixes** per `(node_id, vault_id)`:

- **Empty includes** — sync the entire vault (default).
- **Non-empty includes** — only paths matching any prefix (prefix or `prefix/...` descendants) participate in sync.

Config is scoped to the JWT user on HTTP; gRPC enforcement resolves rules by `(tenant_id, node_id, vault_id)` via `list_node_sync_includes`.

## gRPC enforcement (slice 3)

| RPC | Behavior when includes non-empty |
|-----|----------------------------------|
| `exchange_state` | Omit paths outside includes from `to_download`, `to_upload`, `to_delete` |
| `DeltaDownload` | `PermissionDenied` when path outside includes |
| `DeltaUpload` | `PermissionDenied` when path outside includes |

Streaming `sync_state` (ack-only bidi) is unchanged.

## HTTP API

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| GET | `/selective-sync?vault_id=&node_id=` | Bearer JWT | Returns `{ sync_all, includes[] }` |
| PUT | `/selective-sync` | Bearer JWT (write) | Body: `{ vault_id, node_id, includes: [...] }` — replaces rules |

## Dashboard deep links

- `?selective_sync=1`, `?selective_sync_vault=`, `?selective_sync_node=`
- Devices table **Folders** button

## CLI

```bash
disk selective-sync list --vault default --node macbook
disk selective-sync set --vault default --node macbook --include docs,photos
```

Env: `DISK_API_BASE`, `DISK_ACCESS_TOKEN`.

## Storage

- **Migration 017:** `device_sync_includes`
- Matcher: `disk_core::selective_sync::path_matches_includes`

## Tests

- `crates/disk-core/src/meta_db/selective_sync.rs` — replace/list + `list_node_sync_includes`
- `crates/disk-server/src/selective_sync/routes.rs` — HTTP round-trip
- `crates/disk-server/src/services/sync.rs` — `exchange_state` filter + `delta_download` reject
- `deploy/www/dashboard/index.html` — selective sync panel UI

## References

- `crates/disk-core/src/filter.rs` — scanner ignore rules (orthogonal)
- `docs/design/DISK-0022-sharing.md` — vault RBAC on HTTP API
