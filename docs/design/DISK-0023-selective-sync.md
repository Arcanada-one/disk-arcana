# DISK-0023 — Selective Sync

**Status:** slice 2 on DEVS — dashboard per-device folder picker.  
**Parent:** DISK-0001 commercial / SaaS track.  
**Tracking:** DISK-0023 in Datarim backlog.

## Scope

| Slice | In scope | Out of scope |
|-------|----------|--------------|
| 1 (merged #90) | `device_sync_includes` table, GET/PUT `/selective-sync`, `disk selective-sync` CLI, path prefix normalization + matcher | gRPC SyncState/Delta enforcement, dashboard folder picker UI |
| 2 (this PR) | Dashboard selective-sync panel: vault + device picker, folder prefix textarea, load/save/clear; Devices table "Folders" shortcut | Client daemon auto-apply on sync |
| 3 | Enforce includes on gRPC sync paths (server filters outbound deltas) | Cross-vault moves |

## Model

Each authenticated user may configure folder **include prefixes** per `(node_id, vault_id)`:

- **Empty includes** — sync the entire vault (default).
- **Non-empty includes** — only paths matching any prefix (prefix or `prefix/...` descendants) participate in selective sync once enforcement lands (slice 3).

Config is scoped to the JWT user; `node_id` is the enrolled device identifier (hostname hint).

## HTTP API

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| GET | `/selective-sync?vault_id=&node_id=` | Bearer JWT | Returns `{ sync_all, includes[] }` |
| PUT | `/selective-sync` | Bearer JWT (write) | Body: `{ vault_id, node_id, includes: ["docs", "photos/2024"] }` — replaces rules |

Mounted on the health HTTP listener when `DISK_AUTH_MODE=enforce`.

## Dashboard deep links

- `?selective_sync=1` — open panel and load when node is known
- `?selective_sync_vault=wiki` — preselect vault
- `?selective_sync_node=macbook` — preselect device node id

Devices table includes a **Folders** button per row that scrolls to the selective-sync panel and loads rules for that node.

## CLI

```bash
disk selective-sync list --vault default --node macbook
disk selective-sync set --vault default --node macbook --include docs,photos
disk selective-sync set --vault default --node macbook   # clear filter → sync all
```

Env: `DISK_API_BASE`, `DISK_ACCESS_TOKEN`.

## Storage

- **Migration 017:** `device_sync_includes` — `(tenant_id, user_id, node_id, vault_id, path_prefix)`
- Matcher: `disk_core::selective_sync::path_matches_includes`

## Tests

- `crates/disk-core/src/selective_sync.rs` — prefix normalize + match unit tests
- `crates/disk-core/src/meta_db/selective_sync.rs` — replace/list unit test
- `crates/disk-server/src/selective_sync/routes.rs` — HTTP round-trip integration test
- `deploy/www/dashboard/index.html` — selective sync panel UI

## References

- `crates/disk-core/src/filter.rs` — scanner ignore rules (orthogonal; global, not per-device)
- `docs/design/DISK-0022-sharing.md` — vault RBAC (read/write gates on selective-sync API)
