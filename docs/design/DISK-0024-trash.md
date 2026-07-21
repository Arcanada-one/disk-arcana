# DISK-0024 — Trash / Recycle Bin

**Status:** slice 3 on DEVS — permanent delete + scheduled prune.  
**Parent:** DISK-0001 commercial / SaaS track.  
**Tracking:** DISK-0024 in Datarim backlog.

## Scope

| Slice | In scope | Out of scope |
|-------|----------|--------------|
| 1 (merged #84) | List trashed files (`deleted=1`), restore (undelete), tier retention auto-prune on list, `disk trash list\|restore` CLI | Dashboard undelete UI, permanent empty-trash button, cross-vault moves |
| 2 (merged #85) | Dashboard recycle bin panel: list, restore, retention banner, purge notice | Scheduled purge jobs, manual empty-trash |
| 3 (this PR) | `POST /trash/delete`, `POST /trash/empty`, `disk trash delete\|empty`, dashboard Delete + Empty bin, hourly scheduled prune (`DISK_TRASH_PRUNE_INTERVAL_SECS`, default 3600) | Cross-vault moves, billing-gated trash limits |

## Retention by tier

Trash items older than `max_age_secs` are permanently removed from the `files` index on each list request (`prune_expired_trash`) and by the background scheduler.

| Tier | Max age |
|------|---------|
| Free | 7 days |
| Pro | 90 days |
| Team | 365 days |

Aligns with per-file version history age caps (DISK-0020).

## HTTP API

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| GET | `/trash?vault_id=&limit=&offset=` | Bearer JWT | Lists soft-deleted files; prunes expired rows first |
| POST | `/trash/restore` | Bearer JWT | Body: `{ path, vault_id }` — undelete and rewrite live file when blob available |
| POST | `/trash/delete` | Bearer JWT | Body: `{ path, vault_id }` — permanently remove one trashed file |
| POST | `/trash/empty` | Bearer JWT | Body: `{ vault_id, confirm: true }` — permanently remove all trashed files in vault |

Mounted on the health HTTP listener when `DISK_AUTH_MODE=enforce`.

## CLI

```bash
disk trash list --vault default
disk trash restore --path docs/readme.md --vault default
disk trash delete --path docs/readme.md --vault default
disk trash empty --vault default --yes
```

Env: `DISK_API_BASE`, `DISK_ACCESS_TOKEN`.

## Storage

- **Index:** existing `files.deleted` + `files.deleted_at` (migration 005) — no new schema
- **Blobs:** unchanged `.version-blobs` archive; restore reuses version blob resolution

## Tests

- `crates/disk-core/src/meta_db/trash.rs` — list/restore/prune/delete/empty unit tests
- `crates/disk-server/src/trash/scheduler.rs` — scheduled prune integration test
- `deploy/www/dashboard/index.html` — recycle bin panel (list, restore, delete, empty)

## References

- `docs/design/DISK-0020-file-versioning.md` — version retention tiers
- `crates/disk-core/src/meta_db/tombstones.rs` — sync tombstone propagation (orthogonal)
