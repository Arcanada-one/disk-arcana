# DISK-0024 — Trash / Recycle Bin

**Status:** slice 1 on DEVS — list/restore API + tier retention prune.  
**Parent:** DISK-0001 commercial / SaaS track.  
**Tracking:** DISK-0024 in Datarim backlog.

## Scope

| Slice | In scope | Out of scope |
|-------|----------|--------------|
| 1 (this PR) | List trashed files (`deleted=1`), restore (undelete), tier retention auto-prune on list, `disk trash list\|restore` CLI | Dashboard undelete UI, permanent empty-trash button, cross-vault moves |
| 2 (planned) | Dashboard trash panel (list, restore, retention banner) | Scheduled purge jobs, admin audit export |

## Retention by tier

Trash items older than `max_age_secs` are permanently removed from the `files` index on each list request (`prune_expired_trash`).

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

Mounted on the health HTTP listener when `DISK_AUTH_MODE=enforce`.

## CLI

```bash
disk trash list --vault default
disk trash restore --path docs/readme.md --vault default
```

Env: `DISK_API_BASE`, `DISK_ACCESS_TOKEN`.

## Storage

- **Index:** existing `files.deleted` + `files.deleted_at` (migration 005) — no new schema
- **Blobs:** unchanged `.version-blobs` archive; restore reuses version blob resolution

## Tests

- `crates/disk-core/src/meta_db/trash.rs` — list/restore/prune unit test
- `crates/disk-server/src/trash/routes.rs` — HTTP list/restore round-trip

## References

- `docs/design/DISK-0020-file-versioning.md` — version retention tiers
- `crates/disk-core/src/meta_db/tombstones.rs` — sync tombstone propagation (orthogonal)
