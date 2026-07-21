# DISK-0022 — Sharing & Collaboration

**Status:** slice 3 on DEVS — collaborator RBAC on HTTP vault routes.  
**Parent:** DISK-0001 commercial / SaaS track.  
**Tracking:** DISK-0022 in Datarim backlog.

## Scope

| Slice | In scope | Out of scope |
|-------|----------|--------------|
| 1 (merged #87) | `vault_invites` + `vault_members` tables, invite create/list/accept, member list/remove, `disk sharing` CLI | Dashboard sharing UI, sync-path ACL enforcement, cross-tenant file ACL on gRPC |
| 2 (merged #88) | Dashboard vault sharing panel: create invite, show one-time token/URL, pending invites + collaborators tables, remove member, `?sharing_accept=` deep-link accept | Email delivery of invites, Auth Arcana group sync |
| 3 (this PR) | Enforce collaborator roles on HTTP vault routes (`/versions`, `/trash`, `/snapshots`, `/sharing/*` manage) | gRPC sync ACL, real-time co-editing |

## RBAC model

| Role | Who | Capabilities |
|------|-----|--------------|
| Owner (implicit) | Users in the vault's owning tenant (`tenant_vaults`) | Read + write vault data; manage sharing invites/members; trash delete/empty |
| Editor | External collaborator via invite | Read + write (restore versions, trash, snapshots) |
| Viewer | External collaborator via invite | Read-only (list/get); write/manage → 403 |

Owning-tenant users are implicit owners when the vault exists in `tenant_vaults`. External users join via redeeming an invite token.

### HTTP enforcement matrix (slice 3)

| Route family | Viewer | Editor | Owner |
|--------------|--------|--------|-------|
| `GET /versions`, `GET /trash`, `GET /snapshots` | yes | yes | yes |
| `POST` restore / create snapshot | no | yes | yes |
| `POST /trash/delete`, `/trash/empty` | no | no | yes |
| `POST/GET /sharing/*` (manage) | no | no | yes |

Owning-tenant users are implicit owners when the vault exists in `tenant_vaults`. External users join via redeeming an invite token.

## HTTP API

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| POST | `/sharing/invites` | Bearer JWT (owner tenant) | Body: `{ vault_id, role: viewer\|editor, ttl_hours? }` → invite token |
| GET | `/sharing/invites?vault_id=` | Bearer JWT (owner tenant) | List invites (no token leak) |
| POST | `/sharing/invites/accept` | Bearer JWT (any user) | Body: `{ token }` — 64-char hex token |
| GET | `/sharing/members?vault_id=` | Bearer JWT (owner tenant) | External collaborators only |
| POST | `/sharing/members/remove` | Bearer JWT (owner tenant) | Body: `{ vault_id, user_id }` |

Mounted on the health HTTP listener when `DISK_AUTH_MODE=enforce`.

## Dashboard deep links

- `?sharing=1` — open sharing panel and load default vault
- `?sharing_vault=wiki` — preselect vault
- `?sharing_accept=<hex>` — persist token, prompt sign-in if needed, show Accept invite banner

## CLI

```bash
disk sharing invites create --vault wiki --role viewer
disk sharing invites list --vault wiki
disk sharing invites accept --invite-token <hex>
disk sharing members list --vault wiki
disk sharing members remove --vault wiki --user <user_id>
```

Env: `DISK_API_BASE`, `DISK_ACCESS_TOKEN`.

## Storage

- **Migration 016:** `vault_invites`, `vault_members`
- Invite tokens stored as Blake3 hash; raw token returned once on create

## Tests

- `crates/disk-core/src/meta_db/sharing.rs` — invite/member unit test
- `crates/disk-server/src/sharing/routes.rs` — HTTP round-trip integration test
- `crates/disk-server/src/sharing/access.rs` — vault access resolution unit test
- `crates/disk-server/src/versions/routes.rs` — collaborator RBAC integration test
- `deploy/www/dashboard/index.html` — sharing panel UI

## References

- `proto/disk.proto` — reserved fields 16–19 for future sharing wire fill
- `crates/disk-server/src/acl/` — node cert directional roles (orthogonal sync ACL)
