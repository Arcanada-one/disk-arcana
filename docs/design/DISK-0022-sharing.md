# DISK-0022 — Sharing & Collaboration

**Status:** slice 1 on DEVS — invite links + collaborator RBAC API/CLI.  
**Parent:** DISK-0001 commercial / SaaS track.  
**Tracking:** DISK-0022 in Datarim backlog.

## Scope

| Slice | In scope | Out of scope |
|-------|----------|--------------|
| 1 (this PR) | `vault_invites` + `vault_members` tables, invite create/list/accept, member list/remove, `disk sharing` CLI | Dashboard sharing UI, sync-path ACL enforcement, cross-tenant file ACL on gRPC |
| 2 | Dashboard invite + members panel | Email delivery of invites, Auth Arcana group sync |
| 3 | Enforce collaborator roles on HTTP sync paths | Real-time co-editing |

## RBAC model

| Role | Who | Capabilities (slice 1) |
|------|-----|------------------------|
| Owner (implicit) | Users in the vault's owning tenant | Create/list/revoke invites and members |
| Editor | External collaborator via invite | Stored membership; enforcement deferred to slice 3 |
| Viewer | External collaborator via invite | Stored membership; enforcement deferred to slice 3 |

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

## References

- `proto/disk.proto` — reserved fields 16–19 for future sharing wire fill
- `crates/disk-server/src/acl/` — node cert directional roles (orthogonal sync ACL)
