# DISK-0028 — AI Agents API (webhooks, agent-write protocol, optimistic locks)

**Status:** slice 1 on DEVS — webhook registration + agent-write with optimistic revisions.  
**Parent:** DISK-0001 commercial / SaaS track.  
**Tracking:** DISK-0028 in Datarim backlog.

## Scope

| Slice | In scope | Out of scope |
|-------|----------|--------------|
| 1 (this PR) | `agent_webhooks` + `agent_write_revisions` tables; `GET/POST/DELETE /agents/webhooks`; `GET /agents/revision`; `POST /agents/write` with `if_match_revision` optimistic locking | Async webhook delivery on file events, HMAC outbound signing, CLI `disk agents` |
| 2 | Fire registered webhooks on sync/agent events with HMAC `X-Disk-Signature` | Agent API keys separate from user JWT |
| 3 | `disk agents` CLI (`webhooks`, `write`, `revision`) | LAN sync acceleration (DISK-0027) |

## Agent-write protocol

Agents (or automation using a tenant JWT) write vault files over HTTP instead of gRPC sync.

| Field | Rule |
|-------|------|
| `vault_id` | Target vault (default `default`) |
| `path` | Relative path under sync root; `..` rejected |
| `content_base64` | Raw file bytes (UTF-8 text or binary) |
| `if_match_revision` | **Create:** omit or `0` when no prior revision. **Update:** must equal current revision or `409 revision_conflict` |
| `agent_id` | Optional audit label (defaults to `user_id`) |

Response includes monotonic `revision` per `(tenant, vault, path)` independent of internal `files.version_id`.

## Optimistic locking

`agent_write_revisions` stores the agent-facing revision counter. `GET /agents/revision` returns the current value before a write. Concurrent writers that skip the read-modify-write cycle receive `409`.

## Webhook registration

Tenant owners register HTTPS callback URLs per vault. Secrets are returned once on create (Blake3 hash stored). Delivery is deferred to slice 2.

Supported event names (stored, not yet dispatched):

- `sync.file_changed`
- `sync.file_deleted`
- `agent.write_ok`
- `agent.write_conflict`

## HTTP API

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| GET | `/agents/webhooks` | Bearer JWT (vault owner) | Query: `vault_id` |
| POST | `/agents/webhooks` | Bearer JWT (vault owner) | Body: `{ vault_id, url, events[], label? }` → `webhook_secret` once |
| DELETE | `/agents/webhooks` | Bearer JWT (vault owner) | Body: `{ webhook_id }` |
| GET | `/agents/revision` | Bearer JWT (editor+) | Query: `path`, `vault_id` |
| POST | `/agents/write` | Bearer JWT (editor+) | Optimistic write; `409` on revision mismatch |

Mounted on the health HTTP listener when `DISK_AUTH_MODE=enforce`.

## Storage

- **Migration 020:** `agent_webhooks`, `agent_write_revisions`

## Tests

- `crates/disk-core/src/meta_db/agents.rs` — revision bump + webhook CRUD unit tests
- `crates/disk-server/src/agents/routes.rs` — HTTP round-trip (write conflict + webhook CRUD)
- `crates/disk-core/tests/schema_smoke.rs` — migration 020 tables exist

## References

- `docs/design/DISK-0022-sharing.md` — vault RBAC (`require_write`)
- PRD-DISK-0001 v1.1 §4.11 — `publisher` role for machine-generated content (gRPC path)
- `crates/disk-server/src/versions/routes.rs` — versioned file upsert pattern
