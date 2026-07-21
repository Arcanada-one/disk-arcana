# DISK-0019 — Web Dashboard

**Status:** slice 2 on DEVS — OAuth browser landing + conflict resolve API.  
**Parent:** DISK-0001 commercial / SaaS track.  
**Tracking:** DISK-0019 in Datarim backlog.

## Scope

| Slice | In scope | Out of scope |
|-------|----------|--------------|
| 1 (merged #73) | `GET /dashboard/summary`, static SPA (`deploy/www/dashboard/`), signup/login UI | Stripe checkout UI, OAuth browser redirect handler, conflict resolve actions |
| 2 (this PR) | OAuth browser flow (`flow=browser` + `oauth-callback.html`), `POST /dashboard/conflicts/{id}/resolve` | Stripe checkout, file-level conflict ops |
| 3+ | Billing upgrade CTA | DISK-0018 Billing Arcana integration |

## HTTP API

| Method | Path | Auth | Response |
|--------|------|------|----------|
| GET | `/dashboard/summary` | Bearer JWT | Tenant vaults, devices, billing usage, unresolved conflicts |
| POST | `/dashboard/conflicts/{id}/resolve` | Bearer JWT | `{ "action": "keep-local\|..." }` — metadata-only resolve (no file I/O on server) |

### OAuth browser flow (slice 2)

1. Dashboard calls `GET /auth/oauth/start?flow=browser&redirect_uri={callback_url}`.
2. `redirect_uri` is embedded in signed OAuth `state` and used for stub/Auth Arcana authorize.
3. IdP redirects to `deploy/www/dashboard/oauth-callback.html?code=…&state=…`.
4. Callback page exchanges code via `GET /auth/oauth/callback`, stores token, redirects to dashboard.

`redirect_uri` must be `https://…` or `http://127.0.0.1` / `http://localhost` (dev).

Mounted on the health HTTP listener (`DISK_HEALTH_BIND_ADDR`, default `:9446`) when `DISK_AUTH_MODE=enforce`.

### Summary JSON shape

```json
{
  "user": { "user_id", "email", "tenant_id", "email_verified" },
  "billing": {
    "plan_tier": "free|pro|team",
    "storage_bytes", "storage_limit_bytes",
    "nodes_count", "nodes_limit",
    "vaults_count", "vaults_limit"
  },
  "vaults": [{ "vault_id", "created_at" }],
  "devices": [{ "node_id", "display_name", "platform", "registered_at", "last_seen" }],
  "conflicts": [{ "id", "vault_id", "path", "conflict_type", "fork_path", "created_at" }]
}
```

## Static SPA

- Path: `deploy/www/dashboard/index.html`
- Deploy with `deploy/www/README.md` rsync to `disk.arcanada.ai`
- API base: same origin when health routes are reverse-proxied; override via `?api=https://host:9446` for dev

Signup/login uses DISK-0016 `/auth/signup`, `/auth/login`, `/auth/me`, and OAuth via `oauth-callback.html`.

## Tests

- `crates/disk-core/src/meta_db/dashboard.rs` — tenant-scoped list unit test
- `crates/disk-server/src/dashboard/routes.rs` — `integration_tests` HTTP round-trips

## References

- `docs/design/DISK-0016-auth-scaffold.md`
- `docs/design/DISK-0018-billing-scaffold.md`
- `deploy/www/dashboard/index.html`
