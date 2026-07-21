# DISK-0016 — Auth & Accounts scaffold

**Status:** slice 1 on DEVS — signup/login JWT on health HTTP listener.  
**Parent:** DISK-0001 commercial / SaaS track.  
**Tracking:** DISK-0016 in Datarim backlog.

> **Interim auth.** Local `user_accounts` + HS256 JWT until Auth Arcana OIDC/JWKS
> lands (slice 4+). Aligns with `secret/disk/jwt_signing_key` interim note in
> Disk Arcana operator docs.

## Scope

| Slice | In scope | Out of scope |
|-------|----------|--------------|
| 1 (this PR) | `user_accounts`, Argon2id passwords, HS256 JWT, `/auth/signup\|login\|me` | OAuth, email verify, Auth Arcana |
| 2 | OAuth social login (Auth Arcana RP or stub) | — |
| 3 | Email verification flow | — |
| 4+ | Auth Arcana JWKS, retire interim JWT | — |

## HTTP API (slice 1)

| Method | Path | Body | Response |
|--------|------|------|----------|
| POST | `/auth/signup` | `{ email, password, tenant_id? }` | `201` + Bearer token + user |
| POST | `/auth/login` | `{ email, password }` | `200` + Bearer token |
| GET | `/auth/me` | `Authorization: Bearer` | `200` + user profile |

Signup bootstraps `tenant_billing` → Free tier for the new `tenant_id`.

## Operator config

```bash
DISK_AUTH_MODE=disabled|enforce
DISK_JWT_SIGNING_KEY=<min 32 bytes>   # required when enforce
DISK_JWT_TTL_SECS=86400               # optional, default 24h
```

## Tests

- `crates/disk-core/src/accounts/` — password + JWT unit tests
- `crates/disk-core/src/meta_db/accounts.rs` — CRUD unit test
- `crates/disk-server/src/accounts/routes.rs` — `integration_tests` HTTP round-trips

## References

- Migration `011_user_accounts.sql`
- `crates/disk-server/src/accounts/routes.rs`
