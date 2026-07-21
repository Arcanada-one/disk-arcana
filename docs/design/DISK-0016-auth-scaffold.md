# DISK-0016 — Auth & Accounts scaffold

**Status:** slice 4 on DEVS — Auth Arcana JWKS verification, retire interim JWT in `auth_arcana` mode.  
**Parent:** DISK-0001 commercial / SaaS track.  
**Tracking:** DISK-0016 in Datarim backlog.

> **Interim auth.** Local `user_accounts` + HS256 JWT until Auth Arcana JWKS
> verification retires interim signing (`DISK_JWT_MODE=auth_arcana`). OAuth providers route through
> Auth Arcana per ecosystem mandate — no direct Google/GitHub integrations.

## Scope

| Slice | In scope | Out of scope |
|-------|----------|--------------|
| 1 (merged #68) | `user_accounts`, Argon2id passwords, HS256 JWT, `/auth/signup\|login\|me` | OAuth, email verify, Auth Arcana |
| 2 (merged #69) | OAuth columns, `stub` + `auth_arcana` modes, `/auth/oauth/start\|callback` | Email verify, JWKS retire |
| 3 (merged #70) | HMAC verification tokens, `/auth/verify-email`, `/auth/resend-verification` | SMTP delivery, Auth Arcana |
| 4 (this PR) | `DISK_JWT_MODE`, JWKS cache + verify, OAuth token passthrough | SMTP, DISK-0018 billing |
| 5+ | Full password auth via Auth Arcana (ROPC/device) | — |

## HTTP API

### Slice 1 (password)

| Method | Path | Body | Response |
|--------|------|------|----------|
| POST | `/auth/signup` | `{ email, password, tenant_id? }` | `201` + Bearer token + user |
| POST | `/auth/login` | `{ email, password }` | `200` + Bearer token |
| GET | `/auth/me` | `Authorization: Bearer` | `200` + user profile |

Password signup/login return `403` when `DISK_JWT_MODE=auth_arcana` (use OAuth).

### Slice 2 (OAuth)

| Method | Path | Query | Response |
|--------|------|-------|----------|
| GET | `/auth/oauth/start` | `provider?` | `200` `{ authorization_url, state }` |
| GET | `/auth/oauth/callback` | `code`, `state?` | `200` + Bearer token + user |

- **stub:** `authorization_url` points at local callback with encoded test identity (CI/dev).
- **auth_arcana:** redirects to `{DISK_OAUTH_ISSUER}/authorize` (OIDC code flow); callback exchanges code via discovery + userinfo.
- When `DISK_JWT_MODE=auth_arcana`, OAuth callback returns Auth Arcana `access_token` (passthrough) instead of re-issuing HS256.

OAuth signup bootstraps `tenant_billing` → Free tier. OAuth-only users cannot password-login.

### Slice 3 (email verification)

| Method | Path | Auth | Response |
|--------|------|------|----------|
| GET | `/auth/verify-email` | `token` query | `200` + refreshed Bearer token (`email_verified=true`) |
| POST | `/auth/resend-verification` | Bearer JWT | `200` `{ sent, verification_token?, verification_url? }` |

- **stub:** signup and resend include `verification_token` + `verification_url` in JSON (CI/dev).
- **log:** verification URL logged via `tracing` (no SMTP).
- Password signup with verification active leaves `email_verified=false` until token consumed.
- OAuth users with IdP `email_verified=true` skip this flow (slice 2).

### Slice 4 (JWT / JWKS)

Bearer verification modes:

| `DISK_JWT_MODE` | Issue (signup/login/OAuth) | Verify (`/auth/me`, resend) |
|-----------------|----------------------------|-----------------------------|
| `local` (default) | HS256 interim (`DISK_JWT_SIGNING_KEY`) | HS256 |
| `auth_arcana` | OAuth passthrough only; password `403` | Auth Arcana JWKS |
| `dual` | HS256 issue + OAuth passthrough optional | JWKS first, HS256 fallback |

`DISK_JWT_SIGNING_KEY` remains required for HMAC (OAuth state, email verification) when `DISK_AUTH_MODE=enforce`.

## Operator config

```bash
DISK_AUTH_MODE=disabled|enforce
DISK_JWT_SIGNING_KEY=<min 32 bytes>   # required when enforce (HMAC + local JWT)
DISK_JWT_TTL_SECS=86400               # optional, default 24h
DISK_JWT_MODE=local|auth_arcana|dual  # slice 4
DISK_JWT_ISSUER=https://auth.arcanada.ai
DISK_JWT_JWKS_URI=https://auth.arcanada.ai/.well-known/jwks.json

# OAuth (slice 2) — requires DISK_AUTH_MODE=enforce
DISK_OAUTH_MODE=disabled|stub|auth_arcana
DISK_OAUTH_PUBLIC_BASE_URL=http://host:9446   # stub mode
DISK_OAUTH_ISSUER=https://auth.arcanada.ai    # auth_arcana mode
DISK_OAUTH_CLIENT_ID=...
DISK_OAUTH_CLIENT_SECRET=...
DISK_OAUTH_REDIRECT_URI=https://disk.example/auth/oauth/callback

# Email verification (slice 3) — requires DISK_AUTH_MODE=enforce
DISK_EMAIL_VERIFY_MODE=disabled|stub|log
DISK_EMAIL_VERIFY_BASE_URL=http://host:9446   # stub mode (verification link host)
DISK_EMAIL_VERIFY_TTL_SECS=86400            # optional, default 24h
```

## Tests

- `crates/disk-core/src/accounts/` — password + JWT unit tests
- `crates/disk-core/src/meta_db/accounts.rs` — CRUD unit test
- `crates/disk-core/tests/schema_smoke.rs` — migration 012 oauth columns
- `crates/disk-server/src/accounts/oauth.rs` — stub code + state HMAC unit tests
- `crates/disk-server/src/accounts/email_verify.rs` — verification token HMAC unit tests
- `crates/disk-server/src/accounts/jwt_service.rs` — JWT mode unit tests
- `crates/disk-server/src/accounts/routes.rs` — `integration_tests` HTTP round-trips

## References

- Migrations `011_user_accounts.sql`, `012_user_accounts_oauth.sql`
- `crates/disk-server/src/accounts/oauth.rs`
- `crates/disk-server/src/accounts/email_verify.rs`
- `crates/disk-server/src/accounts/jwt_service.rs`
- `documentation/mandates/auth-arcana-mandate.md` § JWKS
