# DISK-0021 — Compliance (ToS, Privacy, GDPR, DPA, data export)

**Status:** slice 3 on DEVS — sub-processor registry + consent audit trail.  
**Parent:** DISK-0001 commercial / SaaS track.  
**Tracking:** DISK-0021 in Datarim backlog.

## Scope

| Slice | In scope | Out of scope |
|-------|----------|--------------|
| 1 (merged #76) | Static legal pages (`deploy/www/legal/`), `GET /compliance/export`, dashboard export button + signup ToS notice | Account deletion API, signed enterprise DPA workflow, cookie banner |
| 2 (merged #77) | `POST /compliance/delete-account`, tenant metadata purge when last user leaves, dashboard delete UI | Blob storage erasure, Auth Arcana IdP account deletion, cookie banner |
| 3 (this PR) | `GET /compliance/sub-processors`, `GET /compliance/consents`, `consent_events` table, signup/OAuth consent recording, sub-processors page | Cookie banner, Legal Arcana CMS, consent re-prompt on policy update |
| 4+ | Policy version bump workflow, cookie consent | Legal Arcana CMS integration |

## HTTP API

| Method | Path | Auth | Body | Response |
|--------|------|------|------|----------|
| GET | `/compliance/export` | Bearer JWT | — | JSON export bundle |
| POST | `/compliance/delete-account` | Bearer JWT | `{ "confirm_email": "..." }` | `{ deleted, user_id, tenant_purged }` |
| GET | `/compliance/sub-processors` | — (public) | — | JSON processor registry |
| GET | `/compliance/consents` | Bearer JWT | — | `{ events: [...] }` |

Mounted on the health HTTP listener when `DISK_AUTH_MODE=enforce` (auth routes); `/compliance/sub-processors` is public on the same listener.

### Consent audit (slice 3)

- Migration `013_consent_events.sql` stores `terms_of_service` and `privacy_policy` acceptances at signup (password or OAuth).
- Policy versions: `1.0` (must match legal page effective dates).
- Erasure: per-user rows deleted on account deletion; tenant-wide purge when last user leaves.

### Delete account behaviour

1. `confirm_email` must match the authenticated user's normalized email.
2. Deletes consent events and `user_accounts` row.
3. If no users remain for the tenant, purges tenant metadata (see slice 2).

## Static pages

- `deploy/www/legal/` — Terms, Privacy, DPA, **Sub-processors** (slice 3)

## Tests

- `crates/disk-core/src/meta_db/consent.rs` — consent recording unit test
- `crates/disk-core/tests/schema_smoke.rs` — migration 013
- `crates/disk-server/src/compliance/routes.rs` — `integration_tests` HTTP round-trips

## References

- `docs/design/DISK-0019-web-dashboard.md`
- `deploy/www/dashboard/index.html` — export, delete, consent history UI
