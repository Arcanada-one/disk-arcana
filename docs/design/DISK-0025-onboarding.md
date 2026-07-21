# DISK-0025 — Onboarding Flow + Help Center

**Status:** slice 3 on DEVS — server-side onboarding dismiss persistence.  
**Parent:** DISK-0001 commercial / SaaS track.  
**Tracking:** DISK-0025 in Datarim backlog.

## Scope

| Slice | In scope | Out of scope |
|-------|----------|--------------|
| 1 (merged #93) | Static help center at `deploy/www/docs/` (Diátaxis-lite: tutorials + how-to), sitemap + home/dashboard links; canonical host `disk.arcanada.ai/docs/` (alias `docs.disk.arcanada.one` via nginx) | Dashboard onboarding wizard, server-side progress persistence |
| 2 (merged #94) | Dashboard getting-started checklist derived from `/dashboard/summary`; dismiss via localStorage; deep links to help articles | Email drip campaigns, in-app tooltips tour |
| 3 (this PR) | `user_onboarding` table, `GET/PUT /onboarding`, dashboard syncs dismiss to server (localStorage fallback + migration on load) | PostHog funnel analytics (DISK-0026) |

## Help center structure

| Page | Category | Purpose |
|------|----------|---------|
| `docs/index.html` | Hub | Navigation + search keywords |
| `docs/getting-started.html` | Tutorial | End-to-end first sync in ~10 minutes |
| `docs/install-client.html` | How-to | Install `disk` CLI (Linux/macOS/Windows) |
| `docs/enroll-device.html` | How-to | Enrollment token + `disk enroll` |
| `docs/dashboard.html` | How-to | Tenant dashboard features |
| `docs/vaults-and-sync.html` | Reference | Vaults, selective sync, sharing, trash |
| `docs/troubleshooting.html` | How-to | Common errors and fixes |

## Onboarding checklist

Steps auto-completed from dashboard summary:

1. **Verify email** — `user.email_verified`
2. **Enroll a device** — `devices.length > 0`
3. **Create a vault** — `vaults.length > 0`
4. **First sync** — any device `last_seen` within 7 days

Dismiss: `PUT /onboarding` with `{ dismissed: true }`. Dashboard migrates legacy `localStorage` dismiss to server on first load.

## HTTP API (slice 3)

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| GET | `/onboarding` | Bearer JWT | `{ user_id, dismissed, dismissed_at?, updated_at? }` |
| PUT | `/onboarding` | Bearer JWT | Body: `{ dismissed: bool }` — upsert per user |

## Storage

- **Migration 018:** `user_onboarding (user_id PK, dismissed, dismissed_at, updated_at)`

## Tests

- `crates/disk-core/src/meta_db/onboarding.rs` — get/upsert unit tests
- `crates/disk-server/src/onboarding/routes.rs` — HTTP round-trip
- `crates/disk-core/tests/schema_smoke.rs` — migration 018 table exists

## References

- `docs/installation.md` — developer-oriented install guide
- `documentation/runbooks/disk-arcana/DISK-RB-001-enroll.md` — operator enrollment runbook
- `deploy/www/dashboard/index.html` — tenant dashboard SPA
