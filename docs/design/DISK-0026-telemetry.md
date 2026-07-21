# DISK-0026 — Telemetry & Product Analytics (PostHog opt-in)

**Status:** slice 1 on DEVS — dashboard PostHog opt-in + onboarding funnel events.  
**Parent:** DISK-0001 commercial / SaaS track.  
**Tracking:** DISK-0026 in Datarim backlog.

## Scope

| Slice | In scope | Out of scope |
|-------|----------|--------------|
| 1 (this PR) | `user_telemetry` table, `GET/PUT /telemetry`, public `GET /telemetry/config`, dashboard opt-in toggle, PostHog JS loader (EU host default), onboarding funnel events, consent audit + sub-processor registry | CLI `disk.toml` anonymous telemetry sender, server-side event ingestion, cookie banner |
| 2+ | Client daemon opt-in events (`[telemetry] opt_in` in `disk.toml`), ops metrics export | Marketing attribution, session replay |

## Privacy model

- **Opt-in only** — default `opt_in = false` per user; PostHog script loads only after explicit dashboard toggle.
- **No content telemetry** — events are coarse product signals (onboarding step names, dashboard viewed). No vault paths, file names, or sync payloads.
- **Identify** — PostHog `identify` uses internal `user_id` only (no email).
- **Consent audit** — each preference change records `product_analytics` in `consent_events`.
- **Erasure** — `user_telemetry` row deleted on account deletion.

## HTTP API

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| GET | `/telemetry/config` | — (public) | `{ enabled, project_key?, api_host }` from server env |
| GET | `/telemetry` | Bearer JWT | `{ user_id, opt_in, updated_at?, server_enabled }` |
| PUT | `/telemetry` | Bearer JWT | Body: `{ opt_in: bool }` — 503 when server analytics disabled |

## Environment

| Variable | Purpose |
|----------|---------|
| `DISK_POSTHOG_PROJECT_KEY` | Enables analytics when set (exposed to dashboard via `/telemetry/config`) |
| `DISK_POSTHOG_API_HOST` | Ingest host (default `https://eu.i.posthog.com`) |

## Dashboard events (PostHog)

| Event | When |
|-------|------|
| `analytics_opt_in` | User enables the toggle |
| `dashboard_viewed` | Dashboard load while opted in |
| `onboarding_checklist_viewed` | Getting-started panel shown (once per user) |
| `onboarding_step_completed` | Step transitions to done (`verify_email`, `enroll_device`, `create_vault`, `first_sync`) |
| `onboarding_dismissed` | User dismisses checklist |

Funnel dedupe uses `localStorage` key `disk_telemetry_funnel:{user_id}`.

## Storage

- **Migration 019:** `user_telemetry (user_id PK, opt_in, updated_at)`

## Tests

- `crates/disk-core/src/meta_db/telemetry.rs` — get/upsert unit tests
- `crates/disk-server/src/telemetry/routes.rs` — HTTP round-trip + consent recording
- `crates/disk-core/tests/schema_smoke.rs` — migration 019 table exists

## References

- `docs/design/DISK-0025-onboarding.md` — onboarding checklist (funnel source)
- `docs/design/DISK-0021-compliance.md` — consent audit trail
- `deploy/www/dashboard/index.html` — opt-in UI + PostHog loader
- `disk.toml.example` — client-side telemetry flag (slice 2)
