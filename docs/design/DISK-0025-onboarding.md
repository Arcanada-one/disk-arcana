# DISK-0025 — Onboarding Flow + Help Center

**Status:** slice 2 on DEVS — dashboard getting-started checklist.  
**Parent:** DISK-0001 commercial / SaaS track.  
**Tracking:** DISK-0025 in Datarim backlog.

## Scope

| Slice | In scope | Out of scope |
|-------|----------|--------------|
| 1 (merged #93) | Static help center at `deploy/www/docs/` (Diátaxis-lite: tutorials + how-to), sitemap + home/dashboard links; canonical host `disk.arcanada.ai/docs/` (alias `docs.disk.arcanada.one` via nginx) | Dashboard onboarding wizard, server-side progress persistence |
| 2 (this PR) | Dashboard getting-started checklist derived from `/dashboard/summary`; dismiss via localStorage; deep links to help articles | Email drip campaigns, in-app tooltips tour |
| 3 | `user_onboarding` table, `GET/PUT /onboarding`, persist dismiss across devices | PostHog funnel analytics (DISK-0026) |

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

## Onboarding checklist (slice 2)

Steps auto-completed from dashboard summary:

1. **Verify email** — `user.email_verified`
2. **Enroll a device** — `devices.length > 0`
3. **Create a vault** — `vaults.length > 0`
4. **First sync** — any device `last_seen` within 7 days

Dismiss stored in `localStorage` (`disk_onboarding_dismissed:<user_id>`) until slice 3 server persistence.

## Deploy

Static files ship with `deploy/www/` rsync (see `deploy/www/README.md`). Operator may add nginx vhost `docs.disk.arcanada.one` → same `docs/` directory.

## Tests

- Slice 1: manual link check; no Rust tests (static HTML only)
- Slice 2: manual dashboard checklist (verify / enroll / vault / sync steps)
- Slice 3: `crates/disk-server/src/onboarding/routes.rs` integration tests

## References

- `docs/installation.md` — developer-oriented install guide
- `documentation/runbooks/disk-arcana/DISK-RB-001-enroll.md` — operator enrollment runbook
- `deploy/www/dashboard/index.html` — tenant dashboard SPA
