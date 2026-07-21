# DISK-0021 — Compliance (ToS, Privacy, GDPR, DPA, data export)

**Status:** slice 1 on DEVS — legal static pages + GDPR export API.  
**Parent:** DISK-0001 commercial / SaaS track.  
**Tracking:** DISK-0021 in Datarim backlog.

## Scope

| Slice | In scope | Out of scope |
|-------|----------|--------------|
| 1 (this PR) | Static legal pages (`deploy/www/legal/`), `GET /compliance/export`, dashboard export button + signup ToS notice | Account deletion API, signed enterprise DPA workflow, cookie banner |
| 2+ | Right-to-erasure, sub-processor registry page, consent audit trail | Legal Arcana CMS integration |

## HTTP API

| Method | Path | Auth | Response |
|--------|------|------|----------|
| GET | `/compliance/export` | Bearer JWT | JSON bundle: user profile (no secrets), tenant vaults/devices, plan tier, `exported_at` |

Mounted on the health HTTP listener when `DISK_AUTH_MODE=enforce` (same router as `/dashboard/*`).

### Export JSON shape (format_version 1)

```json
{
  "exported_at": 1710000000,
  "format_version": 1,
  "user": {
    "user_id", "email", "tenant_id", "email_verified",
    "oauth_provider", "created_at", "updated_at"
  },
  "tenant": {
    "tenant_id", "plan_tier",
    "vaults": [{ "vault_id", "created_at" }],
    "devices": [{ "node_id", "display_name", "platform", "registered_at", "last_seen" }]
  }
}
```

File content bytes are **not** included (metadata-only portability scaffold). Full vault export is a follow-up tied to DISK-0020 / storage APIs.

## Static pages

- `deploy/www/legal/index.html` — index
- `deploy/www/legal/terms.html` — Terms of Service (MVP scaffold)
- `deploy/www/legal/privacy.html` — Privacy Policy (GDPR-oriented)
- `deploy/www/legal/dpa.html` — DPA summary for B2B customers

Deploy with `deploy/www/README.md` rsync to `disk.arcanada.ai`.

## Tests

- `crates/disk-server/src/compliance/routes.rs` — `integration_tests` HTTP round-trips

## References

- `docs/design/DISK-0019-web-dashboard.md`
- `deploy/www/dashboard/index.html` — export button + legal footer
