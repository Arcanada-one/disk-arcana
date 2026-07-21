# DISK-0018 — Billing scaffold (slice 1)

**Status:** slice 1 on DEVS — plan tiers, storage quota gate, Stripe webhook stub.  
**Parent:** DISK-0001 commercial / SaaS track.  
**Tracking:** DISK-0018 in Datarim backlog (supersedes DISK-0015 slice 5+ billing note).

## Scope

| Slice | In scope | Out of scope |
|-------|----------|--------------|
| 1 (this PR) | `PlanTier`, `tenant_billing` migration, `QuotaEnforcer` on `DeltaUpload`, Stripe JSON parser + `POST /billing/stripe/webhook` stub | Live Stripe API, HMAC verify, invoices, Auth Arcana signup |
| 2+ | Stripe signature verification, Billing Arcana integration, dashboard | — |

## Plan tiers

| Tier | Storage | Nodes | Vaults | Stripe `lookup_key` |
|------|---------|-------|--------|---------------------|
| Free | 5 GiB | 2 | 1 | `disk_free` |
| Pro | 100 GiB | 10 | 5 | `disk_pro` |
| Team | 1 TiB | 50 | 20 | `disk_team` |

## Operator config

```bash
# Self-hosted default — no quota checks
DISK_BILLING_MODE=disabled

# Enforce tiers from tenant_billing / DISK_BILLING_DEFAULT_TIER
DISK_BILLING_MODE=enforce
DISK_BILLING_DEFAULT_TIER=free

# Stripe webhook on health HTTP listener (:9446)
DISK_BILLING_MODE=stripe
DISK_STRIPE_WEBHOOK_REQUIRE_SIG=1   # set 0 for local stub tests
```

## API

```rust
disk_core::billing::{PlanTier, QuotaLimits, check_storage_delta}
MetaDb::get_plan_tier / set_plan_tier / sum_storage_bytes / apply_stripe_subscription
disk_server::QuotaEnforcer::check_upload
POST /billing/stripe/webhook   // health listener, mode=stripe only
```

gRPC clients may send `x-disk-tenant` metadata (DISK-0017 forward-compat); omitted = single-tenant (`tenant_id IS NULL`).

## Tests

- `crates/disk-core/src/billing/*` — tier parse, quota math, Stripe JSON
- `crates/disk-core/src/meta_db/billing.rs` — tier round-trip
- `crates/disk-server/tests/quota_enforcement.rs` — upload accept/reject
- `crates/disk-server/src/billing/webhook.rs` — webhook HTTP IT

## References

- `crates/disk-core/migrations/006_billing.sql`
- `docs/design/DISK-0015-e2ee-scaffold.md` — E2EE track (orthogonal)
