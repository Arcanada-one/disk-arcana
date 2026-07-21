# DISK-0018 — Billing scaffold

**Status:** slice 2 on DEVS — Stripe webhook HMAC verification.  
**Parent:** DISK-0001 commercial / SaaS track.  
**Tracking:** DISK-0018 in Datarim backlog.

## Scope

| Slice | In scope | Out of scope |
|-------|----------|--------------|
| 1 (merged #61) | `PlanTier`, `tenant_billing`, `QuotaEnforcer`, Stripe JSON parser + webhook route | Live Stripe API, HMAC verify |
| 2 (this PR) | `verify_stripe_webhook_signature`, `DISK_STRIPE_WEBHOOK_SECRET`, timestamp tolerance | Billing Arcana, invoices, node/vault quotas |
| 3+ | Node/vault quota gates, Billing Arcana integration, dashboard | — |

## Plan tiers

| Tier | Storage | Nodes | Vaults | Stripe `lookup_key` |
|------|---------|-------|--------|---------------------|
| Free | 5 GiB | 2 | 1 | `disk_free` |
| Pro | 100 GiB | 10 | 5 | `disk_pro` |
| Team | 1 TiB | 50 | 20 | `disk_team` |

## Operator config

```bash
DISK_BILLING_MODE=disabled          # self-hosted default
DISK_BILLING_MODE=enforce           # quota gate only
DISK_BILLING_MODE=stripe            # quota + webhook

DISK_BILLING_DEFAULT_TIER=free
DISK_STRIPE_WEBHOOK_SECRET=whsec_...   # required when stripe + sig verify on
DISK_STRIPE_WEBHOOK_REQUIRE_SIG=1    # set 0 for local stub (no secret)
DISK_STRIPE_WEBHOOK_TOLERANCE_SECS=300
```

## Stripe signature (slice 2)

`POST /billing/stripe/webhook` verifies `Stripe-Signature` before JSON parse:

1. `signed_payload = "{t}.{body}"`
2. `v1 = HMAC-SHA256(webhook_secret, signed_payload)` (hex)
3. Reject when timestamp skew exceeds tolerance (default 300s)

## API

```rust
verify_stripe_webhook_signature(header, body, secret, tolerance_secs)
compute_v1_signature(secret, timestamp, body)  // tests
```

## Tests

- `crates/disk-core/src/billing/stripe_sig.rs` — HMAC unit tests
- `crates/disk-server/src/billing/webhook.rs` — accept valid / reject invalid sig

## References

- `crates/disk-core/migrations/006_billing.sql`
- Stripe: https://stripe.com/docs/webhooks/signatures
