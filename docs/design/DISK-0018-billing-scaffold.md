# DISK-0018 — Billing scaffold

**Status:** slice 3 on DEVS — node/vault `QuotaLimits` enforcement.  
**Parent:** DISK-0001 commercial / SaaS track.  
**Tracking:** DISK-0018 in Datarim backlog.

## Scope

| Slice | In scope | Out of scope |
|-------|----------|--------------|
| 1 (merged #61) | `PlanTier`, `tenant_billing`, storage `QuotaEnforcer`, Stripe JSON + webhook route | HMAC verify |
| 2 (merged #62) | `verify_stripe_webhook_signature`, `DISK_STRIPE_WEBHOOK_SECRET` | node/vault quotas |
| 3 (this PR) | `check_register_node`, vault gate on `DeltaUpload` (`x-disk-share`), `tenant_vaults` table | Billing Arcana, invoices |
| 4+ | Billing Arcana integration, dashboard | — |

## Plan tiers

| Tier | Storage | Nodes | Vaults | Stripe `lookup_key` |
|------|---------|-------|--------|---------------------|
| Free | 5 GiB | 2 | 1 | `disk_free` |
| Pro | 100 GiB | 10 | 5 | `disk_pro` |
| Team | 1 TiB | 50 | 20 | `disk_team` |

## Enforcement points (slice 3)

| Quota | Gate | Key |
|-------|------|-----|
| Nodes | `AuthService::RegisterNode` | In-memory `AuthStore::node_count()` |
| Vaults | `DeltaUpload` pre-check | `x-disk-share` → `tenant_vaults` registry |
| Storage | `DeltaUpload` pre-check | `SUM(files.size)` per tenant |

Vault registration is recorded after successful upload (`INSERT OR IGNORE`).

## Operator config

```bash
DISK_BILLING_MODE=disabled|enforce|stripe
DISK_BILLING_DEFAULT_TIER=free
DISK_STRIPE_WEBHOOK_SECRET=whsec_...
DISK_STRIPE_WEBHOOK_REQUIRE_SIG=1
DISK_STRIPE_WEBHOOK_TOLERANCE_SECS=300
```

## Tests

- `crates/disk-core/src/billing/quota.rs` — node/vault capacity unit tests
- `crates/disk-server/tests/quota_enforcement.rs` — register + vault ITs

## References

- `crates/disk-core/migrations/006_billing.sql`, `007_tenant_vaults.sql`
