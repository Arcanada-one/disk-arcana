-- 006_billing.sql — SaaS subscription tier scaffold (DISK-0018 slice 1).
-- Storage quotas are enforced against SUM(files.size) per tenant; this table
-- holds plan metadata and Stripe linkage for future webhook integration.

CREATE TABLE tenant_billing (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id               TEXT,                              -- NULL = default single-tenant
    plan_tier               TEXT NOT NULL DEFAULT 'free',
    stripe_customer_id      TEXT,
    stripe_subscription_id  TEXT,
    created_at              INTEGER NOT NULL,
    updated_at              INTEGER NOT NULL,
    UNIQUE (tenant_id)
);
CREATE INDEX idx_tenant_billing_stripe_customer ON tenant_billing(stripe_customer_id);
