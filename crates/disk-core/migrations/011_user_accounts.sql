-- 011_user_accounts.sql — SaaS user accounts scaffold (DISK-0016 slice 1).
-- Interim local auth until Auth Arcana OIDC/JWKS integration (slice 4+).

CREATE TABLE user_accounts (
    id              TEXT PRIMARY KEY,
    email           TEXT NOT NULL COLLATE NOCASE,
    password_hash   TEXT NOT NULL,
    tenant_id       TEXT NOT NULL,
    email_verified  INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    UNIQUE (email)
);
CREATE INDEX idx_user_accounts_tenant ON user_accounts(tenant_id);
