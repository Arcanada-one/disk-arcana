-- 007_tenant_vaults.sql — per-tenant vault registry for quota enforcement (DISK-0018 slice 3).
-- `vault_id` maps to gRPC `x-disk-share` until DISK-0017 multi-tenant vault IDs land.

CREATE TABLE tenant_vaults (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   TEXT,
    vault_id    TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    UNIQUE (tenant_id, vault_id)
);
CREATE INDEX idx_tenant_vaults_tenant ON tenant_vaults(tenant_id);
