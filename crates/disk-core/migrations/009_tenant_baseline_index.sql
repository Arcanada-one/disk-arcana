-- DISK-0017 slice 3: index for tenant-scoped node baseline lookups.
CREATE INDEX IF NOT EXISTS idx_node_baselines_tenant_scope
    ON node_baselines(tenant_id, node_id, vault_id);
