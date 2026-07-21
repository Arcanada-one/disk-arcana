-- 017_device_selective_sync.sql — per-device folder include rules (DISK-0023 slice 1).

CREATE TABLE device_sync_includes (
    tenant_id     TEXT,
    user_id       TEXT NOT NULL,
    node_id       TEXT NOT NULL,
    vault_id      TEXT NOT NULL,
    path_prefix   TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, user_id, node_id, vault_id, path_prefix),
    FOREIGN KEY (user_id) REFERENCES user_accounts(id)
);

CREATE INDEX idx_device_sync_includes_lookup
    ON device_sync_includes(tenant_id, user_id, node_id, vault_id);
