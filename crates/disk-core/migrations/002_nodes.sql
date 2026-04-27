-- 002_nodes.sql — server-only node registry.
-- Always applied in Phase 1 (gating moves to a feature flag in DISK-0005).

CREATE TABLE nodes (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Forward-compat
    tenant_id           TEXT,
    user_id             TEXT,
    -- Core
    node_id             TEXT NOT NULL UNIQUE,
    display_name        TEXT,
    platform            TEXT,
    api_key_hash        BLOB NOT NULL,
    vector_clock        TEXT NOT NULL DEFAULT '{}',
    last_seen           INTEGER,
    registered_at       INTEGER NOT NULL,
    revoked             INTEGER NOT NULL DEFAULT 0,
    revoked_at          INTEGER
);
CREATE INDEX idx_nodes_active        ON nodes(revoked) WHERE revoked = 0;
CREATE INDEX idx_nodes_tenant_user   ON nodes(tenant_id, user_id);
