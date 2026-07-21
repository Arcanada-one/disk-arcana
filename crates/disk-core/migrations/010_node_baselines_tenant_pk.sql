-- DISK-0017 slice 3: tenant-aware primary key for node_baselines.
--
-- Legacy PK (node_id, vault_id, path) allowed cross-tenant row collision.
-- Rebuild with tenant_key = COALESCE(tenant_id, '') in the PK.

CREATE TABLE node_baselines_new (
    tenant_key     TEXT    NOT NULL DEFAULT '',
    node_id        TEXT    NOT NULL,
    vault_id       TEXT    NOT NULL,
    path           TEXT    NOT NULL,
    content_hash   BLOB,
    size           INTEGER NOT NULL DEFAULT 0,
    mtime_ns       INTEGER NOT NULL DEFAULT 0,
    vector_clock   TEXT    NOT NULL DEFAULT '{}',
    deleted        INTEGER NOT NULL DEFAULT 0,
    deleted_at     INTEGER,
    node_id_writer TEXT    NOT NULL DEFAULT '',
    updated_at     INTEGER NOT NULL DEFAULT (unixepoch()),
    tenant_id      TEXT,
    PRIMARY KEY (tenant_key, node_id, vault_id, path)
);

INSERT INTO node_baselines_new (
    tenant_key, node_id, vault_id, path, content_hash, size, mtime_ns,
    vector_clock, deleted, deleted_at, node_id_writer, updated_at, tenant_id
)
SELECT
    COALESCE(tenant_id, ''), node_id, vault_id, path, content_hash, size, mtime_ns,
    vector_clock, deleted, deleted_at, node_id_writer, updated_at, tenant_id
FROM node_baselines;

DROP TABLE node_baselines;
ALTER TABLE node_baselines_new RENAME TO node_baselines;

CREATE INDEX IF NOT EXISTS idx_node_baselines_tenant_scope
    ON node_baselines(tenant_id, node_id, vault_id);
