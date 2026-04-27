-- 001_init.sql — Phase 1 schema with forward-compat columns.
-- Forward-compat fields (NULL / default) are populated in DISK-0017 (multi-tenant)
-- and DISK-0020 (versioning).

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE files (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Forward-compat
    tenant_id           TEXT,                              -- DISK-0017
    vault_id            TEXT NOT NULL DEFAULT 'default',   -- DISK-0017
    user_id             TEXT,                              -- DISK-0017
    -- Core fields
    path                TEXT NOT NULL,
    content_hash        BLOB NOT NULL,
    size                INTEGER NOT NULL,
    mtime_ns            INTEGER NOT NULL,
    inode               INTEGER,
    vector_clock        TEXT NOT NULL DEFAULT '{}',
    sync_state          TEXT NOT NULL DEFAULT 'clean',
    last_synced         INTEGER,
    -- Forward-compat: versioning (DISK-0020)
    version_id          INTEGER,
    parent_version_id   INTEGER,
    -- Forward-compat: E2EE (DISK-0015)
    encryption_nonce    BLOB,
    -- Audit
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL,
    UNIQUE (tenant_id, vault_id, path)
);
CREATE INDEX idx_files_sync_state    ON files(sync_state);
CREATE INDEX idx_files_inode         ON files(inode) WHERE inode IS NOT NULL;
CREATE INDEX idx_files_tenant_vault  ON files(tenant_id, vault_id);

CREATE TABLE tombstones (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id           TEXT,
    vault_id            TEXT NOT NULL DEFAULT 'default',
    path                TEXT NOT NULL,
    last_hash           BLOB NOT NULL,
    deleted_by          TEXT NOT NULL,
    deleted_at          INTEGER NOT NULL,
    ttl_expires         INTEGER NOT NULL,
    propagated          INTEGER NOT NULL DEFAULT 0,
    created_at          INTEGER NOT NULL
);
CREATE INDEX idx_tombstones_expires ON tombstones(ttl_expires);
CREATE INDEX idx_tombstones_tenant  ON tombstones(tenant_id, vault_id);

CREATE TABLE sync_queue (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id           TEXT,
    vault_id            TEXT NOT NULL DEFAULT 'default',
    path                TEXT NOT NULL,
    action              TEXT NOT NULL,
    direction           TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'pending',
    error_msg           TEXT,
    retry_count         INTEGER NOT NULL DEFAULT 0,
    max_retries         INTEGER NOT NULL DEFAULT 3,
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL
);
CREATE INDEX idx_queue_status ON sync_queue(status);

CREATE TABLE conflicts (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id           TEXT,
    vault_id            TEXT NOT NULL DEFAULT 'default',
    path                TEXT NOT NULL,
    conflict_type       TEXT NOT NULL,
    local_hash          BLOB,
    remote_hash         BLOB,
    base_hash           BLOB,
    resolution          TEXT,
    fork_path           TEXT,
    resolved            INTEGER NOT NULL DEFAULT 0,
    created_at          INTEGER NOT NULL,
    resolved_at         INTEGER
);
CREATE INDEX idx_conflicts_resolved ON conflicts(resolved);
