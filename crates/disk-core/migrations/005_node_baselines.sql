-- 005_node_baselines.sql — Per-client baseline tracking + tombstone columns on files.
--
-- Additive migration: adds logical-delete columns to the server's authoritative
-- file index so list_all_files / get_file can read back tombstone state, and
-- creates the node_baselines table for per-client last-synced snapshots.

-- Extend files table with tombstone columns.
-- DEFAULT 0 / NULL means existing rows read as not-deleted (safe additive change).
ALTER TABLE files ADD COLUMN deleted   INTEGER NOT NULL DEFAULT 0;
ALTER TABLE files ADD COLUMN deleted_at INTEGER;

-- Per-client baseline snapshot: one FileMeta row per (node, vault, path).
-- Tracks the last-synced state for each authenticated node so the reconciler
-- receives a real indexed argument instead of an empty slice.
CREATE TABLE node_baselines (
    node_id        TEXT    NOT NULL,
    vault_id       TEXT    NOT NULL,
    path           TEXT    NOT NULL,
    content_hash   BLOB,                            -- 32-byte blake3; NULL for tombstone
    size           INTEGER NOT NULL DEFAULT 0,
    mtime_ns       INTEGER NOT NULL DEFAULT 0,
    vector_clock   TEXT    NOT NULL DEFAULT '{}',   -- JSON-encoded VectorClock (forward-compat)
    deleted        INTEGER NOT NULL DEFAULT 0,
    deleted_at     INTEGER,
    node_id_writer TEXT    NOT NULL DEFAULT '',     -- FileMeta.node_id of last writer
    updated_at     INTEGER NOT NULL DEFAULT (unixepoch()),
    tenant_id      TEXT,                            -- forward-compat multi-tenant
    PRIMARY KEY (node_id, vault_id, path)
);
