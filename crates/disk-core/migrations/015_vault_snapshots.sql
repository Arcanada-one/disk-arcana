-- DISK-0020 slice 4: point-in-time vault snapshots (metadata index).

CREATE TABLE vault_snapshots (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id       TEXT,
    vault_id        TEXT NOT NULL DEFAULT 'default',
    label           TEXT,
    file_count      INTEGER NOT NULL DEFAULT 0,
    bytes_total     INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    created_by      TEXT
);

CREATE INDEX idx_vault_snapshots_lookup
    ON vault_snapshots(tenant_id, vault_id, created_at DESC);

CREATE TABLE vault_snapshot_files (
    snapshot_id     INTEGER NOT NULL,
    tenant_id       TEXT,
    vault_id        TEXT NOT NULL,
    path            TEXT NOT NULL,
    version_id      INTEGER NOT NULL DEFAULT 0,
    content_hash    BLOB NOT NULL,
    size            INTEGER NOT NULL,
    deleted         INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (snapshot_id, path),
    FOREIGN KEY (snapshot_id) REFERENCES vault_snapshots(id) ON DELETE CASCADE
);

CREATE INDEX idx_vault_snapshot_files_snapshot
    ON vault_snapshot_files(snapshot_id);
