-- DISK-0020: file version history (metadata index + tier retention).

CREATE TABLE file_versions (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id           TEXT,
    vault_id            TEXT NOT NULL DEFAULT 'default',
    path                TEXT NOT NULL,
    version_id          INTEGER NOT NULL,
    parent_version_id   INTEGER NOT NULL DEFAULT 0,
    content_hash        BLOB NOT NULL,
    size                INTEGER NOT NULL,
    mtime_ns            INTEGER NOT NULL,
    created_at          INTEGER NOT NULL,
    created_by          TEXT,
    UNIQUE (tenant_id, vault_id, path, version_id)
);

CREATE INDEX idx_file_versions_lookup
    ON file_versions(tenant_id, vault_id, path, version_id DESC);

CREATE INDEX idx_file_versions_created
    ON file_versions(tenant_id, vault_id, created_at);
