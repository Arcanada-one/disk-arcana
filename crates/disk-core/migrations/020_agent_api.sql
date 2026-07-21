-- 020_agent_api.sql — AI agent webhooks + optimistic write revisions (DISK-0028 slice 1).

CREATE TABLE agent_webhooks (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT,
    vault_id        TEXT NOT NULL DEFAULT 'default',
    url             TEXT NOT NULL,
    secret_hash     BLOB NOT NULL,
    events_json     TEXT NOT NULL,
    label           TEXT,
    enabled         INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at      INTEGER NOT NULL
);

CREATE INDEX idx_agent_webhooks_tenant_vault
    ON agent_webhooks(tenant_id, vault_id);

CREATE TABLE agent_write_revisions (
    tenant_id       TEXT,
    vault_id        TEXT NOT NULL DEFAULT 'default',
    path            TEXT NOT NULL,
    revision        INTEGER NOT NULL DEFAULT 0,
    content_hash    BLOB,
    updated_at      INTEGER NOT NULL,
    updated_by      TEXT,
    PRIMARY KEY (tenant_id, vault_id, path)
);
