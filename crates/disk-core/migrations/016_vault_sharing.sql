-- 016_vault_sharing.sql — vault collaboration invites + RBAC members (DISK-0022 slice 1).

CREATE TABLE vault_invites (
    id            TEXT PRIMARY KEY,
    tenant_id     TEXT,
    vault_id      TEXT NOT NULL,
    token_hash    BLOB NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('viewer', 'editor')),
    created_by    TEXT NOT NULL,
    expires_at    INTEGER NOT NULL,
    redeemed_at   INTEGER,
    redeemed_by   TEXT,
    created_at    INTEGER NOT NULL,
    FOREIGN KEY (created_by) REFERENCES user_accounts(id)
);

CREATE INDEX idx_vault_invites_tenant_vault ON vault_invites(tenant_id, vault_id);
CREATE UNIQUE INDEX idx_vault_invites_token_hash ON vault_invites(token_hash);

CREATE TABLE vault_members (
    tenant_id     TEXT,
    vault_id      TEXT NOT NULL,
    user_id       TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('editor', 'viewer')),
    granted_by    TEXT,
    created_at    INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, vault_id, user_id),
    FOREIGN KEY (user_id) REFERENCES user_accounts(id),
    FOREIGN KEY (granted_by) REFERENCES user_accounts(id)
);

CREATE INDEX idx_vault_members_user ON vault_members(user_id);
