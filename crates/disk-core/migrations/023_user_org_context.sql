-- 023_user_org_context.sql — persisted active organization workspace (DISK-0030 slice 2).

CREATE TABLE user_org_context (
    user_id         TEXT PRIMARY KEY,
    active_org_id   TEXT,
    updated_at      INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES user_accounts(id),
    FOREIGN KEY (active_org_id) REFERENCES organizations(id)
);

CREATE INDEX idx_user_org_context_active_org ON user_org_context(active_org_id);
