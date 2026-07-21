-- 022_organizations.sql — team/org workspaces scaffold (DISK-0030 slice 1).

CREATE TABLE organizations (
    id          TEXT PRIMARY KEY,
    slug        TEXT NOT NULL COLLATE NOCASE,
    name        TEXT NOT NULL,
    tenant_id   TEXT NOT NULL,
    created_by  TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    UNIQUE (slug),
    UNIQUE (tenant_id),
    FOREIGN KEY (created_by) REFERENCES user_accounts(id)
);

CREATE TABLE organization_members (
    org_id      TEXT NOT NULL,
    user_id     TEXT NOT NULL,
    role        TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (org_id, user_id),
    FOREIGN KEY (org_id) REFERENCES organizations(id),
    FOREIGN KEY (user_id) REFERENCES user_accounts(id)
);

CREATE INDEX idx_organization_members_user ON organization_members(user_id);
