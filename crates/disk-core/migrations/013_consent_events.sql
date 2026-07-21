-- 013_consent_events.sql — policy consent audit trail (DISK-0021 slice 3).

CREATE TABLE consent_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         TEXT NOT NULL,
    tenant_id       TEXT NOT NULL,
    consent_type    TEXT NOT NULL,
    policy_version  TEXT NOT NULL,
    recorded_at     INTEGER NOT NULL
);

CREATE INDEX idx_consent_events_user ON consent_events(user_id);
CREATE INDEX idx_consent_events_tenant ON consent_events(tenant_id);
