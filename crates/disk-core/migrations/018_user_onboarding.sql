-- 018_user_onboarding.sql — dashboard onboarding checklist persistence (DISK-0025 slice 3).

CREATE TABLE user_onboarding (
    user_id         TEXT PRIMARY KEY,
    dismissed       INTEGER NOT NULL DEFAULT 0,
    dismissed_at    INTEGER,
    updated_at      INTEGER NOT NULL
);

CREATE INDEX idx_user_onboarding_dismissed ON user_onboarding(dismissed);
