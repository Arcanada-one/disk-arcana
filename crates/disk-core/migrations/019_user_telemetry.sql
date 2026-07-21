-- 019_user_telemetry.sql — product analytics opt-in persistence (DISK-0026 slice 1).

CREATE TABLE user_telemetry (
    user_id     TEXT PRIMARY KEY,
    opt_in      INTEGER NOT NULL DEFAULT 0,
    updated_at  INTEGER NOT NULL
);

CREATE INDEX idx_user_telemetry_opt_in ON user_telemetry(opt_in);
