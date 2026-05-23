-- 003_acl_enrollment.sql — DISK-0005 v1.1
--
-- Additive migration introducing mTLS-cert identity + per-share role ACL +
-- enrollment lifecycle + publisher signature gate + audit event log.
--
-- Reference: PRD-DISK-0001 v1.1 §4.11 / §4.12, plan `DISK-0005-plan.md`,
-- creative-DISK-0005-architecture-acl-reload.md (state machine F1-F8),
-- creative-DISK-0005-data-model-publisher-signatures.md (counter scheme),
-- creative-DISK-0005-trust-model-enrollment.md (pending-token + bootstrap-file).
--
-- Compatibility: extends DISK-0004 schema (nodes / files / tombstones).
-- The `nodes` table keeps existing PK + api_key_hash column for enrollment-
-- bootstrap continuity (api_key remains valid only until first mTLS cert
-- is issued for that node). All v1.1 lookups MUST keyed by cert fingerprint
-- via the `node_certs` join table, NOT by `node_id` text identifier.

-- Singleton state of the loaded ACL. version is monotonic per
-- creative-DISK-0005-architecture-acl-reload.md F4 (regress detection).
CREATE TABLE acl_meta (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    version     INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,             -- unix ms (ACL file's updated_at)
    signed_by   TEXT NOT NULL,
    file_sha256 BLOB NOT NULL,
    loaded_at   INTEGER NOT NULL              -- unix ms (server load time)
);

-- Join table: cert fingerprint (SHA-256 of DER-encoded client cert) → node.
-- A single node MAY hold multiple certs across rotation; only enabled
-- entries are admitted by the ACL enforcer.
CREATE TABLE node_certs (
    cert_fingerprint BLOB PRIMARY KEY,
    node_id          INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    enrolled_at      INTEGER NOT NULL,        -- unix ms
    expires_at       INTEGER NOT NULL,        -- unix ms; 90d default
    revoked_at       INTEGER,                 -- NULL = active
    last_seen_at     INTEGER
);
CREATE INDEX idx_node_certs_node    ON node_certs(node_id);
CREATE INDEX idx_node_certs_active  ON node_certs(revoked_at) WHERE revoked_at IS NULL;

-- Per-cert × per-share enforced role. Server-authoritative; client
-- declarations are ignored for authZ (creative-acl-reload §authority).
CREATE TABLE node_shares (
    cert_fingerprint BLOB    NOT NULL REFERENCES node_certs(cert_fingerprint) ON DELETE CASCADE,
    share_name       TEXT    NOT NULL,
    enforced_role    TEXT    NOT NULL
        CHECK (enforced_role IN ('bidirectional','receive_only','send_only','publisher')),
    updated_at       INTEGER NOT NULL,
    PRIMARY KEY (cert_fingerprint, share_name)
);
CREATE INDEX idx_node_shares_share ON node_shares(share_name);

-- Pending enrollment tokens (creative-trust-model §A admin-bearer flow).
-- Plaintext token never persisted — only blake3 hash for lookup.
CREATE TABLE pending_enrollments (
    token_hash       BLOB PRIMARY KEY,        -- blake3(token), 32 bytes
    node_id_hint     TEXT NOT NULL,
    issued_at        INTEGER NOT NULL,        -- unix ms
    expires_at       INTEGER NOT NULL,        -- unix ms; 1h default, max 24h
    consumed_at      INTEGER,                 -- NULL = unused
    consumed_cert_fp BLOB,                    -- nullable; cert produced by Enroll
    revoked_at       INTEGER                  -- nullable; admin-bearer RevokePending
);
CREATE INDEX idx_pending_enrollments_expires ON pending_enrollments(expires_at)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;

-- Audit event log. Append-only by application contract; integrity-trigger
-- is added in a later migration (DISK-0014 hardening per PRD §11 v1.0).
-- Event kinds — exact strings (greppable):
--   acl.role_mismatch | acl.version_regress | acl.load_failure | acl.load_ok
--   publisher.signature_failure | publisher.replay_detected | publisher.timestamp_skew
--   publisher.upload_ok
--   enrollment.token_issued | enrollment.completed | enrollment.token_expired
--   enrollment.pending | enrollment.ca_mismatch | enrollment.revoked
--   share.unknown | config.reload | acl.reload_dedup | acl.file_missing
CREATE TABLE audit_event (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ms        INTEGER NOT NULL,            -- unix ms
    kind         TEXT NOT NULL,
    cert_fp      BLOB,                        -- nullable for system-level events
    share        TEXT,
    payload_json TEXT NOT NULL                -- structured details (claimed_role, enforced_role, ...)
);
CREATE INDEX idx_audit_event_ts      ON audit_event(ts_ms);
CREATE INDEX idx_audit_event_kind_ts ON audit_event(kind, ts_ms);

-- Cached publisher public keys fetched from Vault transit.
-- 24h TTL enforced at application layer; cache miss → Vault fetch.
CREATE TABLE publisher_keys (
    cert_fingerprint BLOB PRIMARY KEY REFERENCES node_certs(cert_fingerprint) ON DELETE CASCADE,
    vault_key_ref    TEXT NOT NULL,           -- e.g. "transit/keys/disk-arcana-arcana-ai-publisher"
    pubkey_ed25519   BLOB NOT NULL,           -- 32-byte raw Ed25519 public key
    fetched_at       INTEGER NOT NULL         -- unix ms
);

-- Monotonic counter for publisher replay protection
-- (creative-publisher-signatures §replay).
-- Server tracks MAX(counter) per (cert_fp, share); incoming counter must strictly exceed it.
CREATE TABLE publisher_counter (
    cert_fingerprint BLOB    NOT NULL,
    share_name       TEXT    NOT NULL,
    max_counter      INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL,
    PRIMARY KEY (cert_fingerprint, share_name)
);
