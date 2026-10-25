CREATE TABLE fixture_binding (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    realm_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version = 2)
);
CREATE TABLE attempts (
    operation_id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL UNIQUE,
    object_id TEXT NOT NULL,
    revision_id TEXT NOT NULL,
    request_json TEXT NOT NULL CHECK (length(request_json) <= 2048),
    expected_len INTEGER NOT NULL CHECK (expected_len BETWEEN 0 AND 1048576),
    state TEXT NOT NULL CHECK (state IN ('PREPARED', 'DURABLE')),
    local_commit_id TEXT UNIQUE,
    sequence INTEGER UNIQUE,
    UNIQUE (object_id, revision_id),
    CHECK ((state = 'PREPARED' AND local_commit_id IS NULL AND sequence IS NULL)
        OR (state = 'DURABLE' AND local_commit_id IS NOT NULL AND sequence IS NOT NULL))
);
CREATE TRIGGER immutable_allocation BEFORE UPDATE ON attempts
WHEN NEW.operation_id != OLD.operation_id OR NEW.attempt_id != OLD.attempt_id
 OR NEW.object_id != OLD.object_id OR NEW.revision_id != OLD.revision_id
 OR NEW.request_json != OLD.request_json OR NEW.expected_len != OLD.expected_len
 OR OLD.state = 'DURABLE'
BEGIN SELECT RAISE(ABORT, 'immutable allocation'); END;

-- Fresh profile only: this file is never applied over a v1 inventory.
CREATE TABLE capture_binding (
    operation_id TEXT PRIMARY KEY NOT NULL REFERENCES attempts(operation_id),
    realm_id TEXT NOT NULL,
    capture_id TEXT NOT NULL,
    part_id TEXT NOT NULL,
    cancellation_generation INTEGER NOT NULL CHECK (typeof(cancellation_generation) = 'integer' AND cancellation_generation BETWEEN 0 AND 9007199254740990),
    -- Exact Shared v1 identity upper bound: five 36-byte outer IDs,
    -- two 16-digit counters, fixed literals/fingerprint and two bounded parts.
    descriptor_identity TEXT NOT NULL CHECK (length(descriptor_identity) BETWEEN 1 AND 798),
    UNIQUE (realm_id, capture_id, part_id, cancellation_generation)
);
CREATE TRIGGER immutable_capture_update BEFORE UPDATE ON capture_binding
BEGIN SELECT RAISE(ABORT, 'immutable capture binding'); END;
CREATE TRIGGER immutable_capture_delete BEFORE DELETE ON capture_binding
BEGIN SELECT RAISE(ABORT, 'immutable capture binding'); END;
PRAGMA user_version = 2;
