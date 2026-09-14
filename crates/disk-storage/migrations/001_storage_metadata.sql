CREATE TABLE IF NOT EXISTS storage_objects (
    path TEXT PRIMARY KEY NOT NULL,
    size INTEGER NOT NULL,
    content_sha256 TEXT NOT NULL,
    object_store_key TEXT NOT NULL,
    mtime_ns INTEGER NOT NULL,
    created_at_ns INTEGER NOT NULL,
    tags_json TEXT NOT NULL DEFAULT '{}',
    lifecycle_json TEXT NOT NULL DEFAULT '{"retain_forever":true,"manual_delete_only":true}'
);

CREATE INDEX IF NOT EXISTS idx_storage_objects_sha256 ON storage_objects(content_sha256);
CREATE INDEX IF NOT EXISTS idx_storage_objects_key ON storage_objects(object_store_key);
