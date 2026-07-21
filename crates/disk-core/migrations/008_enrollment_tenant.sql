-- DISK-0017 slice 2: bind tenant_id on enrollment tokens.
ALTER TABLE pending_enrollments ADD COLUMN tenant_id TEXT;
