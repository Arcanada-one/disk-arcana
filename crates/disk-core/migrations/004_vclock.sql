-- 004_vclock.sql — DISK-0005 P4b Step 18
--
-- Additive migration: vector-clock column on the nodes table for causal
-- ordering of concurrent writes from multiple sync nodes.
--
-- vclock is stored as a JSON BLOB (UTF-8 text serialised from BTreeMap<node_id,u64>).
-- Null until the node sends its first ExchangeStateRequest with a vclock payload.

ALTER TABLE nodes ADD COLUMN vclock TEXT;
