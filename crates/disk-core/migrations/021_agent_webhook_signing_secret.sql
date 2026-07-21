-- 021_agent_webhook_signing_secret.sql — persist outbound HMAC key (DISK-0028 slice 2).

ALTER TABLE agent_webhooks ADD COLUMN signing_secret TEXT;
