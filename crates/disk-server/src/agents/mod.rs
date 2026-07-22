//! HTTP handlers for `/agents/*` (DISK-0028).

pub mod dispatch;
pub mod routes;

pub use dispatch::{
    agent_write_conflict_payload, agent_write_ok_payload, embeddings_stale_payload,
    spawn as spawn_agent_webhook_dispatcher, sync_file_changed_payload, sync_file_deleted_payload,
    AgentWebhookDispatcher, AgentWebhookJob,
};
pub use routes::{
    agent_write, delete_webhook, get_revision, list_webhooks, register_webhook,
    report_embeddings_stale,
};
