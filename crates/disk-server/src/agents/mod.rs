//! HTTP handlers for `/agents/*` (DISK-0028 slice 1).

pub mod routes;

pub use routes::{agent_write, delete_webhook, get_revision, list_webhooks, register_webhook};
