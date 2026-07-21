//! HTTP handlers for `/sharing/*` (DISK-0022).

pub mod routes;

pub use routes::{accept_invite, create_invite, list_invites, list_members, remove_member};
