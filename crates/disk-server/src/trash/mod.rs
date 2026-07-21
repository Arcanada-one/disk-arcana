//! HTTP handlers for `/trash/*` (DISK-0024).

pub mod routes;
pub mod scheduler;

pub use routes::{delete_trash, empty_trash, list_trash, restore_trash};
