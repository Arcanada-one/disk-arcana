//! HTTP handlers for `/trash/*` (DISK-0024).

pub mod routes;

pub use routes::{list_trash, restore_trash};
