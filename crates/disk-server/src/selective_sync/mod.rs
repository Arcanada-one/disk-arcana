//! HTTP handlers for `/selective-sync/*` (DISK-0023).

pub mod routes;

pub use routes::{get_selective_sync, put_selective_sync};
