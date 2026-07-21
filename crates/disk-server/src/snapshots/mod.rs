//! Point-in-time vault snapshot HTTP API (DISK-0020 slice 4).

mod routes;

pub use routes::{create_snapshot, get_snapshot, list_snapshots, restore_snapshot};
