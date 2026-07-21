//! Product analytics HTTP surface (DISK-0026 slice 1).

mod config;
mod routes;

pub use routes::{get_telemetry, get_telemetry_config, put_telemetry};
