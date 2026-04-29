//! Disk Arcana gRPC client — Phase 3 transport.
//!
//! Provides a high-level `DiskClient` that manages connection, authentication,
//! and sync operations against a `disk-arcana-server`.

#![forbid(unsafe_code)]

pub mod connection;

pub use connection::{ClientConfig, ClientError, DiskClient};
