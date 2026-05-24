//! Disk Arcana gRPC client — Phase 3 transport.
//!
//! Provides a high-level `DiskClient` that manages connection, authentication,
//! and sync operations against a `disk-arcana-server`.

#![forbid(unsafe_code)]

pub mod config;
pub mod connection;
pub mod enrollment;

pub use connection::{ClientConfig, ClientError, DiskClient};
pub use enrollment::{
    gen_keypair_and_csr, parse_bootstrap_file, redact_token, write_cert_file, write_key_file,
    BootstrapFile, EnrollmentClient, EnrollmentError,
};
