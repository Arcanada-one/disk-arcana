//! Disk Arcana core: types, errors, configuration, metadata DB, and sync traits.
//!
//! Phase 1 lays out structural contracts. Functional logic is filled in
//! DISK-0003 (sync engine) and DISK-0004 (transport).

#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod meta_db;
pub mod traits;
pub mod types;

pub use config::Config;
pub use error::{ConfigError, MetaDbError};
pub use meta_db::MetaDb;
pub use types::{NodeId, TenantId, VaultId, VersionId};
