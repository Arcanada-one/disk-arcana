//! Disk Arcana core: types, errors, configuration, metadata DB, and sync engine.
//!
//! Phase 1 (DISK-0002) shipped scaffolding: types, errors, config parser, and
//! `MetaDb::open` with migrations. Phase 2 (DISK-0003) adds the live sync
//! engine — file scanner, path-traversal guard, ignore filter, vector clock,
//! tombstone helpers, metadata CRUD and the 30-scenario reconciliation engine.

//! Disk Arcana core: types, errors, configuration, metadata DB, sync engine,
//! and delta algorithm.
//!
//! Phase 3 (DISK-0004) adds the delta module: Adler32 rolling checksum, blake3
//! strong hash, fixed-block chunker, and delta plan build/apply.

#![forbid(unsafe_code)]

pub mod conflict;
pub mod config;
pub mod delta;
pub mod error;
pub mod filter;
pub mod meta_db;
pub mod path_guard;
pub mod reconciler;
pub mod scanner;
pub mod tombstone;
pub mod traits;
pub mod types;
pub mod vector_clock;

pub use config::Config;
pub use error::{
    ConfigError, FilterError, MetaDbError, PathGuardError, ReconcileError, ScannerError,
};
pub use filter::{Filter, FilterRules};

pub use meta_db::MetaDb;
pub use path_guard::validate as validate_path;
pub use reconciler::ReconciliationEngine;
pub use scanner::FileScanner;
pub use tombstone::{Tombstone, DEFAULT_TTL_SECS};
pub use types::{
    ActionType, ConflictKind, ConflictRecord, ConflictReport, FileMeta, NodeId, RenamePair,
    SyncAction, TenantId, VaultId, VersionId,
};
pub use vector_clock::{Causality, VectorClock};
