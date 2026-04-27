//! Sync engine traits — implemented in DISK-0003 (`scanner` / `reconciler` / `metadata`).

use crate::error::MetaDbError;

/// Walks a vault root and yields candidate file metadata.
pub trait Scanner {
    fn scan(&self) -> Result<(), MetaDbError>;
}

/// Compares local snapshot with remote SyncState and produces actions.
pub trait Reconciler {
    fn reconcile(&self) -> Result<(), MetaDbError>;
}

/// Persisted metadata index over scanned files.
pub trait MetaStore {
    fn open(&self) -> Result<(), MetaDbError>;
}
