//! Core value types for the Disk Arcana sync engine.
//!
//! Phase 2 (DISK-0003) introduces [`FileMeta`], [`SyncAction`], [`ActionType`],
//! [`ConflictRecord`] and helpers consumed by the scanner, metadata store,
//! and reconciler.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::vector_clock::VectorClock;

/// Stable identifier of a sync node (client or server replica).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub String);

/// Logical vault — namespace inside a tenant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VaultId(pub String);

impl Default for VaultId {
    fn default() -> Self {
        Self("default".into())
    }
}

/// Forward-compat tenant identifier (DISK-0017 multi-tenant SaaS).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct TenantId(pub Option<String>);

/// Forward-compat version identifier (DISK-0020 versioning).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct VersionId(pub u64);

/// Snapshot of one file as recorded by the scanner / metadata store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMeta {
    /// Vault-relative path (POSIX-style separators).
    pub path: PathBuf,
    /// blake3 content digest of the file body.
    pub content_hash: [u8; 32],
    /// File size in bytes.
    pub size: u64,
    /// Last-modified timestamp in nanoseconds since Unix epoch.
    pub mtime_ns: i64,
    /// Filesystem inode (`None` on platforms that do not expose it, e.g. Windows).
    pub inode: Option<u64>,
    /// Causal vector clock as of the last writer.
    pub vector_clock: VectorClock,
    /// Tombstone marker: `true` when the file is logically deleted.
    pub deleted: bool,
    /// Unix timestamp (seconds) when the tombstone was created.
    pub deleted_at: Option<i64>,
    /// Last writer node id.
    pub node_id: String,
}

/// Pair returned by the scanner when an inode survives a path change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenamePair {
    pub from: PathBuf,
    pub to: PathBuf,
    pub inode: u64,
    pub content_hash: [u8; 32],
}

/// Action emitted by the reconciler for one file path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncAction {
    pub path: PathBuf,
    pub action: ActionType,
    /// Remote-side metadata for `Download` / `ConflictFork` consumers.
    pub server_version: Option<FileMeta>,
    /// Optional conflict report produced together with the action.
    pub conflict: Option<ConflictReport>,
    /// Path the file is being renamed to (`RenameRemote` / `RenameLocal`).
    pub rename_to: Option<PathBuf>,
}

/// Outcome classifications for a single path. Mirrors the `ActionType`
/// enum encoded in `proto/disk.proto` (see DISK-0002).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionType {
    Skip,
    Upload,
    Download,
    DeleteLocal,
    DeleteRemote,
    ConflictFork,
    ConflictMerge,
    RenameRemote,
    RenameLocal,
}

/// Diagnostic payload attached to a [`SyncAction`] when a conflict was detected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictReport {
    pub kind: ConflictKind,
    pub local_hash: Option<[u8; 32]>,
    pub remote_hash: Option<[u8; 32]>,
    pub base_hash: Option<[u8; 32]>,
}

/// Type of conflict observed; consumed by the conflict-resolution policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictKind {
    /// Concurrent edits with divergent vector clocks.
    Concurrent,
    /// One side modified, the other deleted.
    ModifiedDeleted,
    /// Both sides renamed the same source to different destinations.
    RenameRename,
    /// Empty-directory delete vs. modified child file.
    DirDeleteChildModify,
}

/// Persisted conflict row (`conflicts` table).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictRecord {
    pub id: Option<i64>,
    pub vault_id: String,
    pub path: String,
    pub conflict_type: String,
    pub local_hash: Option<[u8; 32]>,
    pub remote_hash: Option<[u8; 32]>,
    pub base_hash: Option<[u8; 32]>,
    pub resolution: Option<String>,
    pub fork_path: Option<String>,
    pub resolved: bool,
    pub created_at: i64,
    pub resolved_at: Option<i64>,
}
