//! Platform-specific filesystem identity and path helpers.
//!
//! `FileMeta::inode` remains the wire/database-compatible field for now. On
//! Unix it contains the inode; on Windows the scanner stores the stable file
//! identifier exposed by `MetadataExt::file_id`. This module gives callers a
//! platform-neutral identity type while the richer Windows `FILE_ID_INFO`
//! representation is introduced in a later DISK-0013 phase.

use std::path::{Path, PathBuf};

use crate::types::FileMeta;

/// Stable filesystem identity used for rename matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileIdentity(pub u64);

/// Extract the identity captured in a metadata snapshot.
pub fn identity(meta: &FileMeta) -> Option<FileIdentity> {
    meta.inode.map(FileIdentity)
}

/// Normalize a path for Windows APIs without changing Unix semantics.
#[cfg(windows)]
pub fn normalize_path(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    };
    PathBuf::from(format!(r"\\?\{}", absolute.display()))
}

#[cfg(not(windows))]
pub fn normalize_path(path: &Path) -> PathBuf {
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_round_trips_from_snapshot() {
        let meta = FileMeta {
            path: "a.md".into(),
            content_hash: [0; 32],
            size: 0,
            mtime_ns: 0,
            inode: Some(42),
            vector_clock: Default::default(),
            deleted: false,
            deleted_at: None,
            node_id: "n".into(),
        };
        assert_eq!(identity(&meta), Some(FileIdentity(42)));
    }

    #[cfg(windows)]
    #[test]
    fn windows_paths_use_extended_length_prefix() {
        assert!(normalize_path(Path::new("C:\\vault\\file.md"))
            .to_string_lossy()
            .starts_with(r"\\?\"));
    }
}
