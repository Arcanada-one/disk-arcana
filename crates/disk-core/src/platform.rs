//! Platform-specific filesystem identity and path helpers.
//!
//! `FileMeta::inode` remains the wire/database-compatible `u64` field. On
//! Unix it stores the inode number; on Windows it stores a stable file identity
//! derived from `FILE_ID_INFO` (via the `file-id` crate) for rename detection.

use std::path::{Path, PathBuf};

use file_id::FileId;

use crate::types::FileMeta;

/// Stable filesystem identity used for rename matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileIdentity(pub u64);

/// Extract the identity captured in a metadata snapshot.
pub fn identity(meta: &FileMeta) -> Option<FileIdentity> {
    meta.inode.map(FileIdentity)
}

/// Read the platform file identity for `path` and encode it into the `inode`
/// wire field.
pub fn inode_from_path(path: &Path) -> Option<u64> {
    file_id::get_file_id(path)
        .ok()
        .map(|id| encode_file_id(&id))
}

/// Collapse a platform [`FileId`] into the single `u64` stored on [`FileMeta`].
pub fn encode_file_id(id: &FileId) -> u64 {
    match id {
        FileId::Inode { inode_number, .. } => *inode_number,
        FileId::LowRes {
            volume_serial_number,
            file_index,
        } => ((*volume_serial_number as u64) << 32) | *file_index,
        FileId::HighRes { file_id, .. } => *file_id as u64,
    }
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
            encryption_nonce: None,
            version_id: None,
            parent_version_id: None,
        };
        assert_eq!(identity(&meta), Some(FileIdentity(42)));
    }

    #[test]
    fn encode_file_id_maps_unix_inode() {
        let id = FileId::Inode {
            device_id: 7,
            inode_number: 42,
        };
        assert_eq!(encode_file_id(&id), 42);
    }

    #[test]
    fn encode_file_id_maps_windows_low_res() {
        let id = FileId::LowRes {
            volume_serial_number: 0xABCD,
            file_index: 0x1234_5678,
        };
        assert_eq!(encode_file_id(&id), ((0xABCD_u64) << 32) | 0x1234_5678);
    }

    #[test]
    fn encode_file_id_maps_windows_high_res_low_qword() {
        let id = FileId::HighRes {
            volume_serial_number: 99,
            file_id: 0x0123_4567_89AB_CDEF_0123_4567_89AB_CDEF,
        };
        assert_eq!(encode_file_id(&id), 0x0123_4567_89AB_CDEF);
    }

    #[test]
    fn inode_from_path_reads_live_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("probe.md");
        std::fs::write(&path, b"x").unwrap();
        assert!(inode_from_path(&path).is_some());
    }

    #[cfg(windows)]
    #[test]
    fn windows_paths_use_extended_length_prefix() {
        assert!(normalize_path(Path::new("C:\\vault\\file.md"))
            .to_string_lossy()
            .starts_with(r"\\?\"));
    }
}
