//! Content-addressed blob store for version history (DISK-0020).
//!
//! Layout: `{root}/{first_2_hex}/{remaining_62_hex}` — same fan-out as the
//! client blob cache. Writes are atomic via temp file + rename.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ContentStoreError {
    #[error("content store I/O: {0}")]
    Io(#[from] std::io::Error),
}

/// Filesystem-backed content-addressed store.
#[derive(Debug, Clone)]
pub struct ContentBlobStore {
    root: PathBuf,
}

impl ContentBlobStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn blob_path(&self, hash: &[u8; 32]) -> PathBuf {
        let hex = hex::encode(hash);
        self.root.join(&hex[..2]).join(&hex[2..])
    }

    /// Store bytes under `hash` when not already present.
    pub fn put(&self, hash: &[u8; 32], bytes: &[u8]) -> Result<(), ContentStoreError> {
        let dest = self.blob_path(hash);
        if dest.exists() {
            return Ok(());
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp_name = format!(
            ".tmp-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let tmp_path = dest
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(tmp_name);
        {
            let mut f = std::fs::File::create(&tmp_path)?;
            f.write_all(bytes)?;
            f.sync_all()?;
        }
        match std::fs::rename(&tmp_path, &dest) {
            Ok(()) => Ok(()),
            Err(_) if dest.exists() => {
                let _ = std::fs::remove_file(&tmp_path);
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    pub fn get(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        std::fs::read(self.blob_path(hash)).ok()
    }

    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        self.blob_path(hash).is_file()
    }
}
