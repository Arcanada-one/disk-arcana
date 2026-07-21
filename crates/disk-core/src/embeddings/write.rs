//! External embedder ingest — write manifest + vector blob sidecars (DISK-0029 slice 3).

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;

use super::manifest::SidecarManifest;
use super::paths::{is_co_storage_path, manifest_rel_path, vector_blob_rel_path};
use crate::path_guard;
use crate::scanner::hash_file;

/// Outcome of a successful `write_sidecar` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteSidecarResult {
    pub source_path: String,
    pub source_content_hash: String,
    pub manifest_rel: PathBuf,
    pub vector_rel: PathBuf,
    pub vector_bytes: u64,
}

#[derive(Debug, Error)]
pub enum WriteSidecarError {
    #[error("invalid source path: {0}")]
    InvalidPath(&'static str),
    #[error("source path must not be a co-storage artefact")]
    CoStorageSource,
    #[error("source file not found")]
    SourceNotFound,
    #[error(
        "vector size {actual} does not match dimensions {dimensions} (expected {expected} bytes)"
    )]
    VectorSizeMismatch {
        actual: usize,
        expected: u64,
        dimensions: u32,
    },
    #[error(transparent)]
    PathGuard(#[from] crate::error::PathGuardError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Normalize a vault-relative source path for ingest.
pub fn normalize_source_rel(raw: &str) -> Result<String, WriteSidecarError> {
    let trimmed = raw.trim().replace('\\', "/");
    if trimmed.is_empty() || trimmed.contains("..") {
        return Err(WriteSidecarError::InvalidPath(
            "must be non-empty without '..'",
        ));
    }
    let normalized = trimmed.trim_matches('/').to_string();
    if normalized.is_empty() {
        return Err(WriteSidecarError::InvalidPath("must be non-empty"));
    }
    Ok(normalized)
}

/// Write embedding sidecar artefacts for `source_rel` under `share_root`.
///
/// `vector_bytes` must be exactly `dimensions * 4` bytes (little-endian f32).
pub fn write_sidecar(
    share_root: &Path,
    source_rel: &str,
    vector_bytes: &[u8],
    model_id: &str,
    dimensions: u32,
) -> Result<WriteSidecarResult, WriteSidecarError> {
    let source_path = normalize_source_rel(source_rel)?;
    let source_rel_path = Path::new(&source_path);
    if is_co_storage_path(source_rel_path) {
        return Err(WriteSidecarError::CoStorageSource);
    }

    let expected = u64::from(dimensions) * 4;
    if vector_bytes.len() as u64 != expected {
        return Err(WriteSidecarError::VectorSizeMismatch {
            actual: vector_bytes.len(),
            expected,
            dimensions,
        });
    }

    let source_abs = path_guard::validate(source_rel_path, share_root)?;
    if !source_abs.is_file() {
        return Err(WriteSidecarError::SourceNotFound);
    }

    let hash_hex =
        hex::encode(hash_file(&source_abs).map_err(|e| std::io::Error::other(e.to_string()))?);

    let vector_rel = vector_blob_rel_path(source_rel_path);
    let vector_abs = share_root.join(&vector_rel);
    if let Some(parent) = vector_abs.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&vector_abs, vector_bytes)?;

    let manifest = SidecarManifest {
        schema_version: super::manifest::EMBEDDINGS_SCHEMA_VERSION,
        source_path: source_path.clone(),
        source_content_hash: hash_hex.clone(),
        model_id: model_id.to_string(),
        dimensions,
        vector_bytes: expected,
        created_at_unix: Some(unix_now()),
    };
    manifest.write_to_share(share_root, source_rel_path)?;

    Ok(WriteSidecarResult {
        source_path: source_path.clone(),
        source_content_hash: hash_hex,
        manifest_rel: manifest_rel_path(source_rel_path),
        vector_rel,
        vector_bytes: expected,
    })
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embeddings::manifest::{evaluate_staleness, Staleness};
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn write_sidecar_creates_fresh_artefacts() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("notes")).unwrap();
        fs::write(root.join("notes/a.md"), b"hello").unwrap();

        let vector = vec![0u8; 16];
        let result = write_sidecar(root, "notes/a.md", &vector, "bge-m3", 4).unwrap();
        assert_eq!(result.source_path, "notes/a.md");
        assert!(root.join(&result.manifest_rel).is_file());
        assert!(root.join(&result.vector_rel).is_file());

        let hash = result.source_content_hash;
        let fresh = evaluate_staleness(root, Path::new("notes/a.md"), &hash, "bge-m3", 4);
        assert_eq!(fresh, Staleness::Fresh);
    }

    #[test]
    fn rejects_vector_size_mismatch() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("notes")).unwrap();
        fs::write(root.join("notes/a.md"), b"x").unwrap();

        let err = write_sidecar(root, "notes/a.md", &[0u8; 7], "bge-m3", 4).unwrap_err();
        assert!(matches!(err, WriteSidecarError::VectorSizeMismatch { .. }));
    }

    #[test]
    fn rejects_missing_source() {
        let tmp = TempDir::new().unwrap();
        let err =
            write_sidecar(tmp.path(), "notes/missing.md", &[0u8; 8], "bge-m3", 2).unwrap_err();
        assert!(matches!(err, WriteSidecarError::SourceNotFound));
    }

    #[test]
    fn rejects_path_traversal() {
        let tmp = TempDir::new().unwrap();
        let err = write_sidecar(tmp.path(), "../escape.md", &[0u8; 8], "bge-m3", 2).unwrap_err();
        assert!(matches!(err, WriteSidecarError::InvalidPath(_)));
    }
}
