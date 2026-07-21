//! JSON manifest schema for embedding sidecars.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::paths::{manifest_rel_path, vector_blob_rel_path};

pub const EMBEDDINGS_SCHEMA_VERSION: u32 = 1;

/// On-disk manifest linking a source file to its co-stored vector blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SidecarManifest {
    pub schema_version: u32,
    /// Vault-relative source path (POSIX-style forward slashes).
    pub source_path: String,
    /// BLAKE3 hex digest of the source file bytes at embed time.
    pub source_content_hash: String,
    /// Embedding model identifier (e.g. `bge-m3`).
    pub model_id: String,
    pub dimensions: u32,
    /// Byte length of the `.vec.bin` payload (f32 LE).
    pub vector_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at_unix: Option<u64>,
}

impl SidecarManifest {
    /// Build a new manifest for a freshly embedded source file.
    pub fn new(
        source_path: impl Into<String>,
        source_content_hash: impl Into<String>,
        model_id: impl Into<String>,
        dimensions: u32,
        vector_bytes: u64,
    ) -> Self {
        Self {
            schema_version: EMBEDDINGS_SCHEMA_VERSION,
            source_path: source_path.into(),
            source_content_hash: source_content_hash.into(),
            model_id: model_id.into(),
            dimensions,
            vector_bytes,
            created_at_unix: None,
        }
    }

    /// Serialize manifest to `share_root / manifest_rel_path(source)`.
    pub fn write_to_share(&self, share_root: &Path, source_rel: &Path) -> std::io::Result<()> {
        let rel = manifest_rel_path(source_rel);
        let abs = share_root.join(&rel);
        if let Some(parent) = abs.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        fs::write(abs, json)
    }

    /// Read manifest from share root; returns `None` when absent.
    pub fn read_from_share(share_root: &Path, source_rel: &Path) -> std::io::Result<Option<Self>> {
        let abs = share_root.join(manifest_rel_path(source_rel));
        if !abs.is_file() {
            return Ok(None);
        }
        let raw = fs::read_to_string(abs)?;
        let parsed: Self = serde_json::from_str(&raw)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(Some(parsed))
    }
}

/// Sidecar freshness relative to the current source content hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Staleness {
    Fresh,
    MissingManifest,
    MissingVector,
    StaleHash,
    StaleModel,
    StaleDimensions,
    StaleVectorSize,
}

impl Staleness {
    pub fn is_fresh(&self) -> bool {
        matches!(self, Self::Fresh)
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::MissingManifest => "missing_manifest",
            Self::MissingVector => "missing_vector",
            Self::StaleHash => "stale_hash",
            Self::StaleModel => "stale_model",
            Self::StaleDimensions => "stale_dimensions",
            Self::StaleVectorSize => "stale_vector_size",
        }
    }
}

/// Evaluate sidecar freshness for `source_rel` given the live source hash.
pub fn evaluate_staleness(
    share_root: &Path,
    source_rel: &Path,
    current_hash_hex: &str,
    expected_model_id: &str,
    expected_dimensions: u32,
) -> Staleness {
    let manifest = match SidecarManifest::read_from_share(share_root, source_rel) {
        Ok(Some(m)) => m,
        Ok(None) | Err(_) => return Staleness::MissingManifest,
    };

    let vector_abs = share_root.join(vector_blob_rel_path(source_rel));
    if !vector_abs.is_file() {
        return Staleness::MissingVector;
    }

    if manifest.source_content_hash != current_hash_hex {
        return Staleness::StaleHash;
    }
    if manifest.model_id != expected_model_id {
        return Staleness::StaleModel;
    }
    if manifest.dimensions != expected_dimensions {
        return Staleness::StaleDimensions;
    }

    let actual_bytes = fs::metadata(&vector_abs).map(|m| m.len()).unwrap_or(0);
    if actual_bytes != manifest.vector_bytes {
        return Staleness::StaleVectorSize;
    }

    Staleness::Fresh
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::hash_file;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn manifest_round_trip_and_staleness() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        let source_rel = Path::new("notes/a.md");
        fs::create_dir_all(root.join("notes")).unwrap();
        fs::write(root.join(source_rel), b"hello").unwrap();
        let hash = hex::encode(hash_file(&root.join(source_rel)).unwrap());

        let manifest = SidecarManifest::new(
            "notes/a.md",
            hash.clone(),
            "bge-m3",
            4,
            16,
        );
        manifest.write_to_share(root, source_rel).unwrap();

        let vector_rel = vector_blob_rel_path(source_rel);
        fs::create_dir_all(root.join(vector_rel.parent().unwrap())).unwrap();
        fs::write(root.join(&vector_rel), vec![0u8; 16]).unwrap();

        let fresh = evaluate_staleness(root, source_rel, &hash, "bge-m3", 4);
        assert_eq!(fresh, Staleness::Fresh);

        fs::write(root.join(source_rel), b"changed").unwrap();
        let new_hash = hex::encode(hash_file(&root.join(source_rel)).unwrap());
        let stale = evaluate_staleness(root, source_rel, &new_hash, "bge-m3", 4);
        assert_eq!(stale, Staleness::StaleHash);
    }
}
