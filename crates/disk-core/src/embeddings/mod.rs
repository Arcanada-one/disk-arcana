//! Embeddings co-storage — vector sidecars synced alongside vault files (DISK-0029).
//!
//! Sidecar layout under each share root:
//! ```text
//! .disk-embeddings/
//!   notes/welcome.md.manifest.json
//!   notes/welcome.md.vec.bin
//! ```

pub mod manifest;
pub mod paths;
pub mod scan;

pub use manifest::{SidecarManifest, Staleness, EMBEDDINGS_SCHEMA_VERSION};
pub use paths::{
    is_co_storage_path, manifest_rel_path, vector_blob_rel_path, CO_STORAGE_ROOT,
};
pub use scan::{scan_share_embeddings, ShareEmbeddingsReport, SourceSidecarStatus};
