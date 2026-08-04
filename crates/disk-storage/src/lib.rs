//! Pluggable object-store backends for Disk Arcana company drive (DISK-0074).
//!
//! SQLite holds path metadata; content blobs live in a swappable backend
//! (local disk reference, Azure Blob, Backblaze B2 / S3-compatible, etc.).

#![forbid(unsafe_code)]

mod backend;
mod error;
mod local;
mod metadata;
mod types;

pub use backend::StorageBackend;
pub use error::StorageError;
pub use local::LocalDiskBackend;
pub use metadata::{MetadataStore, MetadataStoreConfig};
pub use types::{
    ListEntry, ListOptions, ObjectLifecyclePolicy, ObjectMetadata, PresignedUrl, PutOptions,
    RenameRequest, StorageObjectKey,
};
