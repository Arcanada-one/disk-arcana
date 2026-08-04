use std::time::SystemTime;

use async_trait::async_trait;

use crate::{
    ListEntry, ListOptions, ObjectLifecyclePolicy, ObjectMetadata, PresignedUrl, PutOptions,
    RenameRequest, StorageError, StorageObjectKey,
};

/// Pluggable object-store backend (DISK-0074).
///
/// Metadata (path, size, checksum, object key) is owned by [`crate::MetadataStore`].
/// Implementations store opaque content blobs addressed by `object_store_key`.
#[async_trait]
pub trait StorageBackend: Send + Sync {
    /// Store bytes at `path`, returning persisted metadata.
    async fn put(
        &self,
        path: &StorageObjectKey,
        data: &[u8],
        options: PutOptions,
    ) -> Result<ObjectMetadata, StorageError>;

    /// Read full object bytes.
    async fn get(&self, path: &StorageObjectKey) -> Result<Vec<u8>, StorageError>;

    /// Delete object and metadata.
    async fn delete(&self, path: &StorageObjectKey) -> Result<(), StorageError>;

    /// Rename metadata path; blob key may be reused when content unchanged.
    async fn rename(&self, request: RenameRequest) -> Result<ObjectMetadata, StorageError>;

    /// List objects under optional prefix.
    async fn list(&self, options: ListOptions) -> Result<Vec<ListEntry>, StorageError>;

    /// Whether `path` exists.
    async fn exists(&self, path: &StorageObjectKey) -> Result<bool, StorageError>;

    /// Time-limited URL for direct download (backend-specific).
    async fn presigned_url(
        &self,
        path: &StorageObjectKey,
        expires_at: SystemTime,
    ) -> Result<PresignedUrl, StorageError>;

    /// Lifecycle policy for an object (forever retention, manual delete only).
    async fn object_lifecycle(
        &self,
        path: &StorageObjectKey,
    ) -> Result<ObjectLifecyclePolicy, StorageError>;
}
