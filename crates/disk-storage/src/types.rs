use std::collections::HashMap;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

/// Logical object key in the metadata store (vault-relative path).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StorageObjectKey(pub String);

impl StorageObjectKey {
    pub fn new(path: impl Into<String>) -> Result<Self, crate::StorageError> {
        let path = path.into();
        if path.is_empty() || path.starts_with('/') || path.contains("..") {
            return Err(crate::StorageError::InvalidPath(path));
        }
        Ok(Self(path))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PutOptions {
    pub content_type: Option<String>,
    pub tags: HashMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListOptions {
    pub prefix: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectMetadata {
    pub path: String,
    pub size: u64,
    pub content_sha256: String,
    pub object_store_key: String,
    pub mtime: SystemTime,
    pub created_at: SystemTime,
    pub tags: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListEntry {
    pub path: String,
    pub size: u64,
    pub content_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresignedUrl {
    pub url: String,
    pub expires_at: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectLifecyclePolicy {
    pub retain_forever: bool,
    pub manual_delete_only: bool,
}

impl Default for ObjectLifecyclePolicy {
    fn default() -> Self {
        Self {
            retain_forever: true,
            manual_delete_only: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameRequest {
    pub from: StorageObjectKey,
    pub to: StorageObjectKey,
}
