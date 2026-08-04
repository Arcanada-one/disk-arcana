use std::path::PathBuf;
use std::time::SystemTime;

use async_trait::async_trait;
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::Client;

use crate::backend::StorageBackend;
use crate::metadata::{content_sha256_hex, object_key_for, MetadataStore, MetadataStoreConfig};
use crate::s3::client::{build_client, delete_object, get_object, put_object};
use crate::s3::config::S3BackendConfig;
use crate::{
    ListEntry, ListOptions, ObjectLifecyclePolicy, ObjectMetadata, PresignedUrl, PutOptions,
    RenameRequest, StorageError, StorageObjectKey,
};

/// S3-compatible `StorageBackend` (DISK-0076 B2 + DISK-0080 R2).
#[derive(Debug)]
pub struct S3StorageBackend {
    config: S3BackendConfig,
    client: Client,
    meta: MetadataStore,
}

impl S3StorageBackend {
    pub async fn open(config: S3BackendConfig, meta_db: PathBuf) -> Result<Self, StorageError> {
        let client = build_client(&config).await?;
        let meta = MetadataStore::open(MetadataStoreConfig { db_path: meta_db }).await?;
        Ok(Self {
            config,
            client,
            meta,
        })
    }

    pub async fn open_backblaze(meta_db: PathBuf) -> Result<Self, StorageError> {
        Self::open(S3BackendConfig::backblaze_from_env()?, meta_db).await
    }

    pub async fn open_cloudflare_r2(meta_db: PathBuf) -> Result<Self, StorageError> {
        Self::open(S3BackendConfig::cloudflare_r2_from_env()?, meta_db).await
    }

    fn bucket(&self) -> &str {
        &self.config.bucket
    }
}

#[async_trait]
impl StorageBackend for S3StorageBackend {
    async fn put(
        &self,
        path: &StorageObjectKey,
        data: &[u8],
        options: PutOptions,
    ) -> Result<ObjectMetadata, StorageError> {
        let sha = content_sha256_hex(data);
        let object_key = object_key_for(path.as_str(), &sha);
        put_object(&self.client, self.bucket(), &object_key, data).await?;
        let now = SystemTime::now();
        let meta = ObjectMetadata {
            path: path.as_str().to_string(),
            size: data.len() as u64,
            content_sha256: sha,
            object_store_key: object_key,
            mtime: now,
            created_at: now,
            tags: options.tags,
        };
        self.meta
            .upsert(&meta, &ObjectLifecyclePolicy::default())
            .await?;
        Ok(meta)
    }

    async fn get(&self, path: &StorageObjectKey) -> Result<Vec<u8>, StorageError> {
        let meta = self
            .meta
            .get(path.as_str())
            .await?
            .ok_or_else(|| StorageError::NotFound {
                path: path.as_str().to_string(),
            })?;
        get_object(&self.client, self.bucket(), &meta.object_store_key).await
    }

    async fn delete(&self, path: &StorageObjectKey) -> Result<(), StorageError> {
        let meta = self
            .meta
            .get(path.as_str())
            .await?
            .ok_or_else(|| StorageError::NotFound {
                path: path.as_str().to_string(),
            })?;
        let store_key = meta.object_store_key.clone();
        let sha = meta.content_sha256.clone();
        if !self.meta.delete(path.as_str()).await? {
            return Err(StorageError::NotFound {
                path: path.as_str().to_string(),
            });
        }
        let refs: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM storage_objects WHERE content_sha256 = ?")
                .bind(&sha)
                .fetch_one(self.meta.pool())
                .await?;
        if refs.0 == 0 {
            delete_object(&self.client, self.bucket(), &store_key).await?;
        }
        Ok(())
    }

    async fn rename(&self, request: RenameRequest) -> Result<ObjectMetadata, StorageError> {
        let from_meta =
            self.meta
                .get(request.from.as_str())
                .await?
                .ok_or_else(|| StorageError::NotFound {
                    path: request.from.as_str().to_string(),
                })?;
        if self.meta.get(request.to.as_str()).await?.is_some() {
            return Err(StorageError::AlreadyExists {
                path: request.to.as_str().to_string(),
            });
        }
        if !self
            .meta
            .rename(request.from.as_str(), request.to.as_str())
            .await?
        {
            return Err(StorageError::NotFound {
                path: request.from.as_str().to_string(),
            });
        }
        let mut updated = from_meta;
        updated.path = request.to.as_str().to_string();
        updated.mtime = SystemTime::now();
        self.meta
            .upsert(&updated, &ObjectLifecyclePolicy::default())
            .await?;
        Ok(updated)
    }

    async fn list(&self, options: ListOptions) -> Result<Vec<ListEntry>, StorageError> {
        let limit = options.limit.unwrap_or(1000);
        let rows = self
            .meta
            .list_prefix(options.prefix.as_deref(), limit)
            .await?;
        Ok(rows
            .into_iter()
            .map(|m| ListEntry {
                path: m.path,
                size: m.size,
                content_sha256: m.content_sha256,
            })
            .collect())
    }

    async fn exists(&self, path: &StorageObjectKey) -> Result<bool, StorageError> {
        Ok(self.meta.get(path.as_str()).await?.is_some())
    }

    async fn presigned_url(
        &self,
        path: &StorageObjectKey,
        expires_at: SystemTime,
    ) -> Result<PresignedUrl, StorageError> {
        let meta = self
            .meta
            .get(path.as_str())
            .await?
            .ok_or_else(|| StorageError::NotFound {
                path: path.as_str().to_string(),
            })?;
        let duration = expires_at
            .duration_since(SystemTime::now())
            .map_err(|e| StorageError::Metadata(e.to_string()))?;
        let presign_cfg = PresigningConfig::expires_in(duration)
            .map_err(|e| StorageError::Metadata(e.to_string()))?;
        let presigned = self
            .client
            .get_object()
            .bucket(self.bucket())
            .key(&meta.object_store_key)
            .presigned(presign_cfg)
            .await
            .map_err(|e| StorageError::Metadata(e.to_string()))?;
        Ok(PresignedUrl {
            url: presigned.uri().to_string(),
            expires_at,
        })
    }

    async fn object_lifecycle(
        &self,
        path: &StorageObjectKey,
    ) -> Result<ObjectLifecyclePolicy, StorageError> {
        Ok(self
            .meta
            .lifecycle(path.as_str())
            .await?
            .unwrap_or_default())
    }
}

#[cfg(test)]
mod smoke_tests {
    //! Live-bucket smoke tests — run manually with credentials:
    //! `cargo test -p disk-storage -- --ignored smoke_b2` or `smoke_r2`.

    use super::*;
    use tempfile::TempDir;

    async fn smoke_roundtrip(
        open: impl std::future::Future<Output = Result<S3StorageBackend, StorageError>>,
    ) {
        let dir = TempDir::new().unwrap();
        let backend = open.await.unwrap();
        let key = StorageObjectKey::new("smoke/demo.bin").unwrap();
        let data = b"disk-arcana-s3-smoke";
        backend
            .put(&key, data, PutOptions::default())
            .await
            .unwrap();
        assert!(backend.exists(&key).await.unwrap());
        assert_eq!(backend.get(&key).await.unwrap(), data);
        backend.delete(&key).await.unwrap();
        assert!(!backend.exists(&key).await.unwrap());
    }

    #[tokio::test]
    #[ignore = "requires DISK_B2_* env and sandbox bucket"]
    async fn smoke_b2_roundtrip() {
        let dir = TempDir::new().unwrap();
        smoke_roundtrip(S3StorageBackend::open_backblaze(dir.path().join("meta.db"))).await;
    }

    #[tokio::test]
    #[ignore = "requires DISK_R2_* env and sandbox bucket"]
    async fn smoke_r2_roundtrip() {
        let dir = TempDir::new().unwrap();
        smoke_roundtrip(S3StorageBackend::open_cloudflare_r2(
            dir.path().join("meta.db"),
        ))
        .await;
    }
}
