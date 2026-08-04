use std::path::PathBuf;
use std::time::SystemTime;

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;

use crate::backend::StorageBackend;
use crate::metadata::{content_sha256_hex, object_key_for, MetadataStore, MetadataStoreConfig};
use crate::{
    ListEntry, ListOptions, ObjectLifecyclePolicy, ObjectMetadata, PresignedUrl, PutOptions,
    RenameRequest, StorageError, StorageObjectKey,
};

/// Reference backend: content blobs under `{blob_root}/{sha[0:2]}/{sha[2:]}`.
#[derive(Debug)]
pub struct LocalDiskBackend {
    meta: MetadataStore,
    blob_root: PathBuf,
    presign_secret: String,
}

impl LocalDiskBackend {
    pub async fn open(
        blob_root: impl Into<PathBuf>,
        meta_db: impl Into<PathBuf>,
    ) -> Result<Self, StorageError> {
        let blob_root = blob_root.into();
        std::fs::create_dir_all(&blob_root)?;
        let meta = MetadataStore::open(MetadataStoreConfig {
            db_path: meta_db.into(),
        })
        .await?;
        Ok(Self {
            meta,
            blob_root,
            presign_secret: "local-reference-backend".into(),
        })
    }

    fn blob_path(&self, sha256_hex: &str) -> PathBuf {
        self.blob_root.join(&sha256_hex[..2]).join(&sha256_hex[2..])
    }

    async fn write_blob(&self, sha256_hex: &str, data: &[u8]) -> Result<(), StorageError> {
        let dest = self.blob_path(sha256_hex);
        if dest.exists() {
            return Ok(());
        }
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let tmp = dest.with_extension("tmp");
        let mut file = tokio::fs::File::create(&tmp).await?;
        file.write_all(data).await?;
        file.sync_all().await?;
        match tokio::fs::rename(&tmp, &dest).await {
            Ok(()) => Ok(()),
            Err(_e) if dest.exists() => {
                let _ = tokio::fs::remove_file(&tmp).await;
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn read_blob(&self, sha256_hex: &str) -> Result<Vec<u8>, StorageError> {
        let path = self.blob_path(sha256_hex);
        if !path.is_file() {
            return Err(StorageError::NotFound {
                path: sha256_hex.into(),
            });
        }
        Ok(tokio::fs::read(path).await?)
    }

    async fn delete_blob_if_unreferenced(&self, sha256_hex: &str) -> Result<(), StorageError> {
        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM storage_objects WHERE content_sha256 = ?")
                .bind(sha256_hex)
                .fetch_one(self.meta.pool())
                .await?;
        if count.0 == 0 {
            let path = self.blob_path(sha256_hex);
            if path.exists() {
                tokio::fs::remove_file(path).await?;
            }
        }
        Ok(())
    }
}

impl LocalDiskBackend {
    pub(crate) fn meta(&self) -> &MetadataStore {
        &self.meta
    }
}

#[async_trait]
impl StorageBackend for LocalDiskBackend {
    async fn put(
        &self,
        path: &StorageObjectKey,
        data: &[u8],
        options: PutOptions,
    ) -> Result<ObjectMetadata, StorageError> {
        let sha = content_sha256_hex(data);
        let object_key = object_key_for(path.as_str(), &sha);
        self.write_blob(&sha, data).await?;
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
        let lifecycle = ObjectLifecyclePolicy::default();
        self.meta.upsert(&meta, &lifecycle).await?;
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
        self.read_blob(&meta.content_sha256).await
    }

    async fn delete(&self, path: &StorageObjectKey) -> Result<(), StorageError> {
        let meta = self
            .meta
            .get(path.as_str())
            .await?
            .ok_or_else(|| StorageError::NotFound {
                path: path.as_str().to_string(),
            })?;
        let sha = meta.content_sha256.clone();
        if !self.meta.delete(path.as_str()).await? {
            return Err(StorageError::NotFound {
                path: path.as_str().to_string(),
            });
        }
        self.delete_blob_if_unreferenced(&sha).await
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
        let lifecycle = ObjectLifecyclePolicy::default();
        self.meta.upsert(&updated, &lifecycle).await?;
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
        let exp = expires_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| StorageError::Metadata(e.to_string()))?
            .as_secs();
        let url = format!(
            "disk-local://{}/{}?sha256={}&exp={}&sig={}",
            self.presign_secret,
            meta.path,
            meta.content_sha256,
            exp,
            &meta.content_sha256[..8]
        );
        Ok(PresignedUrl { url, expires_at })
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
mod contract_tests {
    use super::*;
    use tempfile::TempDir;

    async fn backend() -> (TempDir, LocalDiskBackend) {
        let dir = TempDir::new().unwrap();
        let b = LocalDiskBackend::open(dir.path().join("blobs"), dir.path().join("meta.db"))
            .await
            .unwrap();
        (dir, b)
    }

    #[tokio::test]
    async fn contract_put_get_exists_delete() {
        let (_dir, backend) = backend().await;
        let key = StorageObjectKey::new("videos/demo.mp4").unwrap();
        let data = b"fake-video-bytes";
        let meta = backend
            .put(&key, data, PutOptions::default())
            .await
            .unwrap();
        assert_eq!(meta.size, data.len() as u64);
        assert!(backend.exists(&key).await.unwrap());
        let roundtrip = backend.get(&key).await.unwrap();
        assert_eq!(roundtrip, data);
        backend.delete(&key).await.unwrap();
        assert!(!backend.exists(&key).await.unwrap());
    }

    #[tokio::test]
    async fn contract_rename_and_list() {
        let (_dir, backend) = backend().await;
        let from = StorageObjectKey::new("a/one.bin").unwrap();
        backend
            .put(&from, b"1", PutOptions::default())
            .await
            .unwrap();
        let to = StorageObjectKey::new("b/two.bin").unwrap();
        backend
            .rename(RenameRequest {
                from,
                to: to.clone(),
            })
            .await
            .unwrap();
        let listed = backend
            .list(ListOptions {
                prefix: Some("b/".into()),
                limit: None,
            })
            .await
            .unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].path, "b/two.bin");
    }

    #[tokio::test]
    async fn contract_presigned_and_lifecycle() {
        let (_dir, backend) = backend().await;
        let key = StorageObjectKey::new("archive/clip.mov").unwrap();
        backend
            .put(&key, b"mov", PutOptions::default())
            .await
            .unwrap();
        let exp = SystemTime::now() + std::time::Duration::from_secs(3600);
        let url = backend.presigned_url(&key, exp).await.unwrap();
        assert!(url.url.contains("disk-local://"));
        let lc = backend.object_lifecycle(&key).await.unwrap();
        assert!(lc.retain_forever);
        assert!(lc.manual_delete_only);
    }
}
