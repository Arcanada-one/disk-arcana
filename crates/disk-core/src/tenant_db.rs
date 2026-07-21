//! Per-tenant SQLite file routing (DISK-0017 slice 4).
//!
//! When `tenant_data_root` is set, tenant-scoped tables (`files`, baselines,
//! conflicts, tombstones) live in `{root}/{tenant_key}/meta.sqlite`. The
//! control database (`DISK_DB_PATH`) retains nodes, ACL, enrollment, and
//! billing. Legacy single-DB mode uses one `MetaDb` for everything.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::error::MetaDbError;
use crate::meta_db::MetaDb;

#[derive(Debug)]
struct Inner {
    control: MetaDb,
    tenant_root: Option<PathBuf>,
    shards: RwLock<HashMap<String, MetaDb>>,
}

/// Routes tenant data operations to isolated SQLite files.
#[derive(Debug, Clone)]
pub struct TenantMetaRouter {
    inner: Arc<Inner>,
}

impl TenantMetaRouter {
    /// Legacy / test mode — all data in one database.
    pub fn single(control: MetaDb) -> Self {
        Self {
            inner: Arc::new(Inner {
                control,
                tenant_root: None,
                shards: RwLock::new(HashMap::new()),
            }),
        }
    }

    /// Control DB plus per-tenant data files under `tenant_root`.
    pub fn split(control: MetaDb, tenant_root: PathBuf) -> Self {
        Self {
            inner: Arc::new(Inner {
                control,
                tenant_root: Some(tenant_root),
                shards: RwLock::new(HashMap::new()),
            }),
        }
    }

    /// Whether per-tenant SQLite files are enabled.
    pub fn is_split(&self) -> bool {
        self.inner.tenant_root.is_some()
    }

    /// Control-plane database (nodes, billing, ACL).
    pub fn control(&self) -> MetaDb {
        self.inner.control.clone()
    }

    /// Tenant data database — isolated file when split, else control.
    pub async fn tenant_data(&self, tenant_id: Option<&str>) -> Result<MetaDb, MetaDbError> {
        let Some(root) = self.inner.tenant_root.as_ref() else {
            return Ok(self.inner.control.clone());
        };

        let key = tenant_shard_key(tenant_id)?;
        {
            let cache = self.inner.shards.read().await;
            if let Some(db) = cache.get(&key) {
                return Ok(db.clone());
            }
        }

        let path = tenant_db_path(root, &key);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                MetaDbError::Invalid(format!("create tenant db dir {}: {e}", parent.display()))
            })?;
        }
        let db = MetaDb::open(&path).await?;

        let mut cache = self.inner.shards.write().await;
        let entry = cache.entry(key).or_insert_with(|| db.clone());
        Ok(entry.clone())
    }

    /// Storage accounting for quota enforcement.
    pub async fn sum_storage_bytes(&self, tenant_id: Option<&str>) -> Result<u64, MetaDbError> {
        self.tenant_data(tenant_id)
            .await?
            .sum_storage_bytes(tenant_id)
            .await
    }

    /// File lookup for quota delta calculations.
    pub async fn get_file_scoped(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
        path: &str,
    ) -> Result<Option<crate::types::FileMeta>, MetaDbError> {
        self.tenant_data(tenant_id)
            .await?
            .get_file_scoped(tenant_id, vault_id, path)
            .await
    }
}

/// Sanitized on-disk directory name for a tenant shard.
pub fn tenant_shard_key(tenant_id: Option<&str>) -> Result<String, MetaDbError> {
    match tenant_id.filter(|t| !t.is_empty()) {
        None => Ok("_legacy".into()),
        Some(t) => sanitize_tenant_id(t),
    }
}

/// Path to a tenant's metadata SQLite file.
pub fn tenant_db_path(root: &Path, shard_key: &str) -> PathBuf {
    root.join(shard_key).join("meta.sqlite")
}

fn sanitize_tenant_id(tenant_id: &str) -> Result<String, MetaDbError> {
    if tenant_id.len() > 64 {
        return Err(MetaDbError::Invalid(
            "tenant_id exceeds 64 characters".into(),
        ));
    }
    if !tenant_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(MetaDbError::Invalid(
            "tenant_id contains invalid characters".into(),
        ));
    }
    Ok(tenant_id.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FileMeta;
    use crate::VectorClock;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn sample_meta(path: &str) -> FileMeta {
        FileMeta {
            path: PathBuf::from(path),
            content_hash: [1u8; 32],
            size: 4,
            mtime_ns: 1,
            inode: None,
            vector_clock: VectorClock::default(),
            deleted: false,
            deleted_at: None,
            node_id: "n".into(),
            encryption_nonce: None,
            version_id: None,
            parent_version_id: None,
        }
    }

    #[test]
    fn shard_key_rejects_traversal() {
        assert!(sanitize_tenant_id("../evil").is_err());
        assert_eq!(tenant_shard_key(None).unwrap(), "_legacy");
    }

    #[tokio::test]
    async fn split_mode_uses_separate_files() {
        let dir = tempdir().unwrap();
        let control = MetaDb::open(&dir.path().join("control.sqlite"))
            .await
            .unwrap();
        let router = TenantMetaRouter::split(control, dir.path().join("tenants"));

        let acme = router.tenant_data(Some("acme")).await.unwrap();
        let beta = router.tenant_data(Some("beta")).await.unwrap();

        acme.upsert_file_scoped(Some("acme"), "default", &sample_meta("a.md"))
            .await
            .unwrap();

        assert!(acme
            .get_file_scoped(Some("acme"), "default", "a.md")
            .await
            .unwrap()
            .is_some());
        assert!(beta
            .get_file_scoped(Some("beta"), "default", "a.md")
            .await
            .unwrap()
            .is_none());

        assert!(dir.path().join("tenants/acme/meta.sqlite").exists());
        assert!(dir.path().join("tenants/beta/meta.sqlite").exists());
    }

    #[tokio::test]
    async fn single_mode_aliases_control() {
        let dir = tempdir().unwrap();
        let control = MetaDb::open(&dir.path().join("only.sqlite")).await.unwrap();
        let router = TenantMetaRouter::single(control.clone());

        let data = router.tenant_data(Some("acme")).await.unwrap();
        data.upsert_file_scoped(Some("acme"), "default", &sample_meta("x.md"))
            .await
            .unwrap();

        assert!(control
            .get_file_scoped(Some("acme"), "default", "x.md")
            .await
            .unwrap()
            .is_some());
    }
}
