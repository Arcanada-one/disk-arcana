//! Trash / recycle-bin queries over soft-deleted `files` rows (DISK-0024).

use sqlx::Row;

use super::MetaDb;
use crate::billing::TrashRetention;
use crate::error::MetaDbError;
use crate::types::FileMeta;

/// A soft-deleted file visible in the recycle bin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrashRow {
    pub path: String,
    pub content_hash: [u8; 32],
    pub size: u64,
    pub deleted_at: i64,
    pub version_id: Option<u64>,
}

impl MetaDb {
    /// Return soft-deleted files for a vault, newest first.
    pub async fn list_trash(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<TrashRow>, MetaDbError> {
        let rows = sqlx::query(
            r#"
            SELECT path, content_hash, size, deleted_at, version_id
            FROM files
            WHERE tenant_id IS ?1 AND vault_id = ?2 AND deleted = 1
            ORDER BY deleted_at DESC, path ASC
            LIMIT ?3 OFFSET ?4
            "#,
        )
        .bind(tenant_id)
        .bind(vault_id)
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_trash).collect()
    }

    /// Count soft-deleted files in a vault.
    pub async fn count_trash(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
    ) -> Result<u32, MetaDbError> {
        let row = sqlx::query(
            r#"
            SELECT COUNT(*) AS cnt
            FROM files
            WHERE tenant_id IS ?1 AND vault_id = ?2 AND deleted = 1
            "#,
        )
        .bind(tenant_id)
        .bind(vault_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.try_get::<i64, _>("cnt")? as u32)
    }

    /// Permanently remove trashed files older than the tier retention window.
    pub async fn prune_expired_trash(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
        retention: &TrashRetention,
    ) -> Result<u32, MetaDbError> {
        let cutoff = unix_now() - retention.max_age_secs;
        let result = sqlx::query(
            r#"
            DELETE FROM files
            WHERE tenant_id IS ?1 AND vault_id = ?2
              AND deleted = 1 AND deleted_at IS NOT NULL AND deleted_at < ?3
            "#,
        )
        .bind(tenant_id)
        .bind(vault_id)
        .bind(cutoff)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() as u32)
    }

    /// Permanently remove one soft-deleted file from the index.
    pub async fn delete_trash_item(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
        path: &str,
    ) -> Result<bool, MetaDbError> {
        let result = sqlx::query(
            r#"
            DELETE FROM files
            WHERE tenant_id IS ?1 AND vault_id = ?2 AND path = ?3 AND deleted = 1
            "#,
        )
        .bind(tenant_id)
        .bind(vault_id)
        .bind(path)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Permanently remove all soft-deleted files in a vault.
    pub async fn empty_trash(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
    ) -> Result<u32, MetaDbError> {
        let result = sqlx::query(
            r#"
            DELETE FROM files
            WHERE tenant_id IS ?1 AND vault_id = ?2 AND deleted = 1
            "#,
        )
        .bind(tenant_id)
        .bind(vault_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() as u32)
    }

    /// Distinct tenant ids that currently have trashed files (for scheduled prune).
    pub async fn list_trash_tenant_ids(&self) -> Result<Vec<Option<String>>, MetaDbError> {
        let rows = sqlx::query(
            r#"
            SELECT DISTINCT tenant_id
            FROM files
            WHERE deleted = 1
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                let tenant_id: Option<String> = row.try_get("tenant_id")?;
                Ok(tenant_id)
            })
            .collect()
    }

    /// Distinct vault ids with trashed files for a tenant.
    pub async fn list_vaults_with_trash(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<String>, MetaDbError> {
        let rows = sqlx::query(
            r#"
            SELECT DISTINCT vault_id
            FROM files
            WHERE tenant_id IS ?1 AND deleted = 1
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                let vault_id: String = row.try_get("vault_id")?;
                Ok(vault_id)
            })
            .collect()
    }

    /// Clear soft-delete flags on a trashed file row (caller writes live bytes).
    pub async fn mark_trash_restored(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
        path: &str,
    ) -> Result<Option<FileMeta>, MetaDbError> {
        let existing = self.get_file_scoped(tenant_id, vault_id, path).await?;
        let Some(mut meta) = existing else {
            return Ok(None);
        };
        if !meta.deleted {
            return Ok(Some(meta));
        }

        meta.deleted = false;
        meta.deleted_at = None;
        self.upsert_file_scoped(tenant_id, vault_id, &meta).await?;
        Ok(Some(meta))
    }
}

fn row_to_trash(row: sqlx::sqlite::SqliteRow) -> Result<TrashRow, MetaDbError> {
    let path: String = row.try_get("path")?;
    let content_hash_blob: Vec<u8> = row.try_get("content_hash")?;
    let size: i64 = row.try_get("size")?;
    let deleted_at: i64 = row.try_get("deleted_at")?;
    let version_id: Option<i64> = row.try_get("version_id")?;

    if content_hash_blob.len() != 32 {
        return Err(MetaDbError::Invalid(format!(
            "content_hash length = {}, expected 32",
            content_hash_blob.len()
        )));
    }
    let mut content_hash = [0u8; 32];
    content_hash.copy_from_slice(&content_hash_blob);

    Ok(TrashRow {
        path,
        content_hash,
        size: size as u64,
        deleted_at,
        version_id: version_id.map(|v| v as u64),
    })
}

fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::PlanTier;
    use crate::types::FileMeta;
    use crate::vector_clock::VectorClock;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn deleted_sample(path: &str, deleted_at: i64) -> FileMeta {
        FileMeta {
            path: PathBuf::from(path),
            content_hash: [9u8; 32],
            size: 42,
            mtime_ns: 1,
            inode: None,
            vector_clock: VectorClock::new(),
            deleted: true,
            deleted_at: Some(deleted_at),
            node_id: "n".into(),
            encryption_nonce: None,
            version_id: Some(1),
            parent_version_id: None,
        }
    }

    #[tokio::test]
    async fn list_restore_and_prune_trash() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("trash.sqlite"))
            .await
            .unwrap();
        let now = unix_now();
        let retention = PlanTier::Free.trash_retention();

        db.upsert_file_scoped(Some("t1"), "wiki", &deleted_sample("gone.md", now - 10))
            .await
            .unwrap();
        db.upsert_file_scoped(
            Some("t1"),
            "wiki",
            &deleted_sample("old.md", now - retention.max_age_secs - 60),
        )
        .await
        .unwrap();

        let pruned = db
            .prune_expired_trash(Some("t1"), "wiki", &retention)
            .await
            .unwrap();
        assert_eq!(pruned, 1);

        let listed = db.list_trash(Some("t1"), "wiki", 10, 0).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].path, "gone.md");

        let restored = db
            .mark_trash_restored(Some("t1"), "wiki", "gone.md")
            .await
            .unwrap()
            .unwrap();
        assert!(!restored.deleted);
        assert!(restored.deleted_at.is_none());

        let after = db.count_trash(Some("t1"), "wiki").await.unwrap();
        assert_eq!(after, 0);
    }

    #[tokio::test]
    async fn delete_and_empty_trash() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("trash-del.sqlite"))
            .await
            .unwrap();
        let now = unix_now();

        db.upsert_file_scoped(Some("t1"), "wiki", &deleted_sample("a.md", now))
            .await
            .unwrap();
        db.upsert_file_scoped(Some("t1"), "wiki", &deleted_sample("b.md", now))
            .await
            .unwrap();

        let deleted = db
            .delete_trash_item(Some("t1"), "wiki", "a.md")
            .await
            .unwrap();
        assert!(deleted);
        assert_eq!(db.count_trash(Some("t1"), "wiki").await.unwrap(), 1);

        let emptied = db.empty_trash(Some("t1"), "wiki").await.unwrap();
        assert_eq!(emptied, 1);
        assert_eq!(db.count_trash(Some("t1"), "wiki").await.unwrap(), 0);

        let vaults = db.list_vaults_with_trash(Some("t1")).await.unwrap();
        assert!(vaults.is_empty());
    }
}
