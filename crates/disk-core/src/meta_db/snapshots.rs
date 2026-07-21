//! Point-in-time vault snapshots (DISK-0020 slice 4).

use sqlx::Row;

use super::MetaDb;
use crate::billing::SnapshotRetention;
use crate::error::MetaDbError;

/// Vault-wide capture metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultSnapshotRow {
    pub id: u64,
    pub vault_id: String,
    pub label: Option<String>,
    pub file_count: u32,
    pub bytes_total: u64,
    pub created_at: i64,
    pub created_by: Option<String>,
}

/// One file pointer frozen inside a snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultSnapshotFileRow {
    pub path: String,
    pub version_id: u64,
    pub content_hash: [u8; 32],
    pub size: u64,
    pub deleted: bool,
}

impl MetaDb {
    /// Capture the current vault file index as an immutable snapshot.
    pub async fn create_vault_snapshot(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
        label: Option<&str>,
        created_by: &str,
        retention: &SnapshotRetention,
    ) -> Result<VaultSnapshotRow, MetaDbError> {
        let files = self.list_files_scoped(tenant_id, vault_id).await?;
        let now = unix_now();
        let file_count = files.len() as u32;
        let bytes_total: u64 = files.iter().filter(|f| !f.deleted).map(|f| f.size).sum();

        let mut tx = self.pool.begin().await?;

        let insert = sqlx::query(
            r#"
            INSERT INTO vault_snapshots (
                tenant_id, vault_id, label, file_count, bytes_total, created_at, created_by
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
        )
        .bind(tenant_id)
        .bind(vault_id)
        .bind(label)
        .bind(file_count as i64)
        .bind(bytes_total as i64)
        .bind(now)
        .bind(created_by)
        .execute(&mut *tx)
        .await?;

        let snapshot_id = insert.last_insert_rowid() as u64;

        for meta in &files {
            let path = path_as_str(&meta.path)?;
            let deleted_int = if meta.deleted { 1i64 } else { 0i64 };
            sqlx::query(
                r#"
                INSERT INTO vault_snapshot_files (
                    snapshot_id, tenant_id, vault_id, path, version_id,
                    content_hash, size, deleted
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                "#,
            )
            .bind(snapshot_id as i64)
            .bind(tenant_id)
            .bind(vault_id)
            .bind(path)
            .bind(meta.version_id.unwrap_or(1) as i64)
            .bind(meta.content_hash.to_vec())
            .bind(meta.size as i64)
            .bind(deleted_int)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        self.prune_vault_snapshots(tenant_id, vault_id, retention)
            .await?;

        Ok(VaultSnapshotRow {
            id: snapshot_id,
            vault_id: vault_id.to_string(),
            label: label.map(str::to_string),
            file_count,
            bytes_total,
            created_at: now,
            created_by: Some(created_by.to_string()),
        })
    }

    /// List snapshots for a vault (newest first).
    pub async fn list_vault_snapshots(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<VaultSnapshotRow>, MetaDbError> {
        let cap = limit.clamp(1, 200);
        let skip = offset.min(10_000);
        let rows = sqlx::query(
            r#"
            SELECT id, vault_id, label, file_count, bytes_total, created_at, created_by
            FROM vault_snapshots
            WHERE tenant_id IS ?1 AND vault_id = ?2
            ORDER BY created_at DESC, id DESC
            LIMIT ?3 OFFSET ?4
            "#,
        )
        .bind(tenant_id)
        .bind(vault_id)
        .bind(cap as i64)
        .bind(skip as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_snapshot).collect()
    }

    pub async fn count_vault_snapshots(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
    ) -> Result<u32, MetaDbError> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM vault_snapshots WHERE tenant_id IS ?1 AND vault_id = ?2",
        )
        .bind(tenant_id)
        .bind(vault_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0.max(0) as u32)
    }

    pub async fn get_vault_snapshot(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
        snapshot_id: u64,
    ) -> Result<Option<VaultSnapshotRow>, MetaDbError> {
        let row = sqlx::query(
            r#"
            SELECT id, vault_id, label, file_count, bytes_total, created_at, created_by
            FROM vault_snapshots
            WHERE tenant_id IS ?1 AND vault_id = ?2 AND id = ?3
            "#,
        )
        .bind(tenant_id)
        .bind(vault_id)
        .bind(snapshot_id as i64)
        .fetch_optional(&self.pool)
        .await?;

        row.map(row_to_snapshot).transpose()
    }

    pub async fn list_snapshot_files(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
        snapshot_id: u64,
    ) -> Result<Vec<VaultSnapshotFileRow>, MetaDbError> {
        let rows = sqlx::query(
            r#"
            SELECT path, version_id, content_hash, size, deleted
            FROM vault_snapshot_files
            WHERE tenant_id IS ?1 AND vault_id = ?2 AND snapshot_id = ?3
            ORDER BY path ASC
            "#,
        )
        .bind(tenant_id)
        .bind(vault_id)
        .bind(snapshot_id as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_snapshot_file).collect()
    }

    /// Drop snapshots beyond tier limits for one vault.
    pub async fn prune_vault_snapshots(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
        retention: &SnapshotRetention,
    ) -> Result<(), MetaDbError> {
        let cutoff = unix_now() - retention.max_age_secs;
        sqlx::query(
            r#"
            DELETE FROM vault_snapshots
            WHERE tenant_id IS ?1 AND vault_id = ?2
              AND (
                created_at < ?3
                OR id NOT IN (
                    SELECT id FROM vault_snapshots
                    WHERE tenant_id IS ?1 AND vault_id = ?2
                    ORDER BY created_at DESC, id DESC
                    LIMIT ?4
                )
              )
            "#,
        )
        .bind(tenant_id)
        .bind(vault_id)
        .bind(cutoff)
        .bind(retention.max_snapshots as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete_vault_snapshots_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<(), MetaDbError> {
        sqlx::query("DELETE FROM vault_snapshots WHERE tenant_id IS ?1")
            .bind(tenant_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

fn row_to_snapshot(row: sqlx::sqlite::SqliteRow) -> Result<VaultSnapshotRow, MetaDbError> {
    Ok(VaultSnapshotRow {
        id: row.try_get::<i64, _>("id")? as u64,
        vault_id: row.try_get("vault_id")?,
        label: row.try_get("label")?,
        file_count: row.try_get::<i64, _>("file_count")? as u32,
        bytes_total: row.try_get::<i64, _>("bytes_total")? as u64,
        created_at: row.try_get("created_at")?,
        created_by: row.try_get("created_by")?,
    })
}

fn row_to_snapshot_file(row: sqlx::sqlite::SqliteRow) -> Result<VaultSnapshotFileRow, MetaDbError> {
    let content_hash_blob: Vec<u8> = row.try_get("content_hash")?;
    if content_hash_blob.len() != 32 {
        return Err(MetaDbError::Invalid(format!(
            "content_hash length = {}, expected 32",
            content_hash_blob.len()
        )));
    }
    let mut content_hash = [0u8; 32];
    content_hash.copy_from_slice(&content_hash_blob);

    Ok(VaultSnapshotFileRow {
        path: row.try_get("path")?,
        version_id: row.try_get::<i64, _>("version_id")? as u64,
        content_hash,
        size: row.try_get::<i64, _>("size")? as u64,
        deleted: row.try_get::<i64, _>("deleted")? != 0,
    })
}

fn path_as_str(path: &std::path::Path) -> Result<String, MetaDbError> {
    path.to_str()
        .map(|s| s.replace('\\', "/"))
        .ok_or_else(|| MetaDbError::Invalid("path contains non-UTF-8 bytes".into()))
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
    use crate::billing::{PlanTier, SnapshotRetention};
    use crate::meta_db::FileVersionUpsert;
    use crate::types::FileMeta;
    use crate::vector_clock::VectorClock;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn sample(path: &str, byte: u8) -> FileMeta {
        FileMeta {
            path: PathBuf::from(path),
            content_hash: [byte; 32],
            size: 10,
            mtime_ns: 1,
            inode: None,
            vector_clock: VectorClock::new(),
            deleted: false,
            deleted_at: None,
            node_id: "n".into(),
            encryption_nonce: None,
            version_id: None,
            parent_version_id: None,
        }
    }

    #[tokio::test]
    async fn create_and_list_vault_snapshot() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("snap.sqlite")).await.unwrap();
        let retention = PlanTier::Free.snapshot_retention();
        let ctx = FileVersionUpsert {
            created_by: "server".into(),
            retention: PlanTier::Free.version_retention(),
        };

        db.upsert_file_scoped_versioned(Some("t1"), "wiki", &sample("a.md", 1), &ctx)
            .await
            .unwrap();
        db.upsert_file_scoped_versioned(Some("t1"), "wiki", &sample("b.md", 2), &ctx)
            .await
            .unwrap();

        let snap = db
            .create_vault_snapshot(Some("t1"), "wiki", Some("pre-cutover"), "op", &retention)
            .await
            .unwrap();
        assert_eq!(snap.file_count, 2);
        assert_eq!(snap.label.as_deref(), Some("pre-cutover"));

        let files = db
            .list_snapshot_files(Some("t1"), "wiki", snap.id)
            .await
            .unwrap();
        assert_eq!(files.len(), 2);

        let listed = db
            .list_vault_snapshots(Some("t1"), "wiki", 10, 0)
            .await
            .unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, snap.id);
    }
}
