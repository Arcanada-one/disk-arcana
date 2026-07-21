//! `file_versions` table — version history and tier retention (DISK-0020).

use sqlx::Row;

use super::MetaDb;
use crate::billing::VersionRetention;
use crate::error::MetaDbError;
use crate::types::FileMeta;

/// One historical file revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileVersionRow {
    pub version_id: u64,
    pub parent_version_id: u64,
    pub path: String,
    pub content_hash: [u8; 32],
    pub size: u64,
    pub mtime_ns: i64,
    pub created_at: i64,
    pub created_by: Option<String>,
}

/// Context for a versioned upsert.
#[derive(Debug, Clone)]
pub struct FileVersionUpsert {
    pub created_by: String,
    pub retention: VersionRetention,
}

impl MetaDb {
    /// Insert or update a file row, recording a history row when content changes.
    pub async fn upsert_file_scoped_versioned(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
        meta: &FileMeta,
        ctx: &FileVersionUpsert,
    ) -> Result<u64, MetaDbError> {
        let now = unix_now();
        let path_str = path_as_str(&meta.path)?;
        let existing = self
            .get_file_row_scoped(tenant_id, vault_id, &path_str)
            .await?;

        let (new_version_id, parent_version_id) = if let Some((prior, prior_vid)) = existing {
            let prior_vid = prior_vid.unwrap_or(1);
            if prior.content_hash != meta.content_hash && !prior.deleted {
                self.insert_file_version(
                    tenant_id,
                    vault_id,
                    &path_str,
                    prior_vid,
                    prior.parent_version_id.unwrap_or(0),
                    &prior,
                    now,
                    Some(&ctx.created_by),
                )
                .await?;
                (prior_vid + 1, prior_vid)
            } else {
                (prior_vid, prior.parent_version_id.unwrap_or(0))
            }
        } else {
            (1, 0)
        };

        self.write_file_row(
            tenant_id,
            vault_id,
            meta,
            new_version_id,
            parent_version_id,
            now,
        )
        .await?;

        self.prune_file_versions(tenant_id, vault_id, &path_str, &ctx.retention)
            .await?;

        Ok(new_version_id)
    }

    /// List version history for a path (newest first).
    pub async fn list_file_versions(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
        path: &str,
        limit: u32,
    ) -> Result<Vec<FileVersionRow>, MetaDbError> {
        let cap = limit.clamp(1, 200);
        let rows = sqlx::query(
            r#"
            SELECT version_id, parent_version_id, path, content_hash, size, mtime_ns,
                   created_at, created_by
            FROM file_versions
            WHERE tenant_id IS ?1 AND vault_id = ?2 AND path = ?3
            ORDER BY version_id DESC
            LIMIT ?4
            "#,
        )
        .bind(tenant_id)
        .bind(vault_id)
        .bind(path)
        .bind(cap as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_version).collect()
    }

    /// Fetch one historical revision.
    pub async fn get_file_version(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
        path: &str,
        version_id: u64,
    ) -> Result<Option<FileVersionRow>, MetaDbError> {
        let row = sqlx::query(
            r#"
            SELECT version_id, parent_version_id, path, content_hash, size, mtime_ns,
                   created_at, created_by
            FROM file_versions
            WHERE tenant_id IS ?1 AND vault_id = ?2 AND path = ?3 AND version_id = ?4
            "#,
        )
        .bind(tenant_id)
        .bind(vault_id)
        .bind(path)
        .bind(version_id as i64)
        .fetch_optional(&self.pool)
        .await?;

        row.map(row_to_version).transpose()
    }

    async fn get_file_row_scoped(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
        path: &str,
    ) -> Result<Option<(FileMeta, Option<u64>)>, MetaDbError> {
        let row = sqlx::query(
            r#"
            SELECT path, content_hash, size, mtime_ns, inode, vector_clock, deleted, deleted_at,
                   encryption_nonce, version_id, parent_version_id
            FROM files
            WHERE tenant_id IS ?1 AND vault_id = ?2 AND path = ?3
            "#,
        )
        .bind(tenant_id)
        .bind(vault_id)
        .bind(path)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| {
            let meta = row_to_meta_with_versions(&r)?;
            let vid: Option<i64> = r.try_get("version_id")?;
            Ok((meta, vid.map(|v| v as u64)))
        })
        .transpose()
    }

    #[allow(clippy::too_many_arguments)]
    async fn insert_file_version(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
        path: &str,
        version_id: u64,
        parent_version_id: u64,
        meta: &FileMeta,
        created_at: i64,
        created_by: Option<&str>,
    ) -> Result<(), MetaDbError> {
        sqlx::query(
            r#"
            INSERT INTO file_versions (
                tenant_id, vault_id, path, version_id, parent_version_id,
                content_hash, size, mtime_ns, created_at, created_by
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            "#,
        )
        .bind(tenant_id)
        .bind(vault_id)
        .bind(path)
        .bind(version_id as i64)
        .bind(parent_version_id as i64)
        .bind(meta.content_hash.to_vec())
        .bind(meta.size as i64)
        .bind(meta.mtime_ns)
        .bind(created_at)
        .bind(created_by)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn write_file_row(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
        meta: &FileMeta,
        version_id: u64,
        parent_version_id: u64,
        now: i64,
    ) -> Result<(), MetaDbError> {
        let path_str = path_as_str(&meta.path)?;
        let vc_json = serde_json::to_string(&meta.vector_clock)?;
        let inode = meta.inode.map(|v| v as i64);
        let deleted_int = if meta.deleted { 1i64 } else { 0i64 };

        let updated = sqlx::query(
            r#"
            UPDATE files SET
                content_hash = ?4,
                size         = ?5,
                mtime_ns     = ?6,
                inode        = ?7,
                vector_clock = ?8,
                updated_at   = ?9,
                deleted      = ?10,
                deleted_at   = ?11,
                encryption_nonce = ?12,
                version_id   = ?13,
                parent_version_id = ?14
            WHERE tenant_id IS ?1 AND vault_id = ?2 AND path = ?3
            "#,
        )
        .bind(tenant_id)
        .bind(vault_id)
        .bind(path_str.clone())
        .bind(meta.content_hash.to_vec())
        .bind(meta.size as i64)
        .bind(meta.mtime_ns)
        .bind(inode)
        .bind(vc_json.clone())
        .bind(now)
        .bind(deleted_int)
        .bind(meta.deleted_at)
        .bind(meta.encryption_nonce.as_deref())
        .bind(version_id as i64)
        .bind(parent_version_id as i64)
        .execute(&self.pool)
        .await?;

        if updated.rows_affected() > 0 {
            return Ok(());
        }

        sqlx::query(
            r#"
            INSERT INTO files (
                tenant_id, vault_id, path, content_hash, size, mtime_ns, inode,
                vector_clock, sync_state, last_synced, deleted, deleted_at,
                encryption_nonce, version_id, parent_version_id, created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'clean', NULL, ?9, ?10, ?11, ?12, ?13, ?14, ?14)
            "#,
        )
        .bind(tenant_id)
        .bind(vault_id)
        .bind(path_str)
        .bind(meta.content_hash.to_vec())
        .bind(meta.size as i64)
        .bind(meta.mtime_ns)
        .bind(inode)
        .bind(vc_json)
        .bind(deleted_int)
        .bind(meta.deleted_at)
        .bind(meta.encryption_nonce.as_deref())
        .bind(version_id as i64)
        .bind(parent_version_id as i64)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Drop history rows beyond tier limits for one path.
    pub async fn prune_file_versions(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
        path: &str,
        retention: &VersionRetention,
    ) -> Result<(), MetaDbError> {
        let cutoff = unix_now() - retention.max_age_secs;
        sqlx::query(
            r#"
            DELETE FROM file_versions
            WHERE tenant_id IS ?1 AND vault_id = ?2 AND path = ?3
              AND (
                created_at < ?4
                OR version_id NOT IN (
                    SELECT version_id FROM file_versions
                    WHERE tenant_id IS ?1 AND vault_id = ?2 AND path = ?3
                    ORDER BY version_id DESC
                    LIMIT ?5
                )
              )
            "#,
        )
        .bind(tenant_id)
        .bind(vault_id)
        .bind(path)
        .bind(cutoff)
        .bind(retention.max_versions as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete_file_versions_for_path(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
        path: &str,
    ) -> Result<(), MetaDbError> {
        sqlx::query(
            "DELETE FROM file_versions WHERE tenant_id IS ?1 AND vault_id = ?2 AND path = ?3",
        )
        .bind(tenant_id)
        .bind(vault_id)
        .bind(path)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete_file_versions_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<(), MetaDbError> {
        sqlx::query("DELETE FROM file_versions WHERE tenant_id IS ?1")
            .bind(tenant_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

fn row_to_version(row: sqlx::sqlite::SqliteRow) -> Result<FileVersionRow, MetaDbError> {
    let content_hash_blob: Vec<u8> = row.try_get("content_hash")?;
    if content_hash_blob.len() != 32 {
        return Err(MetaDbError::Invalid(format!(
            "content_hash length = {}, expected 32",
            content_hash_blob.len()
        )));
    }
    let mut content_hash = [0u8; 32];
    content_hash.copy_from_slice(&content_hash_blob);

    Ok(FileVersionRow {
        version_id: row.try_get::<i64, _>("version_id")? as u64,
        parent_version_id: row.try_get::<i64, _>("parent_version_id")? as u64,
        path: row.try_get("path")?,
        content_hash,
        size: row.try_get::<i64, _>("size")? as u64,
        mtime_ns: row.try_get("mtime_ns")?,
        created_at: row.try_get("created_at")?,
        created_by: row.try_get("created_by")?,
    })
}

fn row_to_meta_with_versions(row: &sqlx::sqlite::SqliteRow) -> Result<FileMeta, MetaDbError> {
    let path: String = row.try_get("path")?;
    let content_hash_blob: Vec<u8> = row.try_get("content_hash")?;
    let size: i64 = row.try_get("size")?;
    let mtime_ns: i64 = row.try_get("mtime_ns")?;
    let inode: Option<i64> = row.try_get("inode")?;
    let vector_clock_json: String = row.try_get("vector_clock")?;
    let deleted_int: i64 = row.try_get("deleted")?;
    let deleted_at: Option<i64> = row.try_get("deleted_at")?;
    let encryption_nonce: Option<Vec<u8>> = row.try_get("encryption_nonce")?;
    let version_id: Option<i64> = row.try_get("version_id")?;
    let parent_version_id: Option<i64> = row.try_get("parent_version_id")?;

    if content_hash_blob.len() != 32 {
        return Err(MetaDbError::Invalid(format!(
            "content_hash length = {}, expected 32",
            content_hash_blob.len()
        )));
    }
    let mut content_hash = [0u8; 32];
    content_hash.copy_from_slice(&content_hash_blob);

    let vector_clock: crate::vector_clock::VectorClock =
        serde_json::from_str(&vector_clock_json).unwrap_or_default();

    Ok(FileMeta {
        path: std::path::PathBuf::from(path),
        content_hash,
        size: size as u64,
        mtime_ns,
        inode: inode.map(|v| v as u64),
        vector_clock,
        deleted: deleted_int != 0,
        deleted_at,
        node_id: String::new(),
        encryption_nonce,
        version_id: version_id.map(|v| v as u64),
        parent_version_id: parent_version_id.map(|v| v as u64),
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
    async fn versioned_upsert_records_history_on_hash_change() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("versions.sqlite"))
            .await
            .unwrap();
        let retention = VersionRetention {
            max_versions: 10,
            max_age_secs: 86_400,
        };
        let ctx = FileVersionUpsert {
            created_by: "server".into(),
            retention,
        };

        db.upsert_file_scoped_versioned(Some("t1"), "default", &sample("a.md", 1), &ctx)
            .await
            .unwrap();
        let v2 = db
            .upsert_file_scoped_versioned(Some("t1"), "default", &sample("a.md", 2), &ctx)
            .await
            .unwrap();
        assert_eq!(v2, 2);

        let history = db
            .list_file_versions(Some("t1"), "default", "a.md", 20)
            .await
            .unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].version_id, 1);
        assert_eq!(history[0].content_hash, [1u8; 32]);
    }
}
