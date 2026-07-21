//! `files` table CRUD.

use std::path::PathBuf;

use sqlx::Row;

use super::MetaDb;
use crate::error::MetaDbError;
use crate::types::FileMeta;
use crate::vector_clock::VectorClock;

const VAULT_DEFAULT: &str = "default";

impl MetaDb {
    /// Insert or update a file row keyed by `(vault_id, path)`.
    pub async fn upsert_file(&self, meta: &FileMeta) -> Result<(), MetaDbError> {
        let now = unix_now();
        let path_str = path_as_str(&meta.path)?;
        let vc_json = serde_json::to_string(&meta.vector_clock)?;
        let inode = meta.inode.map(|v| v as i64);

        // SQLite treats NULLs as distinct in multi-column UNIQUE indexes, so
        // the (NULL, vault, path) tuple from a fresh row never collides with a
        // previously-inserted (NULL, vault, path) row. Emulate the UPSERT
        // ourselves: try UPDATE first, then INSERT only when nothing matched.
        let deleted_int = if meta.deleted { 1i64 } else { 0i64 };

        let updated = sqlx::query(
            r#"
            UPDATE files SET
                content_hash = ?3,
                size         = ?4,
                mtime_ns     = ?5,
                inode        = ?6,
                vector_clock = ?7,
                updated_at   = ?8,
                deleted      = ?9,
                deleted_at   = ?10,
                encryption_nonce = ?11
            WHERE vault_id = ?1 AND path = ?2 AND tenant_id IS NULL
            "#,
        )
        .bind(VAULT_DEFAULT)
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
                encryption_nonce, created_at, updated_at
            ) VALUES (NULL, ?1, ?2, ?3, ?4, ?5, ?6, ?7, 'clean', NULL, ?8, ?9, ?10, ?11, ?11)
            "#,
        )
        .bind(VAULT_DEFAULT)
        .bind(path_str)
        .bind(meta.content_hash.to_vec())
        .bind(meta.size as i64)
        .bind(meta.mtime_ns)
        .bind(inode)
        .bind(vc_json)
        .bind(deleted_int)
        .bind(meta.deleted_at)
        .bind(meta.encryption_nonce.as_deref())
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Fetch one file by relative path.
    pub async fn get_file(&self, path: &str) -> Result<Option<FileMeta>, MetaDbError> {
        let row = sqlx::query(
            r#"
            SELECT path, content_hash, size, mtime_ns, inode, vector_clock, deleted, deleted_at,
                   encryption_nonce
            FROM files
            WHERE vault_id = ?1 AND path = ?2
            "#,
        )
        .bind(VAULT_DEFAULT)
        .bind(path)
        .fetch_optional(&self.pool)
        .await?;

        row.map(row_to_meta).transpose()
    }

    /// Delete a file row (used after the reconciler emits `DeleteLocal` /
    /// when a tombstone supersedes the index entry).
    pub async fn delete_file(&self, path: &str) -> Result<(), MetaDbError> {
        sqlx::query("DELETE FROM files WHERE vault_id = ?1 AND path = ?2")
            .bind(VAULT_DEFAULT)
            .bind(path)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Stream all files in the default vault.
    pub async fn list_all_files(&self) -> Result<Vec<FileMeta>, MetaDbError> {
        let rows = sqlx::query(
            r#"
            SELECT path, content_hash, size, mtime_ns, inode, vector_clock, deleted, deleted_at,
                   encryption_nonce
            FROM files
            WHERE vault_id = ?1
            ORDER BY path ASC
            "#,
        )
        .bind(VAULT_DEFAULT)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_meta).collect()
    }
}

fn row_to_meta(row: sqlx::sqlite::SqliteRow) -> Result<FileMeta, MetaDbError> {
    let path: String = row.try_get("path")?;
    let content_hash_blob: Vec<u8> = row.try_get("content_hash")?;
    let size: i64 = row.try_get("size")?;
    let mtime_ns: i64 = row.try_get("mtime_ns")?;
    let inode: Option<i64> = row.try_get("inode")?;
    let vector_clock_json: String = row.try_get("vector_clock")?;
    let deleted_int: i64 = row.try_get("deleted")?;
    let deleted_at: Option<i64> = row.try_get("deleted_at")?;
    let encryption_nonce: Option<Vec<u8>> = row.try_get("encryption_nonce")?;

    if content_hash_blob.len() != 32 {
        return Err(MetaDbError::Invalid(format!(
            "content_hash length = {}, expected 32",
            content_hash_blob.len()
        )));
    }
    let mut content_hash = [0u8; 32];
    content_hash.copy_from_slice(&content_hash_blob);

    let vector_clock: VectorClock = serde_json::from_str(&vector_clock_json).unwrap_or_default();

    Ok(FileMeta {
        path: PathBuf::from(path),
        content_hash,
        size: size as u64,
        mtime_ns,
        inode: inode.map(|v| v as u64),
        vector_clock,
        deleted: deleted_int != 0,
        deleted_at,
        node_id: String::new(),
        encryption_nonce,
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
