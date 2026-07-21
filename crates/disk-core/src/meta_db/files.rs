//! `files` table CRUD.

use std::path::PathBuf;

use sqlx::Row;

use super::MetaDb;
use crate::error::MetaDbError;
use crate::types::FileMeta;
use crate::vector_clock::VectorClock;

const VAULT_DEFAULT: &str = "default";

impl MetaDb {
    /// Insert or update a file row keyed by `(tenant_id, vault_id, path)` — single-tenant default.
    pub async fn upsert_file(&self, meta: &FileMeta) -> Result<(), MetaDbError> {
        self.upsert_file_scoped(None, VAULT_DEFAULT, meta).await
    }

    /// Scoped upsert (DISK-0017).
    pub async fn upsert_file_scoped(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
        meta: &FileMeta,
    ) -> Result<(), MetaDbError> {
        let now = unix_now();
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
                encryption_nonce = ?12
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
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'clean', NULL, ?9, ?10, ?11, ?12, ?12)
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
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Fetch one file by relative path (single-tenant default vault).
    pub async fn get_file(&self, path: &str) -> Result<Option<FileMeta>, MetaDbError> {
        self.get_file_scoped(None, VAULT_DEFAULT, path).await
    }

    /// Scoped fetch (DISK-0017).
    pub async fn get_file_scoped(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
        path: &str,
    ) -> Result<Option<FileMeta>, MetaDbError> {
        let row = sqlx::query(
            r#"
            SELECT path, content_hash, size, mtime_ns, inode, vector_clock, deleted, deleted_at,
                   encryption_nonce
            FROM files
            WHERE tenant_id IS ?1 AND vault_id = ?2 AND path = ?3
            "#,
        )
        .bind(tenant_id)
        .bind(vault_id)
        .bind(path)
        .fetch_optional(&self.pool)
        .await?;

        row.map(row_to_meta).transpose()
    }

    /// Delete a file row (default single-tenant scope).
    pub async fn delete_file(&self, path: &str) -> Result<(), MetaDbError> {
        self.delete_file_scoped(None, VAULT_DEFAULT, path).await
    }

    /// Scoped delete (DISK-0017).
    pub async fn delete_file_scoped(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
        path: &str,
    ) -> Result<(), MetaDbError> {
        sqlx::query("DELETE FROM files WHERE tenant_id IS ?1 AND vault_id = ?2 AND path = ?3")
            .bind(tenant_id)
            .bind(vault_id)
            .bind(path)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Stream all files in the default single-tenant vault.
    pub async fn list_all_files(&self) -> Result<Vec<FileMeta>, MetaDbError> {
        self.list_files_scoped(None, VAULT_DEFAULT).await
    }

    /// Scoped list (DISK-0017).
    pub async fn list_files_scoped(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
    ) -> Result<Vec<FileMeta>, MetaDbError> {
        let rows = sqlx::query(
            r#"
            SELECT path, content_hash, size, mtime_ns, inode, vector_clock, deleted, deleted_at,
                   encryption_nonce
            FROM files
            WHERE tenant_id IS ?1 AND vault_id = ?2
            ORDER BY path ASC
            "#,
        )
        .bind(tenant_id)
        .bind(vault_id)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FileMeta;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn sample(path: &str) -> FileMeta {
        FileMeta {
            path: PathBuf::from(path),
            content_hash: [1u8; 32],
            size: 10,
            mtime_ns: 1,
            inode: None,
            vector_clock: VectorClock::new(),
            deleted: false,
            deleted_at: None,
            node_id: "n".into(),
            encryption_nonce: None,
        }
    }

    #[tokio::test]
    async fn tenant_scoped_paths_are_isolated() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("scoped.sqlite"))
            .await
            .unwrap();

        db.upsert_file_scoped(Some("acme"), "default", &sample("a.md"))
            .await
            .unwrap();
        let mut beta_meta = sample("a.md");
        beta_meta.content_hash = [2u8; 32];
        db.upsert_file_scoped(Some("beta"), "default", &beta_meta)
            .await
            .unwrap();

        let acme = db
            .get_file_scoped(Some("acme"), "default", "a.md")
            .await
            .unwrap()
            .unwrap();
        let beta = db
            .get_file_scoped(Some("beta"), "default", "a.md")
            .await
            .unwrap()
            .unwrap();
        assert_ne!(acme.content_hash, beta.content_hash);
    }
}
