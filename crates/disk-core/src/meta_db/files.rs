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
    ///
    /// # Do not use from production code
    ///
    /// This wrapper silently substitutes `vault_id = "default"`. DISK-0080: one
    /// such call in the client's E2EE index writer put its rows under
    /// `"default"` while every other writer used the share name, producing TWO
    /// rows per path with different content hashes. The server then advertised
    /// metadata from one row while serving bytes matching the other; the
    /// client's hash check correctly rejected the download and retried it
    /// forever, because a hash mismatch is not transient.
    ///
    /// Call [`upsert_file_scoped`] with the real share instead. This wrapper is
    /// kept for tests that genuinely do not care which vault they write to.
    ///
    /// [`upsert_file_scoped`]: Self::upsert_file_scoped
    #[deprecated(
        note = "unscoped: writes vault_id=\"default\" and creates duplicate rows \
                for a path that any other writer scopes by share (DISK-0080). \
                Use upsert_file_scoped with the share name."
    )]
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
                   encryption_nonce, version_id, parent_version_id
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

    /// DISK-0080: the unscoped wrapper and a share-scoped write must not
    /// collide on the same path — and when they do, the duplicate is exactly
    /// the defect that broke delivery.
    ///
    /// Measured on the canon host: `.kb-last-push` had two rows, 71A1F033…
    /// under `datarim-kb` (the file's real blake3) and a stale CEFDE447… under
    /// `default`, both live. The server advertised metadata from one and served
    /// bytes matching the other, so the client's hash check rejected every
    /// download and retried forever — a hash mismatch is never transient.
    ///
    /// This pins the mechanism: same path, two vaults, two independent rows.
    /// If someone removes the `#[deprecated]` guard and a production caller
    /// reaches for `upsert_file` again, this is the shape they will recreate.
    #[tokio::test]
    async fn unscoped_and_scoped_writes_create_separate_rows_for_one_path() {
        let dir = tempfile::tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("meta.sqlite")).await.unwrap();

        let mut meta = FileMeta {
            path: PathBuf::from("notes/probe.md"),
            content_hash: [0xAA; 32],
            size: 3,
            mtime_ns: 1,
            inode: None,
            vector_clock: VectorClock::default(),
            deleted: false,
            deleted_at: None,
            node_id: "n1".into(),
            encryption_nonce: None,
            version_id: None,
            parent_version_id: None,
        };

        // The share-scoped write: what every correct writer does.
        db.upsert_file_scoped(None, "datarim-kb", &meta)
            .await
            .unwrap();

        // The unscoped write, with DIFFERENT content — the stale-hash shape.
        meta.content_hash = [0xBB; 32];
        #[allow(deprecated)]
        db.upsert_file(&meta).await.unwrap();

        let scoped = db.list_files_scoped(None, "datarim-kb").await.unwrap();
        let defaulted = db.list_files_scoped(None, VAULT_DEFAULT).await.unwrap();

        assert_eq!(scoped.len(), 1, "share-scoped row must exist on its own");
        assert_eq!(
            defaulted.len(),
            1,
            "the unscoped write lands in a SEPARATE vault, not on top of the scoped row"
        );
        assert_eq!(
            scoped[0].content_hash, [0xAA; 32],
            "the share-scoped row must keep its own hash — this divergence is what \
             made the server advertise one hash while serving bytes for another"
        );
        assert_eq!(defaulted[0].content_hash, [0xBB; 32]);
    }

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
            version_id: None,
            parent_version_id: None,
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
