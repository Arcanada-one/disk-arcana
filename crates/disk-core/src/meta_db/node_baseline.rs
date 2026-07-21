//! `node_baselines` table CRUD.
//!
//! Stores per-client last-synced snapshots so the reconciler receives a real
//! `indexed` argument rather than an empty slice. One row per
//! `(node_id, vault_id, path)` — upserted after every successful sync pass.

use std::path::PathBuf;

use sqlx::Row;

use super::MetaDb;
use crate::error::MetaDbError;
use crate::types::FileMeta;
use crate::vector_clock::VectorClock;

impl MetaDb {
    /// Load all baseline entries for a `(node_id, vault_id)` pair.
    pub async fn load_node_baseline(
        &self,
        node_id: &str,
        vault_id: &str,
    ) -> Result<Vec<FileMeta>, MetaDbError> {
        let rows = sqlx::query(
            r#"
            SELECT path, content_hash, size, mtime_ns, vector_clock,
                   deleted, deleted_at, node_id_writer
            FROM node_baselines
            WHERE node_id = ?1 AND vault_id = ?2
            ORDER BY path ASC
            "#,
        )
        .bind(node_id)
        .bind(vault_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(baseline_row_to_meta).collect()
    }

    /// Upsert baseline entries inside a single transaction.
    ///
    /// Existing rows with matching `(node_id, vault_id, path)` are replaced.
    /// `content_hash` is stored as NULL for tombstone entries (`deleted=true`)
    /// where the hash is meaningless — though callers may still pass a hash.
    pub async fn upsert_node_baselines(
        &self,
        node_id: &str,
        vault_id: &str,
        baselines: &[FileMeta],
    ) -> Result<(), MetaDbError> {
        let mut tx = self.pool.begin().await?;
        let now = unix_now();

        for meta in baselines {
            let path_str = meta
                .path
                .to_str()
                .ok_or_else(|| MetaDbError::Invalid("path contains non-UTF-8 bytes".into()))?;
            let vc_json = serde_json::to_string(&meta.vector_clock)?;
            let deleted_int = if meta.deleted { 1i64 } else { 0i64 };

            // content_hash: store the actual hash bytes (even for tombstones).
            // The PRIMARY KEY is all-NOT-NULL, so standard SQLite UPSERT is safe here
            // (unlike the files table which has a nullable tenant_id in its UNIQUE index).
            sqlx::query(
                r#"
                INSERT INTO node_baselines (
                    node_id, vault_id, path, content_hash, size, mtime_ns,
                    vector_clock, deleted, deleted_at, node_id_writer, updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                ON CONFLICT(node_id, vault_id, path) DO UPDATE SET
                    content_hash   = excluded.content_hash,
                    size           = excluded.size,
                    mtime_ns       = excluded.mtime_ns,
                    vector_clock   = excluded.vector_clock,
                    deleted        = excluded.deleted,
                    deleted_at     = excluded.deleted_at,
                    node_id_writer = excluded.node_id_writer,
                    updated_at     = excluded.updated_at
                "#,
            )
            .bind(node_id)
            .bind(vault_id)
            .bind(path_str)
            .bind(meta.content_hash.to_vec())
            .bind(meta.size as i64)
            .bind(meta.mtime_ns)
            .bind(vc_json)
            .bind(deleted_int)
            .bind(meta.deleted_at)
            .bind(&meta.node_id)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    /// Delete a single baseline row for `(node_id, vault_id, path)`.
    pub async fn delete_node_baseline(
        &self,
        node_id: &str,
        vault_id: &str,
        path: &str,
    ) -> Result<(), MetaDbError> {
        sqlx::query(
            "DELETE FROM node_baselines WHERE node_id = ?1 AND vault_id = ?2 AND path = ?3",
        )
        .bind(node_id)
        .bind(vault_id)
        .bind(path)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

fn baseline_row_to_meta(row: sqlx::sqlite::SqliteRow) -> Result<FileMeta, MetaDbError> {
    let path: String = row.try_get("path")?;
    let content_hash_blob: Vec<u8> = row.try_get("content_hash")?;
    let size: i64 = row.try_get("size")?;
    let mtime_ns: i64 = row.try_get("mtime_ns")?;
    let vector_clock_json: String = row.try_get("vector_clock")?;
    let deleted_int: i64 = row.try_get("deleted")?;
    let deleted_at: Option<i64> = row.try_get("deleted_at")?;
    let node_id_writer: String = row.try_get("node_id_writer")?;

    if content_hash_blob.len() != 32 {
        return Err(MetaDbError::Invalid(format!(
            "node_baseline content_hash length = {}, expected 32",
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
        inode: None,
        vector_clock,
        deleted: deleted_int != 0,
        deleted_at,
        node_id: node_id_writer,
        encryption_nonce: None,
    })
}

fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
