//! `conflicts` table CRUD.

use sqlx::Row;

use super::MetaDb;
use crate::error::MetaDbError;
use crate::types::ConflictRecord;

const VAULT_DEFAULT: &str = "default";

impl MetaDb {
    /// Insert a new conflict row; returns the freshly-assigned `id`.
    pub async fn create_conflict(&self, c: &ConflictRecord) -> Result<i64, MetaDbError> {
        let now = unix_now();
        let row = sqlx::query(
            r#"
            INSERT INTO conflicts (
                tenant_id, vault_id, path, conflict_type, local_hash,
                remote_hash, base_hash, resolution, fork_path, resolved,
                created_at, resolved_at
            ) VALUES (NULL, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            RETURNING id
            "#,
        )
        .bind(VAULT_DEFAULT)
        .bind(&c.path)
        .bind(&c.conflict_type)
        .bind(c.local_hash.map(|h| h.to_vec()))
        .bind(c.remote_hash.map(|h| h.to_vec()))
        .bind(c.base_hash.map(|h| h.to_vec()))
        .bind(c.resolution.clone())
        .bind(c.fork_path.clone())
        .bind(if c.resolved { 1i32 } else { 0 })
        .bind(now)
        .bind(c.resolved_at)
        .fetch_one(&self.pool)
        .await?;
        let id: i64 = row.try_get("id")?;
        Ok(id)
    }

    /// List all unresolved conflicts (`resolved = 0`).
    pub async fn list_unresolved_conflicts(&self) -> Result<Vec<ConflictRecord>, MetaDbError> {
        let rows = sqlx::query(
            r#"
            SELECT id, path, conflict_type, local_hash, remote_hash, base_hash,
                   resolution, fork_path, resolved, created_at, resolved_at
            FROM conflicts
            WHERE vault_id = ?1 AND resolved = 0
            ORDER BY created_at ASC
            "#,
        )
        .bind(VAULT_DEFAULT)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_conflict).collect()
    }
}

fn row_to_conflict(row: sqlx::sqlite::SqliteRow) -> Result<ConflictRecord, MetaDbError> {
    fn opt_hash(blob: Option<Vec<u8>>) -> Result<Option<[u8; 32]>, MetaDbError> {
        match blob {
            None => Ok(None),
            Some(b) if b.len() == 32 => {
                let mut out = [0u8; 32];
                out.copy_from_slice(&b);
                Ok(Some(out))
            }
            Some(b) => Err(MetaDbError::Invalid(format!(
                "hash blob length = {}, expected 32",
                b.len()
            ))),
        }
    }

    let id: Option<i64> = row.try_get("id")?;
    let local_hash: Option<Vec<u8>> = row.try_get("local_hash")?;
    let remote_hash: Option<Vec<u8>> = row.try_get("remote_hash")?;
    let base_hash: Option<Vec<u8>> = row.try_get("base_hash")?;
    let resolution: Option<String> = row.try_get("resolution")?;
    let fork_path: Option<String> = row.try_get("fork_path")?;
    let resolved_int: i64 = row.try_get("resolved")?;
    let resolved_at: Option<i64> = row.try_get("resolved_at")?;

    Ok(ConflictRecord {
        id,
        vault_id: VAULT_DEFAULT.into(),
        path: row.try_get("path")?,
        conflict_type: row.try_get("conflict_type")?,
        local_hash: opt_hash(local_hash)?,
        remote_hash: opt_hash(remote_hash)?,
        base_hash: opt_hash(base_hash)?,
        resolution,
        fork_path,
        resolved: resolved_int != 0,
        created_at: row.try_get("created_at")?,
        resolved_at,
    })
}

fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
