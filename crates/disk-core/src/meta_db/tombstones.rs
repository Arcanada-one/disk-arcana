//! `tombstones` table CRUD.

use sqlx::Row;

use super::MetaDb;
use crate::error::MetaDbError;
use crate::tombstone::Tombstone;

const VAULT_DEFAULT: &str = "default";

impl MetaDb {
    /// Insert (or replace) a tombstone keyed by `(vault_id, path)`.
    pub async fn create_tombstone(&self, t: &Tombstone) -> Result<(), MetaDbError> {
        let now = unix_now();
        sqlx::query(
            r#"
            INSERT INTO tombstones (
                tenant_id, vault_id, path, last_hash, deleted_by,
                deleted_at, ttl_expires, propagated, created_at
            ) VALUES (NULL, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
        )
        .bind(VAULT_DEFAULT)
        .bind(&t.path)
        .bind(t.last_hash.to_vec())
        .bind(&t.deleted_by)
        .bind(t.deleted_at)
        .bind(t.ttl_expires)
        .bind(if t.propagated { 1i32 } else { 0 })
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Fetch a tombstone by path (most recent if duplicates exist).
    pub async fn get_tombstone(&self, path: &str) -> Result<Option<Tombstone>, MetaDbError> {
        let row = sqlx::query(
            r#"
            SELECT path, last_hash, deleted_by, deleted_at, ttl_expires, propagated
            FROM tombstones
            WHERE vault_id = ?1 AND path = ?2
            ORDER BY created_at DESC LIMIT 1
            "#,
        )
        .bind(VAULT_DEFAULT)
        .bind(path)
        .fetch_optional(&self.pool)
        .await?;

        row.map(row_to_tombstone).transpose()
    }

    /// Return tombstones whose TTL has not yet expired (`ttl_expires > now`).
    pub async fn list_active_tombstones(&self, now: i64) -> Result<Vec<Tombstone>, MetaDbError> {
        let rows = sqlx::query(
            r#"
            SELECT path, last_hash, deleted_by, deleted_at, ttl_expires, propagated
            FROM tombstones
            WHERE vault_id = ?1 AND ttl_expires > ?2
            ORDER BY path ASC
            "#,
        )
        .bind(VAULT_DEFAULT)
        .bind(now)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_tombstone).collect()
    }

    /// Remove a tombstone (e.g. after server-confirmed propagation).
    pub async fn delete_tombstone(&self, path: &str) -> Result<(), MetaDbError> {
        sqlx::query("DELETE FROM tombstones WHERE vault_id = ?1 AND path = ?2")
            .bind(VAULT_DEFAULT)
            .bind(path)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

fn row_to_tombstone(row: sqlx::sqlite::SqliteRow) -> Result<Tombstone, MetaDbError> {
    let path: String = row.try_get("path")?;
    let blob: Vec<u8> = row.try_get("last_hash")?;
    let deleted_by: String = row.try_get("deleted_by")?;
    let deleted_at: i64 = row.try_get("deleted_at")?;
    let ttl_expires: i64 = row.try_get("ttl_expires")?;
    let propagated_int: i64 = row.try_get("propagated")?;

    if blob.len() != 32 {
        return Err(MetaDbError::Invalid(format!(
            "last_hash length = {}, expected 32",
            blob.len()
        )));
    }
    let mut last_hash = [0u8; 32];
    last_hash.copy_from_slice(&blob);

    Ok(Tombstone {
        path,
        last_hash,
        deleted_by,
        deleted_at,
        ttl_expires,
        propagated: propagated_int != 0,
    })
}

fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
