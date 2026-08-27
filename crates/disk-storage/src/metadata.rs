use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};

use crate::{ObjectMetadata, StorageError};

const MIGRATION_SQL: &str = include_str!("../migrations/001_storage_metadata.sql");

#[derive(Debug, Clone)]
pub struct MetadataStoreConfig {
    pub db_path: PathBuf,
}

/// SQLite metadata store for company-drive objects.
#[derive(Debug, Clone)]
pub struct MetadataStore {
    pool: SqlitePool,
}

impl MetadataStore {
    pub async fn open(config: MetadataStoreConfig) -> Result<Self, StorageError> {
        if let Some(parent) = config.db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let opts = SqliteConnectOptions::new()
            .filename(&config.db_path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(opts)
            .await?;
        sqlx::raw_sql(MIGRATION_SQL).execute(&pool).await?;
        Ok(Self { pool })
    }

    pub async fn open_in_memory() -> Result<Self, StorageError> {
        let opts = SqliteConnectOptions::new()
            .filename(":memory:")
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await?;
        sqlx::raw_sql(MIGRATION_SQL).execute(&pool).await?;
        Ok(Self { pool })
    }

    pub(crate) fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn upsert(
        &self,
        meta: &ObjectMetadata,
        lifecycle: &crate::ObjectLifecyclePolicy,
    ) -> Result<(), StorageError> {
        let tags =
            serde_json::to_string(&meta.tags).map_err(|e| StorageError::Metadata(e.to_string()))?;
        let lifecycle_json =
            serde_json::to_string(lifecycle).map_err(|e| StorageError::Metadata(e.to_string()))?;
        let mtime = system_time_to_i64(meta.mtime)?;
        let created = system_time_to_i64(meta.created_at)?;
        sqlx::query(
            r#"
            INSERT INTO storage_objects
                (path, size, content_sha256, object_store_key, mtime_ns, created_at_ns, tags_json, lifecycle_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(path) DO UPDATE SET
                size = excluded.size,
                content_sha256 = excluded.content_sha256,
                object_store_key = excluded.object_store_key,
                mtime_ns = excluded.mtime_ns,
                tags_json = excluded.tags_json,
                lifecycle_json = excluded.lifecycle_json
            "#,
        )
        .bind(&meta.path)
        .bind(meta.size as i64)
        .bind(&meta.content_sha256)
        .bind(&meta.object_store_key)
        .bind(mtime)
        .bind(created)
        .bind(tags)
        .bind(lifecycle_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get(&self, path: &str) -> Result<Option<ObjectMetadata>, StorageError> {
        let row = sqlx::query(
            r#"SELECT path, size, content_sha256, object_store_key, mtime_ns, created_at_ns, tags_json
               FROM storage_objects WHERE path = ?"#,
        )
        .bind(path)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| row_to_metadata(&r)).transpose()
    }

    pub async fn delete(&self, path: &str) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM storage_objects WHERE path = ?")
            .bind(path)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn list_prefix(
        &self,
        prefix: Option<&str>,
        limit: u32,
    ) -> Result<Vec<ObjectMetadata>, StorageError> {
        let rows = if let Some(p) = prefix {
            sqlx::query(
                r#"SELECT path, size, content_sha256, object_store_key, mtime_ns, created_at_ns, tags_json
                   FROM storage_objects WHERE path LIKE ? || '%' ORDER BY path LIMIT ?"#,
            )
            .bind(p)
            .bind(limit as i64)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                r#"SELECT path, size, content_sha256, object_store_key, mtime_ns, created_at_ns, tags_json
                   FROM storage_objects ORDER BY path LIMIT ?"#,
            )
            .bind(limit as i64)
            .fetch_all(&self.pool)
            .await?
        };
        rows.iter().map(row_to_metadata).collect()
    }

    pub async fn rename(&self, from: &str, to: &str) -> Result<bool, StorageError> {
        let result = sqlx::query("UPDATE storage_objects SET path = ? WHERE path = ?")
            .bind(to)
            .bind(from)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn lifecycle(
        &self,
        path: &str,
    ) -> Result<Option<crate::ObjectLifecyclePolicy>, StorageError> {
        let row = sqlx::query("SELECT lifecycle_json FROM storage_objects WHERE path = ?")
            .bind(path)
            .fetch_optional(&self.pool)
            .await?;
        if let Some(r) = row {
            let json: String = r.get("lifecycle_json");
            let policy: crate::ObjectLifecyclePolicy =
                serde_json::from_str(&json).map_err(|e| StorageError::Metadata(e.to_string()))?;
            return Ok(Some(policy));
        }
        Ok(None)
    }
}

fn row_to_metadata(row: &sqlx::sqlite::SqliteRow) -> Result<ObjectMetadata, StorageError> {
    let tags_json: String = row.get("tags_json");
    let tags: HashMap<String, String> =
        serde_json::from_str(&tags_json).map_err(|e| StorageError::Metadata(e.to_string()))?;
    Ok(ObjectMetadata {
        path: row.get("path"),
        size: row.get::<i64, _>("size") as u64,
        content_sha256: row.get("content_sha256"),
        object_store_key: row.get("object_store_key"),
        mtime: i64_to_system_time(row.get("mtime_ns"))?,
        created_at: i64_to_system_time(row.get("created_at_ns"))?,
        tags,
    })
}

fn system_time_to_i64(ts: SystemTime) -> Result<i64, StorageError> {
    ts.duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .map_err(|e| StorageError::Metadata(e.to_string()))
}

fn i64_to_system_time(ns: i64) -> Result<SystemTime, StorageError> {
    Ok(UNIX_EPOCH + Duration::from_nanos(ns.max(0) as u64))
}

pub fn content_sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(data);
    hex::encode(digest)
}

pub fn object_key_for(path: &str, sha256_hex: &str) -> String {
    format!("{path}@{sha256_hex}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn migration_creates_table() {
        let store = MetadataStore::open_in_memory().await.unwrap();
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM storage_objects")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(count.0, 0);
    }
}
