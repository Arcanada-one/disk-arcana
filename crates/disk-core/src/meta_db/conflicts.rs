//! `conflicts` table CRUD.

use sqlx::Row;

use super::MetaDb;
use crate::error::MetaDbError;
use crate::types::ConflictRecord;

/// Default TTL for resolved conflicts: 30 days in seconds.
///
/// Pass to [`MetaDb::cleanup_resolved_conflicts`] from the daemon's periodic
/// maintenance loop to prune old resolved rows.
pub const DEFAULT_CONFLICT_TTL_SECS: i64 = 30 * 24 * 3600;

impl MetaDb {
    /// Insert a new conflict row; returns the freshly-assigned `id` (legacy single-tenant).
    pub async fn create_conflict(&self, c: &ConflictRecord) -> Result<i64, MetaDbError> {
        self.create_conflict_scoped(None, c).await
    }

    /// Tenant-scoped conflict insert (DISK-0017 slice 3).
    pub async fn create_conflict_scoped(
        &self,
        tenant_id: Option<&str>,
        c: &ConflictRecord,
    ) -> Result<i64, MetaDbError> {
        let now = unix_now();
        let row = sqlx::query(
            r#"
            INSERT INTO conflicts (
                tenant_id, vault_id, path, conflict_type, local_hash,
                remote_hash, base_hash, resolution, fork_path, resolved,
                created_at, resolved_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            RETURNING id
            "#,
        )
        .bind(tenant_id)
        .bind(&c.vault_id)
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
            SELECT id, vault_id, path, conflict_type, local_hash, remote_hash, base_hash,
                   resolution, fork_path, resolved, created_at, resolved_at
            FROM conflicts
            WHERE resolved = 0
            ORDER BY created_at ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_conflict).collect()
    }

    /// Mark a conflict as resolved and record the resolution string.
    ///
    /// Sets `resolved = 1`, `resolution = resolution`, and `resolved_at = now()`
    /// for the row with `id`. The row disappears from `list_unresolved_conflicts`
    /// after this call.
    pub async fn resolve_conflict(&self, id: i64, resolution: &str) -> Result<(), MetaDbError> {
        let now = unix_now();
        sqlx::query(
            r#"
            UPDATE conflicts
               SET resolved = 1,
                   resolution = ?1,
                   resolved_at = ?2
             WHERE id = ?3
            "#,
        )
        .bind(resolution)
        .bind(now)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Delete resolved conflicts whose `resolved_at` timestamp is older than
    /// `ttl_secs` seconds ago.
    ///
    /// Returns the number of rows deleted.  Unresolved conflicts are never
    /// touched.  Pass [`DEFAULT_CONFLICT_TTL_SECS`] for the 30-day default.
    pub async fn cleanup_resolved_conflicts(&self, ttl_secs: i64) -> Result<u64, MetaDbError> {
        let cutoff = unix_now() - ttl_secs;
        let result = sqlx::query(
            r#"
            DELETE FROM conflicts
             WHERE resolved = 1
               AND resolved_at IS NOT NULL
               AND resolved_at <= ?1
            "#,
        )
        .bind(cutoff)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
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
        vault_id: row.try_get("vault_id")?,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ConflictRecord;

    async fn open_temp_db() -> (MetaDb, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("meta.db");
        let db = MetaDb::open(&db_path).await.unwrap();
        (db, dir)
    }

    fn sample_record(path: &str) -> ConflictRecord {
        ConflictRecord {
            id: None,
            vault_id: "default".into(),
            path: path.into(),
            conflict_type: "Concurrent".into(),
            local_hash: None,
            remote_hash: None,
            base_hash: None,
            resolution: None,
            fork_path: Some(format!("{path}.sync-conflict-abc12345-20260101-120000")),
            resolved: false,
            created_at: 0,
            resolved_at: None,
        }
    }

    /// create_conflict → list_unresolved_conflicts returns the row.
    #[tokio::test]
    async fn conflicts_lifecycle_create_and_list() {
        let (db, _dir) = open_temp_db().await;
        let rec = sample_record("notes/todo.md");
        let id = db.create_conflict(&rec).await.unwrap();
        assert!(id > 0, "id must be positive");

        let list = db.list_unresolved_conflicts().await.unwrap();
        assert_eq!(list.len(), 1, "one unresolved conflict expected");
        assert_eq!(list[0].path, "notes/todo.md");
        assert!(!list[0].resolved);
    }

    #[tokio::test]
    async fn conflicts_preserve_vault_identity_for_same_path() {
        let (db, _dir) = open_temp_db().await;
        let mut wiki = sample_record("notes/todo.md");
        wiki.vault_id = "wiki".into();
        let mut docs = sample_record("notes/todo.md");
        docs.vault_id = "docs".into();

        db.create_conflict(&wiki).await.unwrap();
        db.create_conflict(&docs).await.unwrap();

        let rows = db.list_unresolved_conflicts().await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].vault_id, "wiki");
        assert_eq!(rows[1].vault_id, "docs");
        assert_eq!(rows[0].path, rows[1].path);
    }

    /// resolve_conflict → row disappears from list_unresolved_conflicts.
    #[tokio::test]
    async fn conflicts_lifecycle_resolve_removes_from_list() {
        let (db, _dir) = open_temp_db().await;
        let rec = sample_record("docs/readme.md");
        let id = db.create_conflict(&rec).await.unwrap();

        // Before resolve: appears in list.
        let before = db.list_unresolved_conflicts().await.unwrap();
        assert_eq!(before.len(), 1);

        db.resolve_conflict(id, "keep-local").await.unwrap();

        // After resolve: gone from list.
        let after = db.list_unresolved_conflicts().await.unwrap();
        assert!(
            after.is_empty(),
            "resolved conflict must not appear in unresolved list"
        );
    }

    /// cleanup_resolved_conflicts deletes only resolved rows older than TTL.
    #[tokio::test]
    async fn conflicts_lifecycle_cleanup_ttl() {
        let (db, _dir) = open_temp_db().await;

        // Insert and immediately resolve a conflict.
        let rec = sample_record("file.txt");
        let id = db.create_conflict(&rec).await.unwrap();
        db.resolve_conflict(id, "fork-local").await.unwrap();

        // Insert an unresolved conflict — must NOT be cleaned up.
        let unrec = sample_record("other.txt");
        db.create_conflict(&unrec).await.unwrap();

        // Cleanup with TTL = 0 (everything resolved is "old enough").
        let deleted = db.cleanup_resolved_conflicts(0).await.unwrap();
        assert_eq!(deleted, 1, "exactly one resolved row should be deleted");

        // The unresolved conflict must still be there.
        let remaining = db.list_unresolved_conflicts().await.unwrap();
        assert_eq!(remaining.len(), 1, "unresolved must survive cleanup");

        // Cleanup with a large TTL (far in the future) — nothing matches.
        let deleted2 = db.cleanup_resolved_conflicts(i64::MAX).await.unwrap();
        assert_eq!(deleted2, 0, "large TTL should delete nothing");
    }
}
