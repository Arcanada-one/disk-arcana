//! `nodes` table tenant wiring (DISK-0017).

use sqlx::Row;

use super::MetaDb;
use crate::error::MetaDbError;

/// Active node row needed to hydrate in-memory [`AuthStore`](crate) peers.
///
/// Loaded at `disk-arcana-server` boot so `Authenticate` survives process
/// restarts without forcing every client to re-`RegisterNode`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthNodeRow {
    pub node_id: String,
    pub display_name: String,
    pub platform: String,
    pub api_key_hash: [u8; 32],
    pub registered_at: i64,
    pub tenant_id: Option<String>,
}

impl MetaDb {
    /// List non-revoked nodes with auth material for AuthStore hydration.
    pub async fn list_active_auth_nodes(&self) -> Result<Vec<AuthNodeRow>, MetaDbError> {
        let rows = sqlx::query(
            r#"
            SELECT node_id, display_name, platform, api_key_hash, registered_at, tenant_id
            FROM nodes
            WHERE revoked = 0
            ORDER BY registered_at ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                let hash_bytes: Vec<u8> = row.try_get("api_key_hash")?;
                let mut api_key_hash = [0u8; 32];
                if hash_bytes.len() != 32 {
                    return Err(MetaDbError::Invalid(format!(
                        "node api_key_hash length {} (want 32)",
                        hash_bytes.len()
                    )));
                }
                api_key_hash.copy_from_slice(&hash_bytes);
                let display_name: Option<String> = row.try_get("display_name")?;
                let platform: Option<String> = row.try_get("platform")?;
                let tenant_id: Option<String> = row.try_get("tenant_id")?;
                Ok(AuthNodeRow {
                    node_id: row.try_get("node_id")?,
                    display_name: display_name.unwrap_or_default(),
                    platform: platform.unwrap_or_default(),
                    api_key_hash,
                    registered_at: row.try_get("registered_at")?,
                    tenant_id: tenant_id.filter(|s| !s.is_empty()),
                })
            })
            .collect()
    }

    /// Persist or update `tenant_id` for a registered node.
    pub async fn upsert_node_tenant(
        &self,
        node_id: &str,
        tenant_id: Option<&str>,
        api_key_hash: &[u8; 32],
        display_name: &str,
        platform: &str,
    ) -> Result<(), MetaDbError> {
        let now = unix_now();
        let updated = sqlx::query(
            r#"
            UPDATE nodes
            SET tenant_id = ?1,
                api_key_hash = ?2,
                display_name = ?3,
                platform = ?4
            WHERE node_id = ?5
            "#,
        )
        .bind(tenant_id)
        .bind(api_key_hash.as_slice())
        .bind(display_name)
        .bind(platform)
        .bind(node_id)
        .execute(&self.pool)
        .await?;

        if updated.rows_affected() > 0 {
            return Ok(());
        }

        sqlx::query(
            r#"
            INSERT INTO nodes (
                tenant_id, node_id, display_name, platform, api_key_hash, registered_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
        )
        .bind(tenant_id)
        .bind(node_id)
        .bind(display_name)
        .bind(platform)
        .bind(api_key_hash.as_slice())
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Lookup tenant bound to a node (if persisted).
    pub async fn get_node_tenant(&self, node_id: &str) -> Result<Option<String>, MetaDbError> {
        let row = sqlx::query(
            r#"
            SELECT tenant_id FROM nodes WHERE node_id = ?1
            "#,
        )
        .bind(node_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => {
                let tid: Option<String> = r.get("tenant_id");
                Ok(tid.filter(|s| !s.is_empty()))
            }
            None => Ok(None),
        }
    }
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
    use tempfile::tempdir;

    #[tokio::test]
    async fn node_tenant_round_trip() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("nodes.sqlite"))
            .await
            .unwrap();
        let hash = [7u8; 32];
        db.upsert_node_tenant("n1", Some("acme"), &hash, "N1", "linux")
            .await
            .unwrap();
        assert_eq!(
            db.get_node_tenant("n1").await.unwrap().as_deref(),
            Some("acme")
        );
    }

    #[tokio::test]
    async fn list_active_auth_nodes_returns_hash() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("nodes.sqlite"))
            .await
            .unwrap();
        let hash = [9u8; 32];
        db.upsert_node_tenant("mac-operator", None, &hash, "Mac", "darwin")
            .await
            .unwrap();
        let rows = db.list_active_auth_nodes().await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].node_id, "mac-operator");
        assert_eq!(rows[0].api_key_hash, hash);
        assert_eq!(rows[0].display_name, "Mac");
        assert_eq!(rows[0].platform, "darwin");
        assert!(rows[0].tenant_id.is_none());
    }
}
