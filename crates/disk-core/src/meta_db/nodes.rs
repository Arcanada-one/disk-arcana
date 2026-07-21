//! `nodes` table tenant wiring (DISK-0017).

use sqlx::Row;

use super::MetaDb;
use crate::error::MetaDbError;

impl MetaDb {
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
}
