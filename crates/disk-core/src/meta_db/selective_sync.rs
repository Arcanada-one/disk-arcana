//! Per-device selective sync include rules (DISK-0023).

use super::MetaDb;
use crate::error::MetaDbError;
use crate::selective_sync::normalize_include_prefix;

impl MetaDb {
    /// List folder prefixes included for a device+vault. Empty = sync all.
    pub async fn list_device_sync_includes(
        &self,
        tenant_id: Option<&str>,
        user_id: &str,
        node_id: &str,
        vault_id: &str,
    ) -> Result<Vec<String>, MetaDbError> {
        let rows = sqlx::query_scalar::<_, String>(
            r#"
            SELECT path_prefix
            FROM device_sync_includes
            WHERE tenant_id IS ?1
              AND user_id = ?2
              AND node_id = ?3
              AND vault_id = ?4
            ORDER BY path_prefix ASC
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(node_id)
        .bind(vault_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Folder include prefixes for a device+vault (any owning user).
    ///
    /// Used by gRPC sync enforcement when only `node_id` is known from the session.
    pub async fn list_node_sync_includes(
        &self,
        tenant_id: Option<&str>,
        node_id: &str,
        vault_id: &str,
    ) -> Result<Vec<String>, MetaDbError> {
        let rows = sqlx::query_scalar::<_, String>(
            r#"
            SELECT DISTINCT path_prefix
            FROM device_sync_includes
            WHERE tenant_id IS ?1
              AND node_id = ?2
              AND vault_id = ?3
            ORDER BY path_prefix ASC
            "#,
        )
        .bind(tenant_id)
        .bind(node_id)
        .bind(vault_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Replace include rules for a device+vault (transactional delete + insert).
    pub async fn replace_device_sync_includes(
        &self,
        tenant_id: Option<&str>,
        user_id: &str,
        node_id: &str,
        vault_id: &str,
        raw_prefixes: &[String],
    ) -> Result<Vec<String>, MetaDbError> {
        let mut normalized = Vec::with_capacity(raw_prefixes.len());
        for raw in raw_prefixes {
            let prefix = normalize_include_prefix(raw).map_err(MetaDbError::Invalid)?;
            if !normalized.iter().any(|p: &String| p == &prefix) {
                normalized.push(prefix);
            }
        }
        normalized.sort();

        let mut tx = self.pool.begin().await?;
        sqlx::query(
            r#"
            DELETE FROM device_sync_includes
            WHERE tenant_id IS ?1
              AND user_id = ?2
              AND node_id = ?3
              AND vault_id = ?4
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(node_id)
        .bind(vault_id)
        .execute(&mut *tx)
        .await?;

        let now = unix_now();
        for prefix in &normalized {
            sqlx::query(
                r#"
                INSERT INTO device_sync_includes (
                    tenant_id, user_id, node_id, vault_id, path_prefix, created_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                "#,
            )
            .bind(tenant_id)
            .bind(user_id)
            .bind(node_id)
            .bind(vault_id)
            .bind(prefix)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(normalized)
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

    async fn user(db: &MetaDb, id: &str, tenant: &str) {
        let email = format!("{id}@example.com");
        let hash = crate::hash_password("long-password").unwrap();
        db.create_user_account(id, &email, &hash, tenant)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn replace_and_list_device_includes() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("selective.sqlite"))
            .await
            .unwrap();
        user(&db, "u1", "corp").await;

        let includes = db
            .replace_device_sync_includes(
                Some("corp"),
                "u1",
                "macbook",
                "default",
                &["/docs/".into(), "photos".into()],
            )
            .await
            .unwrap();
        assert_eq!(includes, vec!["docs".to_string(), "photos".to_string()]);

        let listed = db
            .list_device_sync_includes(Some("corp"), "u1", "macbook", "default")
            .await
            .unwrap();
        assert_eq!(listed, includes);

        let cleared = db
            .replace_device_sync_includes(Some("corp"), "u1", "macbook", "default", &[])
            .await
            .unwrap();
        assert!(cleared.is_empty());
        assert!(db
            .list_device_sync_includes(Some("corp"), "u1", "macbook", "default")
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn list_node_sync_includes_ignores_user_id() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("node-includes.sqlite"))
            .await
            .unwrap();
        user(&db, "u1", "corp").await;
        user(&db, "u2", "corp").await;
        db.replace_device_sync_includes(Some("corp"), "u1", "n1", "wiki", &["docs".into()])
            .await
            .unwrap();
        db.replace_device_sync_includes(Some("corp"), "u2", "n1", "wiki", &["photos".into()])
            .await
            .unwrap();
        let rows = db
            .list_node_sync_includes(Some("corp"), "n1", "wiki")
            .await
            .unwrap();
        assert_eq!(rows, vec!["docs".to_string(), "photos".to_string()]);
    }
}
