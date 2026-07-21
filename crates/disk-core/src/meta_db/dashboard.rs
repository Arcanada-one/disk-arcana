//! Tenant-scoped dashboard queries (DISK-0019).

use sqlx::Row;

use super::MetaDb;
use crate::error::MetaDbError;
use crate::types::ConflictRecord;

/// Registered vault/share for a tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantVaultRow {
    pub vault_id: String,
    pub created_at: i64,
}

/// Registered sync node (device) for a tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantNodeRow {
    pub node_id: String,
    pub display_name: Option<String>,
    pub platform: Option<String>,
    pub registered_at: i64,
    pub last_seen: Option<i64>,
}

impl MetaDb {
    /// List vaults registered for a tenant.
    pub async fn list_tenant_vaults(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<TenantVaultRow>, MetaDbError> {
        let rows = sqlx::query(
            r#"
            SELECT vault_id, created_at
            FROM tenant_vaults
            WHERE tenant_id IS ?1
            ORDER BY created_at ASC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                Ok(TenantVaultRow {
                    vault_id: row.try_get("vault_id")?,
                    created_at: row.try_get("created_at")?,
                })
            })
            .collect()
    }

    /// Count active (non-revoked) nodes for a tenant.
    pub async fn count_tenant_nodes(&self, tenant_id: Option<&str>) -> Result<u32, MetaDbError> {
        let row = sqlx::query(
            r#"
            SELECT COUNT(*) AS cnt
            FROM nodes
            WHERE tenant_id IS ?1 AND revoked = 0
            "#,
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;
        let cnt: i64 = row.get("cnt");
        Ok(cnt.max(0) as u32)
    }

    /// List active nodes for a tenant.
    pub async fn list_tenant_nodes(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<TenantNodeRow>, MetaDbError> {
        let rows = sqlx::query(
            r#"
            SELECT node_id, display_name, platform, registered_at, last_seen
            FROM nodes
            WHERE tenant_id IS ?1 AND revoked = 0
            ORDER BY registered_at ASC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                Ok(TenantNodeRow {
                    node_id: row.try_get("node_id")?,
                    display_name: row.try_get("display_name")?,
                    platform: row.try_get("platform")?,
                    registered_at: row.try_get("registered_at")?,
                    last_seen: row.try_get("last_seen")?,
                })
            })
            .collect()
    }

    /// Unresolved conflicts for a tenant.
    pub async fn list_unresolved_conflicts_for_tenant(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<ConflictRecord>, MetaDbError> {
        let rows = sqlx::query(
            r#"
            SELECT id, vault_id, path, conflict_type, local_hash, remote_hash, base_hash,
                   resolution, fork_path, resolved, created_at, resolved_at
            FROM conflicts
            WHERE resolved = 0 AND tenant_id IS ?1
            ORDER BY created_at ASC
            "#,
        )
        .bind(tenant_id)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ConflictRecord;

    #[tokio::test]
    async fn dashboard_queries_scoped_by_tenant() {
        let dir = tempfile::tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("dash.sqlite")).await.unwrap();

        db.register_tenant_vault(Some("acme"), "wiki")
            .await
            .unwrap();
        db.register_tenant_vault(Some("beta"), "docs")
            .await
            .unwrap();

        let hash = [1u8; 32];
        db.upsert_node_tenant("n1", Some("acme"), &hash, "Mac", "darwin")
            .await
            .unwrap();
        db.upsert_node_tenant("n2", Some("beta"), &hash, "Linux", "linux")
            .await
            .unwrap();

        let mut conflict = ConflictRecord {
            id: None,
            vault_id: "wiki".into(),
            path: "a.md".into(),
            conflict_type: "Concurrent".into(),
            local_hash: None,
            remote_hash: None,
            base_hash: None,
            resolution: None,
            fork_path: None,
            resolved: false,
            created_at: 0,
            resolved_at: None,
        };
        db.create_conflict_scoped(Some("acme"), &conflict)
            .await
            .unwrap();
        conflict.path = "b.md".into();
        db.create_conflict_scoped(Some("beta"), &conflict)
            .await
            .unwrap();

        let vaults = db.list_tenant_vaults(Some("acme")).await.unwrap();
        assert_eq!(vaults.len(), 1);
        assert_eq!(vaults[0].vault_id, "wiki");

        assert_eq!(db.count_tenant_nodes(Some("acme")).await.unwrap(), 1);
        let nodes = db.list_tenant_nodes(Some("acme")).await.unwrap();
        assert_eq!(nodes[0].node_id, "n1");

        let conflicts = db
            .list_unresolved_conflicts_for_tenant(Some("acme"))
            .await
            .unwrap();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].path, "a.md");
    }
}
