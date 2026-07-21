//! GDPR erasure helpers — account deletion and tenant metadata purge (DISK-0021).

use sqlx::Row;

use super::MetaDb;
use crate::error::MetaDbError;

impl MetaDb {
    /// Count active user accounts bound to a tenant.
    pub async fn count_users_for_tenant(&self, tenant_id: &str) -> Result<u32, MetaDbError> {
        let row = sqlx::query(
            r#"
            SELECT COUNT(*) AS cnt
            FROM user_accounts
            WHERE tenant_id = ?1
            "#,
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;
        let cnt: i64 = row.get("cnt");
        Ok(cnt.max(0) as u32)
    }

    /// Delete one user account row. Returns whether a row was removed.
    pub async fn delete_user_by_id(&self, user_id: &str) -> Result<bool, MetaDbError> {
        let result = sqlx::query("DELETE FROM user_accounts WHERE id = ?1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Remove tenant-scoped sync metadata when the last account is deleted.
    ///
    /// Does not delete on-disk blob storage (future DISK-0020); metadata only.
    pub async fn purge_tenant_metadata(&self, tenant_id: &str) -> Result<(), MetaDbError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM conflicts WHERE tenant_id IS ?1")
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM node_baselines WHERE tenant_id IS ?1")
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM tombstones WHERE tenant_id IS ?1")
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM files WHERE tenant_id IS ?1")
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM nodes WHERE tenant_id IS ?1")
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM tenant_vaults WHERE tenant_id IS ?1")
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM tenant_billing WHERE tenant_id IS ?1")
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM pending_enrollments WHERE tenant_id IS ?1")
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::{hash_password, normalize_email};
    use tempfile::tempdir;

    #[tokio::test]
    async fn purge_tenant_after_last_user_deleted() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("erasure.sqlite"))
            .await
            .unwrap();

        let email = normalize_email("erase@example.com");
        let hash = hash_password("long-password").unwrap();
        db.create_user_account("usr_erase", &email, &hash, "erase-corp")
            .await
            .unwrap();
        db.register_tenant_vault(Some("erase-corp"), "wiki")
            .await
            .unwrap();

        assert_eq!(db.count_users_for_tenant("erase-corp").await.unwrap(), 1);
        assert!(db.delete_user_by_id("usr_erase").await.unwrap());
        assert_eq!(db.count_users_for_tenant("erase-corp").await.unwrap(), 0);

        db.purge_tenant_metadata("erase-corp").await.unwrap();
        let vaults = db.list_tenant_vaults(Some("erase-corp")).await.unwrap();
        assert!(vaults.is_empty());
    }
}
