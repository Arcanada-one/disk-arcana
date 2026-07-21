//! `tenant_billing` table CRUD and storage accounting (DISK-0018).

use sqlx::Row;

use super::MetaDb;
use crate::billing::PlanTier;
use crate::error::MetaDbError;

impl MetaDb {
    /// Resolve the plan tier for a tenant (or default single-tenant when `None`).
    pub async fn get_plan_tier(
        &self,
        tenant_id: Option<&str>,
        default: PlanTier,
    ) -> Result<PlanTier, MetaDbError> {
        let row = sqlx::query(
            r#"
            SELECT plan_tier FROM tenant_billing
            WHERE tenant_id IS ?1
            "#,
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => {
                let raw: String = r.get("plan_tier");
                PlanTier::parse(&raw).map_err(|e| MetaDbError::Invalid(e.to_string()))
            }
            None => Ok(default),
        }
    }

    /// Upsert plan tier for a tenant.
    pub async fn set_plan_tier(
        &self,
        tenant_id: Option<&str>,
        tier: PlanTier,
    ) -> Result<(), MetaDbError> {
        let now = unix_now();
        let updated = sqlx::query(
            r#"
            UPDATE tenant_billing
            SET plan_tier = ?2, updated_at = ?3
            WHERE tenant_id IS ?1
            "#,
        )
        .bind(tenant_id)
        .bind(tier.as_str())
        .bind(now)
        .execute(&self.pool)
        .await?;

        if updated.rows_affected() > 0 {
            return Ok(());
        }

        sqlx::query(
            r#"
            INSERT INTO tenant_billing (
                tenant_id, plan_tier, stripe_customer_id, stripe_subscription_id,
                created_at, updated_at
            ) VALUES (?1, ?2, NULL, NULL, ?3, ?3)
            "#,
        )
        .bind(tenant_id)
        .bind(tier.as_str())
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Apply Stripe linkage + tier from a webhook event.
    pub async fn apply_stripe_subscription(
        &self,
        tenant_id: Option<&str>,
        stripe_customer_id: &str,
        stripe_subscription_id: &str,
        tier: PlanTier,
    ) -> Result<(), MetaDbError> {
        let now = unix_now();
        let updated = sqlx::query(
            r#"
            UPDATE tenant_billing
            SET plan_tier = ?2,
                stripe_customer_id = ?3,
                stripe_subscription_id = ?4,
                updated_at = ?5
            WHERE tenant_id IS ?1
            "#,
        )
        .bind(tenant_id)
        .bind(tier.as_str())
        .bind(stripe_customer_id)
        .bind(stripe_subscription_id)
        .bind(now)
        .execute(&self.pool)
        .await?;

        if updated.rows_affected() > 0 {
            return Ok(());
        }

        sqlx::query(
            r#"
            INSERT INTO tenant_billing (
                tenant_id, plan_tier, stripe_customer_id, stripe_subscription_id,
                created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?5)
            "#,
        )
        .bind(tenant_id)
        .bind(tier.as_str())
        .bind(stripe_customer_id)
        .bind(stripe_subscription_id)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Sum `files.size` across all vaults for quota enforcement.
    pub async fn sum_storage_bytes(&self, tenant_id: Option<&str>) -> Result<u64, MetaDbError> {
        let row = sqlx::query(
            r#"
            SELECT COALESCE(SUM(size), 0) AS total
            FROM files
            WHERE tenant_id IS ?1 AND deleted = 0
            "#,
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;
        let total: i64 = row.get("total");
        Ok(total.max(0) as u64)
    }

    /// Count registered vaults for a tenant (`x-disk-share` names).
    pub async fn count_tenant_vaults(&self, tenant_id: Option<&str>) -> Result<u32, MetaDbError> {
        let row = sqlx::query(
            r#"
            SELECT COUNT(*) AS cnt FROM tenant_vaults WHERE tenant_id IS ?1
            "#,
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;
        let cnt: i64 = row.get("cnt");
        Ok(cnt.max(0) as u32)
    }

    /// Whether a vault/share is already registered for the tenant.
    pub async fn tenant_vault_exists(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
    ) -> Result<bool, MetaDbError> {
        let row = sqlx::query(
            r#"
            SELECT 1 AS ok FROM tenant_vaults
            WHERE tenant_id IS ?1 AND vault_id = ?2
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(vault_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.is_some())
    }

    /// Idempotently register a vault after a successful upload.
    pub async fn register_tenant_vault(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
    ) -> Result<(), MetaDbError> {
        let now = unix_now();
        let _ = sqlx::query(
            r#"
            INSERT OR IGNORE INTO tenant_vaults (tenant_id, vault_id, created_at)
            VALUES (?1, ?2, ?3)
            "#,
        )
        .bind(tenant_id)
        .bind(vault_id)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
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
    async fn plan_tier_round_trip() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("billing.sqlite"))
            .await
            .unwrap();
        db.set_plan_tier(None, PlanTier::Pro).await.unwrap();
        let tier = db.get_plan_tier(None, PlanTier::Free).await.unwrap();
        assert_eq!(tier, PlanTier::Pro);
    }

    #[tokio::test]
    async fn sum_storage_bytes_empty() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("billing.sqlite"))
            .await
            .unwrap();
        assert_eq!(db.sum_storage_bytes(None).await.unwrap(), 0);
    }
}
