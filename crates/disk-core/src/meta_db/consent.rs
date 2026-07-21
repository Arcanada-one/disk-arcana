//! Policy consent audit trail (DISK-0021 slice 3).

use sqlx::Row;

use super::MetaDb;
use crate::error::MetaDbError;

/// Current published policy versions (must match deploy/www/legal/* effective dates).
pub const TERMS_POLICY_VERSION: &str = "1.0";
pub const PRIVACY_POLICY_VERSION: &str = "1.0";
pub const CONSENT_TYPE_TERMS: &str = "terms_of_service";
pub const CONSENT_TYPE_PRIVACY: &str = "privacy_policy";

/// One recorded consent event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentEventRow {
    pub id: i64,
    pub user_id: String,
    pub tenant_id: String,
    pub consent_type: String,
    pub policy_version: String,
    pub recorded_at: i64,
}

impl MetaDb {
    /// Record a single consent event.
    pub async fn record_consent_event(
        &self,
        user_id: &str,
        tenant_id: &str,
        consent_type: &str,
        policy_version: &str,
    ) -> Result<(), MetaDbError> {
        let now = unix_now();
        sqlx::query(
            r#"
            INSERT INTO consent_events (user_id, tenant_id, consent_type, policy_version, recorded_at)
            VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .bind(consent_type)
        .bind(policy_version)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Record ToS + Privacy consents at signup (password or OAuth).
    pub async fn record_signup_policy_consents(
        &self,
        user_id: &str,
        tenant_id: &str,
    ) -> Result<(), MetaDbError> {
        self.record_consent_event(user_id, tenant_id, CONSENT_TYPE_TERMS, TERMS_POLICY_VERSION)
            .await?;
        self.record_consent_event(
            user_id,
            tenant_id,
            CONSENT_TYPE_PRIVACY,
            PRIVACY_POLICY_VERSION,
        )
        .await?;
        Ok(())
    }

    /// List consent events for a user, oldest first.
    pub async fn list_consent_events_for_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<ConsentEventRow>, MetaDbError> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, tenant_id, consent_type, policy_version, recorded_at
            FROM consent_events
            WHERE user_id = ?1
            ORDER BY recorded_at ASC, id ASC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                Ok(ConsentEventRow {
                    id: row.try_get("id")?,
                    user_id: row.try_get("user_id")?,
                    tenant_id: row.try_get("tenant_id")?,
                    consent_type: row.try_get("consent_type")?,
                    policy_version: row.try_get("policy_version")?,
                    recorded_at: row.try_get("recorded_at")?,
                })
            })
            .collect()
    }

    /// Remove consent rows for one user (account deletion).
    pub async fn delete_consent_events_for_user(&self, user_id: &str) -> Result<(), MetaDbError> {
        sqlx::query("DELETE FROM consent_events WHERE user_id = ?1")
            .bind(user_id)
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
    use crate::accounts::{hash_password, normalize_email};
    use tempfile::tempdir;

    #[tokio::test]
    async fn signup_policy_consents_recorded() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("consent.sqlite"))
            .await
            .unwrap();

        let email = normalize_email("consent@example.com");
        let hash = hash_password("long-password").unwrap();
        db.create_user_account("usr_c", &email, &hash, "consent-corp")
            .await
            .unwrap();
        db.record_signup_policy_consents("usr_c", "consent-corp")
            .await
            .unwrap();

        let events = db.list_consent_events_for_user("usr_c").await.unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].consent_type, CONSENT_TYPE_TERMS);
        assert_eq!(events[1].consent_type, CONSENT_TYPE_PRIVACY);
    }
}
