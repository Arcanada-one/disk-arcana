//! Per-user onboarding checklist persistence (DISK-0025 slice 3).

use super::MetaDb;
use crate::error::MetaDbError;

/// Persisted onboarding UI state for a user account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserOnboardingState {
    pub dismissed: bool,
    pub dismissed_at: Option<i64>,
    pub updated_at: i64,
}

impl MetaDb {
    /// Load onboarding state. Missing row = not dismissed.
    pub async fn get_user_onboarding(
        &self,
        user_id: &str,
    ) -> Result<UserOnboardingState, MetaDbError> {
        let row = sqlx::query_as::<_, (i64, Option<i64>, i64)>(
            r#"
            SELECT dismissed, dismissed_at, updated_at
            FROM user_onboarding
            WHERE user_id = ?1
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(match row {
            Some((dismissed, dismissed_at, updated_at)) => UserOnboardingState {
                dismissed: dismissed != 0,
                dismissed_at,
                updated_at,
            },
            None => UserOnboardingState {
                dismissed: false,
                dismissed_at: None,
                updated_at: 0,
            },
        })
    }

    /// Upsert whether the getting-started checklist is dismissed.
    pub async fn upsert_user_onboarding_dismissed(
        &self,
        user_id: &str,
        dismissed: bool,
    ) -> Result<UserOnboardingState, MetaDbError> {
        let now = unix_now_secs();
        let dismissed_i = i64::from(dismissed);
        let dismissed_at = if dismissed { Some(now) } else { None };

        sqlx::query(
            r#"
            INSERT INTO user_onboarding (user_id, dismissed, dismissed_at, updated_at)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(user_id) DO UPDATE SET
                dismissed = excluded.dismissed,
                dismissed_at = excluded.dismissed_at,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(user_id)
        .bind(dismissed_i)
        .bind(dismissed_at)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(UserOnboardingState {
            dismissed,
            dismissed_at,
            updated_at: now,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempfile::tempdir;

    fn unix_now_secs() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    #[tokio::test]
    async fn onboarding_defaults_not_dismissed() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("onboarding.sqlite"))
            .await
            .unwrap();

        let state = db.get_user_onboarding("usr1").await.unwrap();
        assert!(!state.dismissed);
        assert!(state.dismissed_at.is_none());
    }

    #[tokio::test]
    async fn onboarding_dismiss_persists_and_clears() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("onboarding2.sqlite"))
            .await
            .unwrap();

        let dismissed = db
            .upsert_user_onboarding_dismissed("usr1", true)
            .await
            .unwrap();
        assert!(dismissed.dismissed);
        assert!(dismissed.dismissed_at.is_some());

        let loaded = db.get_user_onboarding("usr1").await.unwrap();
        assert!(loaded.dismissed);

        let cleared = db
            .upsert_user_onboarding_dismissed("usr1", false)
            .await
            .unwrap();
        assert!(!cleared.dismissed);
        assert!(cleared.dismissed_at.is_none());
    }
}

fn unix_now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
