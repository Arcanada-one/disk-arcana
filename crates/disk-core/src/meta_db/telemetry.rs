//! Per-user product analytics opt-in (DISK-0026 slice 1).

use super::MetaDb;
use crate::error::MetaDbError;

/// Persisted analytics preference for a user account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserTelemetryState {
    pub opt_in: bool,
    pub updated_at: i64,
}

impl MetaDb {
    /// Load analytics opt-in. Missing row = opted out.
    pub async fn get_user_telemetry(
        &self,
        user_id: &str,
    ) -> Result<UserTelemetryState, MetaDbError> {
        let row = sqlx::query_as::<_, (i64, i64)>(
            r#"
            SELECT opt_in, updated_at
            FROM user_telemetry
            WHERE user_id = ?1
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(match row {
            Some((opt_in, updated_at)) => UserTelemetryState {
                opt_in: opt_in != 0,
                updated_at,
            },
            None => UserTelemetryState {
                opt_in: false,
                updated_at: 0,
            },
        })
    }

    /// Upsert whether anonymous product analytics is enabled for this user.
    pub async fn upsert_user_telemetry_opt_in(
        &self,
        user_id: &str,
        opt_in: bool,
    ) -> Result<UserTelemetryState, MetaDbError> {
        let now = unix_now_secs();
        let opt_in_i = i64::from(opt_in);

        sqlx::query(
            r#"
            INSERT INTO user_telemetry (user_id, opt_in, updated_at)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(user_id) DO UPDATE SET
                opt_in = excluded.opt_in,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(user_id)
        .bind(opt_in_i)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(UserTelemetryState {
            opt_in,
            updated_at: now,
        })
    }

    /// Remove analytics preference for one user (account deletion).
    pub async fn delete_user_telemetry(&self, user_id: &str) -> Result<(), MetaDbError> {
        sqlx::query("DELETE FROM user_telemetry WHERE user_id = ?1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

fn unix_now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn telemetry_defaults_opted_out() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("telemetry.sqlite"))
            .await
            .unwrap();

        let state = db.get_user_telemetry("usr1").await.unwrap();
        assert!(!state.opt_in);
        assert_eq!(state.updated_at, 0);
    }

    #[tokio::test]
    async fn telemetry_opt_in_persists_and_clears() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("telemetry2.sqlite"))
            .await
            .unwrap();

        let enabled = db.upsert_user_telemetry_opt_in("usr1", true).await.unwrap();
        assert!(enabled.opt_in);
        assert!(enabled.updated_at > 0);

        let loaded = db.get_user_telemetry("usr1").await.unwrap();
        assert!(loaded.opt_in);

        let disabled = db
            .upsert_user_telemetry_opt_in("usr1", false)
            .await
            .unwrap();
        assert!(!disabled.opt_in);
    }
}
