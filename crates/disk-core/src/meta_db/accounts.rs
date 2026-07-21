//! `user_accounts` table CRUD (DISK-0016).

use sqlx::Row;

use super::MetaDb;
use crate::error::MetaDbError;

/// Persisted SaaS user row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAccount {
    pub id: String,
    pub email: String,
    pub password_hash: String,
    pub tenant_id: String,
    pub email_verified: bool,
    pub oauth_provider: Option<String>,
    pub oauth_subject: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl UserAccount {
    pub fn is_oauth_only(&self) -> bool {
        self.oauth_provider.is_some()
            && self.password_hash == crate::accounts::OAUTH_PASSWORD_SENTINEL
    }
}

/// Input for [`MetaDb::create_oauth_user_account`].
#[derive(Debug, Clone)]
pub struct NewOAuthUser {
    pub id: String,
    pub email: String,
    pub tenant_id: String,
    pub oauth_provider: String,
    pub oauth_subject: String,
    pub email_verified: bool,
}

impl MetaDb {
    /// Insert a new user account. Fails if email already exists.
    pub async fn create_user_account(
        &self,
        id: &str,
        email: &str,
        password_hash: &str,
        tenant_id: &str,
    ) -> Result<(), MetaDbError> {
        let now = unix_now();
        sqlx::query(
            r#"
            INSERT INTO user_accounts (
                id, email, password_hash, tenant_id, email_verified,
                oauth_provider, oauth_subject, created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, 0, NULL, NULL, ?5, ?5)
            "#,
        )
        .bind(id)
        .bind(email)
        .bind(password_hash)
        .bind(tenant_id)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Lookup by normalized email.
    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<UserAccount>, MetaDbError> {
        let row = sqlx::query(
            r#"
            SELECT id, email, password_hash, tenant_id, email_verified,
                   oauth_provider, oauth_subject, created_at, updated_at
            FROM user_accounts
            WHERE email = ?1
            "#,
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| map_user_row(&r)))
    }

    /// Lookup by OAuth provider + subject.
    pub async fn get_user_by_oauth(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<UserAccount>, MetaDbError> {
        let row = sqlx::query(
            r#"
            SELECT id, email, password_hash, tenant_id, email_verified,
                   oauth_provider, oauth_subject, created_at, updated_at
            FROM user_accounts
            WHERE oauth_provider = ?1 AND oauth_subject = ?2
            "#,
        )
        .bind(provider)
        .bind(subject)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| map_user_row(&r)))
    }

    /// Insert an OAuth-provisioned user account.
    pub async fn create_oauth_user_account(
        &self,
        user: &NewOAuthUser,
        password_hash: &str,
    ) -> Result<(), MetaDbError> {
        let now = unix_now();
        let verified = if user.email_verified { 1 } else { 0 };
        sqlx::query(
            r#"
            INSERT INTO user_accounts (
                id, email, password_hash, tenant_id, email_verified,
                oauth_provider, oauth_subject, created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
            "#,
        )
        .bind(&user.id)
        .bind(&user.email)
        .bind(password_hash)
        .bind(&user.tenant_id)
        .bind(verified)
        .bind(&user.oauth_provider)
        .bind(&user.oauth_subject)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Lookup by primary key.
    pub async fn get_user_by_id(&self, id: &str) -> Result<Option<UserAccount>, MetaDbError> {
        let row = sqlx::query(
            r#"
            SELECT id, email, password_hash, tenant_id, email_verified,
                   oauth_provider, oauth_subject, created_at, updated_at
            FROM user_accounts
            WHERE id = ?1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| map_user_row(&r)))
    }
}

fn map_user_row(r: &sqlx::sqlite::SqliteRow) -> UserAccount {
    UserAccount {
        id: r.get("id"),
        email: r.get("email"),
        password_hash: r.get("password_hash"),
        tenant_id: r.get("tenant_id"),
        email_verified: r.get::<i64, _>("email_verified") != 0,
        oauth_provider: r.get("oauth_provider"),
        oauth_subject: r.get("oauth_subject"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
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
    async fn user_account_round_trip() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("users.sqlite"))
            .await
            .unwrap();
        let email = normalize_email("User@Example.com");
        let hash = hash_password("long-password").unwrap();
        db.create_user_account("usr_test", &email, &hash, "acme")
            .await
            .unwrap();

        let row = db.get_user_by_email(&email).await.unwrap().unwrap();
        assert_eq!(row.id, "usr_test");
        assert_eq!(row.tenant_id, "acme");
        assert!(!row.email_verified);
    }
}
