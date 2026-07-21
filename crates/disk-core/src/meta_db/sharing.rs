//! Vault sharing invites and collaborator RBAC (DISK-0022).

use sqlx::Row;

use super::MetaDb;
use crate::error::MetaDbError;

/// Collaborator role granted via invite (owners are implicit tenant members).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultShareRole {
    Viewer,
    Editor,
}

impl VaultShareRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Editor => "editor",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "viewer" => Some(Self::Viewer),
            "editor" => Some(Self::Editor),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultInviteRow {
    pub id: String,
    pub tenant_id: Option<String>,
    pub vault_id: String,
    pub role: VaultShareRole,
    pub created_by: String,
    pub expires_at: i64,
    pub redeemed_at: Option<i64>,
    pub redeemed_by: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultMemberRow {
    pub tenant_id: Option<String>,
    pub vault_id: String,
    pub user_id: String,
    pub email: String,
    pub role: VaultShareRole,
    pub granted_by: Option<String>,
    pub created_at: i64,
}

impl MetaDb {
    /// Lookup collaborator membership for a user on a vault owned by another tenant.
    pub async fn get_collaborator_vault_access(
        &self,
        user_id: &str,
        vault_id: &str,
    ) -> Result<Option<(Option<String>, VaultShareRole)>, MetaDbError> {
        let row = sqlx::query(
            r#"
            SELECT tenant_id, role
            FROM vault_members
            WHERE user_id = ?1 AND vault_id = ?2
            LIMIT 1
            "#,
        )
        .bind(user_id)
        .bind(vault_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };
        let tenant_id: Option<String> = row.try_get("tenant_id")?;
        let role_raw: String = row.try_get("role")?;
        let role = VaultShareRole::parse(&role_raw)
            .ok_or_else(|| MetaDbError::Invalid(format!("unknown vault share role: {role_raw}")))?;
        Ok(Some((tenant_id, role)))
    }

    /// True when the vault is registered for the tenant.
    pub async fn vault_exists_for_tenant(
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

    #[allow(clippy::too_many_arguments)]
    pub async fn insert_vault_invite(
        &self,
        id: &str,
        tenant_id: Option<&str>,
        vault_id: &str,
        token_hash: &[u8; 32],
        role: VaultShareRole,
        created_by: &str,
        expires_at: i64,
    ) -> Result<(), MetaDbError> {
        let now = unix_now();
        sqlx::query(
            r#"
            INSERT INTO vault_invites (
                id, tenant_id, vault_id, token_hash, role,
                created_by, expires_at, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(vault_id)
        .bind(token_hash.as_slice())
        .bind(role.as_str())
        .bind(created_by)
        .bind(expires_at)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_vault_invite_by_token_hash(
        &self,
        token_hash: &[u8; 32],
    ) -> Result<Option<VaultInviteRow>, MetaDbError> {
        let row = sqlx::query(
            r#"
            SELECT id, tenant_id, vault_id, role, created_by,
                   expires_at, redeemed_at, redeemed_by, created_at
            FROM vault_invites
            WHERE token_hash = ?1
            "#,
        )
        .bind(token_hash.as_slice())
        .fetch_optional(&self.pool)
        .await?;

        row.map(invite_from_row).transpose()
    }

    pub async fn list_vault_invites(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
    ) -> Result<Vec<VaultInviteRow>, MetaDbError> {
        let rows = sqlx::query(
            r#"
            SELECT id, tenant_id, vault_id, role, created_by,
                   expires_at, redeemed_at, redeemed_by, created_at
            FROM vault_invites
            WHERE tenant_id IS ?1 AND vault_id = ?2
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(vault_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(invite_from_row).collect()
    }

    pub async fn redeem_vault_invite(
        &self,
        invite_id: &str,
        redeemed_by: &str,
    ) -> Result<bool, MetaDbError> {
        let now = unix_now();
        let result = sqlx::query(
            r#"
            UPDATE vault_invites
            SET redeemed_at = ?2, redeemed_by = ?3
            WHERE id = ?1 AND redeemed_at IS NULL
            "#,
        )
        .bind(invite_id)
        .bind(now)
        .bind(redeemed_by)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn upsert_vault_member(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
        user_id: &str,
        role: VaultShareRole,
        granted_by: &str,
    ) -> Result<(), MetaDbError> {
        let now = unix_now();
        sqlx::query(
            r#"
            INSERT INTO vault_members (tenant_id, vault_id, user_id, role, granted_by, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(tenant_id, vault_id, user_id) DO UPDATE SET
                role = excluded.role,
                granted_by = excluded.granted_by,
                created_at = excluded.created_at
            "#,
        )
        .bind(tenant_id)
        .bind(vault_id)
        .bind(user_id)
        .bind(role.as_str())
        .bind(granted_by)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_vault_members(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
    ) -> Result<Vec<VaultMemberRow>, MetaDbError> {
        let rows = sqlx::query(
            r#"
            SELECT m.tenant_id, m.vault_id, m.user_id, u.email, m.role,
                   m.granted_by, m.created_at
            FROM vault_members m
            JOIN user_accounts u ON u.id = m.user_id
            WHERE m.tenant_id IS ?1 AND m.vault_id = ?2
            ORDER BY m.created_at ASC
            "#,
        )
        .bind(tenant_id)
        .bind(vault_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(member_from_row).collect()
    }

    pub async fn remove_vault_member(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
        user_id: &str,
    ) -> Result<bool, MetaDbError> {
        let result = sqlx::query(
            r#"
            DELETE FROM vault_members
            WHERE tenant_id IS ?1 AND vault_id = ?2 AND user_id = ?3
            "#,
        )
        .bind(tenant_id)
        .bind(vault_id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }
}

fn invite_from_row(row: sqlx::sqlite::SqliteRow) -> Result<VaultInviteRow, MetaDbError> {
    let role_raw: String = row.try_get("role")?;
    let role = VaultShareRole::parse(&role_raw)
        .ok_or_else(|| MetaDbError::Invalid(format!("unknown vault share role: {role_raw}")))?;
    Ok(VaultInviteRow {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        vault_id: row.try_get("vault_id")?,
        role,
        created_by: row.try_get("created_by")?,
        expires_at: row.try_get("expires_at")?,
        redeemed_at: row.try_get("redeemed_at")?,
        redeemed_by: row.try_get("redeemed_by")?,
        created_at: row.try_get("created_at")?,
    })
}

fn member_from_row(row: sqlx::sqlite::SqliteRow) -> Result<VaultMemberRow, MetaDbError> {
    let role_raw: String = row.try_get("role")?;
    let role = VaultShareRole::parse(&role_raw)
        .ok_or_else(|| MetaDbError::Invalid(format!("unknown vault share role: {role_raw}")))?;
    Ok(VaultMemberRow {
        tenant_id: row.try_get("tenant_id")?,
        vault_id: row.try_get("vault_id")?,
        user_id: row.try_get("user_id")?,
        email: row.try_get("email")?,
        role,
        granted_by: row.try_get("granted_by")?,
        created_at: row.try_get("created_at")?,
    })
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
    use crate::accounts::hash_password;
    use crate::normalize_email;
    use tempfile::tempdir;

    async fn seed_vault(db: &MetaDb, tenant: &str, vault: &str) {
        sqlx::query(
            r#"
            INSERT INTO tenant_vaults (tenant_id, vault_id, created_at)
            VALUES (?1, ?2, ?3)
            "#,
        )
        .bind(tenant)
        .bind(vault)
        .bind(unix_now())
        .execute(db.pool())
        .await
        .unwrap();
    }

    async fn seed_user(db: &MetaDb, id: &str, email: &str, tenant: &str) {
        let hash = hash_password("long-password").unwrap();
        db.create_user_account(id, &normalize_email(email), &hash, tenant)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn invite_and_member_round_trip() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("share.sqlite"))
            .await
            .unwrap();
        seed_user(&db, "owner1", "owner@corp.test", "corp").await;
        seed_user(&db, "guest1", "guest@other.test", "other").await;
        seed_vault(&db, "corp", "wiki").await;

        let token_hash = [7u8; 32];
        db.insert_vault_invite(
            "inv1",
            Some("corp"),
            "wiki",
            &token_hash,
            VaultShareRole::Editor,
            "owner1",
            unix_now() + 3600,
        )
        .await
        .unwrap();

        let invite = db
            .get_vault_invite_by_token_hash(&token_hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(invite.vault_id, "wiki");

        assert!(db.redeem_vault_invite("inv1", "guest1").await.unwrap());

        db.upsert_vault_member(
            Some("corp"),
            "wiki",
            "guest1",
            VaultShareRole::Editor,
            "owner1",
        )
        .await
        .unwrap();

        let members = db.list_vault_members(Some("corp"), "wiki").await.unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].email, "guest@other.test");

        assert!(db
            .remove_vault_member(Some("corp"), "wiki", "guest1")
            .await
            .unwrap());
        assert!(db
            .list_vault_members(Some("corp"), "wiki")
            .await
            .unwrap()
            .is_empty());
    }
}
