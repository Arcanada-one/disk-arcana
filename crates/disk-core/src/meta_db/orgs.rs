//! Team / organization workspaces (DISK-0030).

use sqlx::Row;

use super::MetaDb;
use crate::error::MetaDbError;

/// Organization membership role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrgRole {
    Owner,
    Admin,
    Member,
}

impl OrgRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Member => "member",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "owner" => Some(Self::Owner),
            "admin" => Some(Self::Admin),
            "member" => Some(Self::Member),
            _ => None,
        }
    }

    pub fn can_manage_members(self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrganizationRow {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub tenant_id: String,
    pub created_by: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgMemberRow {
    pub org_id: String,
    pub user_id: String,
    pub email: String,
    pub role: OrgRole,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserOrganizationRow {
    pub organization: OrganizationRow,
    pub role: OrgRole,
}

impl MetaDb {
    pub async fn organization_slug_taken(&self, slug: &str) -> Result<bool, MetaDbError> {
        let row = sqlx::query(
            r#"
            SELECT 1 AS ok FROM organizations
            WHERE slug = ?1 COLLATE NOCASE
            LIMIT 1
            "#,
        )
        .bind(slug)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.is_some())
    }

    pub async fn create_organization(
        &self,
        org_id: &str,
        slug: &str,
        name: &str,
        tenant_id: &str,
        created_by: &str,
        now: i64,
    ) -> Result<(), MetaDbError> {
        sqlx::query(
            r#"
            INSERT INTO organizations (id, slug, name, tenant_id, created_by, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
            "#,
        )
        .bind(org_id)
        .bind(slug)
        .bind(name)
        .bind(tenant_id)
        .bind(created_by)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn add_organization_member(
        &self,
        org_id: &str,
        user_id: &str,
        role: OrgRole,
        now: i64,
    ) -> Result<(), MetaDbError> {
        sqlx::query(
            r#"
            INSERT INTO organization_members (org_id, user_id, role, created_at)
            VALUES (?1, ?2, ?3, ?4)
            "#,
        )
        .bind(org_id)
        .bind(user_id)
        .bind(role.as_str())
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_organization(
        &self,
        org_id: &str,
    ) -> Result<Option<OrganizationRow>, MetaDbError> {
        let row = sqlx::query(
            r#"
            SELECT id, slug, name, tenant_id, created_by, created_at, updated_at
            FROM organizations
            WHERE id = ?1
            LIMIT 1
            "#,
        )
        .bind(org_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|row| OrganizationRow {
            id: row.try_get("id").unwrap_or_default(),
            slug: row.try_get("slug").unwrap_or_default(),
            name: row.try_get("name").unwrap_or_default(),
            tenant_id: row.try_get("tenant_id").unwrap_or_default(),
            created_by: row.try_get("created_by").unwrap_or_default(),
            created_at: row.try_get("created_at").unwrap_or_default(),
            updated_at: row.try_get("updated_at").unwrap_or_default(),
        }))
    }

    pub async fn get_org_member_role(
        &self,
        org_id: &str,
        user_id: &str,
    ) -> Result<Option<OrgRole>, MetaDbError> {
        let row = sqlx::query(
            r#"
            SELECT role FROM organization_members
            WHERE org_id = ?1 AND user_id = ?2
            LIMIT 1
            "#,
        )
        .bind(org_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };
        let role_raw: String = row.try_get("role")?;
        OrgRole::parse(&role_raw)
            .ok_or_else(|| MetaDbError::Invalid(format!("unknown org role: {role_raw}")))
            .map(Some)
    }

    pub async fn list_user_organizations(
        &self,
        user_id: &str,
    ) -> Result<Vec<UserOrganizationRow>, MetaDbError> {
        let rows = sqlx::query(
            r#"
            SELECT o.id, o.slug, o.name, o.tenant_id, o.created_by, o.created_at, o.updated_at,
                   m.role
            FROM organization_members m
            JOIN organizations o ON o.id = m.org_id
            WHERE m.user_id = ?1
            ORDER BY o.name COLLATE NOCASE
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let role_raw: String = row.try_get("role")?;
            let role = OrgRole::parse(&role_raw)
                .ok_or_else(|| MetaDbError::Invalid(format!("unknown org role: {role_raw}")))?;
            out.push(UserOrganizationRow {
                organization: OrganizationRow {
                    id: row.try_get("id")?,
                    slug: row.try_get("slug")?,
                    name: row.try_get("name")?,
                    tenant_id: row.try_get("tenant_id")?,
                    created_by: row.try_get("created_by")?,
                    created_at: row.try_get("created_at")?,
                    updated_at: row.try_get("updated_at")?,
                },
                role,
            });
        }
        Ok(out)
    }

    pub async fn list_organization_members(
        &self,
        org_id: &str,
    ) -> Result<Vec<OrgMemberRow>, MetaDbError> {
        let rows = sqlx::query(
            r#"
            SELECT m.org_id, m.user_id, u.email, m.role, m.created_at
            FROM organization_members m
            JOIN user_accounts u ON u.id = m.user_id
            WHERE m.org_id = ?1
            ORDER BY m.created_at ASC
            "#,
        )
        .bind(org_id)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let role_raw: String = row.try_get("role")?;
            let role = OrgRole::parse(&role_raw)
                .ok_or_else(|| MetaDbError::Invalid(format!("unknown org role: {role_raw}")))?;
            out.push(OrgMemberRow {
                org_id: row.try_get("org_id")?,
                user_id: row.try_get("user_id")?,
                email: row.try_get("email")?,
                role,
                created_at: row.try_get("created_at")?,
            });
        }
        Ok(out)
    }

    /// Load persisted active org id for a user (`None` = personal workspace).
    pub async fn get_user_org_context(&self, user_id: &str) -> Result<Option<String>, MetaDbError> {
        let row = sqlx::query(
            r#"
            SELECT active_org_id FROM user_org_context
            WHERE user_id = ?1
            LIMIT 1
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.and_then(|r| {
            r.try_get::<Option<String>, _>("active_org_id")
                .ok()
                .flatten()
        }))
    }

    /// Persist active org workspace; pass `None` to switch back to personal tenant.
    pub async fn set_user_org_context(
        &self,
        user_id: &str,
        active_org_id: Option<&str>,
        now: i64,
    ) -> Result<(), MetaDbError> {
        sqlx::query(
            r#"
            INSERT INTO user_org_context (user_id, active_org_id, updated_at)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(user_id) DO UPDATE SET
                active_org_id = excluded.active_org_id,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(user_id)
        .bind(active_org_id)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{hash_password, normalize_email};

    async fn seed_user(db: &MetaDb, user_id: &str, email: &str, tenant: &str) {
        let hash = hash_password("long-password").unwrap();
        db.create_user_account(user_id, &normalize_email(email), &hash, tenant)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn org_create_and_member_list_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("orgs.sqlite")).await.unwrap();
        seed_user(&db, "usr_a", "alice@acme.test", "alice").await;

        db.create_organization("org_acme", "acme", "Acme Corp", "acme", "usr_a", 100)
            .await
            .unwrap();
        db.add_organization_member("org_acme", "usr_a", OrgRole::Owner, 100)
            .await
            .unwrap();

        let orgs = db.list_user_organizations("usr_a").await.unwrap();
        assert_eq!(orgs.len(), 1);
        assert_eq!(orgs[0].organization.slug, "acme");
        assert_eq!(orgs[0].role, OrgRole::Owner);

        let members = db.list_organization_members("org_acme").await.unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].email, "alice@acme.test");
    }

    #[tokio::test]
    async fn org_context_persists_and_clears() {
        let dir = tempfile::tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("org-ctx.sqlite"))
            .await
            .unwrap();
        seed_user(&db, "usr_a", "alice@acme.test", "alice").await;

        db.create_organization("org_acme", "acme", "Acme Corp", "acme", "usr_a", 100)
            .await
            .unwrap();
        db.add_organization_member("org_acme", "usr_a", OrgRole::Owner, 100)
            .await
            .unwrap();

        assert!(db.get_user_org_context("usr_a").await.unwrap().is_none());

        db.set_user_org_context("usr_a", Some("org_acme"), 200)
            .await
            .unwrap();
        assert_eq!(
            db.get_user_org_context("usr_a").await.unwrap().as_deref(),
            Some("org_acme")
        );

        db.set_user_org_context("usr_a", None, 300).await.unwrap();
        assert!(db.get_user_org_context("usr_a").await.unwrap().is_none());
    }
}
