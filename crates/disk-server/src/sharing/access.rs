//! Vault collaborator access resolution for HTTP vault-scoped routes (DISK-0022 slice 3).

use axum::http::StatusCode;
use disk_core::meta_db::{UserAccount, VaultShareRole};

use crate::accounts::routes::AuthHttpState;

/// Effective access level for a vault-scoped HTTP operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultAccessKind {
    Owner,
    Editor,
    Viewer,
}

/// Resolved tenant + role for vault data-plane HTTP handlers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedVaultAccess {
    /// Tenant id whose MetaDb shard holds the vault data.
    pub data_tenant: Option<String>,
    pub kind: VaultAccessKind,
}

impl ResolvedVaultAccess {
    pub fn tenant_key(&self) -> Option<&str> {
        self.data_tenant.as_deref()
    }

    pub fn allows_read(&self) -> bool {
        true
    }

    pub fn allows_write(&self) -> bool {
        matches!(self.kind, VaultAccessKind::Owner | VaultAccessKind::Editor)
    }

    pub fn allows_manage(&self) -> bool {
        self.kind == VaultAccessKind::Owner
    }
}

/// Resolve whether `user` may access `vault_id` and which tenant shard to query.
pub async fn resolve_vault_access(
    state: &AuthHttpState,
    user: &UserAccount,
    vault_id: &str,
) -> Result<ResolvedVaultAccess, (StatusCode, &'static str)> {
    if state
        .meta_db
        .vault_exists_for_tenant(Some(user.tenant_id.as_str()), vault_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
    {
        return Ok(ResolvedVaultAccess {
            data_tenant: Some(user.tenant_id.clone()),
            kind: VaultAccessKind::Owner,
        });
    }

    let collab = state
        .meta_db
        .get_collaborator_vault_access(&user.id, vault_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let Some((owner_tenant, role)) = collab else {
        return Err((StatusCode::FORBIDDEN, "vault access denied"));
    };

    let kind = match role {
        VaultShareRole::Editor => VaultAccessKind::Editor,
        VaultShareRole::Viewer => VaultAccessKind::Viewer,
    };

    Ok(ResolvedVaultAccess {
        data_tenant: owner_tenant,
        kind,
    })
}

pub fn require_read(access: &ResolvedVaultAccess) -> Result<(), (StatusCode, &'static str)> {
    if access.allows_read() {
        Ok(())
    } else {
        Err((StatusCode::FORBIDDEN, "read access denied"))
    }
}

pub fn require_write(access: &ResolvedVaultAccess) -> Result<(), (StatusCode, &'static str)> {
    if access.allows_write() {
        Ok(())
    } else {
        Err((StatusCode::FORBIDDEN, "write access denied"))
    }
}

pub fn require_manage(access: &ResolvedVaultAccess) -> Result<(), (StatusCode, &'static str)> {
    if access.allows_manage() {
        Ok(())
    } else {
        Err((StatusCode::FORBIDDEN, "manage access denied"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use disk_core::meta_db::MetaDb;
    use std::sync::Arc;
    use tempfile::tempdir;

    async fn user(db: &MetaDb, id: &str, email: &str, tenant: &str) {
        let hash = disk_core::hash_password("long-password").unwrap();
        db.create_user_account(id, &disk_core::normalize_email(email), &hash, tenant)
            .await
            .unwrap();
    }

    async fn seed_vault(db: &MetaDb, tenant: &str, vault: &str) {
        sqlx::query(
            "INSERT INTO tenant_vaults (tenant_id, vault_id, created_at) VALUES (?1, ?2, 1)",
        )
        .bind(tenant)
        .bind(vault)
        .execute(db.pool())
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn resolve_owner_and_collaborator_access() {
        let dir = tempdir().unwrap();
        let meta_db = MetaDb::open(&dir.path().join("access.sqlite"))
            .await
            .unwrap();
        user(&meta_db, "own1", "owner@corp.test", "corp").await;
        user(&meta_db, "gst1", "guest@other.test", "other").await;
        seed_vault(&meta_db, "corp", "wiki").await;
        meta_db
            .upsert_vault_member(Some("corp"), "wiki", "gst1", VaultShareRole::Viewer, "own1")
            .await
            .unwrap();

        let state = Arc::new(crate::accounts::routes::auth_http_state_for_tests(
            meta_db.clone(),
        ));

        let owner = meta_db.get_user_by_id("own1").await.unwrap().unwrap();
        let guest = meta_db.get_user_by_id("gst1").await.unwrap().unwrap();

        let owner_access = resolve_vault_access(&state, &owner, "wiki").await.unwrap();
        assert_eq!(owner_access.kind, VaultAccessKind::Owner);
        assert!(owner_access.allows_manage());

        let guest_access = resolve_vault_access(&state, &guest, "wiki").await.unwrap();
        assert_eq!(guest_access.kind, VaultAccessKind::Viewer);
        assert!(guest_access.allows_read());
        assert!(!guest_access.allows_write());
    }
}
