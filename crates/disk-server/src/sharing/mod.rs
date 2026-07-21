//! HTTP handlers for `/sharing/*` (DISK-0022).

pub mod access;
pub mod routes;

pub use access::{
    require_manage, require_read, require_write, resolve_vault_access, ResolvedVaultAccess,
    VaultAccessKind,
};
pub use routes::{accept_invite, create_invite, list_invites, list_members, remove_member};
