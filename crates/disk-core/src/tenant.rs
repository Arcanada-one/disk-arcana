//! Multi-tenant scope helpers (DISK-0017).

/// Tenant binding violation (request header disagrees with node enrollment).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantViolation {
    Mismatch,
}

/// Resolve tenant id from gRPC metadata (`x-disk-tenant`) or proto field.
///
/// Header wins when both are set. Empty header string maps to `None` without
/// falling back to proto (explicit clear). Missing header uses proto.
pub fn resolve_tenant_id(metadata_header: Option<&str>, proto_field: &str) -> Option<String> {
    if let Some(t) = metadata_header {
        return if t.is_empty() {
            None
        } else {
            Some(t.to_owned())
        };
    }
    if proto_field.is_empty() {
        None
    } else {
        Some(proto_field.to_owned())
    }
}

/// Enforce that a sync RPC tenant matches the node's bound tenant (slice 2).
///
/// - Legacy nodes (`node_tenant = None`): accept any request tenant (may be `None`).
/// - Bound nodes: missing header inherits the binding; mismatched header → error.
pub fn enforce_node_tenant(
    request_tenant: Option<&str>,
    node_tenant: Option<&str>,
) -> Result<Option<String>, TenantViolation> {
    match (node_tenant, request_tenant) {
        (None, req) => Ok(req.map(str::to_owned)),
        (Some(bound), None) => Ok(Some(bound.to_owned())),
        (Some(bound), Some(req)) if bound == req => Ok(Some(bound.to_owned())),
        (Some(_), Some(_)) => Err(TenantViolation::Mismatch),
    }
}

/// Tenant + vault scope for MetaDb queries (DISK-0017 slice 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantScope {
    pub tenant_id: Option<String>,
    pub vault_id: String,
}

impl TenantScope {
    pub fn new(tenant_id: Option<&str>, vault_id: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.map(str::to_owned),
            vault_id: vault_id.into(),
        }
    }

    pub fn tenant_id(&self) -> Option<&str> {
        self.tenant_id.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_wins_over_proto() {
        assert_eq!(resolve_tenant_id(Some("hdr"), "proto"), Some("hdr".into()));
    }

    #[test]
    fn proto_fallback() {
        assert_eq!(resolve_tenant_id(None, "acme"), Some("acme".into()));
    }

    #[test]
    fn empty_is_none() {
        assert_eq!(resolve_tenant_id(None, ""), None);
        assert_eq!(resolve_tenant_id(Some(""), "x"), None);
    }

    #[test]
    fn enforce_inherits_bound_tenant() {
        assert_eq!(
            enforce_node_tenant(None, Some("acme")).unwrap(),
            Some("acme".into())
        );
    }

    #[test]
    fn enforce_matching_header() {
        assert_eq!(
            enforce_node_tenant(Some("acme"), Some("acme")).unwrap(),
            Some("acme".into())
        );
    }

    #[test]
    fn enforce_mismatch_rejected() {
        assert_eq!(
            enforce_node_tenant(Some("other"), Some("acme")),
            Err(TenantViolation::Mismatch)
        );
    }

    #[test]
    fn enforce_legacy_node_accepts_any() {
        assert_eq!(
            enforce_node_tenant(Some("any"), None).unwrap(),
            Some("any".into())
        );
        assert_eq!(enforce_node_tenant(None, None).unwrap(), None);
    }

    #[test]
    fn tenant_scope_holds_ids() {
        let scope = TenantScope::new(Some("acme"), "wiki");
        assert_eq!(scope.tenant_id(), Some("acme"));
        assert_eq!(scope.vault_id, "wiki");
    }
}
