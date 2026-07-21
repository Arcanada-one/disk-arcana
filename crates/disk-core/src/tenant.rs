//! Multi-tenant scope helpers (DISK-0017).

/// Resolve tenant id from gRPC metadata (`x-disk-tenant`) or proto field.
///
/// Header wins when both are set. Empty strings map to `None` (single-tenant).
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
}
