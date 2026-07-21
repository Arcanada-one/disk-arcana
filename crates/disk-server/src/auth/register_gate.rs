//! Production gate for `RegisterNode` (OWASP T2.10).
//!
//! In `enrolled` mode only nodes that completed `Enroll` and present a matching
//! mTLS client certificate may call `RegisterNode`.

use std::time::{SystemTime, UNIX_EPOCH};

use sqlx::SqlitePool;
use tonic::{metadata::MetadataMap, Status};

use crate::acl::CertFingerprint;
use crate::config::RegisterNodeMode;

/// Verify the peer certificate is enrolled for `node_id`.
pub async fn verify_enrolled_register(
    pool: &SqlitePool,
    cert_fp: &CertFingerprint,
    node_id: &str,
) -> Result<(), Status> {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    let found: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM node_certs nc
         INNER JOIN nodes n ON n.id = nc.node_id
         WHERE nc.cert_fingerprint = ?1
           AND n.node_id = ?2
           AND nc.revoked_at IS NULL
           AND nc.expires_at > ?3
           AND n.revoked = 0
         LIMIT 1",
    )
    .bind(&cert_fp[..])
    .bind(node_id)
    .bind(now_ms)
    .fetch_optional(pool)
    .await
    .map_err(|e| Status::internal(format!("db (register gate): {e}")))?;

    if found.is_some() {
        Ok(())
    } else {
        Err(Status::permission_denied(
            "RegisterNode requires enrolled mTLS certificate matching node_id",
        ))
    }
}

/// Admin bearer check — same contract as `EnrollmentServiceImpl::require_admin`.
pub fn check_admin_metadata(meta: &MetadataMap, admin_token: Option<&str>) -> Result<(), Status> {
    let expected = admin_token.filter(|s| !s.is_empty()).ok_or_else(|| {
        Status::permission_denied("RegisterNode admin mode but DISK_ADMIN_TOKEN is unset")
    })?;

    let provided = meta
        .get("x-disk-admin-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if provided == expected {
        Ok(())
    } else {
        Err(Status::permission_denied(
            "missing or invalid x-disk-admin-token",
        ))
    }
}

/// Apply the configured register gate before handling `RegisterNode`.
pub async fn check_register_gate<T>(
    mode: RegisterNodeMode,
    pool: Option<&SqlitePool>,
    admin_token: Option<&str>,
    request: &tonic::Request<T>,
    node_id: &str,
) -> Result<(), Status> {
    match mode {
        RegisterNodeMode::Open => Ok(()),
        RegisterNodeMode::Disabled => Err(Status::permission_denied("RegisterNode is disabled")),
        RegisterNodeMode::Admin => check_admin_metadata(request.metadata(), admin_token),
        RegisterNodeMode::Enrolled => {
            let pool = pool.ok_or_else(|| {
                Status::internal("RegisterNode enrolled mode requires SQLite pool")
            })?;
            let identity = crate::auth::CertIdentity::from_request(request).ok_or_else(|| {
                Status::unauthenticated("mTLS client certificate required for RegisterNode")
            })?;
            verify_enrolled_register(pool, &identity.fingerprint, node_id).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::metadata::MetadataValue;

    #[test]
    fn admin_metadata_accepts_matching_token() {
        let mut meta = MetadataMap::new();
        meta.insert("x-disk-admin-token", MetadataValue::from_static("secret"));
        check_admin_metadata(&meta, Some("secret")).unwrap();
    }

    #[test]
    fn admin_metadata_rejects_wrong_token() {
        let mut meta = MetadataMap::new();
        meta.insert("x-disk-admin-token", MetadataValue::from_static("wrong"));
        let err = check_admin_metadata(&meta, Some("secret")).unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }
}
