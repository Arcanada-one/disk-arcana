//! Audit event emitter.
//!
//! Writes structured audit events to the `audit_event` table (migration
//! `003_acl_enrollment.sql`). P4b step 16 adds `ops_bot::Forwarder` which
//! receives the same events via `AuditEmitter::emit_with_forwarder`.
//!
//! Event-kind enumeration matches creative-DISK-0005-architecture-acl-reload.md
//! §F1-F8 and creative-DISK-0005-data-model-publisher-signatures.md §6. The
//! kind strings are part of the contract (audit consumers grep on them).

pub mod ops_bot;

use serde::Serialize;
use sqlx::SqlitePool;

use super::acl::CertFingerprint;

/// Audit event kinds — exact strings (greppable from logs and dashboards).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditKind {
    AclRoleMismatch,
    AclVersionRegress,
    AclLoadFailure,
    AclLoadOk,
    AclReloadDedup,
    AclFileMissing,
    PublisherSignatureFailure,
    PublisherReplayDetected,
    PublisherTimestampSkew,
    PublisherUploadOk,
    EnrollmentTokenIssued,
    EnrollmentCompleted,
    EnrollmentTokenExpired,
    EnrollmentPending,
    EnrollmentCaMismatch,
    EnrollmentRevoked,
    ShareUnknown,
    ConfigReload,
}

impl AuditKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AclRoleMismatch => "acl.role_mismatch",
            Self::AclVersionRegress => "acl.version_regress",
            Self::AclLoadFailure => "acl.load_failure",
            Self::AclLoadOk => "acl.load_ok",
            Self::AclReloadDedup => "acl.reload_dedup",
            Self::AclFileMissing => "acl.file_missing",
            Self::PublisherSignatureFailure => "publisher.signature_failure",
            Self::PublisherReplayDetected => "publisher.replay_detected",
            Self::PublisherTimestampSkew => "publisher.timestamp_skew",
            Self::PublisherUploadOk => "publisher.upload_ok",
            Self::EnrollmentTokenIssued => "enrollment.token_issued",
            Self::EnrollmentCompleted => "enrollment.completed",
            Self::EnrollmentTokenExpired => "enrollment.token_expired",
            Self::EnrollmentPending => "enrollment.pending",
            Self::EnrollmentCaMismatch => "enrollment.ca_mismatch",
            Self::EnrollmentRevoked => "enrollment.revoked",
            Self::ShareUnknown => "share.unknown",
            Self::ConfigReload => "config.reload",
        }
    }
}

/// Builder for an audit event row.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub kind: AuditKind,
    pub cert_fp: Option<CertFingerprint>,
    pub share: Option<String>,
    pub payload: serde_json::Value,
}

impl AuditEvent {
    pub fn new(kind: AuditKind) -> Self {
        Self {
            kind,
            cert_fp: None,
            share: None,
            payload: serde_json::Value::Object(Default::default()),
        }
    }

    pub fn with_cert(mut self, fp: CertFingerprint) -> Self {
        self.cert_fp = Some(fp);
        self
    }

    pub fn with_share(mut self, share: impl Into<String>) -> Self {
        self.share = Some(share.into());
        self
    }

    pub fn with_payload<T: Serialize>(mut self, payload: &T) -> Self {
        self.payload =
            serde_json::to_value(payload).unwrap_or(serde_json::Value::Object(Default::default()));
        self
    }
}

#[derive(thiserror::Error, Debug)]
pub enum AuditError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),

    #[error("system clock before unix epoch")]
    Clock,
}

/// Emitter wrapping the shared SqlitePool. Cheap to clone (Pool is Arc inside).
#[derive(Debug, Clone)]
pub struct AuditEmitter {
    pool: SqlitePool,
}

impl AuditEmitter {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Insert one audit event row. Failure to write is logged but does not
    /// propagate — audit is best-effort observability, not an authZ gate.
    ///
    /// Returns the auto-generated row id on success.
    pub async fn emit(&self, event: AuditEvent) -> Result<i64, AuditError> {
        let ts_ms = unix_now_ms()?;
        let kind = event.kind.as_str();
        let payload_json =
            serde_json::to_string(&event.payload).unwrap_or_else(|_| "{}".to_string());

        let id = sqlx::query_scalar::<_, i64>(
            "INSERT INTO audit_event (ts_ms, kind, cert_fp, share, payload_json)
             VALUES (?1, ?2, ?3, ?4, ?5)
             RETURNING id",
        )
        .bind(ts_ms as i64)
        .bind(kind)
        .bind(event.cert_fp.as_ref().map(|fp| fp.as_slice()))
        .bind(event.share.as_deref())
        .bind(&payload_json)
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    /// Emit with optional Ops Bot forwarding. The forwarder is fire-and-forget;
    /// failure to enqueue never fails the audit write.
    pub async fn emit_with_forwarder(
        &self,
        event: AuditEvent,
        forwarder: Option<&ops_bot::Forwarder>,
    ) -> Result<i64, AuditError> {
        let ts_ms = unix_now_ms()?;
        if let Some(fwd) = forwarder {
            fwd.enqueue(&event, ts_ms);
        }
        let kind = event.kind.as_str();
        let payload_json =
            serde_json::to_string(&event.payload).unwrap_or_else(|_| "{}".to_string());
        let id = sqlx::query_scalar::<_, i64>(
            "INSERT INTO audit_event (ts_ms, kind, cert_fp, share, payload_json)
             VALUES (?1, ?2, ?3, ?4, ?5)
             RETURNING id",
        )
        .bind(ts_ms as i64)
        .bind(kind)
        .bind(event.cert_fp.as_ref().map(|fp| fp.as_slice()))
        .bind(event.share.as_deref())
        .bind(&payload_json)
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    /// Read events of a given kind for assertions and tooling.
    pub async fn count_by_kind(&self, kind: AuditKind) -> Result<i64, AuditError> {
        let count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_event WHERE kind = ?1")
                .bind(kind.as_str())
                .fetch_one(&self.pool)
                .await?;
        Ok(count)
    }

    /// Snapshot the most recent event of a given kind. Returns the raw
    /// payload JSON string and timestamp. None when no row of that kind exists.
    pub async fn latest(&self, kind: AuditKind) -> Result<Option<(i64, String)>, AuditError> {
        let row = sqlx::query_as::<_, (i64, String)>(
            "SELECT ts_ms, payload_json FROM audit_event
             WHERE kind = ?1
             ORDER BY id DESC LIMIT 1",
        )
        .bind(kind.as_str())
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }
}

fn unix_now_ms() -> Result<u64, AuditError> {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuditError::Clock)
        .map(|d| d.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_strings_match_documented_contract() {
        // These exact strings are referenced by SQL migrations + dashboards.
        // Any rename must update consumers in lockstep.
        assert_eq!(AuditKind::AclRoleMismatch.as_str(), "acl.role_mismatch");
        assert_eq!(AuditKind::AclVersionRegress.as_str(), "acl.version_regress");
        assert_eq!(AuditKind::AclLoadFailure.as_str(), "acl.load_failure");
        assert_eq!(AuditKind::AclLoadOk.as_str(), "acl.load_ok");
        assert_eq!(
            AuditKind::PublisherSignatureFailure.as_str(),
            "publisher.signature_failure"
        );
        assert_eq!(
            AuditKind::PublisherReplayDetected.as_str(),
            "publisher.replay_detected"
        );
        assert_eq!(
            AuditKind::EnrollmentTokenIssued.as_str(),
            "enrollment.token_issued"
        );
        assert_eq!(AuditKind::ShareUnknown.as_str(), "share.unknown");
    }

    #[test]
    fn audit_event_builder_threads_metadata() {
        let event = AuditEvent::new(AuditKind::AclRoleMismatch)
            .with_cert([0xAA; 32])
            .with_share("wiki")
            .with_payload(&serde_json::json!({"claimed":"publisher","enforced":"receive_only"}));
        assert_eq!(event.kind, AuditKind::AclRoleMismatch);
        assert_eq!(event.share.as_deref(), Some("wiki"));
        assert_eq!(event.cert_fp, Some([0xAA; 32]));
        assert_eq!(event.payload["claimed"], "publisher");
    }
}
