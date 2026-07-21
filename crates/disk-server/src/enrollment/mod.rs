//! Enrollment service — mTLS certificate issuance workflow.
//!
//! Implements the `EnrollmentService` gRPC service (proto §DISK-0005 v1.1):
//! - `IssuePendingToken` — admin-bearer scope; generates a 32-byte opaque token
//!   and stores its blake3 hash in `pending_enrollments`.
//! - `Enroll` — public scope (bearer = opaque_token); validates token, calls CA
//!   client, stores cert fingerprint, marks token consumed.
//! - `RevokePending` — admin-bearer scope; marks an unconsumed token revoked.
//!
//! ## Admin-bearer check
//!
//! The `x-disk-admin-token` gRPC metadata header must match the value of
//! `DISK_ADMIN_TOKEN` env var. This is a bootstrap credential — it MUST be
//! rotated to Auth Arcana OIDC in P4c. Backlog entry: DISK-0006.
//!
//! ## Token flow
//!
//! 1. Admin calls `IssuePendingToken(node_id_hint, ttl_secs)`.
//! 2. Server generates 32 random bytes, stores blake3(token) → `pending_enrollments`.
//! 3. Admin delivers plaintext token to the node (out of band).
//! 4. Node calls `Enroll(token, csr_pem)`.
//! 5. Server validates token, calls CA, stores cert, marks token `consumed`.
//! 6. Node uses returned cert for future mTLS connections.

pub mod ca_client;

use std::env;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::auth::rate_limit::{AuthAttemptLimiter, SharedAuthAttemptLimiter};

use rand::RngCore;
use sqlx::SqlitePool;
use tonic::{Request, Response, Status};

use disk_proto::disk::{
    enrollment_service_server::EnrollmentService, EnrollRequest, EnrollResponse,
    EnrollmentTokenRequest, EnrollmentTokenResponse, RevokePendingRequest, RevokePendingResponse,
};

use crate::audit::{AuditEmitter, AuditEvent, AuditKind};

use self::ca_client::CaClient;

/// Default token TTL: 1 hour.
const DEFAULT_TTL_SECS: u64 = 3_600;

/// Maximum token TTL: 24 hours.
const MAX_TTL_SECS: u64 = 86_400;

/// Structured error kinds for enrollment failures (returned via Status details).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollErrorKind {
    /// Token hash not found in `pending_enrollments`.
    NotFound,
    /// Token was already used to enroll a node.
    Replay,
    /// Token TTL has elapsed.
    Expired,
    /// Token was administratively revoked before use.
    Revoked,
}

impl EnrollErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "enrollment.not_found",
            Self::Replay => "enrollment.replay",
            Self::Expired => "enrollment.expired",
            Self::Revoked => "enrollment.revoked",
        }
    }
}

#[derive(Clone)]
pub struct EnrollmentServiceImpl {
    pool: SqlitePool,
    audit: AuditEmitter,
    ca: Arc<dyn CaClient>,
    /// Admin token override for testing. If `None`, read from env `DISK_ADMIN_TOKEN`.
    admin_token_override: Option<String>,
    /// Per-peer-IP failed `Enroll` rate limiter for the public `:9445` listener.
    enroll_limiter: Option<SharedAuthAttemptLimiter>,
}

impl EnrollmentServiceImpl {
    pub fn new(pool: SqlitePool, audit: AuditEmitter, ca: Arc<dyn CaClient>) -> Self {
        Self::with_rate_limiter(
            pool,
            audit,
            ca,
            Some(Arc::new(AuthAttemptLimiter::new(
                crate::auth::rate_limit::DEFAULT_ENROLL_MAX_FAILURES,
                crate::auth::rate_limit::DEFAULT_WINDOW,
            ))),
        )
    }

    /// Create a service with an optional per-peer failed-enroll rate limiter.
    pub fn with_rate_limiter(
        pool: SqlitePool,
        audit: AuditEmitter,
        ca: Arc<dyn CaClient>,
        enroll_limiter: Option<SharedAuthAttemptLimiter>,
    ) -> Self {
        Self {
            pool,
            audit,
            ca,
            admin_token_override: None,
            enroll_limiter,
        }
    }

    /// Inject a fixed admin token (for tests that cannot set env vars).
    pub fn with_admin_token(mut self, token: impl Into<String>) -> Self {
        self.admin_token_override = Some(token.into());
        self
    }

    /// Check x-disk-admin-token header against DISK_ADMIN_TOKEN env var.
    #[allow(clippy::result_large_err)]
    fn require_admin(&self, meta: &tonic::metadata::MetadataMap) -> Result<(), Status> {
        let expected = self
            .admin_token_override
            .clone()
            .or_else(|| env::var("DISK_ADMIN_TOKEN").ok())
            .unwrap_or_default();
        if expected.is_empty() {
            return Err(Status::unauthenticated(
                "DISK_ADMIN_TOKEN is not configured",
            ));
        }
        let provided = meta
            .get("x-disk-admin-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if provided != expected {
            return Err(Status::unauthenticated("invalid admin token"));
        }
        Ok(())
    }

    fn peer_key<T>(request: &Request<T>) -> String {
        request
            .remote_addr()
            .map(|addr| addr.ip().to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }

    fn check_enroll_rate_limit_peer(&self, peer: &str, now_secs: u64) -> Result<(), Status> {
        let Some(limiter) = &self.enroll_limiter else {
            return Ok(());
        };
        limiter.check(peer, now_secs).map_err(|e| {
            Status::resource_exhausted(format!(
                "too many failed enroll attempts; retry after {}s",
                e.retry_after_secs
            ))
        })
    }

    fn record_enroll_failure_peer(&self, peer: &str, now_secs: u64) {
        if let Some(limiter) = &self.enroll_limiter {
            limiter.record_failure(peer, now_secs);
        }
    }

    fn clear_enroll_failures_peer(&self, peer: &str) {
        if let Some(limiter) = &self.enroll_limiter {
            limiter.clear(peer);
        }
    }
}

#[allow(clippy::result_large_err)]
fn unix_now_ms() -> Result<u64, Status> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .map_err(|_| Status::internal("system clock before unix epoch"))
}

#[tonic::async_trait]
impl EnrollmentService for EnrollmentServiceImpl {
    async fn issue_pending_token(
        &self,
        request: Request<EnrollmentTokenRequest>,
    ) -> Result<Response<EnrollmentTokenResponse>, Status> {
        self.require_admin(request.metadata())?;

        let req = request.into_inner();
        let now_ms = unix_now_ms()?;

        // Clamp TTL.
        let ttl_secs = if req.ttl_seconds == 0 {
            DEFAULT_TTL_SECS
        } else {
            req.ttl_seconds.min(MAX_TTL_SECS)
        };
        let expires_at_ms = now_ms + ttl_secs * 1_000;

        // Generate 32-byte cryptographic random token.
        let mut token = [0u8; 32];
        rand::rng().fill_bytes(&mut token);
        let token_hash = blake3::hash(&token);

        sqlx::query(
            "INSERT INTO pending_enrollments
             (token_hash, node_id_hint, issued_at, expires_at)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(token_hash.as_bytes().as_slice())
        .bind(&req.node_id_hint)
        .bind(now_ms as i64)
        .bind(expires_at_ms as i64)
        .execute(&self.pool)
        .await
        .map_err(|e| Status::internal(format!("db: {e}")))?;

        let _ = self
            .audit
            .emit(
                AuditEvent::new(AuditKind::EnrollmentTokenIssued)
                    .with_payload(&serde_json::json!({ "node_id_hint": req.node_id_hint })),
            )
            .await;

        Ok(Response::new(EnrollmentTokenResponse {
            opaque_token: token.to_vec(),
            expires_at_ms: expires_at_ms as i64,
        }))
    }

    async fn enroll(
        &self,
        request: Request<EnrollRequest>,
    ) -> Result<Response<EnrollResponse>, Status> {
        let now_ms = unix_now_ms()?;
        let now_secs = now_ms / 1_000;
        let peer = Self::peer_key(&request);
        self.check_enroll_rate_limit_peer(&peer, now_secs)?;
        let req = request.into_inner();

        let token_hash = blake3::hash(&req.opaque_token);

        // Lookup token row.
        let row: Option<(i64, Option<i64>, Option<i64>)> = sqlx::query_as(
            "SELECT expires_at, consumed_at, revoked_at
             FROM pending_enrollments WHERE token_hash = ?1",
        )
        .bind(token_hash.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Status::internal(format!("db: {e}")))?;

        let (expires_at, consumed_at, revoked_at) = match row {
            None => {
                self.record_enroll_failure_peer(&peer, now_secs);
                let _ = self
                    .audit
                    .emit(AuditEvent::new(AuditKind::EnrollmentPending).with_payload(
                        &serde_json::json!({ "kind": EnrollErrorKind::NotFound.as_str() }),
                    ))
                    .await;
                return Err(Status::failed_precondition(
                    EnrollErrorKind::NotFound.as_str(),
                ));
            }
            Some(r) => r,
        };

        if revoked_at.is_some() {
            self.record_enroll_failure_peer(&peer, now_secs);
            let _ = self
                .audit
                .emit(AuditEvent::new(AuditKind::EnrollmentRevoked))
                .await;
            return Err(Status::failed_precondition(
                EnrollErrorKind::Revoked.as_str(),
            ));
        }

        if consumed_at.is_some() {
            self.record_enroll_failure_peer(&peer, now_secs);
            let _ =
                self.audit
                    .emit(AuditEvent::new(AuditKind::EnrollmentPending).with_payload(
                        &serde_json::json!({ "kind": EnrollErrorKind::Replay.as_str() }),
                    ))
                    .await;
            return Err(Status::failed_precondition(
                EnrollErrorKind::Replay.as_str(),
            ));
        }

        if (expires_at as u64) < now_ms {
            self.record_enroll_failure_peer(&peer, now_secs);
            let _ = self
                .audit
                .emit(AuditEvent::new(AuditKind::EnrollmentTokenExpired))
                .await;
            return Err(Status::failed_precondition(
                EnrollErrorKind::Expired.as_str(),
            ));
        }

        // Post CSR to CA.
        let cert = self
            .ca
            .issue_cert(&req.csr_pem)
            .await
            .map_err(|e| Status::internal(format!("CA request failed: {e}")))?;

        // Compute cert fingerprint: blake3(DER) — matches mTLS `CertIdentity`.
        let cert_fp = crate::auth::fingerprint_from_pem(&cert.client_cert_pem)
            .map_err(|e| Status::internal(format!("cert fingerprint: {e}")))?;

        // Ensure node exists or insert a placeholder node row.
        sqlx::query(
            "INSERT OR IGNORE INTO nodes (node_id, display_name, platform, api_key_hash, registered_at)
             VALUES (?1, ?1, 'unknown', '', ?2)",
        )
        .bind(&req.node_id_hint)
        .bind(now_ms as i64)
        .execute(&self.pool)
        .await
        .map_err(|e| Status::internal(format!("db (node insert): {e}")))?;

        let node_row: (i64,) = sqlx::query_as("SELECT id FROM nodes WHERE node_id = ?1")
            .bind(&req.node_id_hint)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| Status::internal(format!("db (node lookup): {e}")))?;

        let expires_cert_ms = now_ms + 90 * 24 * 3600 * 1_000; // 90 days

        sqlx::query(
            "INSERT INTO node_certs (cert_fingerprint, node_id, enrolled_at, expires_at)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(&cert_fp[..])
        .bind(node_row.0)
        .bind(now_ms as i64)
        .bind(expires_cert_ms as i64)
        .execute(&self.pool)
        .await
        .map_err(|e| Status::internal(format!("db (cert insert): {e}")))?;

        // Mark token consumed.
        sqlx::query(
            "UPDATE pending_enrollments
             SET consumed_at = ?1, consumed_cert_fp = ?2
             WHERE token_hash = ?3",
        )
        .bind(now_ms as i64)
        .bind(&cert_fp[..])
        .bind(token_hash.as_bytes().as_slice())
        .execute(&self.pool)
        .await
        .map_err(|e| Status::internal(format!("db (token consume): {e}")))?;

        let _ = self
            .audit
            .emit(
                AuditEvent::new(AuditKind::EnrollmentCompleted)
                    .with_payload(&serde_json::json!({ "node_id_hint": req.node_id_hint })),
            )
            .await;

        self.clear_enroll_failures_peer(&peer);

        Ok(Response::new(EnrollResponse {
            client_cert_pem: cert.client_cert_pem,
            ca_chain_pem: cert.ca_chain_pem,
            expires_at_ms: expires_cert_ms as i64,
        }))
    }

    async fn revoke_pending(
        &self,
        request: Request<RevokePendingRequest>,
    ) -> Result<Response<RevokePendingResponse>, Status> {
        self.require_admin(request.metadata())?;

        let now_ms = unix_now_ms()?;
        let req = request.into_inner();
        let token_hash = blake3::hash(&req.opaque_token);

        let result = sqlx::query(
            "UPDATE pending_enrollments
             SET revoked_at = ?1
             WHERE token_hash = ?2
               AND consumed_at IS NULL
               AND revoked_at IS NULL",
        )
        .bind(now_ms as i64)
        .bind(token_hash.as_bytes().as_slice())
        .execute(&self.pool)
        .await
        .map_err(|e| Status::internal(format!("db: {e}")))?;

        let revoked = result.rows_affected() > 0;

        if revoked {
            let _ = self
                .audit
                .emit(
                    AuditEvent::new(AuditKind::EnrollmentRevoked)
                        .with_payload(&serde_json::json!({ "kind": "enrollment.pending_revoked" })),
                )
                .await;
        }

        Ok(Response::new(RevokePendingResponse { revoked }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrollment::ca_client::{stub_cert_pem, StubCaClient};

    const ADMIN_TOKEN: &str = "test-admin-token";

    async fn make_pool() -> SqlitePool {
        let pool = SqlitePool::connect(":memory:").await.unwrap();
        sqlx::migrate!("../../crates/disk-core/migrations")
            .run(&pool)
            .await
            .unwrap();
        pool
    }

    fn make_service(pool: SqlitePool, ca: Arc<dyn CaClient>) -> EnrollmentServiceImpl {
        let audit = AuditEmitter::new(pool.clone());
        EnrollmentServiceImpl::new(pool, audit, ca).with_admin_token(ADMIN_TOKEN)
    }

    fn admin_request<T>(inner: T) -> Request<T> {
        let mut req = Request::new(inner);
        req.metadata_mut()
            .insert("x-disk-admin-token", ADMIN_TOKEN.parse().unwrap());
        req
    }

    #[tokio::test]
    async fn issue_token_requires_admin() {
        let pool = make_pool().await;
        // Service with no token override and no env var — must reject.
        let audit = AuditEmitter::new(pool.clone());
        let svc = EnrollmentServiceImpl::new(pool, audit, Arc::new(StubCaClient::missing_token()));
        let req = Request::new(EnrollmentTokenRequest {
            node_id_hint: "node-1".into(),
            ttl_seconds: 0,
        });
        let err = svc.issue_pending_token(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn issue_token_stores_row_and_returns_token() {
        let pool = make_pool().await;
        let svc = make_service(pool.clone(), Arc::new(StubCaClient::missing_token()));

        let req = admin_request(EnrollmentTokenRequest {
            node_id_hint: "node-2".into(),
            ttl_seconds: 3600,
        });

        let resp = svc.issue_pending_token(req).await.unwrap();
        let inner = resp.into_inner();
        assert_eq!(inner.opaque_token.len(), 32);
        assert!(inner.expires_at_ms > 0);

        // Verify row was stored.
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM pending_enrollments")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count.0, 1);
    }

    #[tokio::test]
    async fn enroll_with_valid_token_marks_consumed() {
        let pool = make_pool().await;
        let cert_pem = stub_cert_pem(0x01);
        let ca = Arc::new(StubCaClient::ok(cert_pem.clone(), b"CHAIN".to_vec()));
        let svc = make_service(pool.clone(), ca);

        // Issue token.
        let token_resp = svc
            .issue_pending_token(admin_request(EnrollmentTokenRequest {
                node_id_hint: "node-3".into(),
                ttl_seconds: 3600,
            }))
            .await
            .unwrap();
        let token = token_resp.into_inner().opaque_token;

        // Enroll with the token.
        let enroll_resp = svc
            .enroll(Request::new(EnrollRequest {
                opaque_token: token,
                csr_pem: b"FAKE-CSR".to_vec(),
                node_id_hint: "node-3".into(),
            }))
            .await
            .unwrap();
        let cert = enroll_resp.into_inner();
        assert_eq!(cert.client_cert_pem, cert_pem);
        assert_eq!(cert.ca_chain_pem, b"CHAIN");

        // Token must be consumed.
        let consumed: (Option<i64>,) =
            sqlx::query_as("SELECT consumed_at FROM pending_enrollments")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(consumed.0.is_some());
    }

    #[tokio::test]
    async fn enroll_replay_returns_failed_precondition() {
        let pool = make_pool().await;
        let cert_pem = stub_cert_pem(0x01);
        let ca = Arc::new(StubCaClient::ok(cert_pem.clone(), b"CHAIN".to_vec()));
        let svc = make_service(pool.clone(), ca);

        let token = svc
            .issue_pending_token(admin_request(EnrollmentTokenRequest {
                node_id_hint: "node-4".into(),
                ttl_seconds: 3600,
            }))
            .await
            .unwrap()
            .into_inner()
            .opaque_token;

        // First enroll succeeds.
        svc.enroll(Request::new(EnrollRequest {
            opaque_token: token.clone(),
            csr_pem: b"CSR".to_vec(),
            node_id_hint: "node-4".into(),
        }))
        .await
        .unwrap();

        // Second enroll is replay → FailedPrecondition.
        let err = svc
            .enroll(Request::new(EnrollRequest {
                opaque_token: token,
                csr_pem: b"CSR".to_vec(),
                node_id_hint: "node-4".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert_eq!(err.message(), EnrollErrorKind::Replay.as_str());
    }

    #[tokio::test]
    async fn enroll_expired_token_returns_failed_precondition() {
        let pool = make_pool().await;
        let cert_pem = stub_cert_pem(0x01);
        let ca = Arc::new(StubCaClient::ok(cert_pem.clone(), b"CHAIN".to_vec()));
        let svc = make_service(pool.clone(), ca);

        // Insert an already-expired token row manually.
        let token = [0xFFu8; 32];
        let token_hash = blake3::hash(&token);
        let past_ms = 1_000i64; // unix ms far in the past
        sqlx::query(
            "INSERT INTO pending_enrollments
             (token_hash, node_id_hint, issued_at, expires_at)
             VALUES (?1, 'node-5', ?2, ?3)",
        )
        .bind(token_hash.as_bytes().as_slice())
        .bind(past_ms)
        .bind(past_ms + 1)
        .execute(&pool)
        .await
        .unwrap();

        let err = svc
            .enroll(Request::new(EnrollRequest {
                opaque_token: token.to_vec(),
                csr_pem: b"CSR".to_vec(),
                node_id_hint: "node-5".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert_eq!(err.message(), EnrollErrorKind::Expired.as_str());
    }

    #[tokio::test]
    async fn revoke_pending_marks_row_revoked() {
        let pool = make_pool().await;
        let svc = make_service(pool.clone(), Arc::new(StubCaClient::missing_token()));

        let token = svc
            .issue_pending_token(admin_request(EnrollmentTokenRequest {
                node_id_hint: "node-6".into(),
                ttl_seconds: 3600,
            }))
            .await
            .unwrap()
            .into_inner()
            .opaque_token;

        // Revoke.
        let resp = svc
            .revoke_pending(admin_request(RevokePendingRequest {
                opaque_token: token.clone(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(resp.revoked);

        // Enrolling after revoke should fail.
        let err = svc
            .enroll(Request::new(EnrollRequest {
                opaque_token: token,
                csr_pem: b"CSR".to_vec(),
                node_id_hint: "node-6".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert_eq!(err.message(), EnrollErrorKind::Revoked.as_str());
    }
}
