//! Integration test — enrollment with an already-expired token.
//!
//! Step 19 P4b: token with `expires_at` in the past must return
//! `FailedPrecondition` + `EnrollErrorKind::Expired`.

use std::sync::Arc;

use disk_proto::disk::{enrollment_service_server::EnrollmentService, EnrollRequest};
use disk_server::enrollment::{
    ca_client::{stub_cert_pem, StubCaClient},
    EnrollErrorKind, EnrollmentServiceImpl,
};
use sqlx::SqlitePool;
use tonic::Request;

async fn make_pool() -> SqlitePool {
    let pool = SqlitePool::connect(":memory:").await.unwrap();
    sqlx::migrate!("../../crates/disk-core/migrations")
        .run(&pool)
        .await
        .unwrap();
    pool
}

const ADMIN_TOK: &str = "integ-admin-expired";

fn make_svc(pool: SqlitePool) -> EnrollmentServiceImpl {
    let audit = disk_server::audit::AuditEmitter::new(pool.clone());
    EnrollmentServiceImpl::new(
        pool,
        audit,
        Arc::new(StubCaClient::ok(stub_cert_pem(0x22), b"CHAIN".to_vec())),
    )
    .with_admin_token(ADMIN_TOK)
}

#[tokio::test]
async fn expired_token_returns_failed_precondition() {
    let pool = make_pool().await;
    let svc = make_svc(pool.clone());

    // Insert a token row with `expires_at` 1ms after epoch (always expired).
    let token = [0xEEu8; 32];
    let token_hash = blake3::hash(&token);
    sqlx::query(
        "INSERT INTO pending_enrollments
         (token_hash, node_id_hint, issued_at, expires_at)
         VALUES (?1, 'expired-node', 1, 2)",
    )
    .bind(token_hash.as_bytes().as_slice())
    .execute(&pool)
    .await
    .unwrap();

    let err = svc
        .enroll(Request::new(EnrollRequest {
            opaque_token: token.to_vec(),
            csr_pem: b"CSR".to_vec(),
            node_id_hint: "expired-node".into(),
        }))
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert_eq!(err.message(), EnrollErrorKind::Expired.as_str());
}
