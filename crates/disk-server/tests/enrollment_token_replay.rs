//! Integration test — enrollment token replay rejection.
//!
//! Step 19 P4b: second Enroll call with the same token must return
//! `FailedPrecondition` + `EnrollErrorKind::Replay`.

use std::sync::Arc;

use disk_proto::disk::{
    enrollment_service_server::EnrollmentService, EnrollRequest, EnrollmentTokenRequest,
    RevokePendingRequest,
};
use disk_server::enrollment::{ca_client::StubCaClient, EnrollErrorKind, EnrollmentServiceImpl};
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

const ADMIN_TOK: &str = "integ-admin-replay";

fn admin_request<T>(inner: T) -> Request<T> {
    let mut req = Request::new(inner);
    req.metadata_mut()
        .insert("x-disk-admin-token", ADMIN_TOK.parse().unwrap());
    req
}

fn make_svc(pool: SqlitePool) -> EnrollmentServiceImpl {
    let audit = disk_server::audit::AuditEmitter::new(pool.clone());
    EnrollmentServiceImpl::new(
        pool,
        audit,
        Arc::new(StubCaClient::ok(b"CERT".to_vec(), b"CHAIN".to_vec())),
    )
    .with_admin_token(ADMIN_TOK)
}

#[tokio::test]
async fn token_used_twice_returns_replay() {
    let pool = make_pool().await;
    let svc = make_svc(pool);

    // Issue one token.
    let token = svc
        .issue_pending_token(admin_request(EnrollmentTokenRequest {
            node_id_hint: "replay-node".into(),
            ttl_seconds: 3600,
        }))
        .await
        .unwrap()
        .into_inner()
        .opaque_token;

    // First Enroll succeeds.
    svc.enroll(Request::new(EnrollRequest {
        opaque_token: token.clone(),
        csr_pem: b"CSR".to_vec(),
        node_id_hint: "replay-node".into(),
    }))
    .await
    .expect("first enroll should succeed");

    // Second Enroll → replay.
    let err = svc
        .enroll(Request::new(EnrollRequest {
            opaque_token: token,
            csr_pem: b"CSR".to_vec(),
            node_id_hint: "replay-node".into(),
        }))
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert_eq!(err.message(), EnrollErrorKind::Replay.as_str());
}

#[tokio::test]
async fn revoked_token_enrolls_with_revoked_error() {
    let pool = make_pool().await;
    let svc = make_svc(pool);

    let token = svc
        .issue_pending_token(admin_request(EnrollmentTokenRequest {
            node_id_hint: "revoke-before-enroll".into(),
            ttl_seconds: 3600,
        }))
        .await
        .unwrap()
        .into_inner()
        .opaque_token;

    // Revoke.
    svc.revoke_pending(admin_request(RevokePendingRequest {
        opaque_token: token.clone(),
    }))
    .await
    .unwrap();

    // Enroll → revoked.
    let err = svc
        .enroll(Request::new(EnrollRequest {
            opaque_token: token,
            csr_pem: b"CSR".to_vec(),
            node_id_hint: "revoke-before-enroll".into(),
        }))
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert_eq!(err.message(), EnrollErrorKind::Revoked.as_str());
}
