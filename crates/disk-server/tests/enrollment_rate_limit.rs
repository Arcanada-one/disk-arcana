//! Integration: public `Enroll` returns `ResourceExhausted` after repeated failures per peer IP.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use disk_proto::disk::{enrollment_service_server::EnrollmentService, EnrollRequest};
use disk_server::auth::rate_limit::AuthAttemptLimiter;
use disk_server::enrollment::{ca_client::StubCaClient, EnrollmentServiceImpl};
use sqlx::SqlitePool;
use tonic::{transport::server::TcpConnectInfo, Code, Request};

const PEER: &str = "198.51.100.42:4242";

async fn make_pool() -> SqlitePool {
    let pool = SqlitePool::connect(":memory:").await.unwrap();
    sqlx::migrate!("../../crates/disk-core/migrations")
        .run(&pool)
        .await
        .unwrap();
    pool
}

fn enroll_request(token: Vec<u8>) -> Request<EnrollRequest> {
    let mut req = Request::new(EnrollRequest {
        opaque_token: token,
        csr_pem: b"CSR".to_vec(),
        node_id_hint: "rl-enroll-node".into(),
    });
    req.extensions_mut().insert(TcpConnectInfo {
        local_addr: Some("127.0.0.1:9445".parse().unwrap()),
        remote_addr: Some(PEER.parse::<SocketAddr>().unwrap()),
    });
    req
}

#[tokio::test]
async fn enroll_rate_limited_resource_exhausted() {
    let pool = make_pool().await;
    let limiter = Arc::new(AuthAttemptLimiter::new(5, Duration::from_secs(60)));
    let audit = disk_server::audit::AuditEmitter::new(pool.clone());
    let svc = EnrollmentServiceImpl::with_rate_limiter(
        pool,
        audit,
        Arc::new(StubCaClient::ok(b"CERT".to_vec(), b"CHAIN".to_vec())),
        Some(limiter),
    );

    for _ in 0..5 {
        let err = svc
            .enroll(enroll_request(vec![0xAA; 32]))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
    }

    let err = svc
        .enroll(enroll_request(vec![0xBB; 32]))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted);
    assert!(
        err.message().contains("retry after"),
        "expected retry hint in message: {}",
        err.message()
    );
}
