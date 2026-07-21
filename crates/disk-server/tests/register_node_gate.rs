//! Integration tests — `RegisterNode` production gate (OWASP T2.10).

use disk_proto::disk::{auth_service_server::AuthService, NodeRegisterRequest};
use disk_server::auth::CertIdentity;
use disk_server::config::RegisterNodeMode;
use disk_server::{AuthServiceImpl, AuthStore};
use rustls::pki_types::CertificateDer;
use sqlx::SqlitePool;
use tonic::{Code, Request};

async fn make_pool() -> SqlitePool {
    let pool = SqlitePool::connect(":memory:").await.unwrap();
    sqlx::migrate!("../../crates/disk-core/migrations")
        .run(&pool)
        .await
        .unwrap();
    pool
}

async fn insert_enrolled_node(pool: &SqlitePool, node_id: &str, fp: &[u8; 32]) {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    sqlx::query(
        "INSERT INTO nodes (node_id, display_name, platform, api_key_hash, registered_at)
         VALUES (?1, ?1, 'linux', '', ?2)",
    )
    .bind(node_id)
    .bind(now_ms)
    .execute(pool)
    .await
    .unwrap();

    let (id,): (i64,) = sqlx::query_as("SELECT id FROM nodes WHERE node_id = ?1")
        .bind(node_id)
        .fetch_one(pool)
        .await
        .unwrap();

    sqlx::query(
        "INSERT INTO node_certs (cert_fingerprint, node_id, enrolled_at, expires_at)
         VALUES (?1, ?2, ?3, ?4)",
    )
    .bind(&fp[..])
    .bind(id)
    .bind(now_ms)
    .bind(now_ms + 86_400_000)
    .execute(pool)
    .await
    .unwrap();
}

fn register_request_with_cert(node_id: &str, der: &[u8]) -> Request<NodeRegisterRequest> {
    let mut req = Request::new(NodeRegisterRequest {
        node_id: node_id.into(),
        display_name: "gate-test".into(),
        platform: "linux".into(),
        ..Default::default()
    });
    req.extensions_mut()
        .insert(CertificateDer::from(der.to_vec()));
    req
}

#[tokio::test]
async fn enrolled_mode_allows_matching_cert() {
    let pool = make_pool().await;
    let der = vec![0x42u8; 64];
    let fp = CertIdentity::from_der(&der).fingerprint;
    insert_enrolled_node(&pool, "node-enrolled", &fp).await;

    let svc = AuthServiceImpl::new(AuthStore::new()).with_register_gate(
        RegisterNodeMode::Enrolled,
        pool,
        None,
    );

    let resp = svc
        .register_node(register_request_with_cert("node-enrolled", &der))
        .await
        .unwrap()
        .into_inner();
    assert!(resp.api_key.starts_with("arc_disk_"));
}

#[tokio::test]
async fn enrolled_mode_rejects_without_cert() {
    let pool = make_pool().await;
    insert_enrolled_node(&pool, "node-enrolled", &[0x11; 32]).await;

    let svc = AuthServiceImpl::new(AuthStore::new()).with_register_gate(
        RegisterNodeMode::Enrolled,
        pool,
        None,
    );

    let err = svc
        .register_node(Request::new(NodeRegisterRequest {
            node_id: "node-enrolled".into(),
            ..Default::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);
}

#[tokio::test]
async fn enrolled_mode_rejects_cert_node_mismatch() {
    let pool = make_pool().await;
    let der = vec![0x55u8; 64];
    let fp = CertIdentity::from_der(&der).fingerprint;
    insert_enrolled_node(&pool, "node-a", &fp).await;

    let svc = AuthServiceImpl::new(AuthStore::new()).with_register_gate(
        RegisterNodeMode::Enrolled,
        pool,
        None,
    );

    let err = svc
        .register_node(register_request_with_cert("node-b", &der))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
}

#[tokio::test]
async fn disabled_mode_rejects_register() {
    let pool = make_pool().await;
    let svc = AuthServiceImpl::new(AuthStore::new()).with_register_gate(
        RegisterNodeMode::Disabled,
        pool,
        None,
    );

    let err = svc
        .register_node(Request::new(NodeRegisterRequest {
            node_id: "any".into(),
            ..Default::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
}

#[tokio::test]
async fn admin_mode_requires_bearer() {
    let pool = make_pool().await;
    let svc = AuthServiceImpl::new(AuthStore::new()).with_register_gate(
        RegisterNodeMode::Admin,
        pool,
        Some("admin-secret".into()),
    );

    let err = svc
        .register_node(Request::new(NodeRegisterRequest {
            node_id: "admin-node".into(),
            ..Default::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);

    let mut req = Request::new(NodeRegisterRequest {
        node_id: "admin-node".into(),
        ..Default::default()
    });
    req.metadata_mut()
        .insert("x-disk-admin-token", "admin-secret".parse().unwrap());

    svc.register_node(req).await.unwrap();
}
