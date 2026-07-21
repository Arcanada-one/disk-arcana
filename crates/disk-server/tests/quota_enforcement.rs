//! Integration tests for storage quota enforcement (DISK-0018).

use std::path::PathBuf;
use std::time::Duration;

use disk_core::billing::{PlanTier, QuotaLimits};
use disk_core::meta_db::MetaDb;
use disk_core::types::FileMeta;
use disk_core::VectorClock;
use disk_proto::disk::{
    auth_service_client::AuthServiceClient, auth_service_server::AuthServiceServer,
    sync_service_client::SyncServiceClient, sync_service_server::SyncServiceServer,
    DeltaChunk, DeltaUploadRequest, NodeAuthRequest, NodeRegisterRequest,
};
use disk_server::{AuthServiceImpl, AuthStore, BillingMode, QuotaEnforcer, SyncServiceImpl};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use tempfile::tempdir;
use tonic::{
    transport::{Certificate, ClientTlsConfig, Endpoint, Server, ServerTlsConfig},
    Code, Request,
};

async fn connect(port: u16, cert_pem: &str) -> tonic::transport::Channel {
    let ca = Certificate::from_pem(cert_pem);
    let tls = ClientTlsConfig::new()
        .ca_certificate(ca)
        .domain_name("localhost");
    Endpoint::new(format!("https://localhost:{port}"))
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect()
        .await
        .expect("connect to test server")
}

async fn authenticate(ch: &tonic::transport::Channel, node_id: &str) -> String {
    let mut auth = AuthServiceClient::new(ch.clone());
    let reg = auth
        .register_node(Request::new(NodeRegisterRequest {
            node_id: node_id.into(),
            display_name: "Test Node".into(),
            platform: "test".into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();

    auth.authenticate(Request::new(NodeAuthRequest {
        node_id: node_id.into(),
        api_key: reg.api_key,
    }))
    .await
    .unwrap()
    .into_inner()
    .session_token
}

fn make_upload_request(
    path: &str,
    bytes: &[u8],
    token: &str,
    share: &str,
) -> Request<tokio_stream::Iter<std::vec::IntoIter<DeltaUploadRequest>>> {
    let content_hash = disk_core::delta::blake3_hash(bytes);
    let proto_chunk = DeltaChunk {
        offset: 0,
        weak_checksum: 0,
        strong_hash: content_hash.to_vec(),
        data: bytes.to_vec(),
    };
    let msgs = vec![DeltaUploadRequest {
        path: path.to_owned(),
        content_hash: content_hash.to_vec(),
        chunks: vec![proto_chunk],
        ..Default::default()
    }];
    let stream = tokio_stream::iter(msgs);
    let mut req = Request::new(stream);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req.metadata_mut()
        .insert("x-disk-share", share.parse().unwrap());
    req
}

async fn spawn_server_with_quota(
    sync_root: PathBuf,
    meta_db: MetaDb,
    limits: QuotaLimits,
) -> (u16, String) {
    let store = AuthStore::new();
    let CertifiedKey {
        cert,
        signing_key: key_pair,
    } = generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    let enforcer = QuotaEnforcer::new(BillingMode::Enforce, meta_db.clone())
        .unwrap()
        .with_test_limits(limits);

    let auth_svc = AuthServiceServer::new(AuthServiceImpl::new(store.clone()));
    let sync_impl = SyncServiceImpl::new(store.clone(), sync_root)
        .with_meta_db(meta_db, "server-test")
        .with_quota_enforcer(enforcer);
    let sync_svc = SyncServiceServer::new(sync_impl);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    let server_tls = ServerTlsConfig::new().identity(tonic::transport::Identity::from_pem(
        cert_pem.clone(),
        key_pem,
    ));

    tokio::spawn(async move {
        Server::builder()
            .tls_config(server_tls)
            .unwrap()
            .add_service(auth_svc)
            .add_service(sync_svc)
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    tokio::time::sleep(Duration::from_millis(80)).await;
    (port, cert_pem)
}

#[tokio::test]
async fn upload_rejected_when_storage_quota_exceeded() {
    let root = tempdir().unwrap();
    let db_path = root.path().join("meta.db");
    let meta_db = MetaDb::open(&db_path).await.unwrap();
    meta_db.set_plan_tier(None, PlanTier::Free).await.unwrap();

    let existing = FileMeta {
        path: "seed.bin".into(),
        content_hash: [0u8; 32],
        size: 90,
        mtime_ns: 1,
        inode: None,
        vector_clock: VectorClock::new(),
        deleted: false,
        deleted_at: None,
        node_id: "seed".into(),
        encryption_nonce: None,
    };
    meta_db.upsert_file(&existing).await.unwrap();

    let limits = QuotaLimits {
        max_storage_bytes: 100,
        max_nodes: 1,
        max_vaults: 1,
    };

    let sync_root = root.path().to_path_buf();
    let (port, cert_pem) = spawn_server_with_quota(sync_root, meta_db, limits).await;
    let ch = connect(port, &cert_pem).await;
    let tok = authenticate(&ch, "quota-uploader").await;

    let content: Vec<u8> = vec![1u8; 20];
    let req = make_upload_request("new.bin", &content, &tok, "default");

    let mut sync = SyncServiceClient::new(ch);
    let err = sync.delta_upload(req).await.unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted);
    assert!(
        err.message().contains("storage quota"),
        "expected quota message, got: {}",
        err.message()
    );
}

#[tokio::test]
async fn upload_allowed_when_within_quota() {
    let root = tempdir().unwrap();
    let db_path = root.path().join("meta.db");
    let meta_db = MetaDb::open(&db_path).await.unwrap();

    let limits = QuotaLimits {
        max_storage_bytes: 1_000,
        max_nodes: 1,
        max_vaults: 1,
    };

    let sync_root = root.path().to_path_buf();
    let (port, cert_pem) = spawn_server_with_quota(sync_root.clone(), meta_db, limits).await;
    let ch = connect(port, &cert_pem).await;
    let tok = authenticate(&ch, "ok-uploader").await;

    let content: Vec<u8> = vec![7u8; 50];
    let req = make_upload_request("ok.bin", &content, &tok, "default");

    let mut sync = SyncServiceClient::new(ch);
    let resp = sync.delta_upload(req).await.unwrap().into_inner();
    assert!(resp.accepted);
    assert_eq!(std::fs::read(sync_root.join("ok.bin")).unwrap(), content);
}
