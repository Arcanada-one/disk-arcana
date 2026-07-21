//! Integration tests — tenant-scoped file index (DISK-0017).

use std::path::PathBuf;
use std::time::Duration;

use disk_core::meta_db::MetaDb;
use disk_proto::disk::{
    auth_service_client::AuthServiceClient, auth_service_server::AuthServiceServer,
    sync_service_client::SyncServiceClient, sync_service_server::SyncServiceServer, DeltaChunk,
    DeltaUploadRequest, NodeAuthRequest, NodeRegisterRequest,
};
use disk_server::{AuthServiceImpl, AuthStore, SyncServiceImpl};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use tempfile::tempdir;
use tonic::{
    transport::{Certificate, ClientTlsConfig, Endpoint, Server, ServerTlsConfig},
    Request,
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
        .unwrap()
}

async fn spawn_server(sync_root: PathBuf, meta_db: MetaDb) -> (u16, String) {
    let store = AuthStore::new();
    let CertifiedKey {
        cert,
        signing_key: key_pair,
    } = generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    let auth_svc =
        AuthServiceServer::new(AuthServiceImpl::new(store.clone()).with_meta_db(meta_db.clone()));
    let sync_impl = SyncServiceImpl::new(store, sync_root).with_meta_db(meta_db, "server-test");
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

async fn register_and_auth(ch: &tonic::transport::Channel, node_id: &str, tenant: &str) -> String {
    let mut auth = AuthServiceClient::new(ch.clone());
    let mut reg = Request::new(NodeRegisterRequest {
        node_id: node_id.into(),
        display_name: "T".into(),
        platform: "test".into(),
        tenant_id: tenant.into(),
        ..Default::default()
    });
    reg.metadata_mut()
        .insert("x-disk-tenant", tenant.parse().unwrap());
    let api_key = auth.register_node(reg).await.unwrap().into_inner().api_key;

    auth.authenticate(Request::new(NodeAuthRequest {
        node_id: node_id.into(),
        api_key,
    }))
    .await
    .unwrap()
    .into_inner()
    .session_token
}

fn upload_req(
    path: &str,
    bytes: &[u8],
    token: &str,
    tenant: &str,
    share: &str,
) -> Request<tokio_stream::Iter<std::vec::IntoIter<DeltaUploadRequest>>> {
    let content_hash = disk_core::delta::blake3_hash(bytes);
    let msgs = vec![DeltaUploadRequest {
        path: path.into(),
        content_hash: content_hash.to_vec(),
        chunks: vec![DeltaChunk {
            offset: 0,
            weak_checksum: 0,
            strong_hash: content_hash.to_vec(),
            data: bytes.to_vec(),
        }],
        ..Default::default()
    }];
    let mut req = Request::new(tokio_stream::iter(msgs));
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req.metadata_mut()
        .insert("x-disk-tenant", tenant.parse().unwrap());
    req.metadata_mut()
        .insert("x-disk-share", share.parse().unwrap());
    req
}

#[tokio::test]
async fn same_path_isolated_per_tenant() {
    let root = tempdir().unwrap();
    let db_path = root.path().join("mt.db");
    let meta_db = MetaDb::open(&db_path).await.unwrap();
    let meta_check = meta_db.clone();
    let sync_root = root.path().to_path_buf();

    let (port, cert_pem) = spawn_server(sync_root, meta_db).await;
    let ch = connect(port, &cert_pem).await;

    let tok_a = register_and_auth(&ch, "node-a", "tenant-a").await;
    let tok_b = register_and_auth(&ch, "node-b", "tenant-b").await;

    let body_a: Vec<u8> = vec![0xAA; 16];
    let body_b: Vec<u8> = vec![0xBB; 32];

    let mut sync = SyncServiceClient::new(ch);
    sync.delta_upload(upload_req(
        "docs/x.bin",
        &body_a,
        &tok_a,
        "tenant-a",
        "default",
    ))
    .await
    .unwrap();
    sync.delta_upload(upload_req(
        "docs/x.bin",
        &body_b,
        &tok_b,
        "tenant-b",
        "default",
    ))
    .await
    .unwrap();

    let row_a = meta_check
        .get_file_scoped(Some("tenant-a"), "default", "docs/x.bin")
        .await
        .unwrap()
        .unwrap();
    let row_b = meta_check
        .get_file_scoped(Some("tenant-b"), "default", "docs/x.bin")
        .await
        .unwrap()
        .unwrap();

    assert_eq!(row_a.size, 16);
    assert_eq!(row_b.size, 32);

    let tenant = meta_check.get_node_tenant("node-a").await.unwrap();
    assert_eq!(tenant.as_deref(), Some("tenant-a"));
}

#[tokio::test]
async fn register_node_persists_tenant() {
    let root = tempdir().unwrap();
    let db_path = root.path().join("mt2.db");
    let meta_db = MetaDb::open(&db_path).await.unwrap();
    let (port, cert_pem) = spawn_server(root.path().to_path_buf(), meta_db.clone()).await;
    let ch = connect(port, &cert_pem).await;
    let _ = register_and_auth(&ch, "persist-node", "corp-1").await;
    assert_eq!(
        meta_db
            .get_node_tenant("persist-node")
            .await
            .unwrap()
            .as_deref(),
        Some("corp-1")
    );
}
