//! exchange_state tenant-scoped server index (DISK-0017 slice 3).

use std::path::PathBuf;
use std::time::Duration;

use disk_core::meta_db::MetaDb;
use disk_core::types::FileMeta;
use disk_core::vector_clock::VectorClock;
use disk_proto::disk::{
    auth_service_client::AuthServiceClient, auth_service_server::AuthServiceServer,
    sync_service_client::SyncServiceClient, sync_service_server::SyncServiceServer,
    NodeAuthRequest, NodeRegisterRequest, SyncStateRequest,
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

fn file_meta(path: &str, hash_byte: u8) -> FileMeta {
    FileMeta {
        path: PathBuf::from(path),
        content_hash: [hash_byte; 32],
        size: 8,
        mtime_ns: 1,
        inode: None,
        vector_clock: VectorClock::default(),
        deleted: false,
        deleted_at: None,
        node_id: "server-test".into(),
        encryption_nonce: None,
        version_id: None,
        parent_version_id: None,
    }
}

async fn register_and_auth(ch: &tonic::transport::Channel, node_id: &str, tenant: &str) -> String {
    let mut auth = AuthServiceClient::new(ch.clone());
    let mut reg = Request::new(NodeRegisterRequest {
        node_id: node_id.into(),
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

#[tokio::test]
async fn exchange_state_only_sees_own_tenant_files() {
    let root = tempdir().unwrap();
    let meta_db = MetaDb::open(&root.path().join("exchange-tenant.db"))
        .await
        .unwrap();

    meta_db
        .upsert_file_scoped(
            Some("tenant-a"),
            "default",
            &file_meta("shared/doc.bin", 0xAA),
        )
        .await
        .unwrap();
    meta_db
        .upsert_file_scoped(
            Some("tenant-b"),
            "default",
            &file_meta("shared/doc.bin", 0xBB),
        )
        .await
        .unwrap();

    let (port, cert_pem) = spawn_server(root.path().to_path_buf(), meta_db).await;
    let ch = connect(port, &cert_pem).await;
    let token = register_and_auth(&ch, "node-a", "tenant-a").await;

    let mut sync = SyncServiceClient::new(ch);
    let mut req = Request::new(SyncStateRequest {
        node_id: "node-a".into(),
        session_token: token.clone(),
        files: vec![],
        node_clock: Default::default(),
        tenant_id: "tenant-a".into(),
        vault_id: String::new(),
    });
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req.metadata_mut()
        .insert("x-disk-share", "default".parse().unwrap());
    req.metadata_mut()
        .insert("x-disk-tenant", "tenant-a".parse().unwrap());

    let resp = sync.exchange_state(req).await.unwrap().into_inner();
    assert_eq!(resp.to_download.len(), 1);
    assert_eq!(resp.to_download[0].path, "shared/doc.bin");
    assert_eq!(resp.to_download[0].content_hash, vec![0xAA; 32]);
}
