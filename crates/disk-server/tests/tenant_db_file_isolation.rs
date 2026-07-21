//! Per-tenant SQLite file isolation (DISK-0017 slice 4).

use std::path::PathBuf;
use std::time::Duration;

use disk_core::meta_db::MetaDb;
use disk_core::types::FileMeta;
use disk_core::{TenantMetaRouter, VectorClock};
use disk_proto::disk::{
    auth_service_client::AuthServiceClient, auth_service_server::AuthServiceServer,
    sync_service_client::SyncServiceClient, sync_service_server::SyncServiceServer,
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

async fn spawn_split_server(sync_root: PathBuf, router: TenantMetaRouter) -> (u16, String) {
    let store = AuthStore::new();
    let CertifiedKey {
        cert,
        signing_key: key_pair,
    } = generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    let auth_svc =
        AuthServiceServer::new(AuthServiceImpl::new(store.clone()).with_meta_db(router.control()));
    let sync_impl = SyncServiceImpl::new(store, sync_root).with_meta_router(router, "server-test");
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
        node_id: "server".into(),
        encryption_nonce: None,
        version_id: None,
        parent_version_id: None,
    }
}

#[tokio::test]
async fn upload_lands_in_tenant_shard_file() {
    let root = tempdir().unwrap();
    let control = MetaDb::open(&root.path().join("control.sqlite"))
        .await
        .unwrap();
    let router = TenantMetaRouter::split(control, root.path().join("tenants"));

    let (port, cert_pem) = spawn_split_server(root.path().join("sync"), router.clone()).await;
    std::fs::create_dir_all(root.path().join("sync")).unwrap();
    let ch = connect(port, &cert_pem).await;
    let mut auth = AuthServiceClient::new(ch.clone());

    let reg = auth
        .register_node(Request::new(NodeRegisterRequest {
            node_id: "node-a".into(),
            display_name: "A".into(),
            platform: "test".into(),
            tenant_id: "acme".into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    let token = auth
        .authenticate(Request::new(NodeAuthRequest {
            node_id: "node-a".into(),
            api_key: reg.api_key,
        }))
        .await
        .unwrap()
        .into_inner()
        .session_token;

    let bytes = b"tenant-payload";
    let hash = disk_core::delta::blake3_hash(bytes);
    let mut upload = Request::new(tokio_stream::iter(vec![DeltaUploadRequest {
        path: "docs/a.md".into(),
        content_hash: hash.to_vec(),
        chunks: vec![disk_proto::disk::DeltaChunk {
            offset: 0,
            weak_checksum: 0,
            strong_hash: hash.to_vec(),
            data: bytes.to_vec(),
        }],
        ..Default::default()
    }]));
    upload
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    upload
        .metadata_mut()
        .insert("x-disk-tenant", "acme".parse().unwrap());

    let mut sync = SyncServiceClient::new(ch);
    sync.delta_upload(upload).await.unwrap();

    let acme_db = router.tenant_data(Some("acme")).await.unwrap();
    assert!(acme_db
        .get_file_scoped(Some("acme"), "default", "docs/a.md")
        .await
        .unwrap()
        .is_some());

    let beta_db = router.tenant_data(Some("beta")).await.unwrap();
    assert!(beta_db
        .get_file_scoped(Some("beta"), "default", "docs/a.md")
        .await
        .unwrap()
        .is_none());

    assert!(root.path().join("tenants/acme/meta.sqlite").exists());
    assert!(
        !root.path().join("tenants/beta/meta.sqlite").exists()
            || beta_db
                .get_file_scoped(Some("beta"), "default", "docs/a.md")
                .await
                .unwrap()
                .is_none()
    );
}

#[tokio::test]
async fn exchange_state_reads_tenant_shard_only() {
    let root = tempdir().unwrap();
    let control = MetaDb::open(&root.path().join("control.sqlite"))
        .await
        .unwrap();
    let router = TenantMetaRouter::split(control, root.path().join("tenants"));

    router
        .tenant_data(Some("acme"))
        .await
        .unwrap()
        .upsert_file_scoped(Some("acme"), "wiki", &file_meta("only-acme.md", 0x11))
        .await
        .unwrap();
    router
        .tenant_data(Some("beta"))
        .await
        .unwrap()
        .upsert_file_scoped(Some("beta"), "wiki", &file_meta("only-beta.md", 0x22))
        .await
        .unwrap();

    let (port, cert_pem) = spawn_split_server(root.path().join("sync"), router).await;
    let ch = connect(port, &cert_pem).await;
    let mut auth = AuthServiceClient::new(ch.clone());

    let reg = auth
        .register_node(Request::new(NodeRegisterRequest {
            node_id: "node-b".into(),
            display_name: "B".into(),
            platform: "test".into(),
            tenant_id: "acme".into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    let token = auth
        .authenticate(Request::new(NodeAuthRequest {
            node_id: "node-b".into(),
            api_key: reg.api_key,
        }))
        .await
        .unwrap()
        .into_inner()
        .session_token;

    let mut req = Request::new(disk_proto::disk::SyncStateRequest {
        node_id: "node-b".into(),
        session_token: token.clone(),
        files: vec![],
        ..Default::default()
    });
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req.metadata_mut()
        .insert("x-disk-tenant", "acme".parse().unwrap());
    req.metadata_mut()
        .insert("x-disk-share", "wiki".parse().unwrap());

    let resp = SyncServiceClient::new(ch)
        .exchange_state(req)
        .await
        .unwrap()
        .into_inner();

    let paths: Vec<_> = resp.to_download.iter().map(|f| f.path.as_str()).collect();
    assert!(paths.contains(&"only-acme.md"));
    assert!(!paths.contains(&"only-beta.md"));
}
