//! Two-node integration test: real TCP loopback, real TLS.
//!
//! Tests three scenarios (V-7):
//!   1. Clean sync: register → authenticate → delta_download → assert file equality.
//!   2. Path traversal rejection (V-11).
//!   3. Unauthenticated access to SyncService rejected (V-12).
//!
//! DISK-0004 Step 14.

use std::time::Duration;

use disk_proto::disk::{
    auth_service_client::AuthServiceClient, auth_service_server::AuthServiceServer,
    sync_service_client::SyncServiceClient, sync_service_server::SyncServiceServer,
    DeltaDownloadRequest, NodeAuthRequest, NodeRegisterRequest,
};
use disk_server::{AuthServiceImpl, AuthStore, SyncServiceImpl};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use tempfile::tempdir;
use tokio_stream::StreamExt;
use tonic::{
    transport::{Certificate, ClientTlsConfig, Endpoint, Server, ServerTlsConfig},
    Request,
};

/// Spawn a `disk-arcana-server` on an ephemeral port.
/// Returns `(port, store, cert_pem)`.
async fn spawn_server(root: std::path::PathBuf) -> (u16, AuthStore, String) {
    let store = AuthStore::new();

    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    let auth_svc = AuthServiceServer::new(AuthServiceImpl::new(store.clone()));
    let sync_svc = SyncServiceServer::new(SyncServiceImpl::new(store.clone(), root));

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
    (port, store, cert_pem)
}

async fn make_channel(port: u16, cert_pem: &str) -> tonic::transport::Channel {
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

// -------------------------------------------------------------------------
// Scenario 1: Clean sync — register, authenticate, delta_download file
// -------------------------------------------------------------------------

#[tokio::test]
async fn scenario_clean_sync() {
    let root = tempdir().unwrap();
    let content: Vec<u8> = (0u8..=255u8).cycle().take(12_000).collect();
    std::fs::write(root.path().join("vault.md"), &content).unwrap();

    let (port, _store, cert_pem) = spawn_server(root.path().to_path_buf()).await;
    let ch = make_channel(port, &cert_pem).await;

    let mut auth = AuthServiceClient::new(ch.clone());
    let reg = auth
        .register_node(Request::new(NodeRegisterRequest {
            node_id: "client-a".into(),
            display_name: "Client A".into(),
            platform: "test".into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(reg.api_key.starts_with("arc_disk_"));

    let tok = auth
        .authenticate(Request::new(NodeAuthRequest {
            node_id: "client-a".into(),
            api_key: reg.api_key,
        }))
        .await
        .unwrap()
        .into_inner()
        .session_token;
    assert!(tok.starts_with("arc_disk_sess_"));

    let mut sync = SyncServiceClient::new(ch);
    let mut req = Request::new(DeltaDownloadRequest {
        path: "vault.md".into(),
        ..Default::default()
    });
    req.metadata_mut()
        .insert("authorization", format!("Bearer {tok}").parse().unwrap());
    let resp = sync.delta_download(req).await.unwrap();
    let mut stream = resp.into_inner();
    let mut reassembled = Vec::new();
    while let Some(c) = stream.next().await {
        reassembled.extend_from_slice(&c.unwrap().data);
    }
    assert_eq!(reassembled, content, "reassembled file must match original");
}

// -------------------------------------------------------------------------
// Scenario 2: Path traversal rejected (V-11)
// -------------------------------------------------------------------------

#[tokio::test]
async fn scenario_path_traversal_rejected() {
    let root = tempdir().unwrap();
    let (port, _store, cert_pem) = spawn_server(root.path().to_path_buf()).await;
    let ch = make_channel(port, &cert_pem).await;

    let mut auth = AuthServiceClient::new(ch.clone());
    let reg = auth
        .register_node(Request::new(NodeRegisterRequest {
            node_id: "traversal-node".into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    let tok = auth
        .authenticate(Request::new(NodeAuthRequest {
            node_id: "traversal-node".into(),
            api_key: reg.api_key,
        }))
        .await
        .unwrap()
        .into_inner()
        .session_token;

    let mut sync = SyncServiceClient::new(ch);
    let mut req = Request::new(DeltaDownloadRequest {
        path: "../../etc/passwd".into(),
        ..Default::default()
    });
    req.metadata_mut()
        .insert("authorization", format!("Bearer {tok}").parse().unwrap());
    let err = sync.delta_download(req).await.unwrap_err();
    assert_eq!(
        err.code(),
        tonic::Code::InvalidArgument,
        "path traversal must be rejected as InvalidArgument"
    );
}

// -------------------------------------------------------------------------
// Scenario 3: Unauthenticated access to SyncService rejected (V-12)
// -------------------------------------------------------------------------

#[tokio::test]
async fn scenario_unauthenticated_rejected() {
    let root = tempdir().unwrap();
    let (port, _store, cert_pem) = spawn_server(root.path().to_path_buf()).await;
    let ch = make_channel(port, &cert_pem).await;

    let mut sync = SyncServiceClient::new(ch);
    let req = Request::new(DeltaDownloadRequest {
        path: "any.md".into(),
        ..Default::default()
    });
    let err = sync.delta_download(req).await.unwrap_err();
    assert_eq!(
        err.code(),
        tonic::Code::Unauthenticated,
        "no-auth request must be Unauthenticated"
    );
}
