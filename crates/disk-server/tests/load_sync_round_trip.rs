//! Local multi-node sync harness (DISK-0012 / G3 / T6.2 tail).
//!
//! Ignored in default `cargo test` — run via `scripts/load-test-sync-smoke.sh`.

use std::time::{Duration, Instant};

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

async fn spawn_server(root: std::path::PathBuf) -> (u16, String) {
    let store = AuthStore::new();
    let CertifiedKey {
        cert,
        signing_key: key_pair,
    } = generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    let auth_svc = AuthServiceServer::new(AuthServiceImpl::new(store.clone()));
    let sync_svc = SyncServiceServer::new(SyncServiceImpl::new(store, root));

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

async fn register_and_authenticate(
    ch: tonic::transport::Channel,
    node_id: &str,
) -> (AuthServiceClient<tonic::transport::Channel>, String) {
    let mut auth = AuthServiceClient::new(ch);
    let reg = auth
        .register_node(Request::new(NodeRegisterRequest {
            node_id: node_id.into(),
            display_name: node_id.into(),
            platform: "load-harness".into(),
            ..Default::default()
        }))
        .await
        .expect("register_node")
        .into_inner();
    let token = auth
        .authenticate(Request::new(NodeAuthRequest {
            node_id: node_id.into(),
            api_key: reg.api_key,
        }))
        .await
        .expect("authenticate")
        .into_inner()
        .session_token;
    (auth, token)
}

async fn download_file(ch: tonic::transport::Channel, session_token: &str, path: &str) -> Vec<u8> {
    let mut sync = SyncServiceClient::new(ch);
    let mut req = Request::new(DeltaDownloadRequest {
        path: path.into(),
        ..Default::default()
    });
    req.metadata_mut().insert(
        "authorization",
        format!("Bearer {session_token}").parse().unwrap(),
    );
    let resp = sync.delta_download(req).await.expect("delta_download");
    let mut stream = resp.into_inner();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        bytes.extend_from_slice(&chunk.expect("chunk").data);
    }
    bytes
}

#[tokio::test]
#[ignore = "load test — run scripts/load-test-sync-smoke.sh"]
async fn load_sync_three_nodes_round_trip() {
    let root = tempdir().expect("tempdir");
    let files: [(&str, Vec<u8>); 3] = [
        ("node-a.md", (0u8..=255).cycle().take(8_192).collect()),
        ("node-b.md", (1u8..=255).cycle().take(8_192).collect()),
        ("node-c.md", (2u8..=255).cycle().take(8_192).collect()),
    ];
    for (name, content) in &files {
        std::fs::write(root.path().join(name), content).expect("seed vault file");
    }

    let started = Instant::now();
    let (port, cert_pem) = spawn_server(root.path().to_path_buf()).await;

    for (node_id, (path, expected)) in ["node-a", "node-b", "node-c"].into_iter().zip(files.iter())
    {
        let ch = make_channel(port, &cert_pem).await;
        let (_auth, token) = register_and_authenticate(ch.clone(), node_id).await;
        let got = download_file(ch, &token, path).await;
        assert_eq!(
            got, *expected,
            "{node_id} download must match seeded content"
        );
    }

    let elapsed = started.elapsed();
    eprintln!("load_sync_three_nodes: 3 register/auth/download cycles in {elapsed:?}");
    assert!(
        elapsed < Duration::from_secs(120),
        "3-node local harness should finish within 120s, took {elapsed:?}"
    );
}
