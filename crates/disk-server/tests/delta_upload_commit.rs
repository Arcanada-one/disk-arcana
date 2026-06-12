//! Integration tests for delta_upload data-plane (DISK-0043).
//!
//! V-AC-3: Uploaded bytes persist to sync_root AND a MetaDb row is created.
//! V-AC-4: Round-trip — upload then download returns identical bytes.
//! V-AC-6: Upload with path `../escape` is rejected with InvalidArgument.
//!
//! The server is started on port 0 (OS-assigned) to avoid DISK-0041 flaky class.

use std::path::PathBuf;
use std::time::Duration;

use disk_core::meta_db::MetaDb;
use disk_proto::disk::{
    auth_service_client::AuthServiceClient, auth_service_server::AuthServiceServer,
    sync_service_client::SyncServiceClient, sync_service_server::SyncServiceServer, DeltaChunk,
    DeltaDownloadRequest, DeltaUploadRequest, NodeAuthRequest, NodeRegisterRequest,
};
use disk_server::{AuthServiceImpl, AuthStore, SyncServiceImpl};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use tempfile::tempdir;
use tokio_stream::StreamExt;
use tonic::{
    transport::{Certificate, ClientTlsConfig, Endpoint, Server, ServerTlsConfig},
    Request,
};

/// Spawn a test server with `MetaDb` wired into `SyncServiceImpl`.
/// Returns `(port, auth_store, cert_pem, sync_root, meta_db)`.
async fn spawn_server_with_meta_db(
    sync_root: PathBuf,
    meta_db: MetaDb,
) -> (u16, AuthStore, String) {
    let store = AuthStore::new();

    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    let auth_svc = AuthServiceServer::new(AuthServiceImpl::new(store.clone()));
    let sync_impl =
        SyncServiceImpl::new(store.clone(), sync_root).with_meta_db(meta_db, "server-test");
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
    (port, store, cert_pem)
}

/// Connect a client to the test server.
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

/// Register + authenticate a node, returning its session token.
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

/// Build messages for a streaming `delta_upload` request from raw bytes + path,
/// returning a `Request<tokio_stream::Iter<...>>` suitable for the tonic client.
fn make_upload_request(
    path: &str,
    bytes: &[u8],
    token: &str,
    share: &str,
) -> Request<tokio_stream::Iter<std::vec::IntoIter<DeltaUploadRequest>>> {
    let content_hash = disk_core::delta::blake3_hash(bytes);
    let mut msgs: Vec<DeltaUploadRequest> = Vec::new();
    let mut first = true;
    for chunk_result in disk_core::delta::chunks(bytes) {
        let chunk = chunk_result.unwrap();
        let proto_chunk = DeltaChunk {
            offset: chunk.offset,
            weak_checksum: chunk.weak,
            strong_hash: chunk.strong.to_vec(),
            data: chunk.data,
        };
        if first {
            msgs.push(DeltaUploadRequest {
                path: path.to_owned(),
                content_hash: content_hash.to_vec(),
                chunks: vec![proto_chunk],
                ..Default::default()
            });
            first = false;
        } else {
            msgs.push(DeltaUploadRequest {
                path: String::new(),
                content_hash: Vec::new(),
                chunks: vec![proto_chunk],
                ..Default::default()
            });
        }
    }
    if msgs.is_empty() {
        msgs.push(DeltaUploadRequest {
            path: path.to_owned(),
            content_hash: content_hash.to_vec(),
            chunks: vec![],
            ..Default::default()
        });
    }

    let stream = tokio_stream::iter(msgs);
    let mut req = Request::new(stream);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req.metadata_mut()
        .insert("x-disk-share", share.parse().unwrap());
    req
}

// ---------------------------------------------------------------------------
// V-AC-3: Uploaded bytes persist to sync_root AND MetaDb row is created
// ---------------------------------------------------------------------------

#[tokio::test]
async fn v_ac_3_upload_persists_to_sync_root_and_meta_db() {
    let root = tempdir().unwrap();
    let db_path = root.path().join("meta.db");
    let meta_db = MetaDb::open(&db_path).await.unwrap();
    let meta_db_check = meta_db.clone();
    let sync_root = root.path().to_path_buf();

    let (port, _store, cert_pem) = spawn_server_with_meta_db(sync_root.clone(), meta_db).await;
    let ch = connect(port, &cert_pem).await;
    let tok = authenticate(&ch, "uploader-a").await;

    let content: Vec<u8> = (0u8..200u8).collect();
    let req = make_upload_request("notes/hello.md", &content, &tok, "default");

    let mut sync = SyncServiceClient::new(ch);
    let resp = sync.delta_upload(req).await.unwrap().into_inner();

    assert!(resp.accepted, "server must accept the upload");

    // V-AC-3a: file on disk.
    let on_disk = std::fs::read(sync_root.join("notes/hello.md")).unwrap();
    assert_eq!(
        on_disk, content,
        "persisted bytes must match uploaded content"
    );

    // V-AC-3b: MetaDb row exists.
    let row = meta_db_check.get_file("notes/hello.md").await.unwrap();
    assert!(
        row.is_some(),
        "MetaDb must contain a row for notes/hello.md"
    );
}

// ---------------------------------------------------------------------------
// V-AC-4: Round-trip — upload then download returns identical bytes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn v_ac_4_upload_then_download_returns_same_bytes() {
    let root = tempdir().unwrap();
    let db_path = root.path().join("meta.db");
    let meta_db = MetaDb::open(&db_path).await.unwrap();
    let sync_root = root.path().to_path_buf();

    let (port, _store, cert_pem) = spawn_server_with_meta_db(sync_root, meta_db).await;
    let ch = connect(port, &cert_pem).await;
    let tok = authenticate(&ch, "roundtrip-node").await;

    let content: Vec<u8> = (0u8..=255u8).cycle().take(16_000).collect();
    let up_req = make_upload_request("archive/doc.md", &content, &tok, "default");

    let mut sync = SyncServiceClient::new(ch);
    sync.delta_upload(up_req).await.unwrap();

    // Download the same path.
    let mut down_req = Request::new(DeltaDownloadRequest {
        path: "archive/doc.md".into(),
        ..Default::default()
    });
    down_req
        .metadata_mut()
        .insert("authorization", format!("Bearer {tok}").parse().unwrap());

    let mut stream = sync.delta_download(down_req).await.unwrap().into_inner();
    let mut reassembled = Vec::new();
    while let Some(c) = stream.next().await {
        reassembled.extend_from_slice(&c.unwrap().data);
    }

    assert_eq!(
        reassembled, content,
        "downloaded bytes must match uploaded content"
    );
}

// ---------------------------------------------------------------------------
// V-AC-6: Path traversal upload is rejected with InvalidArgument
// ---------------------------------------------------------------------------

#[tokio::test]
async fn v_ac_6_upload_path_traversal_rejected() {
    let root = tempdir().unwrap();
    let db_path = root.path().join("meta.db");
    let meta_db = MetaDb::open(&db_path).await.unwrap();
    let sync_root = root.path().to_path_buf();

    let (port, _store, cert_pem) = spawn_server_with_meta_db(sync_root.clone(), meta_db).await;
    let ch = connect(port, &cert_pem).await;
    let tok = authenticate(&ch, "attacker").await;

    let content = b"evil payload";
    let req = make_upload_request("../escape", content, &tok, "default");

    let mut sync = SyncServiceClient::new(ch);
    let err = sync.delta_upload(req).await.unwrap_err();

    assert_eq!(
        err.code(),
        tonic::Code::InvalidArgument,
        "path traversal upload must be rejected as InvalidArgument"
    );

    // The file must NOT have been written outside the sync_root.
    let escaped_path = sync_root.parent().unwrap().join("escape");
    assert!(
        !escaped_path.exists(),
        "attacker file must not exist outside sync_root"
    );
}
