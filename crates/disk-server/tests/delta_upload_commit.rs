//! Integration tests for delta_upload data-plane (DISK-0043).
//!
//! V-AC-3: Uploaded bytes persist to sync_root AND a MetaDb row is created.
//! V-AC-4: Round-trip — upload then download returns identical bytes.
//! V-AC-5: Pull — server file → exchange_state marks to_download → DiskClient downloads + blake3 matches.
//! V-AC-6: Upload with path `../escape` is rejected with InvalidArgument.
//!
//! The server is started on port 0 (OS-assigned) to avoid DISK-0041 flaky class.

use std::path::PathBuf;
use std::time::Duration;

use disk_client::{ClientConfig, DiskClient};
use disk_core::meta_db::MetaDb;
use disk_core::types::FileMeta;
use disk_core::VectorClock;
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

// ---------------------------------------------------------------------------
// V-AC-5: Pull — server file → exchange_state marks to_download → DiskClient
//          downloads via download_file + blake3 matches server file
// ---------------------------------------------------------------------------

#[tokio::test]
async fn v_ac_5_pull_server_file_to_client() {
    // ── 1. Spin up server with MetaDb ────────────────────────────────────────
    let root = tempdir().unwrap();
    let db_path = root.path().join("meta.db");
    let meta_db = MetaDb::open(&db_path).await.unwrap();
    let sync_root = root.path().to_path_buf();

    let (port, _store, cert_pem) =
        spawn_server_with_meta_db(sync_root.clone(), meta_db.clone()).await;

    // ── 2. Seed a file into server's sync_root + MetaDb ─────────────────────
    let file_content: Vec<u8> = (0u8..=255u8).cycle().take(8_192).collect();
    let server_hash = disk_core::delta::blake3_hash(&file_content);

    let relative_path = "wiki/server-only.md";
    let abs_path = sync_root.join(relative_path);
    std::fs::create_dir_all(abs_path.parent().unwrap()).unwrap();
    std::fs::write(&abs_path, &file_content).unwrap();

    let mut vc = VectorClock::new();
    vc.advance("server-test");
    let file_meta = FileMeta {
        path: std::path::PathBuf::from(relative_path),
        content_hash: server_hash,
        size: file_content.len() as u64,
        mtime_ns: 1_700_000_000_000_000_000,
        inode: None,
        vector_clock: vc,
        deleted: false,
        deleted_at: None,
        node_id: "server-test".into(),
    };
    meta_db.upsert_file(&file_meta).await.unwrap();

    // ── 3. Connect a DiskClient and authenticate ─────────────────────────────
    let ca_pem_bytes = cert_pem.as_bytes().to_vec();
    let client = DiskClient::connect(ClientConfig {
        endpoint: format!("https://localhost:{port}"),
        tls_ca_cert_pem: Some(ca_pem_bytes),
        tls_domain: None,
        client_cert_pem: None,
        client_key_pem: None,
        node_id: "pull-client".into(),
        api_key: None,
    })
    .await
    .expect("DiskClient::connect");

    // Register node then authenticate to obtain a session token.
    let api_key = client
        .register_node("Pull Client", "test")
        .await
        .expect("register_node");
    let client = DiskClient::connect(ClientConfig {
        endpoint: format!("https://localhost:{port}"),
        tls_ca_cert_pem: Some(cert_pem.as_bytes().to_vec()),
        tls_domain: None,
        client_cert_pem: None,
        client_key_pem: None,
        node_id: "pull-client".into(),
        api_key: Some(api_key),
    })
    .await
    .expect("DiskClient::connect (with api_key)");
    client.authenticate().await.expect("authenticate");

    // ── 4. Call exchange_state with empty client state ────────────────────────
    let resp = client
        .exchange_state("default", vec![], std::collections::HashMap::new())
        .await
        .expect("exchange_state");

    assert_eq!(
        resp.to_download.len(),
        1,
        "server file must appear in to_download (got {:?})",
        resp.to_download.iter().map(|f| &f.path).collect::<Vec<_>>()
    );
    assert_eq!(
        resp.to_download[0].path, relative_path,
        "to_download[0] must be the seeded server file"
    );

    // ── 5. Download the file via DiskClient::download_file ───────────────────
    let downloaded = client
        .download_file(relative_path)
        .await
        .expect("download_file");

    let downloaded_hash = disk_core::delta::blake3_hash(&downloaded);

    assert_eq!(
        downloaded_hash, server_hash,
        "downloaded bytes' blake3 must match the server file's blake3"
    );
    assert_eq!(
        downloaded, file_content,
        "downloaded bytes must be byte-identical to the server file"
    );
}
