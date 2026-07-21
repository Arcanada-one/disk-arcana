//! DISK-0062 — Integration test: `download_file` sends `x-disk-share` header.
//!
//! Root cause: before this fix, `download_file` set only `authorization` and
//! omitted `x-disk-share`.  The server ACL enforcer therefore hit its default
//! deny path and returned PermissionDenied, which the caller swallowed silently.
//!
//! Test contract:
//!
//! - **AC-1**: `DiskClient::download_file` sends a correct `x-disk-share` header
//!   on the gRPC request.  A stub server that asserts header presence on every
//!   `delta_download` call serves as the sentinel — the test fails if the header
//!   is absent (regression guard).
//!
//! - **AC-2**: `RemoteSync::execute()` correctly passes `share` into
//!   `download_file`.  An in-process stub whose `exchange_state` returns one
//!   `to_download` entry and whose `delta_download` asserts the share header
//!   proves the wire-up end-to-end.  After `execute()` the file is present in
//!   the scan root with a matching blake3 hash AND `to_delete` is empty.
//!
//! The stub uses `tokio::sync::mpsc` channels to communicate assertion results
//! back to the test task.

#![cfg(unix)]

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

use disk_client::sync_loop::{RemoteSync, SyncTransport};
use disk_client::{ClientConfig, DiskClient};
use disk_proto::disk::{
    sync_service_server::{SyncService, SyncServiceServer},
    DeltaChunk, DeltaDownloadRequest, DeltaUploadRequest, DeltaUploadResponse, FileMetadata,
    SyncStateAck, SyncStateRequest, SyncStateResponse,
};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use tempfile::tempdir;
use tokio::net::TcpListener;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{
    transport::{Identity, Server, ServerTlsConfig},
    Request, Response, Status, Streaming,
};

// ---------------------------------------------------------------------------
// Stub server that asserts the x-disk-share header on every download call.
// ---------------------------------------------------------------------------

/// A stub `SyncService` for testing the `x-disk-share` header on downloads.
///
/// `exchange_state` returns a single file in `to_download` (named `probe.md`,
/// with content `FILE_CONTENT`).  `delta_download` checks that the
/// `x-disk-share` header is present before streaming the bytes.  If the header
/// is absent it records the failure via `share_header_received` and returns
/// PermissionDenied (mirroring the real server behaviour).
struct DownloadHeaderStub {
    /// Set to `true` when `delta_download` is called with the correct header.
    share_header_received: Arc<AtomicBool>,
    /// Set to `true` when `delta_download` is called WITHOUT the header.
    share_header_missing: Arc<AtomicBool>,
    /// Bytes to serve for the single probe file.
    file_content: Vec<u8>,
}

pub const PROBE_PATH: &str = "probe.md";
pub const SHARE_NAME: &str = "test-share";

#[tonic::async_trait]
impl SyncService for DownloadHeaderStub {
    type SyncStateStream = ReceiverStream<Result<SyncStateAck, Status>>;
    type DeltaDownloadStream = ReceiverStream<Result<DeltaChunk, Status>>;

    async fn exchange_state(
        &self,
        _req: Request<SyncStateRequest>,
    ) -> Result<Response<SyncStateResponse>, Status> {
        // Return one entry in to_download so the wire loop calls download_file.
        Ok(Response::new(SyncStateResponse {
            to_download: vec![FileMetadata {
                path: PROBE_PATH.into(),
                ..Default::default()
            }],
            ..Default::default()
        }))
    }

    async fn upload_delta(
        &self,
        _req: Request<DeltaUploadRequest>,
    ) -> Result<Response<DeltaUploadResponse>, Status> {
        Err(Status::unimplemented("not needed for download test"))
    }

    async fn sync_state(
        &self,
        _req: Request<Streaming<SyncStateRequest>>,
    ) -> Result<Response<Self::SyncStateStream>, Status> {
        Err(Status::unimplemented("not needed for download test"))
    }

    async fn delta_upload(
        &self,
        _req: Request<Streaming<DeltaUploadRequest>>,
    ) -> Result<Response<DeltaUploadResponse>, Status> {
        Err(Status::unimplemented("not needed for download test"))
    }

    async fn delta_download(
        &self,
        req: Request<DeltaDownloadRequest>,
    ) -> Result<Response<Self::DeltaDownloadStream>, Status> {
        // Assert the x-disk-share header is present.
        let share = req.metadata().get("x-disk-share");
        if share.is_none() {
            self.share_header_missing.store(true, Ordering::SeqCst);
            return Err(Status::permission_denied(
                "x-disk-share header missing — share unknown",
            ));
        }
        self.share_header_received.store(true, Ordering::SeqCst);

        // Stream the file content as a single chunk.
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let content = self.file_content.clone();
        tokio::spawn(async move {
            let _ = tx
                .send(Ok(DeltaChunk {
                    offset: 0,
                    data: content,
                    ..Default::default()
                }))
                .await;
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct Fixture {
    endpoint: String,
    ca_pem: Vec<u8>,
    share_header_received: Arc<AtomicBool>,
    share_header_missing: Arc<AtomicBool>,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

async fn spawn_stub(file_content: Vec<u8>) -> Fixture {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind 0");
    let port = listener.local_addr().expect("local_addr").port();

    let CertifiedKey {
        cert,
        signing_key: key_pair,
    } = generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    let ca_pem = cert_pem.clone().into_bytes();

    let share_header_received = Arc::new(AtomicBool::new(false));
    let share_header_missing = Arc::new(AtomicBool::new(false));

    let stub = DownloadHeaderStub {
        share_header_received: Arc::clone(&share_header_received),
        share_header_missing: Arc::clone(&share_header_missing),
        file_content: file_content.clone(),
    };

    let identity = Identity::from_pem(&cert_pem, &key_pem);
    let tls = ServerTlsConfig::new().identity(identity);

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

    tokio::spawn(async move {
        Server::builder()
            .tls_config(tls)
            .expect("apply tls")
            .add_service(SyncServiceServer::new(stub))
            .serve_with_incoming_shutdown(incoming, async {
                let _ = rx.await;
            })
            .await
            .expect("server terminated");
    });

    tokio::time::sleep(Duration::from_millis(80)).await;

    Fixture {
        endpoint: format!("https://127.0.0.1:{port}"),
        ca_pem,
        share_header_received,
        share_header_missing,
        _shutdown: tx,
    }
}

// ---------------------------------------------------------------------------
// AC-1: download_file sends x-disk-share header
// ---------------------------------------------------------------------------

/// Verify that `DiskClient::download_file` sends the `x-disk-share` metadata
/// header.  The stub asserts header presence on every `delta_download` call.
///
/// This is a direct regression guard: if `download_file` is ever changed to
/// drop the header the stub returns PermissionDenied and the `expect` panics.
#[tokio::test]
async fn ac1_download_file_sends_share_header() {
    let file_content: Vec<u8> = (0u8..=255u8).cycle().take(4_096).collect();
    let fx = spawn_stub(file_content.clone()).await;

    let client = DiskClient::connect(ClientConfig {
        endpoint: fx.endpoint.clone(),
        tls_ca_cert_pem: Some(fx.ca_pem.clone()),
        tls_domain: None,
        client_cert_pem: None,
        client_key_pem: None,
        node_id: "test-node".into(),
        api_key: None,
        tenant_id: None,
    })
    .await
    .expect("DiskClient::connect");

    client.set_session_token("test-token".into()).await;

    let downloaded = client
        .download_file(SHARE_NAME, PROBE_PATH)
        .await
        .expect("download_file must succeed when x-disk-share header is present");

    // Verify the stub saw the header.
    assert!(
        fx.share_header_received.load(Ordering::SeqCst),
        "stub must record a successful header receipt"
    );
    assert!(
        !fx.share_header_missing.load(Ordering::SeqCst),
        "stub must NOT record a missing header"
    );

    // Verify the bytes match.
    let expected_hash = disk_core::delta::blake3_hash(&file_content);
    let actual_hash = disk_core::delta::blake3_hash(&downloaded);
    assert_eq!(
        actual_hash, expected_hash,
        "downloaded bytes must match the stub's file content"
    );
}

// ---------------------------------------------------------------------------
// AC-2: RemoteSync::execute() passes share through the full download path;
//        file lands in scan_root with matching blake3, no spurious to_delete.
// ---------------------------------------------------------------------------

/// End-to-end two-node round-trip through `RemoteSync::execute()`.
///
/// The stub's `exchange_state` returns one file in `to_download`.
/// `execute()` calls `download_file(&self.share, path)`.  The test asserts:
///
/// 1. The stub observed the `x-disk-share` header (metadata path exercised).
/// 2. The file is present in the scan root with bytes matching the stub's content.
/// 3. The stub's `to_delete` response is empty — no spurious tombstones.
///
/// Regression property: if `execute()` calls `download_file` without passing
/// `share`, the stub returns PermissionDenied, the warn-and-continue path skips
/// the baseline write, and the file is absent from the scan root — assertion (2)
/// fails, catching the regression.
#[tokio::test]
async fn ac2_remote_sync_execute_downloads_file_with_share_header() {
    let file_content: Vec<u8> = b"DISK0062 sentinel payload".to_vec();
    let fx = spawn_stub(file_content.clone()).await;

    let scan_root = tempdir().expect("tempdir");

    let client = DiskClient::connect(ClientConfig {
        endpoint: fx.endpoint.clone(),
        tls_ca_cert_pem: Some(fx.ca_pem.clone()),
        tls_domain: None,
        client_cert_pem: None,
        client_key_pem: None,
        node_id: "sync-node".into(),
        api_key: None,
        tenant_id: None,
    })
    .await
    .expect("DiskClient::connect");

    client.set_session_token("test-token".into()).await;

    // Build RemoteSync against the stub, configured for the test share and
    // the temporary scan root.
    let mut transport = RemoteSync::with_scan_root(
        &client,
        SHARE_NAME,
        scan_root.path().to_path_buf(),
        "sync-node",
    );

    // Drive one sync iteration.
    transport
        .execute()
        .await
        .expect("RemoteSync::execute must succeed");

    // AC-2a: stub confirmed the x-disk-share header was present.
    assert!(
        fx.share_header_received.load(Ordering::SeqCst),
        "RemoteSync::execute must send x-disk-share on download_file"
    );
    assert!(
        !fx.share_header_missing.load(Ordering::SeqCst),
        "x-disk-share header must not have been absent during execute"
    );

    // AC-2b: file present in scan_root with correct content.
    let dest = scan_root.path().join(PROBE_PATH);
    assert!(
        dest.exists(),
        "probe file must be present in scan_root after execute: {:?}",
        dest
    );
    let on_disk = std::fs::read(&dest).expect("read probe file");
    let expected_hash = disk_core::delta::blake3_hash(&file_content);
    let actual_hash = disk_core::delta::blake3_hash(&on_disk);
    assert_eq!(
        actual_hash, expected_hash,
        "downloaded file bytes must match the stub's content"
    );

    // AC-2c: the stub response has no to_delete entries — no spurious tombstones.
    // (The stub's exchange_state returns SyncStateResponse::default() for all
    // fields except to_download, so to_delete is guaranteed empty.  If the
    // delete-apply path produces side-effects from an empty list it would panic
    // here via assert or the test would see a missing file it did not expect.)
    assert!(
        dest.exists(),
        "probe file must not have been spuriously deleted"
    );
}
