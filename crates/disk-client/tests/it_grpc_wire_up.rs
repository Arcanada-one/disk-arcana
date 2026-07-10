//! DISK-0006 R6 — gRPC client wire-up against an in-process `SyncService`.
//!
//! Validates the two error pathways the [`SyncLoop`] state machine cares
//! about plus the metadata plumbing required for ACL admission:
//!
//! - **IT-1** `share_unknown_drives_loop_into_backoff`: server replies
//!   `PermissionDenied("share unknown: ...; retry after ACL provisioning")`.
//!   Also asserts the client correctly attached `authorization: Bearer ...`
//!   plus `x-disk-share` metadata (otherwise the server-side hook would
//!   never see the share name).
//! - **IT-2** `acl_role_mismatch_pins_loop_in_sticky_state`: server replies
//!   `PermissionDenied` with `AclMismatchDetails` proto encoded into
//!   `Status::details()`. Loop must transition to sticky `AclMismatch`;
//!   a subsequent `run_iteration` must return `None` (begin_sync refused).
//!
//! The stub server mirrors the TLS topology used by `it_enrollment_e2e.rs`
//! (self-signed cert, SNI `localhost`) — the production server runs with
//! mTLS but R6 exercises the unary `ExchangeState` admission probe before
//! the client cert chain is fully wired through the test fixture.
//!
//! [`SyncLoop`]: disk_client::SyncLoop

#![cfg(unix)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use disk_client::{
    ClientConfig, DiskClient, LoopError, LoopState, LoopTrigger, RemoteSync, SyncLoop,
};
use disk_proto::disk::{
    sync_service_server::{SyncService, SyncServiceServer},
    AclMismatchDetails, DeltaChunk, DeltaDownloadRequest, DeltaUploadRequest, DeltaUploadResponse,
    SyncStateAck, SyncStateRequest, SyncStateResponse,
};
use prost::Message;
use rand::rngs::StdRng;
use rand::SeedableRng;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use tokio::net::TcpListener;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{
    transport::{Identity, Server, ServerTlsConfig},
    Code, Request, Response, Status, Streaming,
};

const SESSION_TOKEN: &str = "test-session-token";
const NODE_ID: &str = "macos-laptop-r6";
const SHARE_NAME: &str = "vault";

#[derive(Default)]
struct Capture {
    authz_seen: Mutex<Option<String>>,
    share_seen: Mutex<Option<String>>,
    node_id_seen: Mutex<Option<String>>,
}

enum StubResponse {
    ShareUnknown,
    AclMismatchWithDetails,
}

struct StubSync {
    cap: Arc<Capture>,
    response: StubResponse,
}

#[tonic::async_trait]
impl SyncService for StubSync {
    type SyncStateStream = ReceiverStream<Result<SyncStateAck, Status>>;
    type DeltaDownloadStream = ReceiverStream<Result<DeltaChunk, Status>>;

    async fn exchange_state(
        &self,
        request: Request<SyncStateRequest>,
    ) -> Result<Response<SyncStateResponse>, Status> {
        *self.cap.authz_seen.lock().unwrap() = request
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        *self.cap.share_seen.lock().unwrap() = request
            .metadata()
            .get("x-disk-share")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let inner = request.into_inner();
        *self.cap.node_id_seen.lock().unwrap() = Some(inner.node_id.clone());

        match self.response {
            StubResponse::ShareUnknown => Err(Status::permission_denied(format!(
                "share unknown: {SHARE_NAME}; retry after ACL provisioning"
            ))),
            StubResponse::AclMismatchWithDetails => {
                let details = AclMismatchDetails {
                    claimed_role: "send_only".into(),
                    enforced_role: "receive_only".into(),
                    share: SHARE_NAME.into(),
                    cert_fingerprint: vec![0xAA, 0xBB, 0xCC],
                    ts_ms: 1_700_000_000_000,
                };
                let mut buf = Vec::new();
                details.encode(&mut buf).unwrap();
                Err(Status::with_details(
                    Code::PermissionDenied,
                    "ACL role mismatch: enforced=receive_only claimed=send_only",
                    buf.into(),
                ))
            }
        }
    }

    async fn upload_delta(
        &self,
        _req: Request<DeltaUploadRequest>,
    ) -> Result<Response<DeltaUploadResponse>, Status> {
        Err(Status::unimplemented("R6 stub"))
    }

    async fn sync_state(
        &self,
        _req: Request<Streaming<SyncStateRequest>>,
    ) -> Result<Response<Self::SyncStateStream>, Status> {
        Err(Status::unimplemented("R6 stub"))
    }

    async fn delta_upload(
        &self,
        _req: Request<Streaming<DeltaUploadRequest>>,
    ) -> Result<Response<DeltaUploadResponse>, Status> {
        Err(Status::unimplemented("R6 stub"))
    }

    async fn delta_download(
        &self,
        _req: Request<DeltaDownloadRequest>,
    ) -> Result<Response<Self::DeltaDownloadStream>, Status> {
        Err(Status::unimplemented("R6 stub"))
    }
}

struct Fixture {
    server_url: String,
    ca_pem: Vec<u8>,
    capture: Arc<Capture>,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

async fn spawn_stub(response: StubResponse) -> Fixture {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind 0");
    let port = listener.local_addr().expect("local_addr").port();

    let CertifiedKey { cert, signing_key: key_pair } =
        generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    let ca_pem = cert_pem.clone().into_bytes();

    let identity = Identity::from_pem(&cert_pem, &key_pem);
    let tls = ServerTlsConfig::new().identity(identity);

    let capture = Arc::new(Capture::default());
    let svc = StubSync {
        cap: capture.clone(),
        response,
    };

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

    tokio::spawn(async move {
        Server::builder()
            .tls_config(tls)
            .expect("apply tls")
            .add_service(SyncServiceServer::new(svc))
            .serve_with_incoming_shutdown(incoming, async {
                let _ = rx.await;
            })
            .await
            .expect("server terminated");
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    Fixture {
        server_url: format!("https://localhost:{port}"),
        ca_pem,
        capture,
        _shutdown: tx,
    }
}

async fn connect(fx: &Fixture) -> DiskClient {
    let client = DiskClient::connect(ClientConfig {
        endpoint: fx.server_url.clone(),
        tls_ca_cert_pem: Some(fx.ca_pem.clone()),
        client_cert_pem: None,
        client_key_pem: None,
        node_id: NODE_ID.into(),
        api_key: None,
    })
    .await
    .expect("connect");
    client.set_session_token(SESSION_TOKEN.into()).await;
    client
}

#[tokio::test]
async fn share_unknown_drives_loop_into_backoff() {
    let fx = spawn_stub(StubResponse::ShareUnknown).await;
    let client = connect(&fx).await;
    let mut transport = RemoteSync::new(&client, SHARE_NAME);
    let mut loop_state = SyncLoop::new();
    let mut rng = StdRng::seed_from_u64(0xC0FFEE);

    let outcome = loop_state
        .run_iteration(&mut transport, LoopTrigger::Manual, &mut rng)
        .await;

    assert_eq!(outcome, Some(Err(LoopError::ShareUnknown)));
    assert_eq!(loop_state.state(), LoopState::Backoff);
    assert_eq!(loop_state.last_error(), Some(LoopError::ShareUnknown));
    assert_eq!(loop_state.backoff().attempt(), 1);
    assert!(loop_state.backoff_until().is_some());

    assert_eq!(
        fx.capture.authz_seen.lock().unwrap().as_deref(),
        Some(&*format!("Bearer {SESSION_TOKEN}")),
        "server must observe Authorization: Bearer <token>"
    );
    assert_eq!(
        fx.capture.share_seen.lock().unwrap().as_deref(),
        Some(SHARE_NAME),
        "server must observe x-disk-share metadata"
    );
    assert_eq!(
        fx.capture.node_id_seen.lock().unwrap().as_deref(),
        Some(NODE_ID),
        "server must observe the node_id from the request body"
    );
}

#[tokio::test]
async fn acl_role_mismatch_pins_loop_in_sticky_state() {
    let fx = spawn_stub(StubResponse::AclMismatchWithDetails).await;
    let client = connect(&fx).await;
    let mut transport = RemoteSync::new(&client, SHARE_NAME);
    let mut loop_state = SyncLoop::new();
    let mut rng = StdRng::seed_from_u64(0xBEEF);

    let outcome = loop_state
        .run_iteration(&mut transport, LoopTrigger::Manual, &mut rng)
        .await;

    assert_eq!(outcome, Some(Err(LoopError::AclRoleMismatch)));
    assert_eq!(loop_state.state(), LoopState::AclMismatch);
    assert_eq!(loop_state.last_error(), Some(LoopError::AclRoleMismatch));
    assert_eq!(
        loop_state.backoff().attempt(),
        0,
        "AclRoleMismatch must not advance the backoff curve"
    );
    assert!(
        loop_state.backoff_until().is_none(),
        "AclRoleMismatch must not set a backoff deadline"
    );

    // Sticky check: a second iteration must refuse to begin_sync.
    let second = loop_state
        .run_iteration(&mut transport, LoopTrigger::Manual, &mut rng)
        .await;
    assert!(
        second.is_none(),
        "AclMismatch is sticky — run_iteration must skip until clear_acl_mismatch()"
    );

    loop_state.clear_acl_mismatch();
    assert_eq!(loop_state.state(), LoopState::Idle);
}
