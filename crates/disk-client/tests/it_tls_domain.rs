//! DISK-0060 — TLS domain-name override integration test.
//!
//! Root cause: `DiskClient::connect` never called `ClientTlsConfig::domain_name`,
//! so connecting by IP to a server whose cert only has a DNS SAN fails name
//! verification.  This test reproduces the defect (RED) and proves the fix (GREEN).
//!
//! **Test topology:**
//! - Self-signed server cert with a **single DNS SAN** (`disk.arcanada.ai`) and
//!   **no IP SAN** — exactly what the production cert carries.
//! - Client connects via `https://127.0.0.1:{port}` (IP endpoint).
//!
//! **RED assertion (V-AC-1):** without `tls_domain`, the TLS handshake fails because
//! the IP address cannot match a DNS SAN entry.
//!
//! **GREEN assertion (V-AC-2):** with `tls_domain: Some("disk.arcanada.ai")`, the
//! handshake succeeds and an `exchange_state` unary RPC reaches the stub server.

#![cfg(unix)]

use std::collections::HashMap;
use std::time::Duration;

use disk_client::{ClientConfig, DiskClient};
use disk_proto::disk::{
    sync_service_server::{SyncService, SyncServiceServer},
    DeltaChunk, DeltaDownloadRequest, DeltaUploadRequest, DeltaUploadResponse, SyncStateAck,
    SyncStateRequest, SyncStateResponse,
};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use tokio::net::TcpListener;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{
    transport::Identity, transport::Server, transport::ServerTlsConfig, Request, Response, Status,
    Streaming,
};

// ---------------------------------------------------------------------------
// Minimal stub SyncService — just enough for exchange_state to succeed.
// ---------------------------------------------------------------------------

struct OkStub;

#[tonic::async_trait]
impl SyncService for OkStub {
    type SyncStateStream = ReceiverStream<Result<SyncStateAck, Status>>;
    type DeltaDownloadStream = ReceiverStream<Result<DeltaChunk, Status>>;

    async fn exchange_state(
        &self,
        _req: Request<SyncStateRequest>,
    ) -> Result<Response<SyncStateResponse>, Status> {
        Ok(Response::new(SyncStateResponse::default()))
    }

    async fn upload_delta(
        &self,
        _req: Request<DeltaUploadRequest>,
    ) -> Result<Response<DeltaUploadResponse>, Status> {
        Err(Status::unimplemented("tls-domain stub"))
    }

    async fn sync_state(
        &self,
        _req: Request<Streaming<SyncStateRequest>>,
    ) -> Result<Response<Self::SyncStateStream>, Status> {
        Err(Status::unimplemented("tls-domain stub"))
    }

    async fn delta_upload(
        &self,
        _req: Request<Streaming<DeltaUploadRequest>>,
    ) -> Result<Response<DeltaUploadResponse>, Status> {
        Err(Status::unimplemented("tls-domain stub"))
    }

    async fn delta_download(
        &self,
        _req: Request<DeltaDownloadRequest>,
    ) -> Result<Response<Self::DeltaDownloadStream>, Status> {
        Err(Status::unimplemented("tls-domain stub"))
    }
}

// ---------------------------------------------------------------------------
// Fixture: loopback server with DNS-SAN-only cert.
// ---------------------------------------------------------------------------

struct Fixture {
    /// `https://127.0.0.1:{port}` — IP-form endpoint (not the DNS name).
    ip_endpoint: String,
    /// PEM bytes of the self-signed CA (same cert used as server cert).
    ca_pem: Vec<u8>,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

/// Spin up a real gRPC server over TLS on a loopback port.
///
/// The server cert is signed with a **DNS-only SAN** (`disk.arcanada.ai`).
/// No IP SAN is added, so an IP-address client endpoint cannot match it
/// without an explicit `domain_name` override.
async fn spawn_dns_san_only_server() -> Fixture {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind 0");
    let port = listener.local_addr().expect("local_addr").port();

    // Generate a cert with ONLY a DNS SAN — no IP SAN.  rcgen 0.13
    // `generate_simple_self_signed` puts each string as a DNS SAN entry.
    // Passing only the domain name guarantees no IP SAN leaks in.
    let CertifiedKey {
        cert,
        signing_key: key_pair,
    } = generate_simple_self_signed(vec!["disk.arcanada.ai".into()]).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    let ca_pem = cert_pem.clone().into_bytes();

    let identity = Identity::from_pem(&cert_pem, &key_pem);
    let tls = ServerTlsConfig::new().identity(identity);

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

    tokio::spawn(async move {
        Server::builder()
            .tls_config(tls)
            .expect("apply tls")
            .add_service(SyncServiceServer::new(OkStub))
            .serve_with_incoming_shutdown(incoming, async {
                let _ = rx.await;
            })
            .await
            .expect("server terminated");
    });

    // Give the server a moment to accept connections.
    tokio::time::sleep(Duration::from_millis(100)).await;

    Fixture {
        ip_endpoint: format!("https://127.0.0.1:{port}"),
        ca_pem,
        _shutdown: tx,
    }
}

// ---------------------------------------------------------------------------
// AC-1 (RED precondition): IP endpoint + DNS-SAN-only cert + no tls_domain
// must fail.  This proves the defect is real and our fixture is correct.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ip_endpoint_without_tls_domain_fails_handshake() {
    let fx = spawn_dns_san_only_server().await;

    let result = DiskClient::connect(ClientConfig {
        endpoint: fx.ip_endpoint.clone(),
        tls_ca_cert_pem: Some(fx.ca_pem.clone()),
        tls_domain: None, // <-- no domain override (pre-fix behaviour)
        client_cert_pem: None,
        client_key_pem: None,
        node_id: "test-node".into(),
        api_key: None,
    })
    .await;

    assert!(
        result.is_err(),
        "IP endpoint with DNS-SAN-only cert and no tls_domain MUST fail \
         (TLS name mismatch). Got Ok instead — the fixture may have injected \
         an IP SAN or the library changed behaviour."
    );
}

// ---------------------------------------------------------------------------
// AC-2 (GREEN): same topology but tls_domain pins the expected cert name.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ip_endpoint_with_tls_domain_connects_and_rpc_succeeds() {
    let fx = spawn_dns_san_only_server().await;

    let client = DiskClient::connect(ClientConfig {
        endpoint: fx.ip_endpoint.clone(),
        tls_ca_cert_pem: Some(fx.ca_pem.clone()),
        tls_domain: Some("disk.arcanada.ai".into()), // <-- the fix
        client_cert_pem: None,
        client_key_pem: None,
        node_id: "test-node".into(),
        api_key: None,
    })
    .await
    .expect("connect with tls_domain must succeed (cert SAN matches override)");

    // Set a dummy session token so exchange_state does not fail with
    // NotAuthenticated before even reaching the transport.
    client.set_session_token("dummy-token".into()).await;

    // A successful unary RPC proves the TLS channel is fully established.
    let resp = client
        .exchange_state("test-share", vec![], HashMap::new())
        .await
        .expect("exchange_state must succeed over the established TLS channel");

    // Stub returns default SyncStateResponse — all lists empty.
    assert_eq!(resp.to_upload.len(), 0, "stub returns empty to_upload list");
    assert_eq!(resp.to_delete.len(), 0, "stub returns empty to_delete list");
}

// ---------------------------------------------------------------------------
// AC-3 partial: connect_lazy_for_test also accepts tls_domain (compile check).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn connect_lazy_for_test_accepts_tls_domain() {
    // No server needed — connect_lazy defers the handshake to first RPC.
    // This purely verifies the field is present and accepted.
    // Uses #[tokio::test] because Endpoint::new internally requires a Tokio
    // runtime context even when no I/O is performed.
    let result = DiskClient::connect_lazy_for_test(ClientConfig {
        endpoint: "https://127.0.0.1:9999".into(),
        tls_ca_cert_pem: None,
        tls_domain: Some("disk.arcanada.ai".into()),
        client_cert_pem: None,
        client_key_pem: None,
        node_id: "lazy-node".into(),
        api_key: None,
    });
    assert!(
        result.is_ok(),
        "connect_lazy_for_test must succeed for construction (no I/O)"
    );
}
