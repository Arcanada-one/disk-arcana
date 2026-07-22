//! DISK-0061 — TLS domain-name override for `EnrollmentClient::connect`.
//!
//! Mirrors `it_tls_domain.rs` (DISK-0060 sync client) for the enrollment path:
//! connecting by IP to a server whose cert only has a DNS SAN fails unless
//! `tls_domain` pins the expected name.

#![cfg(unix)]

use std::time::Duration;

use disk_client::EnrollmentClient;
use disk_proto::disk::{
    enrollment_service_server::{EnrollmentService, EnrollmentServiceServer},
    EnrollRequest, EnrollResponse, EnrollmentTokenRequest, EnrollmentTokenResponse,
    RevokePendingRequest, RevokePendingResponse,
};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use tokio::net::TcpListener;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};

struct OkStub;

#[tonic::async_trait]
impl EnrollmentService for OkStub {
    async fn issue_pending_token(
        &self,
        _req: Request<EnrollmentTokenRequest>,
    ) -> Result<Response<EnrollmentTokenResponse>, Status> {
        Ok(Response::new(EnrollmentTokenResponse {
            opaque_token: vec![0xAB; 32],
            expires_at_ms: 9_999_999_999,
        }))
    }

    async fn enroll(
        &self,
        _req: Request<EnrollRequest>,
    ) -> Result<Response<EnrollResponse>, Status> {
        Ok(Response::new(EnrollResponse {
            client_cert_pem: b"-----BEGIN CERTIFICATE-----\nSTUB\n-----END CERTIFICATE-----\n"
                .to_vec(),
            ca_chain_pem: b"CHAIN".to_vec(),
            expires_at_ms: 1_000_000_000,
        }))
    }

    async fn revoke_pending(
        &self,
        _req: Request<RevokePendingRequest>,
    ) -> Result<Response<RevokePendingResponse>, Status> {
        Err(Status::unimplemented("not exercised"))
    }
}

struct Fixture {
    ip_endpoint: String,
    ca_pem: Vec<u8>,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

async fn spawn_dns_san_only_enrollment_server() -> Fixture {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind 0");
    let port = listener.local_addr().expect("local_addr").port();

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
            .add_service(EnrollmentServiceServer::new(OkStub))
            .serve_with_incoming_shutdown(incoming, async {
                let _ = rx.await;
            })
            .await
            .expect("server terminated");
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    Fixture {
        ip_endpoint: format!("https://127.0.0.1:{port}"),
        ca_pem,
        _shutdown: tx,
    }
}

#[tokio::test]
async fn enrollment_ip_without_tls_domain_fails_handshake() {
    let fx = spawn_dns_san_only_enrollment_server().await;

    let result = EnrollmentClient::connect(&fx.ip_endpoint, Some(&fx.ca_pem), false, None).await;

    assert!(
        result.is_err(),
        "IP enrollment endpoint with DNS-SAN-only cert and no tls_domain must fail"
    );
}

#[tokio::test]
async fn enrollment_ip_with_tls_domain_connects_and_enrolls() {
    let fx = spawn_dns_san_only_enrollment_server().await;

    let client = EnrollmentClient::connect(
        &fx.ip_endpoint,
        Some(&fx.ca_pem),
        false,
        Some("disk.arcanada.ai"),
    )
    .await
    .expect("connect with tls_domain");

    let (_key, csr) = disk_client::gen_keypair_and_csr("test-node").unwrap();
    let resp = client
        .enroll(vec![0xAB; 32], csr.into_bytes(), "test-node".into())
        .await
        .expect("enroll RPC over TLS channel");

    assert!(
        !resp.client_cert_pem.is_empty(),
        "stub must return a cert PEM over the established channel"
    );
}
