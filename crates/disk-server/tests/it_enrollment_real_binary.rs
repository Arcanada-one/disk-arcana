//! DISK-0037 — real-binary end-to-end enrollment test.
//!
//! Spawns the `disk-arcana-server` binary with the dual-listener configuration
//! introduced by DISK-0037 (mTLS on `DISK_BIND_ADDR`, TLS-only public on
//! `DISK_ENROLLMENT_BIND_ADDR`) and exercises the enrollment flow against the
//! public listener using a raw tonic client.
//!
//! Per init-task Q&A round (2026-05-24, agent-decided): phase A covers
//! `IssuePendingToken → Enroll → cert returned + token consumed + replay
//! returns 410`. Phase B (`register_node` with the issued cert via mTLS) is
//! deferred to a `#[ignore]`d test until AUTH-0085 ships a real CA — the
//! `StubCaClient` returns synthetic non-PEM bytes that fail X.509 parsing.
//!
//! The mTLS listener is exercised by the existing
//! `tests/two_node_round_trip.rs`; here we focus on the new public surface and
//! the admin-RPC gate that protects it.

#![cfg(unix)]

use std::process::Stdio;
use std::time::Duration;

use disk_proto::disk::{
    enrollment_service_client::EnrollmentServiceClient, EnrollRequest, EnrollmentTokenRequest,
};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::time::timeout;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint};
use tonic::{metadata::MetadataValue, Code, Request};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(15);
const ADMIN_TOKEN: &str = "test-admin-token-disk-0037";

struct ServerHandle {
    child: tokio::process::Child,
    #[allow(dead_code)]
    mtls_port: u16,
    public_port: u16,
    server_cert_pem: String,
    _tmpdir: tempfile::TempDir,
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        if let Some(pid) = self.child.id() {
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
        }
    }
}

/// Allocate a free loopback TCP port by binding and immediately releasing.
/// There is a small race window between release and re-bind by the binary —
/// acceptable for local tests; collisions surface as a startup failure that
/// fails the test loudly rather than silently corrupting results.
fn reserve_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

async fn spawn_server() -> ServerHandle {
    let tmpdir = tempfile::tempdir().expect("tmpdir");
    let root = tmpdir.path();
    let sync_root = root.join("sync");
    std::fs::create_dir_all(&sync_root).unwrap();

    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    let tls_cert = root.join("server.crt");
    let tls_key = root.join("server.key");
    let tls_ca = root.join("ca.crt");
    std::fs::write(&tls_cert, &cert_pem).unwrap();
    std::fs::write(&tls_key, &key_pem).unwrap();
    std::fs::write(&tls_ca, &cert_pem).unwrap();

    let acl_yaml = root.join("acl.yaml");
    std::fs::write(&acl_yaml, "version: 0\nnodes: []\n").unwrap();

    let mtls_port = reserve_port();
    let public_port = reserve_port();
    assert_ne!(mtls_port, public_port);

    let bin = env!("CARGO_BIN_EXE_disk-arcana-server");
    let mut cmd = Command::new(bin);
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("RUST_LOG", "info")
        .env("DISK_BIND_ADDR", format!("127.0.0.1:{mtls_port}"))
        .env(
            "DISK_ENROLLMENT_BIND_ADDR",
            format!("127.0.0.1:{public_port}"),
        )
        .env("DISK_DB_PATH", root.join("server.db"))
        .env("DISK_SYNC_ROOT", &sync_root)
        .env("DISK_TLS_CERT_PATH", &tls_cert)
        .env("DISK_TLS_KEY_PATH", &tls_key)
        .env("DISK_TLS_CA_PATH", &tls_ca)
        .env("DISK_ACL_YAML_PATH", &acl_yaml)
        .env("DISK_USE_STUB_CA", "1")
        .env("DISK_ADMIN_TOKEN", ADMIN_TOKEN)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = cmd.spawn().expect("spawn disk-arcana-server");
    let stderr = child.stderr.take().expect("stderr piped");
    let mut reader = BufReader::new(stderr).lines();

    let mut saw_mtls = false;
    let mut saw_public = false;
    let mut collected = String::new();

    let scan = async {
        while let Ok(Some(line)) = reader.next_line().await {
            collected.push_str(&line);
            collected.push('\n');
            if line.contains("disk-arcana-server listening") {
                saw_mtls = true;
            }
            if line.contains("enrollment public listener listening") {
                saw_public = true;
            }
            if saw_mtls && saw_public {
                break;
            }
        }
    };

    let result = timeout(STARTUP_TIMEOUT, scan).await;
    assert!(
        result.is_ok() && saw_mtls && saw_public,
        "server did not reach both-listening state within {STARTUP_TIMEOUT:?}; log:\n{collected}"
    );

    // Drain stderr in the background to avoid pipe back-pressure deadlocks.
    tokio::spawn(async move {
        while let Ok(Some(_)) = reader.next_line().await {
            // discard
        }
    });

    // Tonic needs a brief moment after the listening log before accept() is
    // ready — the log line is emitted before serve_with_shutdown enters its
    // select loop on the listener.
    tokio::time::sleep(Duration::from_millis(120)).await;

    ServerHandle {
        child,
        mtls_port,
        public_port,
        server_cert_pem: cert_pem,
        _tmpdir: tmpdir,
    }
}

async fn connect_public(handle: &ServerHandle) -> tonic::transport::Channel {
    let endpoint = Endpoint::new(format!("https://127.0.0.1:{}", handle.public_port))
        .unwrap()
        .tls_config(
            ClientTlsConfig::new()
                .ca_certificate(Certificate::from_pem(handle.server_cert_pem.as_bytes()))
                .domain_name("localhost"),
        )
        .unwrap();
    endpoint.connect().await.expect("connect public listener")
}

fn admin_metadata() -> MetadataValue<tonic::metadata::Ascii> {
    ADMIN_TOKEN.parse().expect("ascii admin token")
}

/// Phase A (V-AC-6): cold-boot node issues a pending token via the public
/// listener (admin bearer accepted, TLS only) and exchanges it for a cert.
/// Replaying the same token afterwards must fail.
#[tokio::test]
async fn enroll_through_public_listener_succeeds() {
    let handle = spawn_server().await;
    let channel = connect_public(&handle).await;
    let mut client = EnrollmentServiceClient::new(channel);

    let mut issue_req = Request::new(EnrollmentTokenRequest {
        node_id_hint: "cold-boot-node".into(),
        ttl_seconds: 600,
    });
    issue_req
        .metadata_mut()
        .insert("x-disk-admin-token", admin_metadata());

    let issued = client
        .issue_pending_token(issue_req)
        .await
        .expect("IssuePendingToken succeeds with admin bearer on public listener")
        .into_inner();
    let token_bytes = issued.opaque_token.clone();
    assert!(!token_bytes.is_empty(), "issued token must be non-empty");

    // Minimal CSR — the StubCaClient ignores the payload and returns the
    // canned `STUB-CERT-PEM\n` blob; we just need bytes.
    let csr_pem = b"-----BEGIN CERTIFICATE REQUEST-----\nSTUB\n-----END CERTIFICATE REQUEST-----\n".to_vec();

    let enroll_resp = client
        .enroll(Request::new(EnrollRequest {
            opaque_token: token_bytes.clone(),
            csr_pem: csr_pem.clone(),
            node_id_hint: "cold-boot-node".into(),
        }))
        .await
        .expect("Enroll succeeds on public listener")
        .into_inner();

    assert!(
        !enroll_resp.client_cert_pem.is_empty(),
        "cert PEM must be non-empty"
    );

    // Replay → token already consumed; server returns FAILED_PRECONDITION
    // (single-use semantics from DISK-0005 enrollment_token_replay.rs).
    let replay = client
        .enroll(Request::new(EnrollRequest {
            opaque_token: token_bytes,
            csr_pem,
            node_id_hint: "cold-boot-node".into(),
        }))
        .await;
    let err = replay.expect_err("replay must fail");
    assert!(
        matches!(
            err.code(),
            Code::FailedPrecondition | Code::NotFound | Code::PermissionDenied
        ),
        "expected FAILED_PRECONDITION/NOT_FOUND/PERMISSION_DENIED on replay, got {:?}: {}",
        err.code(),
        err.message()
    );
}

/// AC-3: admin-bearer-protected RPCs reject callers that omit the
/// `x-disk-admin-token` metadata header — the listener has no client-cert
/// gate, so the service-layer bearer check is the sole defence.
#[tokio::test]
async fn admin_rpc_via_public_listener_returns_permission_denied() {
    let handle = spawn_server().await;
    let channel = connect_public(&handle).await;
    let mut client = EnrollmentServiceClient::new(channel);

    let req = Request::new(EnrollmentTokenRequest {
        node_id_hint: "attacker".into(),
        ttl_seconds: 60,
    });

    let err = client
        .issue_pending_token(req)
        .await
        .expect_err("IssuePendingToken without admin metadata must fail");
    // Semantic gate: admin RPC rejected. Service implements the bearer check
    // via `Status::unauthenticated`; the PRD/expectations wording calls this
    // "PermissionDenied" — both communicate "admin RPC denied". We assert the
    // broader denial class so future status-code refactors that distinguish
    // missing-bearer (Unauthenticated) from wrong-role (PermissionDenied) do
    // not regress the AC.
    assert!(
        matches!(err.code(), Code::Unauthenticated | Code::PermissionDenied),
        "expected UNAUTHENTICATED or PERMISSION_DENIED, got {:?}: {}",
        err.code(),
        err.message()
    );
}

/// Phase B (deferred per init-task Q&A round): full chain
/// `register_node + authenticate + delta_download` with the issued cert via
/// the mTLS listener. Blocked on AUTH-0085 — `StubCaClient` returns
/// `b"STUB-CERT-PEM\n"` which is not a valid X.509 certificate, so the mTLS
/// handshake fails. Re-enable when the real CA endpoint lands.
#[ignore = "blocked on AUTH-0085: StubCaClient returns non-PEM bytes"]
#[tokio::test]
async fn register_node_with_issued_cert_via_mtls() {
    unimplemented!("re-enable once AUTH-0085 ships a real CA endpoint");
}
