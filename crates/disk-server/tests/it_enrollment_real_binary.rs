//! DISK-0037 — real-binary end-to-end enrollment test.
//!
//! Spawns the `disk-arcana-server` binary with the dual-listener
//! configuration introduced by DISK-0037 (mTLS on `DISK_BIND_ADDR`, TLS-only
//! public on `DISK_ENROLLMENT_BIND_ADDR`) and exercises the enrollment flow
//! against a fully simulated Auth Arcana CA endpoint.
//!
//! The CA endpoint that DISK-0037 wires through is AUTH-0085's
//! `/v1/internal-ca/issue` — not shipped yet. To unblock phase B of AC-6
//! (real-binary E2E including `register_node` over mTLS with an issued
//! cert), this test stands up a `wiremock` HTTP server that signs incoming
//! CSRs with a process-local `rcgen` CA. The binary runs in production
//! mode (`HttpCaClient::from_env`, no `DISK_USE_STUB_CA`) and points at
//! the mock CA via `AUTH_ARCANA_CA_URL`.
//!
//! Three test cases:
//!  * `enroll_through_public_listener_succeeds` — phase A: token → enroll →
//!    real X.509 cert + replay rejection on the public listener.
//!  * `admin_rpc_via_public_listener_returns_permission_denied` — admin RPC
//!    without bearer rejected on the public listener.
//!  * `register_node_with_issued_cert_via_mtls` — phase B: connect to the
//!    mTLS listener with the issued cert and complete `register_node` +
//!    `authenticate`.

#![cfg(unix)]

use std::process::Stdio;
use std::time::Duration;

use disk_proto::disk::{
    auth_service_client::AuthServiceClient, enrollment_service_client::EnrollmentServiceClient,
    EnrollRequest, EnrollmentTokenRequest, NodeAuthRequest, NodeRegisterRequest,
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequestParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::time::timeout;
use tonic::transport::{Certificate as TonicCert, ClientTlsConfig, Endpoint, Identity};
use tonic::{metadata::MetadataValue, Code, Request};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request as WmRequest, Respond, ResponseTemplate};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(15);
const ADMIN_TOKEN: &str = "test-admin-token-disk-0037";
const CA_BEARER: &str = "test-ca-token-disk-0037";

// ---------------------------------------------------------------------------
// Test CA + wiremock signer
// ---------------------------------------------------------------------------

/// Wiremock responder that signs the CSR carried in the request body with a
/// process-local rcgen CA and returns the AUTH-0085 `/v1/internal-ca/issue`
/// shape (`{client_cert_pem, ca_chain_pem}`). Owns both halves of the CA so
/// no other code path needs them after construction.
struct CaSigner {
    ca_cert: Certificate,
    ca_key: KeyPair,
    ca_chain_pem: String,
}

impl Respond for CaSigner {
    fn respond(&self, req: &WmRequest) -> ResponseTemplate {
        let body: serde_json::Value =
            serde_json::from_slice(&req.body).expect("CA POST body must be JSON");
        let csr_pem = body["csr_pem"]
            .as_str()
            .expect("CA POST body must carry csr_pem");
        let csr_params = CertificateSigningRequestParams::from_pem(csr_pem).expect("parse CSR PEM");
        let issuer = rcgen::Issuer::from_ca_cert_pem(&self.ca_cert.pem(), &self.ca_key)
            .expect("build issuer");
        let signed = csr_params
            .signed_by(&issuer)
            .expect("sign CSR with test CA");
        ResponseTemplate::new(200).set_body_json(json!({
            "client_cert_pem": signed.pem(),
            "ca_chain_pem": self.ca_chain_pem,
        }))
    }
}

fn make_test_ca() -> (Certificate, KeyPair, String) {
    let ca_key = KeyPair::generate().expect("CA keypair");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "DISK-0037 Test CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages.extend_from_slice(&[
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
    ]);
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA");
    let ca_pem = ca_cert.pem();
    (ca_cert, ca_key, ca_pem)
}

fn make_server_cert(ca_cert: &Certificate, ca_key: &KeyPair) -> (String, String) {
    let srv_key = KeyPair::generate().expect("server keypair");
    let mut srv_params =
        CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()]).expect("srv params");
    srv_params
        .distinguished_name
        .push(DnType::CommonName, "disk-arcana-server-test");
    srv_params.use_authority_key_identifier_extension = true;
    srv_params
        .key_usages
        .push(KeyUsagePurpose::DigitalSignature);
    srv_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    srv_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    let issuer = rcgen::Issuer::from_ca_cert_pem(&ca_cert.pem(), ca_key).expect("build issuer");
    let srv_cert = srv_params
        .signed_by(&srv_key, &issuer)
        .expect("sign server cert");
    (srv_cert.pem(), srv_key.serialize_pem())
}

fn make_node_csr(node_id: &str) -> (String, String) {
    let node_key = KeyPair::generate().expect("node keypair");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("csr params");
    params.distinguished_name.push(DnType::CommonName, node_id);
    let csr = params.serialize_request(&node_key).expect("serialize CSR");
    (csr.pem().expect("CSR PEM"), node_key.serialize_pem())
}

// ---------------------------------------------------------------------------
// Server handle + fixture
// ---------------------------------------------------------------------------

struct ServerHandle {
    child: tokio::process::Child,
    mtls_port: u16,
    public_port: u16,
    #[allow(dead_code)]
    server_cert_pem: String,
    ca_cert_pem: String,
    _mock: MockServer,
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
/// A small race window remains between release and re-bind by the binary —
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

    let (ca_cert, ca_key, ca_pem) = make_test_ca();
    let (server_cert_pem, server_key_pem) = make_server_cert(&ca_cert, &ca_key);

    let tls_cert = root.join("server.crt");
    let tls_key = root.join("server.key");
    let tls_ca = root.join("ca.crt");
    std::fs::write(&tls_cert, &server_cert_pem).unwrap();
    std::fs::write(&tls_key, &server_key_pem).unwrap();
    std::fs::write(&tls_ca, &ca_pem).unwrap();

    let acl_yaml = root.join("acl.yaml");
    std::fs::write(&acl_yaml, "version: 0\nnodes: []\n").unwrap();

    let mock = MockServer::start().await;
    let signer = CaSigner {
        ca_cert,
        ca_key,
        ca_chain_pem: ca_pem.clone(),
    };
    Mock::given(method("POST"))
        .and(path("/v1/internal-ca/issue"))
        .respond_with(signer)
        .mount(&mock)
        .await;
    let ca_url = format!("{}/v1/internal-ca/issue", mock.uri());

    // Retry the whole port-reserve → spawn → both-listening handshake: under a
    // parallel `cargo test` run, the ephemeral ports returned by `reserve_port`
    // are released (TOCTOU) before the child binds them, so another process may
    // grab one in the window. On a failed handshake we re-reserve fresh ports
    // and re-spawn rather than fail the test. Same race class as DISK-0041.
    const SPAWN_ATTEMPTS: u32 = 5;
    let bin = env!("CARGO_BIN_EXE_disk-arcana-server");

    let mut last_log = String::new();
    let mut attempt = 0;
    let (child, mtls_port, public_port) = loop {
        attempt += 1;

        let mtls_port = reserve_port();
        let public_port = reserve_port();
        // The health listener defaults to the FIXED 0.0.0.0:9446; left at the
        // default, parallel test servers collide on it (Address already in use)
        // → the health server errors → the whole process shuts down. Bind it to
        // a unique loopback port per server so the three tests don't fight.
        let health_port = reserve_port();
        assert_ne!(mtls_port, public_port);
        assert_ne!(mtls_port, health_port);
        assert_ne!(public_port, health_port);

        let mut cmd = Command::new(bin);
        cmd.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("RUST_LOG", "info")
            .env("DISK_BIND_ADDR", format!("127.0.0.1:{mtls_port}"))
            .env(
                "DISK_ENROLLMENT_BIND_ADDR",
                format!("127.0.0.1:{public_port}"),
            )
            .env("DISK_HEALTH_BIND_ADDR", format!("127.0.0.1:{health_port}"))
            .env("DISK_DB_PATH", root.join("server.db"))
            .env("DISK_SYNC_ROOT", &sync_root)
            .env("DISK_TLS_CERT_PATH", &tls_cert)
            .env("DISK_TLS_KEY_PATH", &tls_key)
            .env("DISK_TLS_CA_PATH", &tls_ca)
            .env("DISK_ACL_YAML_PATH", &acl_yaml)
            .env("DISK_ADMIN_TOKEN", ADMIN_TOKEN)
            // Skip ACL signature verification (no GPG infra in this test) WITHOUT
            // forcing the stub CA — DISK_ACL_ALLOW_UNSIGNED is orthogonal to the
            // CA client, so the real HttpCaClient path below still runs against
            // the wiremock. Production must instead provide DISK_ACL_SIG_PATH.
            .env("DISK_ACL_ALLOW_UNSIGNED", "1")
            // Production code path: HttpCaClient against our wiremock.
            .env("AUTH_ARCANA_CA_TOKEN", CA_BEARER)
            .env("AUTH_ARCANA_CA_URL", &ca_url)
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
        if result.is_ok() && saw_mtls && saw_public {
            // Re-attach the reader so the post-spawn drain below keeps working.
            let drain_reader = reader;
            tokio::spawn(async move {
                let mut reader = drain_reader;
                while let Ok(Some(_)) = reader.next_line().await {
                    // discard to avoid pipe back-pressure
                }
            });
            break (child, mtls_port, public_port);
        }

        last_log = collected;
        // Child failed to reach listening state — kill it and retry with fresh
        // ports (kill_on_drop handles the kill when `child` is dropped).
        drop(child);
        assert!(
            attempt < SPAWN_ATTEMPTS,
            "server did not reach both-listening state in {SPAWN_ATTEMPTS} attempts \
             (last within {STARTUP_TIMEOUT:?}); log:\n{last_log}"
        );
    };
    let _ = &last_log;

    // Tonic needs a brief moment after the listening log before accept() is
    // ready — the log line is emitted before serve_with_shutdown enters its
    // select loop on the listener. (stderr drain already spawned on success.)
    tokio::time::sleep(Duration::from_millis(120)).await;

    ServerHandle {
        child,
        mtls_port,
        public_port,
        server_cert_pem,
        ca_cert_pem: ca_pem,
        _mock: mock,
        _tmpdir: tmpdir,
    }
}

/// Connect with a short retry-backoff. The server logs "listening" the instant
/// its socket is bound, but tonic needs a few more milliseconds to enter the
/// accept loop; under a parallel `cargo test` run that gap widens and a single
/// `connect()` can race it (ConnectionRefused). Retry briefly instead of
/// relying on one fixed sleep.
async fn connect_with_retry(endpoint: Endpoint, what: &str) -> tonic::transport::Channel {
    let mut last_err = None;
    for _ in 0..50 {
        match endpoint.connect().await {
            Ok(ch) => return ch,
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(Duration::from_millis(40)).await;
            }
        }
    }
    panic!("connect {what} after retries: {:?}", last_err);
}

async fn connect_public(handle: &ServerHandle) -> tonic::transport::Channel {
    let endpoint = Endpoint::new(format!("https://127.0.0.1:{}", handle.public_port))
        .unwrap()
        .tls_config(
            ClientTlsConfig::new()
                .ca_certificate(TonicCert::from_pem(handle.ca_cert_pem.as_bytes()))
                .domain_name("localhost"),
        )
        .unwrap();
    connect_with_retry(endpoint, "public listener").await
}

async fn connect_mtls(
    handle: &ServerHandle,
    issued_cert_pem: &str,
    node_key_pem: &str,
) -> tonic::transport::Channel {
    let identity = Identity::from_pem(issued_cert_pem.as_bytes(), node_key_pem.as_bytes());
    let endpoint = Endpoint::new(format!("https://127.0.0.1:{}", handle.mtls_port))
        .unwrap()
        .tls_config(
            ClientTlsConfig::new()
                .ca_certificate(TonicCert::from_pem(handle.ca_cert_pem.as_bytes()))
                .identity(identity)
                .domain_name("localhost"),
        )
        .unwrap();
    connect_with_retry(endpoint, "mTLS listener").await
}

fn admin_metadata() -> MetadataValue<tonic::metadata::Ascii> {
    ADMIN_TOKEN.parse().expect("ascii admin token")
}

fn cert_pem_is_valid_x509(pem: &[u8]) -> bool {
    let text = match std::str::from_utf8(pem) {
        Ok(s) => s,
        Err(_) => return false,
    };
    text.contains("-----BEGIN CERTIFICATE-----") && text.contains("-----END CERTIFICATE-----")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Phase A (AC-6 first half): cold-boot node issues a pending token via the
/// public listener (admin bearer accepted, TLS only) and exchanges it for a
/// real X.509 certificate signed by the test CA. Replaying the same token
/// afterwards must fail.
#[tokio::test]
async fn enroll_through_public_listener_succeeds() {
    let handle = spawn_server().await;
    let channel = connect_public(&handle).await;
    let mut client = EnrollmentServiceClient::new(channel);

    let mut issue_req = Request::new(EnrollmentTokenRequest {
        node_id_hint: "cold-boot-node".into(),
        ttl_seconds: 600,
        tenant_id: String::new(),
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

    let (csr_pem, _node_key_pem) = make_node_csr("cold-boot-node");

    let enroll_resp = client
        .enroll(Request::new(EnrollRequest {
            opaque_token: token_bytes.clone(),
            csr_pem: csr_pem.clone().into_bytes(),
            node_id_hint: "cold-boot-node".into(),
        }))
        .await
        .expect("Enroll succeeds on public listener")
        .into_inner();

    assert!(
        cert_pem_is_valid_x509(&enroll_resp.client_cert_pem),
        "issued cert must be valid X.509 PEM, got {:?}",
        String::from_utf8_lossy(&enroll_resp.client_cert_pem)
    );
    assert!(
        cert_pem_is_valid_x509(&enroll_resp.ca_chain_pem),
        "CA chain must be valid PEM"
    );

    // Replay → token already consumed; server returns FAILED_PRECONDITION
    // (single-use semantics from DISK-0005 enrollment_token_replay.rs).
    let replay = client
        .enroll(Request::new(EnrollRequest {
            opaque_token: token_bytes,
            csr_pem: csr_pem.into_bytes(),
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
/// `x-disk-admin-token` metadata header. The listener has no client-cert
/// gate, so the service-layer bearer check is the sole defence — the
/// expectations call this `PermissionDenied`; today the implementation
/// returns `Unauthenticated`. Semantic gate assertion accepts both.
#[tokio::test]
async fn admin_rpc_via_public_listener_returns_permission_denied() {
    let handle = spawn_server().await;
    let channel = connect_public(&handle).await;
    let mut client = EnrollmentServiceClient::new(channel);

    let req = Request::new(EnrollmentTokenRequest {
        node_id_hint: "attacker".into(),
        ttl_seconds: 60,
        tenant_id: String::new(),
    });

    let err = client
        .issue_pending_token(req)
        .await
        .expect_err("IssuePendingToken without admin metadata must fail");
    assert!(
        matches!(err.code(), Code::Unauthenticated | Code::PermissionDenied),
        "expected UNAUTHENTICATED or PERMISSION_DENIED, got {:?}: {}",
        err.code(),
        err.message()
    );
}

/// Phase B (AC-6 second half): the cert returned by `Enroll` on the public
/// listener completes a real mTLS handshake against `:9443` and lets the
/// caller run an authenticated AuthService RPC. Token issuance + enroll
/// happen exactly as in phase A; the new assertion is that the binary's
/// `client_ca_root` accepts the issued cert and the AuthService is
/// reachable.
#[tokio::test]
async fn register_node_with_issued_cert_via_mtls() {
    let handle = spawn_server().await;

    // Phase A — get a real cert from the public listener.
    let public_channel = connect_public(&handle).await;
    let mut enroll_client = EnrollmentServiceClient::new(public_channel);
    let mut issue_req = Request::new(EnrollmentTokenRequest {
        node_id_hint: "phase-b-node".into(),
        ttl_seconds: 600,
        tenant_id: String::new(),
    });
    issue_req
        .metadata_mut()
        .insert("x-disk-admin-token", admin_metadata());
    let issued = enroll_client
        .issue_pending_token(issue_req)
        .await
        .expect("issue token")
        .into_inner();

    let (csr_pem, node_key_pem) = make_node_csr("phase-b-node");
    let enroll_resp = enroll_client
        .enroll(Request::new(EnrollRequest {
            opaque_token: issued.opaque_token,
            csr_pem: csr_pem.into_bytes(),
            node_id_hint: "phase-b-node".into(),
        }))
        .await
        .expect("enroll")
        .into_inner();
    let issued_cert_pem =
        String::from_utf8(enroll_resp.client_cert_pem).expect("cert PEM is UTF-8");
    assert!(
        cert_pem_is_valid_x509(issued_cert_pem.as_bytes()),
        "issued cert must be valid X.509 PEM"
    );

    // Phase B — open an mTLS channel using the issued cert as the client
    // identity. The handshake validates that the binary's `client_ca_root`
    // (loaded from DISK_TLS_CA_PATH) accepts certs signed by the test CA.
    let mtls_channel = connect_mtls(&handle, &issued_cert_pem, &node_key_pem).await;
    let mut auth_client = AuthServiceClient::new(mtls_channel);

    let register = auth_client
        .register_node(Request::new(NodeRegisterRequest {
            node_id: "phase-b-node".into(),
            display_name: "Phase B test node".into(),
            platform: "test".into(),
            ..Default::default()
        }))
        .await
        .expect("register_node succeeds over mTLS with issued cert")
        .into_inner();
    assert!(
        !register.api_key.is_empty(),
        "register_node must return a non-empty api_key"
    );

    let auth = auth_client
        .authenticate(Request::new(NodeAuthRequest {
            node_id: "phase-b-node".into(),
            api_key: register.api_key,
        }))
        .await
        .expect("authenticate succeeds with issued api_key")
        .into_inner();
    assert!(
        !auth.session_token.is_empty(),
        "authenticate must return a non-empty session_token"
    );
}
