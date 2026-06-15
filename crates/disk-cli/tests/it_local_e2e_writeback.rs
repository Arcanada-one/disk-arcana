//! Local E2E writeback integration test — real loopback server + daemon.
//!
//! Spawns a real `disk-arcana-server` with a throwaway rcgen CA and verifies
//! that the `disk` daemon's sync-loop drives a genuine share-state transition:
//!
//!   idle → syncing → idle
//!
//! with `last_success_at` advancing from `null` to a non-null timestamp,
//! proving that `ExchangeState` completed successfully against a live server.
//!
//! Architecture:
//!  1. Generate a throwaway CA, server cert (SAN localhost/127.0.0.1), and
//!     node cert (client identity for mTLS).
//!  2. Compute blake3(node_cert_der) as the cert fingerprint used in the ACL
//!     so the server grants the share to this node.
//!  3. Write ACL YAML, disk.toml, and cert files to a temp directory.
//!  4. Spawn `disk-arcana-server` with DISK_ACL_ALLOW_UNSIGNED=1 and
//!     DISK_USE_STUB_CA=1.
//!  5. Spawn `disk daemon start --foreground` pointing at the server.
//!  6. Poll `/status` until the share's `state` transitions away from `idle`
//!     AND `last_success_at` is non-null.
//!  7. Assert the final state is `idle` (full sync cycle completed).
//!  8. SIGTERM both processes and assert clean exits.
//!
//! The `status_schema_at_startup` test below remains as a fast (< 5 s)
//! smoke test for the `/status` JSON schema contract that does NOT require
//! a live server.
//!
//! `cfg(unix)`: SIGTERM delivery via `libc::kill` is unix-only.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn parse_port_from_listening_line(line: &str) -> Option<u16> {
    let tail = line.rsplit_once(':')?.1;
    tail.trim().parse::<u16>().ok()
}

/// Find the `disk-arcana-server` binary produced by the current cargo build.
///
/// During `cargo test`, the test binary lives in `target/<profile>/deps/`.
/// Stepping up two levels (`deps` → `<profile>`) gives the directory that
/// holds `disk-arcana-server`.  Falls back to `PATH` lookup if not found.
fn find_server_bin() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(deps_dir) = exe.parent() {
            if let Some(profile_dir) = deps_dir.parent() {
                let candidate = profile_dir.join("disk-arcana-server");
                if candidate.exists() {
                    return candidate;
                }
            }
        }
    }
    // Fall back: let the shell resolve it from PATH.
    PathBuf::from("disk-arcana-server")
}

/// Allocate a free loopback TCP port.  There is a TOCTOU window between
/// releasing and rebinding; acceptable for local tests.
fn reserve_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

/// Minimal deserialization targets for `/status`.
#[derive(Debug, Deserialize)]
struct StatusBody {
    node: String,
    daemon_uptime_s: u64,
    config_version: String,
    shares: Vec<StatusShare>,
}

#[derive(Debug, Deserialize)]
struct StatusShare {
    name: String,
    state: String,
    last_success_at: Option<serde_json::Value>,
}

// ── Cert helpers ──────────────────────────────────────────────────────────────

fn make_test_ca() -> (rcgen::Certificate, KeyPair, String) {
    let ca_key = KeyPair::generate().expect("CA keypair");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "E2E-Writeback Test CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages.extend_from_slice(&[
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
    ]);
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA");
    let ca_pem = ca_cert.pem();
    (ca_cert, ca_key, ca_pem)
}

fn make_server_cert(ca_cert: &rcgen::Certificate, ca_key: &KeyPair) -> (String, String) {
    let srv_key = KeyPair::generate().expect("server keypair");
    let mut srv_params =
        CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()]).expect("srv params");
    srv_params
        .distinguished_name
        .push(DnType::CommonName, "disk-arcana-server-e2e");
    srv_params.use_authority_key_identifier_extension = true;
    srv_params
        .key_usages
        .push(KeyUsagePurpose::DigitalSignature);
    srv_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    let srv_cert = srv_params
        .signed_by(&srv_key, ca_cert, ca_key)
        .expect("sign server cert");
    (srv_cert.pem(), srv_key.serialize_pem())
}

/// Returns `(cert_pem, key_pem, cert_der_bytes)`.
fn make_node_cert(ca_cert: &rcgen::Certificate, ca_key: &KeyPair) -> (String, String, Vec<u8>) {
    let node_key = KeyPair::generate().expect("node keypair");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("node params");
    params
        .distinguished_name
        .push(DnType::CommonName, "e2e-writeback-node");
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    let node_cert = params
        .signed_by(&node_key, ca_cert, ca_key)
        .expect("sign node cert");
    let cert_der = node_cert.der().to_vec();
    (node_cert.pem(), node_key.serialize_pem(), cert_der)
}

/// Compute blake3(der_bytes) as a 64-char lowercase hex string.
///
/// Mirrors `CertIdentity::from_der` in the server's `auth/cert_identity.rs`:
/// the ACL fingerprint the enforcer compares against is blake3(DER bytes).
fn cert_fingerprint_hex(der: &[u8]) -> String {
    let hash = disk_core::delta::blake3_hash(der);
    hex::encode(hash)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Full E2E cycle: seeded edit → `idle → syncing → idle` with
/// `last_success_at` advancing from null.
///
/// Uses a real `disk-arcana-server` binary found in the cargo target directory
/// (same directory as the `disk` binary under test).
#[tokio::test]
async fn share_state_transitions_after_poll_tick() {
    // ── 1. Generate CA + server cert + node cert ──────────────────────────
    // Both certs are signed by the same CA so:
    //   - the server trusts the client cert (DISK_TLS_CA_PATH = that CA)
    //   - the client trusts the server cert (disk.toml server_ca = that CA)
    let (ca_cert, ca_key, ca_pem) = make_test_ca();
    let (server_cert_pem, server_key_pem) = make_server_cert(&ca_cert, &ca_key);
    let (node_cert_pem, node_key_pem, node_cert_der) = make_node_cert(&ca_cert, &ca_key);

    let tmpdir = tempfile::tempdir().expect("tmpdir");
    let root = tmpdir.path();

    std::fs::write(root.join("ca.crt"), &ca_pem).unwrap();
    std::fs::write(root.join("server.crt"), &server_cert_pem).unwrap();
    std::fs::write(root.join("server.key"), &server_key_pem).unwrap();
    std::fs::write(root.join("node.crt"), &node_cert_pem).unwrap();
    std::fs::write(root.join("node.key"), &node_key_pem).unwrap();
    std::fs::create_dir_all(root.join("sync-root")).unwrap();

    let vault_dir = root.join("vault");
    std::fs::create_dir_all(&vault_dir).unwrap();
    // Seed a file so the scanner has something to report in ExchangeState.
    std::fs::write(vault_dir.join("seed.md"), b"hello loopback e2e\n").unwrap();

    // ── 2. Write ACL with the node cert fingerprint ───────────────────────
    let fp = cert_fingerprint_hex(&node_cert_der);
    let acl_content = format!(
        "version: 1\nupdated_at: \"2025-01-01T00:00:00Z\"\nsigned_by: \"test-signer\"\nnodes:\n  - cert_fingerprint: \"{fp}\"\n    shares:\n      test-share: bidirectional\n"
    );
    std::fs::write(root.join("acl.yaml"), &acl_content).unwrap();

    let server_bin = find_server_bin();
    let daemon_bin = env!("CARGO_BIN_EXE_disk");

    // ── 3. Spawn server ───────────────────────────────────────────────────
    const SPAWN_ATTEMPTS: u32 = 5;
    let mut last_log;
    let mut attempt = 0u32;

    let (mut server_child, mtls_port) = loop {
        attempt += 1;
        let mtls_port = reserve_port();
        let public_port = reserve_port();
        let health_port = reserve_port();

        let mut cmd = Command::new(&server_bin);
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
            .env("DISK_SYNC_ROOT", root.join("sync-root"))
            .env("DISK_TLS_CERT_PATH", root.join("server.crt"))
            .env("DISK_TLS_KEY_PATH", root.join("server.key"))
            .env("DISK_TLS_CA_PATH", root.join("ca.crt"))
            .env("DISK_ACL_YAML_PATH", root.join("acl.yaml"))
            .env("DISK_ADMIN_TOKEN", "e2e-admin-token")
            .env("DISK_ACL_ALLOW_UNSIGNED", "1")
            .env("DISK_USE_STUB_CA", "1")
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

        let result = tokio::time::timeout(Duration::from_secs(20), scan).await;
        if result.is_ok() && saw_mtls && saw_public {
            // Drain stderr in the background so pipe back-pressure doesn't
            // block the server.
            tokio::spawn(async move {
                let mut r = reader;
                while let Ok(Some(_)) = r.next_line().await {}
            });
            break (child, mtls_port);
        }

        last_log = collected;
        drop(child);
        assert!(
            attempt < SPAWN_ATTEMPTS,
            "server did not reach listening state in {SPAWN_ATTEMPTS} attempts; log:\n{last_log}"
        );
    };
    // Brief sleep so tonic's accept loop is ready.
    tokio::time::sleep(Duration::from_millis(120)).await;

    // ── 4. Write disk.toml for the daemon ─────────────────────────────────
    let disk_toml = format!(
        "[node]\nid = \"e2e-writeback-node\"\n\n[node.default]\nintended_direction = \"bidirectional\"\n\n[server]\naddress = \"127.0.0.1:{mtls_port}\"\nclient_cert = \"{node_crt}\"\nclient_key  = \"{node_key}\"\nserver_ca   = \"{ca_crt}\"\n\n[[share]]\nname = \"test-share\"\npath = \"{vault}\"\n",
        mtls_port = mtls_port,
        node_crt = root.join("node.crt").display(),
        node_key = root.join("node.key").display(),
        ca_crt = root.join("ca.crt").display(),
        vault = vault_dir.display(),
    );
    let cfg_path = root.join("disk.toml");
    std::fs::write(&cfg_path, &disk_toml).unwrap();

    // ── 5. Spawn daemon ───────────────────────────────────────────────────
    let state_dir = root.join("state");
    std::fs::create_dir_all(&state_dir).unwrap();

    let mut daemon_child = Command::new(daemon_bin)
        .args([
            "daemon",
            "start",
            "--foreground",
            "--status-bind",
            "127.0.0.1:0",
            "--config",
        ])
        .arg(&cfg_path)
        .args(["--state-dir"])
        .arg(&state_dir)
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn disk daemon");

    let stdout = daemon_child.stdout.take().expect("stdout pipe");
    let daemon_port = {
        let read_port = async {
            let mut reader = BufReader::new(stdout).lines();
            while let Some(line) = reader.next_line().await.ok().flatten() {
                if let Some(p) = parse_port_from_listening_line(&line) {
                    return Some(p);
                }
            }
            None
        };
        tokio::time::timeout(Duration::from_secs(30), read_port)
            .await
            .expect("daemon must emit 'listening on …' within 30 s")
            .expect("listening line absent before stdout closed")
    };

    // Drain daemon stderr in background.
    let daemon_stderr = daemon_child.stderr.take().expect("daemon stderr");
    tokio::spawn(async move {
        let mut r = BufReader::new(daemon_stderr).lines();
        while let Ok(Some(_)) = r.next_line().await {}
    });

    let http = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{daemon_port}/status");

    // ── 6. Capture before-state ───────────────────────────────────────────
    // Allow a short boot window then capture the initial state.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let before_json: serde_json::Value = if let Ok(resp) = http.get(&url).send().await {
        resp.json().await.unwrap_or_default()
    } else {
        serde_json::Value::Null
    };

    // ── 7. Poll /status for idle + non-null last_success_at ───────────────
    //
    // Timeout: 40 s.  The daemon's POLL_INTERVAL is 5 s so the first
    // ExchangeState call happens within seconds of boot.
    let final_body: Option<StatusBody> = tokio::time::timeout(Duration::from_secs(40), async {
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let body: StatusBody = match http.get(&url).send().await {
                Ok(r) => match r.json().await {
                    Ok(b) => b,
                    Err(_) => continue,
                },
                Err(_) => continue,
            };
            if body.shares.is_empty() {
                continue;
            }
            let share = &body.shares[0];
            let success_at_present = share
                .last_success_at
                .as_ref()
                .map(|v| !v.is_null())
                .unwrap_or(false);
            if success_at_present && share.state == "idle" {
                return body;
            }
        }
    })
    .await
    .ok();

    // ── 8. Assertions ─────────────────────────────────────────────────────
    let after_json: serde_json::Value = if let Ok(resp) = http.get(&url).send().await {
        resp.json().await.unwrap_or_default()
    } else {
        serde_json::Value::Null
    };

    let body = final_body.unwrap_or_else(|| {
        panic!(
            "share did not reach idle+last_success_at within 40 s.\n\
             BEFORE: {before_json}\n\
             AFTER:  {after_json}\n\
             Check: mTLS cert wired? ACL fingerprint match? Server logs?"
        )
    });

    assert_eq!(body.node, "e2e-writeback-node");
    assert_eq!(body.shares.len(), 1, "must have exactly one share");
    assert_eq!(body.shares[0].name, "test-share");
    assert_eq!(
        body.shares[0].state, "idle",
        "share must reach idle after a successful sync cycle; \
         got state: {}",
        body.shares[0].state
    );
    let last_success = body.shares[0]
        .last_success_at
        .as_ref()
        .expect("last_success_at must be non-null after a successful sync");
    assert!(!last_success.is_null(), "last_success_at must not be null");

    eprintln!(
        "[it_local_e2e_writeback] PASS\n\
         BEFORE: {before_json}\n\
         AFTER:  {after_json}\n\
         share '{}' reached idle with last_success_at={last_success}",
        body.shares[0].name
    );

    // ── 9. SIGTERM both processes ──────────────────────────────────────────
    let daemon_pid = daemon_child.id().expect("daemon PID") as libc::pid_t;
    unsafe {
        libc::kill(daemon_pid, libc::SIGTERM);
    }
    let daemon_exit = tokio::time::timeout(Duration::from_secs(10), daemon_child.wait())
        .await
        .expect("daemon did not exit within 10 s of SIGTERM")
        .expect("wait daemon");
    assert!(
        daemon_exit.success(),
        "daemon exited non-zero after SIGTERM: {daemon_exit:?}"
    );

    let server_pid = server_child.id().expect("server PID") as libc::pid_t;
    unsafe {
        libc::kill(server_pid, libc::SIGTERM);
    }
    let _ = tokio::time::timeout(Duration::from_secs(10), server_child.wait()).await;
}

/// Fast schema smoke test — does NOT require a running `disk-arcana-server`.
///
/// Starts the daemon with a dead gRPC port so the sync task fails fast
/// (server_unreachable) and asserts the `/status` JSON schema is correct
/// at startup.  Runs in < 5 s.
#[tokio::test]
async fn status_schema_at_startup() {
    const CONFIG_UNREACHABLE_SERVER: &str = r#"
[node]
id = "e2e-writeback-test"
[node.default]
intended_direction = "bidirectional"

[server]
address = "127.0.0.1:19999"
client_cert = "/etc/disk-arcana/client.crt"
client_key  = "/etc/disk-arcana/client.key"

[[share]]
name = "test-vault"
path = "/tmp/disk-e2e-vault"
"#;

    let bin = env!("CARGO_BIN_EXE_disk");
    let dir = tempfile::tempdir().unwrap();
    let cfg_path = dir.path().join("disk.toml");
    std::fs::write(&cfg_path, CONFIG_UNREACHABLE_SERVER).unwrap();
    std::fs::create_dir_all("/tmp/disk-e2e-vault").unwrap();

    let mut child = Command::new(bin)
        .args([
            "daemon",
            "start",
            "--foreground",
            "--status-bind",
            "127.0.0.1:0",
            "--config",
        ])
        .arg(&cfg_path)
        .args(["--state-dir"])
        .arg(dir.path().join("state"))
        .env("RUST_LOG", "error")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn disk daemon");

    let stdout = child.stdout.take().expect("stdout pipe");
    let port = {
        let read_port = async {
            let mut reader = BufReader::new(stdout).lines();
            while let Some(line) = reader.next_line().await.ok().flatten() {
                if let Some(p) = parse_port_from_listening_line(&line) {
                    return Some(p);
                }
            }
            None
        };
        tokio::time::timeout(Duration::from_secs(30), read_port)
            .await
            .expect("listening line within 30 s")
            .expect("missing listening line")
    };

    let url = format!("http://127.0.0.1:{port}/status");
    let body: StatusBody = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("GET /status")
        .json()
        .await
        .expect("decode JSON");

    assert_eq!(body.node, "e2e-writeback-test");
    assert_eq!(body.config_version, "1.1");
    assert_eq!(body.shares.len(), 1);
    assert_eq!(body.shares[0].name, "test-vault");
    let valid_states = [
        "idle",
        "syncing",
        "server_unreachable",
        "unknown_share",
        "acl_mismatch",
        "error",
    ];
    assert!(
        valid_states.contains(&body.shares[0].state.as_str()),
        "share state must be a valid schema string; got: {}",
        body.shares[0].state
    );
    assert!(
        body.shares[0].last_success_at.is_none()
            || body.shares[0]
                .last_success_at
                .as_ref()
                .map(|v| v.is_null())
                .unwrap_or(false),
        "last_success_at must be null at startup"
    );
    assert!(body.daemon_uptime_s < 30, "uptime must be small at boot");

    let pid = child.id().expect("PID") as libc::pid_t;
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    let _ = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .ok();
}
