//! DISK-0006 R1 — integration test for production server bootstrap.
//!
//! Asserts that the `disk-arcana-server` binary built from `src/main.rs`:
//! 1. Loads `ServerConfig` from env vars and refuses missing-required-vars.
//! 2. Runs migrations + spawns ACL reload + F-1 forwarder + F-1 tombstone task,
//!    surfacing each via tracing log lines.
//! 3. Reaches the «listening» state on the configured bind address.
//! 4. Shuts down cleanly on SIGTERM (no orphaned background tasks, exit
//!    status 0).
//!
//! Unlike `tests/two_node_round_trip.rs` (which uses a `spawn_server` helper
//! that duplicates bootstrap logic), this test invokes the real binary so any
//! drift between `main.rs` and library wiring fails the build before it
//! reaches production.

#![cfg(unix)]

use std::process::Stdio;
use std::time::Duration;

use rcgen::{generate_simple_self_signed, CertifiedKey};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::time::{sleep, timeout};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(15);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

struct ServerFixture {
    // Held for Drop side-effect (tempdir cleanup).
    _tmpdir: tempfile::TempDir,
    db_path: std::path::PathBuf,
    sync_root: std::path::PathBuf,
    tls_cert: std::path::PathBuf,
    tls_key: std::path::PathBuf,
    tls_ca: std::path::PathBuf,
    acl_yaml: std::path::PathBuf,
}

impl ServerFixture {
    fn build() -> Self {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let root = tmpdir.path();
        let sync_root = root.join("sync");
        std::fs::create_dir_all(&sync_root).unwrap();

        // Self-signed cert used as both server identity and CA root — handshake
        // never runs in this test (no client connects), but ServerTlsConfig
        // validates PEM parsing at boot.
        let CertifiedKey {
            cert,
            signing_key: key_pair,
        } = generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        let tls_cert = root.join("server.crt");
        let tls_key = root.join("server.key");
        let tls_ca = root.join("ca.crt");
        std::fs::write(&tls_cert, &cert_pem).unwrap();
        std::fs::write(&tls_key, &key_pem).unwrap();
        std::fs::write(&tls_ca, &cert_pem).unwrap();

        let acl_yaml = root.join("acl.yaml");
        // Minimal placeholder — reload loop will pick this up; initial state
        // stays Unhealthy until a valid YAML lands (test does not exercise that).
        std::fs::write(&acl_yaml, "version: 0\nnodes: []\n").unwrap();

        Self {
            db_path: root.join("server.db"),
            sync_root,
            tls_cert,
            tls_key,
            tls_ca,
            acl_yaml,
            _tmpdir: tmpdir,
        }
    }

    fn spawn_server(&self, bind_addr: &str) -> Command {
        self.spawn_server_with(bind_addr, "127.0.0.1:0")
    }

    fn spawn_server_with(&self, bind_addr: &str, enrollment_bind_addr: &str) -> Command {
        let bin = env!("CARGO_BIN_EXE_disk-arcana-server");
        let mut cmd = Command::new(bin);
        cmd.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("RUST_LOG", "info")
            .env("DISK_BIND_ADDR", bind_addr)
            .env("DISK_ENROLLMENT_BIND_ADDR", enrollment_bind_addr)
            .env("DISK_DB_PATH", &self.db_path)
            .env("DISK_SYNC_ROOT", &self.sync_root)
            .env("DISK_TLS_CERT_PATH", &self.tls_cert)
            .env("DISK_TLS_KEY_PATH", &self.tls_key)
            .env("DISK_TLS_CA_PATH", &self.tls_ca)
            .env("DISK_ACL_YAML_PATH", &self.acl_yaml)
            .env("DISK_USE_STUB_CA", "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        cmd
    }
}

#[tokio::test]
async fn missing_required_env_var_aborts_startup() {
    let bin = env!("CARGO_BIN_EXE_disk-arcana-server");
    // Clear all DISK_* vars; do NOT set the required ones.
    let output = Command::new(bin)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("RUST_LOG", "warn")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("spawn binary");

    assert!(
        !output.status.success(),
        "binary should refuse to start without required env vars (status: {:?})",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("missing required env var"),
        "expected MissingEnv error in stderr, got: {stderr}"
    );
}

#[tokio::test]
async fn boot_wiring_emits_f1_markers_and_shuts_down_clean() {
    let fixture = ServerFixture::build();
    let mut cmd = fixture.spawn_server("127.0.0.1:0");
    let mut child = cmd.spawn().expect("spawn disk-arcana-server");

    // tonic binds the supplied address even with port 0; the listening
    // log line lands on stderr because tracing's default fmt layer writes
    // there. Drain stderr looking for the F-1 markers + listening line.
    let stderr = child.stderr.take().expect("stderr piped");
    let mut reader = BufReader::new(stderr).lines();

    let mut saw_forwarder = false;
    let mut saw_tombstone = false;
    let mut saw_listening = false;
    let mut saw_acl_reload = false;
    let mut saw_public_listening = false;
    let mut collected = String::new();

    let scan = async {
        while let Ok(Some(line)) = reader.next_line().await {
            collected.push_str(&line);
            collected.push('\n');
            if line.contains("ops_bot forwarder spawned") {
                saw_forwarder = true;
            }
            if line.contains("tombstone publisher spawned") {
                saw_tombstone = true;
            }
            if line.contains("acl reload loop spawned") {
                saw_acl_reload = true;
            }
            if line.contains("disk-arcana-server listening") {
                saw_listening = true;
            }
            if line.contains("enrollment public listener listening") {
                saw_public_listening = true;
            }
            if saw_forwarder
                && saw_tombstone
                && saw_acl_reload
                && saw_listening
                && saw_public_listening
            {
                break;
            }
        }
    };

    let scan_result = timeout(STARTUP_TIMEOUT, scan).await;
    assert!(
        scan_result.is_ok(),
        "server did not reach listening state within {STARTUP_TIMEOUT:?}; collected log:\n{collected}"
    );

    assert!(
        saw_forwarder,
        "F-1 forwarder spawn marker missing; log:\n{collected}"
    );
    assert!(
        saw_tombstone,
        "F-1 tombstone publisher spawn marker missing; log:\n{collected}"
    );
    assert!(
        saw_acl_reload,
        "ACL reload loop spawn marker missing; log:\n{collected}"
    );
    assert!(saw_listening, "listening marker missing; log:\n{collected}");
    assert!(
        saw_public_listening,
        "enrollment public listener marker missing; log:\n{collected}"
    );

    // Drain in background to avoid a stalled pipe interfering with shutdown.
    tokio::spawn(async move {
        while let Ok(Some(_)) = reader.next_line().await {
            // discard
        }
    });

    // Graceful shutdown: SIGTERM.
    let pid = child.id().expect("child has pid");
    // SAFETY: kill(2) on unix; pid is a valid child handle until exit.
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }

    // Allow shutdown_signal() handler + tonic drain to complete.
    let exit = timeout(SHUTDOWN_TIMEOUT, child.wait())
        .await
        .expect("shutdown timed out")
        .expect("child wait failed");
    // tonic exits 0 on graceful shutdown.
    assert!(
        exit.success(),
        "server exited non-zero on SIGTERM: {exit:?}"
    );

    // Tmpdir held until here.
    drop(fixture);
    let _ = sleep(Duration::from_millis(50)).await;
}

/// DISK-0063 regression: the server must create `DISK_SYNC_ROOT` at startup.
///
/// A freshly-provisioned host (MetaDb reprovisioned, sync-root dir not yet
/// created) previously had EVERY `delta_upload` silently rejected, because
/// `path_guard::validate` canonicalizes `self.root` and `canonicalize()` on a
/// non-existent directory returns `OutsideRoot` → `invalid_argument "path
/// guard"` on the first chunk. The fix (main.rs `create_dir_all(&cfg.sync_root)`
/// before wiring the SyncService) means a missing sync-root can no longer break
/// all uploads invisibly. This test deletes the fixture's sync-root before boot
/// and asserts the binary recreates it and still reaches the listening state.
#[tokio::test]
async fn boot_creates_missing_sync_root() {
    let fixture = ServerFixture::build();

    // Remove the sync-root the fixture pre-created, to simulate a host where the
    // dir does not exist yet (the DISK-0063 live scenario).
    std::fs::remove_dir_all(&fixture.sync_root).expect("remove sync_root");
    assert!(
        !fixture.sync_root.exists(),
        "precondition: sync_root must be absent before boot"
    );

    let mut cmd = fixture.spawn_server("127.0.0.1:0");
    let mut child = cmd.spawn().expect("spawn disk-arcana-server");

    let stderr = child.stderr.take().expect("stderr piped");
    let mut reader = BufReader::new(stderr).lines();
    let mut collected = String::new();

    let scan = async {
        while let Ok(Some(line)) = reader.next_line().await {
            collected.push_str(&line);
            collected.push('\n');
            if line.contains("disk-arcana-server listening") {
                break;
            }
        }
    };
    let scan_result = timeout(STARTUP_TIMEOUT, scan).await;
    assert!(
        scan_result.is_ok(),
        "server did not reach listening state within {STARTUP_TIMEOUT:?}; collected log:\n{collected}"
    );

    // The decisive assertion: the binary recreated the sync-root at startup.
    assert!(
        fixture.sync_root.is_dir(),
        "server must create DISK_SYNC_ROOT at startup; dir still absent. log:\n{collected}"
    );

    // Drain remaining output so the pipe never stalls shutdown.
    tokio::spawn(async move { while let Ok(Some(_)) = reader.next_line().await {} });

    let pid = child.id().expect("child has pid");
    // SAFETY: kill(2) on unix; pid is a valid child handle until exit.
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }
    let exit = timeout(SHUTDOWN_TIMEOUT, child.wait())
        .await
        .expect("shutdown timed out")
        .expect("child wait failed");
    assert!(
        exit.success(),
        "server exited non-zero on SIGTERM: {exit:?}"
    );

    drop(fixture);
    let _ = sleep(Duration::from_millis(50)).await;
}
