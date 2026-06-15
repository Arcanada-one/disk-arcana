//! Local E2E writeback integration test.
//!
//! Spawns the real `disk daemon` binary over loopback and asserts that the
//! sync-loop status writeback is functional: `/status` must show a share
//! state that has transitioned away from `idle` after at least one sync
//! attempt.
//!
//! This test does NOT require a running `disk-arcana-server` — the daemon
//! starts its sync tasks, they attempt to connect to the (absent) gRPC
//! server, fail with a transport error, and set the share state to
//! `server_unreachable`.  That transition proves the P1 writeback wiring
//! (`update_share` on the final snapshot after `run_iteration`) is live.
//!
//! For a full idle→syncing→idle cycle over loopback mTLS, use the manual
//! `scripts/dev-local-e2e.sh` bring-up (which requires release binaries
//! and openssl; documented in DISK-0056 V-AC-5 operator smoke checklist).
//!
//! `cfg(unix)`: SIGTERM delivery via `libc::kill` is unix-only.

#![cfg(unix)]

use std::process::Stdio;
use std::time::Duration;

use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn parse_port_from_listening_line(line: &str) -> Option<u16> {
    let tail = line.rsplit_once(':')?.1;
    tail.trim().parse::<u16>().ok()
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

// A disk.toml that points at a server that will never answer (no gRPC
// listener on 127.0.0.1:19999) so the sync task transitions to
// server_unreachable after the first poll tick.
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

// ── Main test ─────────────────────────────────────────────────────────────────

/// Prove that `update_share` wiring is live: the sync task must write a
/// live state into `/status` (not leave it frozen at the startup idle seed).
///
/// Proof strategy: spawn a daemon whose share points at a gRPC server that
/// has no listener (port 19999).  The sync task calls `build_disk_client`,
/// fails with connection refused, and immediately writes `server_unreachable`
/// via `update_share`.  Because `connect()` fails fast, this state is often
/// visible even on the first `/status` poll after the daemon starts listening.
/// We accept any state != "idle" as proof that writeback fired.
///
/// Timeline:
///  1. Spawn daemon; wait for the «listening on» port announcement.
///  2. Poll `/status` up to 12 s looking for a non-idle state.
///  3. Assert the share state is not idle (proves writeback fired).
///  4. SIGTERM daemon, assert clean exit.
#[tokio::test]
async fn share_state_transitions_after_poll_tick() {
    let bin = env!("CARGO_BIN_EXE_disk");
    let dir = tempfile::tempdir().unwrap();
    let cfg_path = dir.path().join("disk.toml");
    std::fs::write(&cfg_path, CONFIG_UNREACHABLE_SERVER).unwrap();

    // Create the vault dir so the sync task can scan it.
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
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn disk daemon");

    // Read the bound port from the daemon's stdout «listening on» line.
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
            .expect("daemon must emit 'listening on …' within 30 s")
            .expect("listening line absent before stdout closed")
    };

    let http = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{port}/status");

    // Poll up to 12 s for a non-idle state.  This accepts the case where
    // writeback has already fired before we reach the first poll.
    let final_body = tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let body: StatusBody = match http.get(&url).send().await {
                Ok(r) => match r.json().await {
                    Ok(b) => b,
                    Err(_) => continue,
                },
                Err(_) => continue,
            };
            if !body.shares.is_empty() && body.shares[0].state != "idle" {
                return body;
            }
        }
    })
    .await
    .expect("share state must transition away from idle within 12 s (writeback not wired?)");

    assert_eq!(final_body.node, "e2e-writeback-test");
    assert_eq!(final_body.config_version, "1.1");
    assert_eq!(final_body.shares.len(), 1);
    assert_eq!(final_body.shares[0].name, "test-vault");
    assert!(
        final_body.daemon_uptime_s < 30,
        "uptime must be small at boot"
    );

    // Assert the transition: any state except idle is proof that
    // `update_share` fired.  Expected: "server_unreachable".
    let final_state = &final_body.shares[0].state;
    assert_ne!(
        final_state.as_str(),
        "idle",
        "P1 writeback must set the share state after a failed connect; \
         still 'idle' — update_share not called"
    );
    eprintln!(
        "[it_local_e2e_writeback] PASS — share '{}' state after writeback: {}",
        final_body.shares[0].name, final_state
    );

    // SIGTERM the daemon.
    let pid = child.id().expect("child PID") as libc::pid_t;
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    let exit = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .expect("daemon did not exit within 10 s of SIGTERM")
        .expect("await child");
    assert!(exit.success(), "daemon exited non-zero: {exit:?}");
}

/// Verify the initial `/status` schema: node, uptime, config_version, and a
/// single share with the expected descriptor fields and a null last_success_at.
///
/// This test is intentionally narrow (no state transition wait) and runs in
/// < 5 s, making it a fast smoke gate for schema conformance independent of
/// the poll-tick timing.
#[tokio::test]
async fn status_schema_at_startup() {
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
    // At startup the share starts idle; writeback may have already fired
    // (setting server_unreachable) by the first poll.  Accept either state:
    // the schema contract is that `state` is a known string.
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
    // last_success_at must be null at startup (no successful sync yet).
    assert!(
        body.shares[0].last_success_at.is_none()
            || body.shares[0]
                .last_success_at
                .as_ref()
                .map(|v| v.is_null())
                .unwrap_or(false),
        "last_success_at must be null at startup"
    );

    let pid = child.id().expect("PID") as libc::pid_t;
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    let _ = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .ok();
}

// ── V-AC-5 Operator smoke checklist (GUI) ────────────────────────────────────
//
// The following checks require a running `disk-gui` and cannot be automated
// in this test file. Run them manually after `scripts/dev-local-e2e.sh`:
//
// 1. Launch `disk-gui` (connects to 127.0.0.1:9444 by default).
// 2. Observe: green "daemon connected" indicator; node id "local-test";
//    uptime counter incrementing; config_version present; one share named
//    "test-share" listed.
// 3. Edit a file in /tmp/disk-local/vault/ (e.g. `echo hello > /tmp/disk-local/vault/note.txt`).
// 4. Within ~10 seconds, observe the share's state indicator change
//    (idle → syncing → back to idle or server_unreachable if gRPC not configured)
//    and last_success_at update (if the gRPC round-trip completes).
// 5. Confirm no GUI crash, no frozen state, no "loading…" spinner stuck.
