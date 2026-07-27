//! DISK-0006 R11 — daemon foreground smoke IT.
//!
//! Plan §All Rounds R11: «smoke test on Mac (manual + CI dry-run)».
//! This IT spawns the real `disk` binary with `daemon start --foreground`
//! against a tmpdir-hosted `disk.toml`, asserts the REST endpoint comes up
//! within 5 seconds, GETs `/status` and verifies it parses against the
//! §4.12.4 schema, then SIGTERMs the child and asserts a clean exit.
//!
//! `cfg(unix)`: SIGTERM delivery via `libc::kill` is unix-only — same
//! gate as the server bootstrap IT (`it_main_boot_wiring.rs`).

#![cfg(unix)]

mod common;

use std::process::Stdio;
use std::time::Duration;

use serde::Deserialize;
use tokio::process::Command;

use common::read_daemon_listen_port;

const CONFIG: &str = r#"
[node]
id = "smoke-host"
[node.default]
intended_direction = "bidirectional"

[server]
address = "host:9443"
client_cert = "/etc/disk-arcana/client.crt"
client_key  = "/etc/disk-arcana/client.key"

[[share]]
name = "wiki"
path = "/data/wiki"
"#;

#[derive(Debug, Deserialize)]
struct StatusBody {
    node: String,
    daemon_uptime_s: u64,
    config_version: String,
    shares: Vec<StatusShareBody>,
}

#[derive(Debug, Deserialize)]
struct StatusShareBody {
    name: String,
    path: String,
    declared_direction: String,
    state: String,
}

#[tokio::test]
async fn daemon_serves_status_and_terminates_on_sigterm() {
    let bin = env!("CARGO_BIN_EXE_disk");
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("disk.toml");
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(&cfg, CONFIG).unwrap();

    let mut child = Command::new(bin)
        .args([
            "daemon",
            "start",
            "--foreground",
            "--status-bind",
            "127.0.0.1:0",
            "--state-dir",
        ])
        .arg(&state_dir)
        .args(["--config"])
        .arg(&cfg)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn disk daemon");

    let stderr = child.stderr.take().expect("stderr pipe");
    let port = read_daemon_listen_port(stderr).await;

    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{port}/status");
    let body: StatusBody = client
        .get(&url)
        .send()
        .await
        .expect("GET /status")
        .json()
        .await
        .expect("decode JSON");

    assert_eq!(body.node, "smoke-host");
    assert_eq!(body.config_version, "1.1");
    assert_eq!(body.shares.len(), 1);
    assert_eq!(body.shares[0].name, "wiki");
    assert_eq!(body.shares[0].path, "/data/wiki");
    assert_eq!(body.shares[0].declared_direction, "bidirectional");
    // The sync task writes back live state after its first connect attempt.
    // With no server at host:9443 the sync task transitions to server_unreachable.
    // Accept any valid schema state — this test verifies the schema shape.
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
        "unexpected share state: {}",
        body.shares[0].state
    );
    // daemon_uptime_s is small but must be non-negative — sanity.
    assert!(body.daemon_uptime_s < 30, "uptime should be small at boot");

    // SIGTERM the child — daemon should shut down cleanly.
    let pid = child.id().expect("child PID") as i32;
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }

    let exit = tokio::time::timeout(Duration::from_secs(15), child.wait())
        .await
        .expect("daemon did not exit within 15 s of SIGTERM")
        .expect("await child");
    assert!(
        exit.success(),
        "daemon exited non-zero on SIGTERM: {exit:?}"
    );
}

#[tokio::test]
async fn daemon_refuses_background_mode() {
    let bin = env!("CARGO_BIN_EXE_disk");
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("disk.toml");
    std::fs::write(&cfg, CONFIG).unwrap();

    let output = Command::new(bin)
        .args(["daemon", "start", "--config"])
        .arg(&cfg)
        .output()
        .await
        .expect("run disk daemon start");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("background mode is not supported"),
        "expected background-not-supported hint, got: {stderr}"
    );
}

#[test]
fn parse_port_from_listening_line_unit() {
    use common::parse_port_from_listening_line;
    assert_eq!(
        parse_port_from_listening_line("disk daemon listening on 127.0.0.1:54321\n"),
        Some(54321)
    );
}
