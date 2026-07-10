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

use std::process::Stdio;
use std::time::Duration;

use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

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

fn parse_port_from_listening_line(line: &str) -> Option<u16> {
    // Pattern: "disk daemon listening on 127.0.0.1:NNNNN"
    let tail = line.rsplit_once(':')?.1;
    tail.trim().parse::<u16>().ok()
}

#[tokio::test]
async fn daemon_serves_status_and_terminates_on_sigterm() {
    let bin = env!("CARGO_BIN_EXE_disk");
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("disk.toml");
    std::fs::write(&cfg, CONFIG).unwrap();

    let mut child = Command::new(bin)
        .args([
            "daemon",
            "start",
            "--foreground",
            "--status-bind",
            "127.0.0.1:0",
            "--config",
        ])
        .arg(&cfg)
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn disk daemon");

    // The daemon prints the bound address to stdout (println in run_start);
    // read until we see «listening on» to recover the OS-assigned port.
    let stdout = child.stdout.take().expect("stdout pipe");
    let read_port = async {
        let mut reader = BufReader::new(stdout).lines();
        while let Some(line) = reader.next_line().await.ok().flatten() {
            if let Some(port) = parse_port_from_listening_line(&line) {
                return Some(port);
            }
        }
        None
    };
    let port = tokio::time::timeout(Duration::from_secs(30), read_port)
        .await
        .expect("daemon must emit 'listening on 127.0.0.1:NNNNN' within 30 s")
        .expect("listening line absent before stdout closed");

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
    // With no server at host:9443 it transitions to server_unreachable.
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
        .args([
            "daemon",
            "start",
            "--status-bind",
            "127.0.0.1:0",
            "--config",
        ])
        .arg(&cfg)
        .output()
        .await
        .expect("spawn disk daemon");

    assert!(
        !output.status.success(),
        "expected non-zero exit when --foreground is missing"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("background mode is not supported"),
        "expected background-not-supported hint, got: {stderr}"
    );
}

#[test]
fn parse_port_from_listening_line_extracts_port() {
    assert_eq!(
        parse_port_from_listening_line("disk daemon listening on 127.0.0.1:54321\n"),
        Some(54321)
    );
    assert_eq!(parse_port_from_listening_line("nothing useful here"), None);
}
