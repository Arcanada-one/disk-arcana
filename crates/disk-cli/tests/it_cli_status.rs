//! DISK-0039 — `disk status` CLI shortcut IT.
//!
//! Spawns the real `disk` binary as a foreground daemon on an ephemeral
//! loopback port (reusing the R11 harness pattern from `it_daemon_smoke.rs`),
//! then runs `disk status --addr 127.0.0.1:<port>` as a separate process and
//! asserts the pretty-printed snapshot contains the node id, the share row,
//! and the share state. SIGTERMs the daemon at the end.

#![cfg(unix)]

mod common;

use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

use common::read_daemon_listen_port;

const CONFIG: &str = r#"
[node]
id = "status-host"
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

#[tokio::test]
async fn status_command_prints_daemon_snapshot() {
    let bin = env!("CARGO_BIN_EXE_disk");
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("disk.toml");
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(&cfg, CONFIG).unwrap();

    let mut daemon = Command::new(bin)
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

    let stderr = daemon.stderr.take().expect("stderr pipe");
    let port = read_daemon_listen_port(stderr).await;

    // Run `disk status --addr 127.0.0.1:<port>` as a child process.
    let addr = format!("127.0.0.1:{port}");
    let out = Command::new(bin)
        .args(["status", "--addr", &addr])
        .output()
        .await
        .expect("run disk status");

    assert!(
        out.status.success(),
        "disk status exited non-zero: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("status-host"), "node id missing: {stdout}");
    assert!(stdout.contains("wiki"), "share name missing: {stdout}");
    // The share state is now live-written by the sync task.  With a
    // non-reachable server (host:9443 has no listener) the sync task
    // immediately transitions to server_unreachable.  Accept any valid
    // schema state — we are testing the CLI's pretty-print path, not the
    // sync engine.
    let valid_states = [
        "idle",
        "syncing",
        "server_unreachable",
        "unknown_share",
        "acl_mismatch",
        "error",
    ];
    assert!(
        valid_states.iter().any(|s| stdout.contains(s)),
        "share state not in output: {stdout}"
    );

    let pid = daemon.id().expect("child PID") as i32;
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }
    let _ = tokio::time::timeout(Duration::from_secs(10), daemon.wait())
        .await
        .ok();
}
