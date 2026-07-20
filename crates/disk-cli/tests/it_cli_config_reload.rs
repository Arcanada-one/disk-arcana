//! DISK-0039 — `disk config reload [--addr <ip:port>]` CLI shortcut IT.
//!
//! Spawns a foreground daemon on an ephemeral loopback port, then runs
//! `disk config reload --addr 127.0.0.1:<port>` and asserts the queued
//! confirmation. Also checks the unreachable-daemon error path.

#![cfg(unix)]

use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::Command;

const CONFIG: &str = r#"
[node]
id = "reload-host"
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

fn parse_port_from_listening_line(line: &str) -> Option<u16> {
    let tail = line.rsplit_once(':')?.1;
    tail.trim().parse::<u16>().ok()
}

#[tokio::test]
async fn config_reload_command_queues_reload() {
    let bin = env!("CARGO_BIN_EXE_disk");
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("disk.toml");
    let state_dir = dir.path().join("state");
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
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn disk daemon");

    let stdout = daemon.stdout.take().expect("stdout pipe");
    let mut stderr = daemon.stderr.take().expect("stderr pipe");
    let read_port = async {
        let mut reader = BufReader::new(stdout).lines();
        while let Some(line) = reader.next_line().await.ok().flatten() {
            if let Some(port) = parse_port_from_listening_line(&line) {
                return Some(port);
            }
        }
        None
    };
    let maybe_port = tokio::time::timeout(Duration::from_secs(30), read_port)
        .await
        .expect("daemon must emit listening line within 30 s");
    let port = match maybe_port {
        Some(port) => port,
        None => {
            let mut error = String::new();
            stderr.read_to_string(&mut error).await.unwrap();
            panic!("listening line absent before stdout closed; stderr={error}");
        }
    };

    let addr = format!("127.0.0.1:{port}");
    let out = Command::new(bin)
        .args(["config", "reload", "--addr", &addr])
        .output()
        .await
        .expect("run disk config reload");

    assert!(
        out.status.success(),
        "disk config reload exited non-zero: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.to_lowercase().contains("queued") || stdout.to_lowercase().contains("reload"),
        "expected a queued/reload confirmation, got: {stdout}"
    );

    let pid = daemon.id().expect("child PID") as i32;
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }
    let _ = tokio::time::timeout(Duration::from_secs(15), daemon.wait()).await;
}

#[tokio::test]
async fn config_reload_command_errors_when_no_daemon() {
    let bin = env!("CARGO_BIN_EXE_disk");
    let out = Command::new(bin)
        .args(["config", "reload", "--addr", "127.0.0.1:1"])
        .output()
        .await
        .expect("run disk config reload");
    assert!(
        !out.status.success(),
        "expected non-zero exit when daemon unreachable"
    );
}
