//! DISK-0039 — `disk config reload` CLI shortcut IT.

#![cfg(unix)]

mod common;

use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

use common::read_daemon_listen_port;

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

#[tokio::test]
async fn config_reload_command_queues_daemon_reload() {
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
    let _ = tokio::time::timeout(Duration::from_secs(10), daemon.wait())
        .await
        .ok();
}
