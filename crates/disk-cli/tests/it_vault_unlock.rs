//! `disk vault unlock|lock|status` CLI integration tests.

use std::process::Command;

use tempfile::tempdir;

const CONFIG: &str = r#"
[node]
id = "vault-test-node"
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

fn disk_bin() -> String {
    std::env::var("CARGO_BIN_EXE_disk").expect("CARGO_BIN_EXE_disk")
}

#[test]
fn vault_unlock_lock_status_round_trip() {
    let tmp = tempdir().unwrap();
    let cfg_path = tmp.path().join("disk.toml");
    let state_dir = tmp.path().join("state");
    std::fs::write(&cfg_path, CONFIG).unwrap();
    std::fs::create_dir_all(&state_dir).unwrap();

    let bin = disk_bin();

    let status_locked = Command::new(&bin)
        .args([
            "vault",
            "status",
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
        ])
        .output()
        .expect("vault status");
    assert!(status_locked.status.success());
    assert!(String::from_utf8_lossy(&status_locked.stdout).contains("locked"));

    let unlock = Command::new(&bin)
        .args([
            "vault",
            "unlock",
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--passphrase",
            "test-secret",
        ])
        .output()
        .expect("vault unlock");
    assert!(
        unlock.status.success(),
        "unlock failed: {}",
        String::from_utf8_lossy(&unlock.stderr)
    );

    let status_unlocked = Command::new(&bin)
        .args([
            "vault",
            "status",
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
        ])
        .output()
        .expect("vault status after unlock");
    assert!(status_unlocked.status.success());
    assert!(String::from_utf8_lossy(&status_unlocked.stdout).contains("unlocked"));

    let lock = Command::new(&bin)
        .args([
            "vault",
            "lock",
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
        ])
        .output()
        .expect("vault lock");
    assert!(lock.status.success());

    let status_locked_again = Command::new(&bin)
        .args([
            "vault",
            "status",
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
        ])
        .output()
        .expect("vault status after lock");
    assert!(status_locked_again.status.success());
    assert!(String::from_utf8_lossy(&status_locked_again.stdout).contains("locked"));
}
