//! DISK-0006 R10 — `disk share init --preset` subprocess IT.
//!
//! Plan §All Rounds R10: 1 IT. The pure-data wizard logic
//! (`render_share_section`, `append_share`) is covered by inline UT in
//! `crates/disk-cli/src/share_init.rs`. This IT spawns the real `disk`
//! binary and asserts the end-to-end happy path for the most complex
//! preset (`publish` — requires `--sign-key-ref` and emits a
//! `[share.publisher]` block).
//!
//! Spawned via `env!("CARGO_BIN_EXE_disk")` — same pattern as the
//! server's `it_main_boot_wiring.rs`.

use std::fs;
use std::process::Command;

#[cfg(not(windows))]
const BASE: &str = r#"
[node]
id = "arcana-ai"
[node.default]
intended_direction = "bidirectional"

[server]
address = "host:9443"
client_cert = "/etc/disk-arcana/client.crt"
client_key  = "/etc/disk-arcana/client.key"
"#;

#[cfg(windows)]
const BASE: &str = r#"
[node]
id = "arcana-ai"
[node.default]
intended_direction = "bidirectional"

[server]
address = "host:9443"
client_cert = "C:\\ProgramData\\disk-arcana\\client.crt"
client_key  = "C:\\ProgramData\\disk-arcana\\client.key"
"#;

fn hermes_share_path() -> &'static str {
    if cfg!(windows) {
        r"C:\var\disk-arcana\hermes"
    } else {
        "/var/disk-arcana/hermes"
    }
}

fn temp_share_path() -> &'static str {
    if cfg!(windows) {
        r"C:\temp\x"
    } else {
        "/tmp/x"
    }
}

#[test]
fn share_init_publish_appends_publisher_block_end_to_end() {
    let bin = env!("CARGO_BIN_EXE_disk");
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("disk.toml");
    fs::write(&cfg, BASE).unwrap();

    let status = Command::new(bin)
        .args([
            "share",
            "init",
            "--preset",
            "publish",
            "--name",
            "hermes-artefacts",
            "--path",
            hermes_share_path(),
            "--sign-key-ref",
            "vault:transit/keys/hermes-publisher",
            "--config",
        ])
        .arg(&cfg)
        .status()
        .expect("spawn disk binary");

    assert!(status.success(), "disk share init exited non-zero");

    let written = fs::read_to_string(&cfg).unwrap();
    assert!(written.contains("name = \"hermes-artefacts\""));
    assert!(written.contains("intended_direction = \"publisher\""));
    assert!(written.contains("[share.publisher]"));
    assert!(written.contains("sign_key_ref = \"vault:transit/keys/hermes-publisher\""));
    assert!(written.contains("quarantine_on_failure = true"));

    // Sanity: the file remains a valid disk.toml after the wizard.
    use disk_client::config::{Direction, DiskConfig};
    use std::str::FromStr;
    let parsed = DiskConfig::from_str(&written).expect("re-parse after wizard");
    assert_eq!(parsed.shares.len(), 1);
    assert_eq!(
        parsed.share_direction("hermes-artefacts"),
        Some(Direction::Publisher)
    );
}

#[test]
fn share_init_publish_missing_sign_key_ref_exits_nonzero() {
    let bin = env!("CARGO_BIN_EXE_disk");
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("disk.toml");
    fs::write(&cfg, BASE).unwrap();

    let output = Command::new(bin)
        .args([
            "share",
            "init",
            "--preset",
            "publish",
            "--name",
            "x",
            "--path",
            temp_share_path(),
            "--config",
        ])
        .arg(&cfg)
        .output()
        .expect("spawn disk binary");

    assert!(
        !output.status.success(),
        "expected non-zero exit when --sign-key-ref is missing for publish"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--sign-key-ref"),
        "stderr should mention --sign-key-ref; got: {stderr}"
    );

    // Original file untouched.
    let after = fs::read_to_string(&cfg).unwrap();
    assert_eq!(after, BASE);
}
