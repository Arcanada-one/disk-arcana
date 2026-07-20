//! DISK-0039 — `disk config validate [--file <path>]` CLI shortcut IT.
//!
//! Pure static check — no daemon, no network. Drives the real `disk` binary
//! against a temp `disk.toml`: a valid file exits 0 and prints a confirmation;
//! a malformed / invalid file exits non-zero and surfaces the validation error.

use std::process::Command;

#[cfg(not(windows))]
const VALID: &str = r#"
[node]
id = "validate-host"
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

#[cfg(windows)]
const VALID: &str = r#"
[node]
id = "validate-host"
[node.default]
intended_direction = "bidirectional"

[server]
address = "host:9443"
client_cert = "C:\\ProgramData\\disk-arcana\\client.crt"
client_key  = "C:\\ProgramData\\disk-arcana\\client.key"

[[share]]
name = "wiki"
path = "C:\\data\\wiki"
"#;

// Invalid: share path is relative (validator requires absolute).
const INVALID_RELATIVE_PATH: &str = r#"
[node]
id = "validate-host"
[node.default]
intended_direction = "bidirectional"

[server]
address = "host:9443"
client_cert = "/etc/disk-arcana/client.crt"
client_key  = "/etc/disk-arcana/client.key"

[[share]]
name = "wiki"
path = "relative/wiki"
"#;

// Malformed TOML — parser error path.
const MALFORMED: &str = "this is not = valid = toml [[[";

#[test]
fn config_validate_accepts_valid_file() {
    let bin = env!("CARGO_BIN_EXE_disk");
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("disk.toml");
    std::fs::write(&cfg, VALID).unwrap();

    let out = Command::new(bin)
        .args(["config", "validate", "--file"])
        .arg(&cfg)
        .output()
        .expect("run disk config validate");

    assert!(
        out.status.success(),
        "valid config rejected: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.to_lowercase().contains("valid"),
        "expected a 'valid' confirmation, got: {stdout}"
    );
}

#[test]
fn config_validate_rejects_invalid_file() {
    let bin = env!("CARGO_BIN_EXE_disk");
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("disk.toml");
    std::fs::write(&cfg, INVALID_RELATIVE_PATH).unwrap();

    let out = Command::new(bin)
        .args(["config", "validate", "--file"])
        .arg(&cfg)
        .output()
        .expect("run disk config validate");

    assert!(
        !out.status.success(),
        "invalid config (relative path) accepted"
    );
    // The ConfigError message must reach the operator on stderr.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.trim().is_empty(),
        "expected a validation error on stderr"
    );
}

#[test]
fn config_validate_rejects_malformed_toml() {
    let bin = env!("CARGO_BIN_EXE_disk");
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("disk.toml");
    std::fs::write(&cfg, MALFORMED).unwrap();

    let out = Command::new(bin)
        .args(["config", "validate", "--file"])
        .arg(&cfg)
        .output()
        .expect("run disk config validate");

    assert!(!out.status.success(), "malformed TOML accepted");
}

#[test]
fn config_validate_errors_on_missing_file() {
    let bin = env!("CARGO_BIN_EXE_disk");
    let out = Command::new(bin)
        .args([
            "config",
            "validate",
            "--file",
            "/nonexistent/disk-arcana/disk.toml",
        ])
        .output()
        .expect("run disk config validate");

    assert!(!out.status.success(), "missing file accepted");
}
