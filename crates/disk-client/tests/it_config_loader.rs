//! DISK-0006 R3 — disk.toml loader against on-disk fixture files.
//!
//! Exercises `DiskConfig::load(&Path)` end-to-end: filesystem read, TOML
//! parse, validation, and inheritance resolution. The fixtures live at
//! `tests/fixtures/{minimal,full}.toml` and are tracked in-repo so the
//! schema's serialisation surface has a versioned reference.

use std::path::PathBuf;

use disk_client::config::{ConfigError, Direction, DiskConfig};

fn fixture(name: &str) -> PathBuf {
    let file = if cfg!(windows) {
        format!("{}.windows.toml", name.trim_end_matches(".toml"))
    } else {
        name.to_string()
    };
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(file)
}

#[test]
fn loads_minimal_fixture() {
    let cfg = DiskConfig::load(&fixture("minimal.toml")).expect("minimal.toml must parse");
    assert_eq!(cfg.node.id, "dev-server");
    assert_eq!(
        cfg.node.default.intended_direction,
        Some(Direction::ReceiveOnly)
    );
    assert_eq!(cfg.server.tls, "auto");
    assert!(cfg.shares.is_empty());
    assert!(cfg.server.server_ca.is_none());
}

#[test]
fn loads_full_fixture_and_resolves_inheritance() {
    let cfg = DiskConfig::load(&fixture("full.toml")).expect("full.toml must parse");

    assert_eq!(cfg.node.id, "arcana-ai");
    assert_eq!(cfg.shares.len(), 3);

    // Explicit publisher direction.
    assert_eq!(
        cfg.share_direction("hermes-artefacts"),
        Some(Direction::Publisher)
    );

    // No explicit direction → inherits node default (bidirectional).
    assert_eq!(cfg.share_direction("wiki"), Some(Direction::Bidirectional));

    // Explicit override of node default.
    assert_eq!(
        cfg.share_direction("downloads"),
        Some(Direction::ReceiveOnly)
    );

    // Publisher section only attached to the publisher-direction share.
    let hermes = cfg
        .shares
        .iter()
        .find(|s| s.name == "hermes-artefacts")
        .unwrap();
    let publisher = hermes
        .publisher
        .as_ref()
        .expect("publisher section present");
    assert!(publisher.sign_key_ref.starts_with("vault:transit/"));
    assert!(publisher.quarantine_on_failure);
}

#[test]
fn load_reports_io_error_for_missing_path() {
    let err = DiskConfig::load(&fixture("does-not-exist.toml")).unwrap_err();
    match err {
        ConfigError::Io(_) => {}
        other => panic!("expected Io error, got {other:?}"),
    }
}

#[test]
fn load_reports_validation_error_for_invalid_toml() {
    let tmp = tempfile::tempdir().unwrap();
    let bad = tmp.path().join("bad.toml");
    std::fs::write(
        &bad,
        r#"
[node]
id = "ok"
[node.default]
intended_direction = "bidirectional"
[server]
address = "host:9443"
client_cert = "/a"
client_key = "/b"
[[share]]
name = "rel"
path = "relative/no/slash"
"#,
    )
    .unwrap();
    let err = DiskConfig::load(&bad).unwrap_err();
    match err {
        ConfigError::Validation(msg) => assert!(msg.contains("absolute")),
        other => panic!("expected Validation, got {other:?}"),
    }
}

#[test]
fn load_reports_toml_parse_error_for_malformed_input() {
    let tmp = tempfile::tempdir().unwrap();
    let bad = tmp.path().join("malformed.toml");
    std::fs::write(&bad, "this is not = [valid toml\n").unwrap();
    let err = DiskConfig::load(&bad).unwrap_err();
    match err {
        ConfigError::Toml(_) => {}
        other => panic!("expected Toml, got {other:?}"),
    }
}
