//! Integration test for DISK-0006 R4 plan AC `it_mtls_perms_audit`.
//!
//! Plan §Test Plan row: `client.key mode 0644 → daemon refuses start;
//! mode 0600 → start ok`. R4 ships the load-side guard; the actual
//! daemon boot wiring lands in later rounds (R5+) but reuses
//! `load_client_identity` as its entry point, so this IT is the
//! upstream contract that the future boot path will inherit.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use disk_client::config::ServerSection;
use disk_client::{audit_key_permissions, build_client_tls_config, load_client_identity};
use tempfile::TempDir;

/// Generate a self-signed cert+key pair valid for `localhost`. The
/// concrete key algorithm does not matter for the permission audit —
/// we only need rustls-loadable PEM blocks.
fn ephemeral_pem() -> (String, String) {
    let bundle = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("rcgen");
    (bundle.cert.pem(), bundle.signing_key.serialize_pem())
}

fn write_with_mode(dir: &TempDir, name: &str, contents: &str, mode: u32) -> PathBuf {
    let path = dir.path().join(name);
    fs::write(&path, contents).expect("write");
    let mut perms = fs::metadata(&path).expect("stat").permissions();
    perms.set_mode(mode);
    fs::set_permissions(&path, perms).expect("chmod");
    path
}

fn dir_mode(dir: &TempDir, mode: u32) {
    let mut perms = fs::metadata(dir.path()).expect("stat").permissions();
    perms.set_mode(mode);
    fs::set_permissions(dir.path(), perms).expect("chmod dir");
}

#[test]
fn it_mtls_perms_audit_rejects_world_readable_key() {
    let dir = TempDir::new().expect("tmp");
    dir_mode(&dir, 0o700);

    let (cert_pem, key_pem) = ephemeral_pem();
    let cert = write_with_mode(&dir, "client.crt", &cert_pem, 0o644);
    let key = write_with_mode(&dir, "client.key", &key_pem, 0o644);

    // Direct audit fails.
    audit_key_permissions(&key).expect_err("0644 must be rejected");

    // Identity loader propagates the same failure.
    load_client_identity(&cert, &key).expect_err("loader must refuse 0644 key");

    // High-level `build_client_tls_config` also fails — daemon boot
    // path inherits the guarantee.
    let server = ServerSection {
        address: "disk.local:9443".to_owned(),
        tls: "manual".to_owned(),
        client_cert: cert.clone(),
        client_key: key.clone(),
        server_ca: None,
        tls_domain: None,
    };
    build_client_tls_config(&server).expect_err("build_client_tls_config must refuse 0644 key");
}

#[test]
fn it_mtls_perms_audit_accepts_owner_only_key() {
    let dir = TempDir::new().expect("tmp");
    dir_mode(&dir, 0o700);

    let (cert_pem, key_pem) = ephemeral_pem();
    let cert = write_with_mode(&dir, "client.crt", &cert_pem, 0o644);
    let key = write_with_mode(&dir, "client.key", &key_pem, 0o600);

    audit_key_permissions(&key).expect("0600 must pass");
    let _ident = load_client_identity(&cert, &key).expect("loader must accept 0600 key");

    let server = ServerSection {
        address: "disk.local:9443".to_owned(),
        tls: "manual".to_owned(),
        client_cert: cert,
        client_key: key,
        server_ca: None,
        tls_domain: None,
    };
    let _cfg = build_client_tls_config(&server).expect("build must succeed at 0600");
}

#[test]
fn it_mtls_perms_audit_accepts_read_only_owner_key() {
    let dir = TempDir::new().expect("tmp");
    dir_mode(&dir, 0o700);

    let (cert_pem, key_pem) = ephemeral_pem();
    let cert = write_with_mode(&dir, "client.crt", &cert_pem, 0o644);
    let key = write_with_mode(&dir, "client.key", &key_pem, 0o400);

    let _ident = load_client_identity(&cert, &key).expect("0400 must also pass — read-only owner");
}
