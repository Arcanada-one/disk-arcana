#![cfg(all(target_os = "linux", feature = "synthetic-fixtures"))]
use std::path::Path;
use std::process::{Command, Output};

const A: &str = "10000000-0000-4000-8000-000000000001";
const B: &str = "10000000-0000-4000-8000-000000000002";
const DA: &str = "20000000-0000-4000-8000-000000000001";
const DB: &str = "20000000-0000-4000-8000-000000000002";

fn worker(mode: &str, path: &Path, realm: &str, deployment: &str, selector: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_disk-capture-fixture-worker"))
        .arg(mode)
        .arg(path)
        .args([realm, deployment, selector])
        .output()
        .unwrap()
}
fn success(out: Output) -> Vec<u8> {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

#[test]
fn two_real_roots_distinct_bytes_and_process_restart_receipts() {
    let folder = tempfile::tempdir().unwrap();
    let a = folder.path().join("disk-personal-fixture-a");
    let b = folder.path().join("disk-personal-fixture-b");
    let first_a = success(worker("seed", &a, A, DA, "a"));
    let first_b = success(worker("seed", &b, B, DB, "b"));
    assert_ne!(first_a, first_b);
    for _ in 0..2 {
        assert_eq!(first_a, success(worker("read", &a, A, DA, "a")));
        assert_eq!(first_b, success(worker("read", &b, B, DB, "b")));
    }
    for (path, realm, deployment, selector) in [
        (&a, B, DA, "a"),
        (&a, A, DB, "a"),
        (&a, A, DA, "b"),
        (&b, A, DB, "b"),
        (&b, B, DA, "b"),
        (&b, B, DB, "a"),
    ] {
        let out = worker("read", path, realm, deployment, selector);
        assert!(!out.status.success());
        assert!(out.stdout.is_empty());
    }
    assert_eq!(first_a, success(worker("read", &a, A, DA, "a")));
    assert_eq!(first_b, success(worker("read", &b, B, DB, "b")));
}

#[test]
fn malformed_interface_and_unavailable_startup_do_not_create_root() {
    let folder = tempfile::tempdir().unwrap();
    let root = folder.path().join("disk-personal-fixture-denied");
    for (mode, realm, deployment, selector) in [
        ("unknown", A, DA, "a"),
        ("seed", "not-a-uuid", DA, "a"),
        ("seed", A, "20000000-0000-4000-8000-00000000000A", "a"),
        ("seed", A, DA, "private-payload"),
    ] {
        assert!(!worker(mode, &root, realm, deployment, selector)
            .status
            .success());
        assert!(!root.exists());
    }
    let historical = Command::new(env!("CARGO_BIN_EXE_disk-capture-fixture-worker"))
        .arg("seed")
        .arg(&root)
        .output()
        .unwrap();
    assert!(!historical.status.success());
    assert!(!root.exists());
    assert_eq!(
        success(worker("denied", &root, A, DA, "a")),
        b"STARTUP_UNAVAILABLE\n"
    );
    assert!(!root.exists());
}
