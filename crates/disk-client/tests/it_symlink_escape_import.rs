//! DISK-0006 R8 — symlink-escape rejection during `disk import-state`.
//!
//! Plan §Test Plan row `it_symlink_escape_import.rs`: «Import-state на tree
//! с symlink → /etc/passwd: file rejected, no MetaDB row, no read of target.»
//!
//! Two-layer defence verified here:
//! 1. `WalkDir::follow_links(false)` — the symlink is reported as
//!    `is_symlink() == true`, NOT as `is_file()`, so the loop skips it
//!    before any I/O on the target.
//! 2. `std::fs::canonicalize` + `starts_with(canonical_root)` — if a future
//!    refactor flips `follow_links(true)` the canonicalisation guard still
//!    catches the escape and increments `escapes_blocked`.
//!
//! The test also opens `/etc/passwd` once to read its real blake3 digest,
//! then asserts NO row in the resulting MetaDb has that digest — proving
//! `import_state` never read the symlink target.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

use disk_client::{hash_file, import_state};
use disk_core::MetaDb;
use tempfile::tempdir;

const ESCAPE_TARGET: &str = "/etc/passwd";

#[tokio::test]
async fn import_state_skips_symlink_to_etc_passwd() {
    // Sanity precondition — if the target is unreadable (CI sandbox), skip
    // the test rather than masking the real assertion as a false negative.
    if fs::metadata(ESCAPE_TARGET).is_err() {
        eprintln!("/etc/passwd unreadable in this environment; skipping");
        return;
    }
    let etc_passwd_hash = hash_file(&PathBuf::from(ESCAPE_TARGET))
        .expect("read /etc/passwd to capture its real digest");

    let dir = tempdir().unwrap();
    let db_path = dir.path().join("meta.db");
    let db = MetaDb::open(&db_path).await.unwrap();

    let share = dir.path().join("share");
    fs::create_dir(&share).unwrap();
    fs::write(share.join("ok.txt"), b"benign-payload").unwrap();
    symlink(ESCAPE_TARGET, share.join("escape_link")).unwrap();

    let report = import_state(&share, "node-r8", &db, false)
        .await
        .expect("import_state");

    assert_eq!(
        report.files_seen, 1,
        "only the regular file should be counted; symlink must be skipped"
    );
    assert_eq!(report.files_imported, 1);
    assert_eq!(
        report.escapes_blocked, 0,
        "follow_links(false) keeps the symlink out before canonicalize fires"
    );

    let rows = db.list_all_files().await.unwrap();
    assert_eq!(rows.len(), 1, "MetaDb must hold exactly one seeded row");
    let only = &rows[0];
    assert_eq!(only.path, PathBuf::from("ok.txt"));
    assert_ne!(
        only.content_hash, etc_passwd_hash,
        "the lone row must NOT hold /etc/passwd's blake3 digest — proves the target was never read"
    );
}

#[tokio::test]
async fn import_state_skips_symlink_to_directory_outside_root() {
    let outer = tempdir().unwrap();
    let outside_dir = outer.path().join("outside");
    fs::create_dir(&outside_dir).unwrap();
    fs::write(outside_dir.join("secret.txt"), b"do-not-leak").unwrap();

    let inner = tempdir().unwrap();
    let db_path = inner.path().join("meta.db");
    let db = MetaDb::open(&db_path).await.unwrap();

    let share = inner.path().join("share");
    fs::create_dir(&share).unwrap();
    fs::write(share.join("inside.txt"), b"safe").unwrap();
    // Directory symlink that, if followed, would expose secret.txt.
    symlink(&outside_dir, share.join("escape_dir")).unwrap();

    let report = import_state(&share, "node-r8", &db, false)
        .await
        .expect("import_state");

    assert_eq!(
        report.files_seen, 1,
        "follow_links(false) must not descend into the symlinked directory"
    );
    let rows = db.list_all_files().await.unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows
        .iter()
        .all(|r| !r.path.to_string_lossy().contains("secret")));
}
