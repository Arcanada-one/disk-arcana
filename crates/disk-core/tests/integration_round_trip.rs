#![allow(clippy::cmp_owned)]
//! End-to-end round trip: scan a tempdir, persist into MetaDb, mutate the
//! tree, re-scan, run the reconciler, and verify the emitted actions.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use disk_core::{
    ActionType, FileMeta, FileScanner, Filter, FilterRules, MetaDb, ReconciliationEngine,
};
use tempfile::tempdir;

fn default_filter() -> Filter {
    Filter::from_config(&FilterRules::default()).unwrap()
}

#[tokio::test]
async fn full_round_trip_detects_modified_file() {
    // 1. Seed a vault with two files.
    let root = tempdir().unwrap();
    fs::write(root.path().join("a.md"), b"alpha").unwrap();
    fs::write(root.path().join("b.md"), b"bravo").unwrap();

    // 2. Initial scan + persist into MetaDb.
    let db_dir = tempdir().unwrap();
    let db = MetaDb::open(&db_dir.path().join("meta.sqlite"))
        .await
        .unwrap();
    let scanner = FileScanner::new(
        root.path().to_path_buf(),
        default_filter(),
        HashMap::new(),
        "node-A".into(),
    );
    let initial = scanner.scan().unwrap();
    for m in &initial {
        db.upsert_file(m).await.unwrap();
    }
    assert_eq!(db.list_all_files().await.unwrap().len(), 2);

    // 3. Modify a.md on disk + add c.md.
    std::thread::sleep(std::time::Duration::from_millis(20));
    fs::write(root.path().join("a.md"), b"alpha-mutated").unwrap();
    fs::write(root.path().join("c.md"), b"charlie").unwrap();

    // 4. Re-scan with last_known seeded from the DB so the fast-path trips
    //    where appropriate, then reconcile against an empty remote (server
    //    sees only the indexed snapshot).
    let last_known: HashMap<PathBuf, FileMeta> = initial
        .iter()
        .map(|m| (m.path.clone(), m.clone()))
        .collect();
    let scanner = FileScanner::new(
        root.path().to_path_buf(),
        default_filter(),
        last_known,
        "node-A".into(),
    );
    let local = scanner.scan().unwrap();
    let indexed = db.list_all_files().await.unwrap();
    let remote = indexed.clone();

    let actions = ReconciliationEngine::new("node-A".into())
        .reconcile(&local, &remote, &indexed)
        .unwrap();

    // a.md should be Upload (modified locally, remote == indexed).
    let a = actions
        .iter()
        .find(|x| x.path == PathBuf::from("a.md"))
        .unwrap();
    assert_eq!(a.action, ActionType::Upload);
    // b.md unchanged → Skip.
    let b = actions
        .iter()
        .find(|x| x.path == PathBuf::from("b.md"))
        .unwrap();
    assert_eq!(b.action, ActionType::Skip);
    // c.md is brand new locally → Upload.
    let c = actions
        .iter()
        .find(|x| x.path == PathBuf::from("c.md"))
        .unwrap();
    assert_eq!(c.action, ActionType::Upload);
}

#[tokio::test]
async fn round_trip_handles_local_delete() {
    let root = tempdir().unwrap();
    fs::write(root.path().join("a.md"), b"alpha").unwrap();
    fs::write(root.path().join("b.md"), b"bravo").unwrap();

    let db_dir = tempdir().unwrap();
    let db = MetaDb::open(&db_dir.path().join("meta.sqlite"))
        .await
        .unwrap();
    let initial = FileScanner::new(
        root.path().to_path_buf(),
        default_filter(),
        HashMap::new(),
        "node-A".into(),
    )
    .scan()
    .unwrap();
    for m in &initial {
        db.upsert_file(m).await.unwrap();
    }

    // Delete b.md locally.
    fs::remove_file(root.path().join("b.md")).unwrap();

    let last_known: HashMap<PathBuf, FileMeta> = initial
        .iter()
        .map(|m| (m.path.clone(), m.clone()))
        .collect();
    let local = FileScanner::new(
        root.path().to_path_buf(),
        default_filter(),
        last_known,
        "node-A".into(),
    )
    .scan()
    .unwrap();
    let indexed = db.list_all_files().await.unwrap();
    let remote = indexed.clone();

    let actions = ReconciliationEngine::new("node-A".into())
        .reconcile(&local, &remote, &indexed)
        .unwrap();
    let b = actions
        .iter()
        .find(|x| x.path == PathBuf::from("b.md"))
        .unwrap();
    // Local missing, remote+indexed match → DeleteRemote (propagate delete).
    assert_eq!(b.action, ActionType::DeleteRemote);
}

#[test]
fn integration_path_traversal_skips_outside_links() {
    // Symlinks pointing outside the root must never enter the snapshot,
    // regardless of whether walkdir discovers them.
    let root = tempdir().unwrap();
    let outside = tempdir().unwrap();
    fs::write(outside.path().join("secret.txt"), b"x").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            outside.path().join("secret.txt"),
            root.path().join("escape.md"),
        )
        .unwrap();
    }
    fs::write(root.path().join("a.md"), b"a").unwrap();

    let scanned = FileScanner::new(
        root.path().to_path_buf(),
        default_filter(),
        HashMap::new(),
        "node-A".into(),
    )
    .scan()
    .unwrap();
    let secret_observed = scanned.iter().any(|m| m.path == PathBuf::from("escape.md"));
    assert!(
        !secret_observed,
        "scanner must not surface outside-root symlinks"
    );
}

#[test]
fn integration_git_dir_never_appears_even_with_explicit_md_filter() {
    let root = tempdir().unwrap();
    fs::create_dir_all(root.path().join(".git")).unwrap();
    fs::write(root.path().join(".git/HEAD"), b"ref:").unwrap();
    fs::write(root.path().join(".git/config.md"), b"[core]").unwrap();
    fs::write(root.path().join("a.md"), b"a").unwrap();

    let cfg = FilterRules {
        extensions_whitelist: vec!["md".into()],
        deny_segments: vec![],
        ignore_globs: vec![],
    };
    let filter = Filter::from_config(&cfg).unwrap();
    let scanned = FileScanner::new(
        root.path().to_path_buf(),
        filter,
        HashMap::new(),
        "node-A".into(),
    )
    .scan()
    .unwrap();
    assert!(scanned.iter().all(|m| !m.path.starts_with(".git")));
}
