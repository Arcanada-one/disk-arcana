#![allow(clippy::cmp_owned)]
//! End-to-end scanner tests against a temporary directory tree.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use disk_core::{FileScanner, Filter, FilterRules};
use tempfile::tempdir;

fn default_filter() -> Filter {
    Filter::from_config(&FilterRules::default()).unwrap()
}

fn md_filter() -> Filter {
    Filter::from_config(&FilterRules {
        extensions_whitelist: vec!["md".into()],
        deny_segments: vec![],
        ignore_globs: vec![],
    })
    .unwrap()
}

#[test]
fn scan_empty_directory_returns_empty_vec() {
    let root = tempdir().unwrap();
    let scanner = FileScanner::new(
        root.path().to_path_buf(),
        default_filter(),
        HashMap::new(),
        "node-A".into(),
    );
    assert!(scanner.scan().unwrap().is_empty());
}

#[test]
fn scan_single_file_returns_one_meta() {
    let root = tempdir().unwrap();
    fs::write(root.path().join("a.md"), b"hello").unwrap();
    let scanner = FileScanner::new(
        root.path().to_path_buf(),
        default_filter(),
        HashMap::new(),
        "node-A".into(),
    );
    let scanned = scanner.scan().unwrap();
    assert_eq!(scanned.len(), 1);
    assert_eq!(scanned[0].path, PathBuf::from("a.md"));
    assert_eq!(scanned[0].size, 5);
}

#[test]
fn scan_nested_tree_walks_all_files_sorted() {
    let root = tempdir().unwrap();
    fs::create_dir_all(root.path().join("dir1/dir2")).unwrap();
    fs::write(root.path().join("a.md"), b"a").unwrap();
    fs::write(root.path().join("dir1/b.md"), b"b").unwrap();
    fs::write(root.path().join("dir1/dir2/c.md"), b"c").unwrap();

    let scanner = FileScanner::new(
        root.path().to_path_buf(),
        default_filter(),
        HashMap::new(),
        "node-A".into(),
    );
    let scanned = scanner.scan().unwrap();
    let paths: Vec<_> = scanned
        .iter()
        .map(|m| m.path.to_string_lossy().to_string())
        .collect();
    let sep = std::path::MAIN_SEPARATOR;
    assert_eq!(
        paths,
        vec![
            "a.md".to_string(),
            format!("dir1{sep}b.md"),
            format!("dir1{sep}dir2{sep}c.md"),
        ]
    );
}

#[test]
fn scan_excludes_dot_git_directory() {
    let root = tempdir().unwrap();
    fs::create_dir_all(root.path().join(".git")).unwrap();
    fs::write(root.path().join(".git/HEAD"), b"ref:").unwrap();
    fs::write(root.path().join("a.md"), b"a").unwrap();

    let scanned = FileScanner::new(
        root.path().to_path_buf(),
        default_filter(),
        HashMap::new(),
        "node-A".into(),
    )
    .scan()
    .unwrap();
    assert_eq!(scanned.len(), 1);
    assert_eq!(scanned[0].path, PathBuf::from("a.md"));
}

#[test]
fn scan_extension_whitelist_filters_other_extensions() {
    let root = tempdir().unwrap();
    fs::write(root.path().join("a.md"), b"a").unwrap();
    fs::write(root.path().join("b.txt"), b"b").unwrap();

    let scanned = FileScanner::new(
        root.path().to_path_buf(),
        md_filter(),
        HashMap::new(),
        "node-A".into(),
    )
    .scan()
    .unwrap();
    assert_eq!(scanned.len(), 1);
    assert_eq!(scanned[0].path, PathBuf::from("a.md"));
}

#[test]
fn scan_is_idempotent_on_unchanged_tree() {
    let root = tempdir().unwrap();
    fs::write(root.path().join("a.md"), b"hello").unwrap();
    fs::write(root.path().join("b.md"), b"world").unwrap();

    let scanner = FileScanner::new(
        root.path().to_path_buf(),
        default_filter(),
        HashMap::new(),
        "node-A".into(),
    );
    let first = scanner.scan().unwrap();
    let second = scanner.scan().unwrap();
    assert_eq!(first, second);
}

#[cfg(unix)]
#[test]
fn scan_skips_symlinks() {
    let root = tempdir().unwrap();
    fs::write(root.path().join("a.md"), b"a").unwrap();
    let outside = tempdir().unwrap();
    fs::write(outside.path().join("secret.txt"), b"x").unwrap();
    std::os::unix::fs::symlink(
        outside.path().join("secret.txt"),
        root.path().join("link.md"),
    )
    .unwrap();

    let scanned = FileScanner::new(
        root.path().to_path_buf(),
        default_filter(),
        HashMap::new(),
        "node-A".into(),
    )
    .scan()
    .unwrap();
    // walkdir with follow_links(false) reports the symlink as a file but its
    // file_type().is_file() is false on Linux/macOS; we expect a.md only.
    assert_eq!(scanned.len(), 1);
    assert_eq!(scanned[0].path, PathBuf::from("a.md"));
}

#[test]
fn fast_path_skips_rehash_when_size_mtime_unchanged() {
    let root = tempdir().unwrap();
    fs::write(root.path().join("a.md"), b"original").unwrap();

    // First scan to populate "last_known".
    let initial = FileScanner::new(
        root.path().to_path_buf(),
        default_filter(),
        HashMap::new(),
        "node-A".into(),
    )
    .scan()
    .unwrap();
    let mut last_known: HashMap<PathBuf, _> = HashMap::new();
    for m in &initial {
        last_known.insert(m.path.clone(), m.clone());
    }

    // Mutate the cached hash to something obviously fake — if fast-path runs,
    // the fake value should propagate; if it doesn't, the real blake3 will.
    let key = PathBuf::from("a.md");
    let mut tampered = last_known.get(&key).unwrap().clone();
    tampered.content_hash = [0xEEu8; 32];
    last_known.insert(key.clone(), tampered);

    let second = FileScanner::new(
        root.path().to_path_buf(),
        default_filter(),
        last_known,
        "node-A".into(),
    )
    .scan()
    .unwrap();
    assert_eq!(second[0].content_hash, [0xEEu8; 32]);
}

#[test]
fn fast_path_rehashes_when_mtime_advances() {
    let root = tempdir().unwrap();
    let p = root.path().join("a.md");
    fs::write(&p, b"v1").unwrap();
    let initial = FileScanner::new(
        root.path().to_path_buf(),
        default_filter(),
        HashMap::new(),
        "node-A".into(),
    )
    .scan()
    .unwrap();
    let mut last_known: HashMap<PathBuf, _> = HashMap::new();
    for m in &initial {
        last_known.insert(m.path.clone(), m.clone());
    }

    // Rewrite content + bump mtime.
    std::thread::sleep(std::time::Duration::from_millis(20));
    fs::write(&p, b"v2-different-content").unwrap();

    let second = FileScanner::new(
        root.path().to_path_buf(),
        default_filter(),
        last_known,
        "node-A".into(),
    )
    .scan()
    .unwrap();
    assert_ne!(second[0].content_hash, initial[0].content_hash);
    assert_eq!(second[0].size, b"v2-different-content".len() as u64);
}

#[cfg(windows)]
#[test]
fn scan_preserves_file_id_across_rename() {
    use disk_core::scanner::detect_renames;

    let root = tempdir().unwrap();
    let from = root.path().join("a.md");
    fs::write(&from, b"rename-me").unwrap();

    let first = FileScanner::new(
        root.path().to_path_buf(),
        default_filter(),
        HashMap::new(),
        "node-A".into(),
    )
    .scan()
    .unwrap();
    assert_eq!(first.len(), 1);
    assert!(first[0].inode.is_some());

    let to = root.path().join("b.md");
    fs::rename(&from, &to).unwrap();

    let second = FileScanner::new(
        root.path().to_path_buf(),
        default_filter(),
        HashMap::new(),
        "node-A".into(),
    )
    .scan()
    .unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].inode, first[0].inode);

    let renames = detect_renames(&first, &second);
    assert_eq!(renames.len(), 1);
    assert_eq!(renames[0].from, PathBuf::from("a.md"));
    assert_eq!(renames[0].to, PathBuf::from("b.md"));
}
