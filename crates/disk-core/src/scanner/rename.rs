//! Inode-based rename detection.
//!
//! When the same `(inode, content_hash)` pair appears under different paths in
//! the previous scan and the current scan, we treat it as a rename. Hash
//! equality alone is not enough — many small files can share an identical hash
//! (empty file, zero-byte placeholders) — so the inode adds an identity bit.

use std::collections::HashMap;
use std::path::PathBuf;

use crate::types::{FileMeta, RenamePair};

/// Pair up disappeared paths in `prior` with new paths in `current` whose
/// `(inode, content_hash)` matches.
pub fn detect_renames(prior: &[FileMeta], current: &[FileMeta]) -> Vec<RenamePair> {
    let mut prior_by_key: HashMap<(u64, [u8; 32]), &FileMeta> = HashMap::new();
    for f in prior {
        if let Some(inode) = f.inode {
            prior_by_key.insert((inode, f.content_hash), f);
        }
    }

    let current_paths: std::collections::HashSet<&PathBuf> =
        current.iter().map(|f| &f.path).collect();
    let prior_paths: std::collections::HashSet<&PathBuf> = prior.iter().map(|f| &f.path).collect();

    let mut out = Vec::new();
    for f in current {
        let inode = match f.inode {
            Some(i) => i,
            None => continue,
        };
        let key = (inode, f.content_hash);
        let Some(prev) = prior_by_key.get(&key) else {
            continue;
        };
        if prev.path == f.path {
            continue;
        }
        // The prior path must have disappeared (delete-then-create with same
        // inode = rename); the current path must be new (didn't exist before).
        if current_paths.contains(&prev.path) {
            continue;
        }
        if prior_paths.contains(&f.path) {
            continue;
        }
        out.push(RenamePair {
            from: prev.path.clone(),
            to: f.path.clone(),
            inode,
            content_hash: f.content_hash,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(path: &str, inode: u64, hash: [u8; 32]) -> FileMeta {
        FileMeta {
            path: path.into(),
            content_hash: hash,
            size: 1,
            mtime_ns: 0,
            inode: Some(inode),
            vector_clock: Default::default(),
            deleted: false,
            deleted_at: None,
            node_id: "n".into(),
            encryption_nonce: None,
            version_id: None,
            parent_version_id: None,
        }
    }

    #[test]
    fn detects_simple_rename() {
        let prior = vec![meta("a.md", 100, [1u8; 32])];
        let current = vec![meta("b.md", 100, [1u8; 32])];
        let pairs = detect_renames(&prior, &current);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].from, PathBuf::from("a.md"));
        assert_eq!(pairs[0].to, PathBuf::from("b.md"));
    }

    #[test]
    fn no_rename_when_path_unchanged() {
        let prior = vec![meta("a.md", 100, [1u8; 32])];
        let current = vec![meta("a.md", 100, [1u8; 32])];
        assert!(detect_renames(&prior, &current).is_empty());
    }

    #[test]
    fn no_rename_when_inode_differs() {
        let prior = vec![meta("a.md", 100, [1u8; 32])];
        let current = vec![meta("b.md", 200, [1u8; 32])];
        assert!(detect_renames(&prior, &current).is_empty());
    }

    #[test]
    fn no_rename_when_prior_path_still_present() {
        // Same inode at two different filenames: one of them is the original,
        // not a rename.
        let prior = vec![meta("a.md", 100, [1u8; 32])];
        let current = vec![meta("a.md", 100, [1u8; 32]), meta("b.md", 100, [1u8; 32])];
        assert!(detect_renames(&prior, &current).is_empty());
    }
}
