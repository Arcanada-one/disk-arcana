//! Helpers for indexing the `(local, remote, indexed)` triple by path.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;

use crate::types::FileMeta;

/// Index a slice of [`FileMeta`] by path for O(1) triple lookups.
pub fn index_by_path(items: &[FileMeta]) -> HashMap<PathBuf, &FileMeta> {
    items.iter().map(|m| (m.path.clone(), m)).collect()
}

/// Union of all paths present in any of the three snapshots, sorted for
/// deterministic iteration.
pub fn union_paths(
    local: &HashMap<PathBuf, &FileMeta>,
    remote: &HashMap<PathBuf, &FileMeta>,
    indexed: &HashMap<PathBuf, &FileMeta>,
) -> Vec<PathBuf> {
    let mut set: BTreeSet<PathBuf> = BTreeSet::new();
    set.extend(local.keys().cloned());
    set.extend(remote.keys().cloned());
    set.extend(indexed.keys().cloned());
    set.into_iter().collect()
}
