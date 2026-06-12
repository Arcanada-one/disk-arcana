//! 30-scenario decision tree for the reconciliation engine.
//!
//! `local`, `remote`, and `indexed` snapshots each carry zero or one
//! [`FileMeta`] per path. A `FileMeta` with `deleted = true` is treated as a
//! **tombstone** — i.e. the side knows the file existed and was logically
//! deleted; `None` means the side never observed the file.
//!
//! Scenario numbering follows
//! `Projects/Arganize.me/origin/Vault syncronizer/conflict-matrix.md`.

use std::collections::HashMap;
use std::path::PathBuf;

use super::triple::{index_by_path, union_paths};
use crate::error::ReconcileError;
use crate::types::{ActionType, ConflictKind, ConflictReport, FileMeta, SyncAction};
use crate::vector_clock::Causality;

/// Pure-function reconciler. Holds only the local node id (used as a tag in
/// emitted actions); state lives in the input slices.
#[derive(Debug, Clone)]
pub struct ReconciliationEngine {
    node_id: String,
}

impl ReconciliationEngine {
    /// Build a new engine.
    pub fn new(node_id: String) -> Self {
        Self { node_id }
    }

    /// Read-only accessor used by tests / consumers.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Classify every path in the union of `local`, `remote`, and `indexed`
    /// into a [`SyncAction`]. The output is sorted by path.
    pub fn reconcile(
        &self,
        local: &[FileMeta],
        remote: &[FileMeta],
        indexed: &[FileMeta],
    ) -> Result<Vec<SyncAction>, ReconcileError> {
        let local_idx = index_by_path(local);
        let remote_idx = index_by_path(remote);
        let indexed_idx = index_by_path(indexed);
        let paths = union_paths(&local_idx, &remote_idx, &indexed_idx);

        let mut actions: Vec<SyncAction> = Vec::with_capacity(paths.len());
        for path in &paths {
            let l = local_idx.get(path).copied();
            let r = remote_idx.get(path).copied();
            let i = indexed_idx.get(path).copied();
            let action = resolve_one(path.clone(), l, r, i)?;
            actions.push(action);
        }

        Self::detect_remote_renames(&local_idx, &remote_idx, &indexed_idx, &mut actions);

        Ok(actions)
    }

    /// Re-classify pairs of (Upload at path A, DeleteRemote at path B) where
    /// the inode and content_hash match — they're a rename, not delete+upload.
    fn detect_remote_renames(
        local: &HashMap<PathBuf, &FileMeta>,
        _remote: &HashMap<PathBuf, &FileMeta>,
        indexed: &HashMap<PathBuf, &FileMeta>,
        actions: &mut [SyncAction],
    ) {
        let mut delete_remote_idx: HashMap<(u64, [u8; 32]), usize> = HashMap::new();
        let mut upload_idx: HashMap<(u64, [u8; 32]), usize> = HashMap::new();

        for (idx, action) in actions.iter().enumerate() {
            match action.action {
                ActionType::DeleteRemote => {
                    if let Some(prev) = indexed.get(&action.path) {
                        if let Some(inode) = prev.inode {
                            delete_remote_idx.insert((inode, prev.content_hash), idx);
                        }
                    }
                }
                ActionType::Upload => {
                    if let Some(now) = local.get(&action.path) {
                        if let Some(inode) = now.inode {
                            upload_idx.insert((inode, now.content_hash), idx);
                        }
                    }
                }
                _ => {}
            }
        }

        let pairs: Vec<((u64, [u8; 32]), usize, usize)> = upload_idx
            .iter()
            .filter_map(|(k, &up_idx)| {
                delete_remote_idx
                    .get(k)
                    .map(|&del_idx| (*k, up_idx, del_idx))
            })
            .collect();

        for (_, upload_idx, delete_idx) in pairs {
            let renamed_to = actions[upload_idx].path.clone();
            let renamed_from = actions[delete_idx].path.clone();
            actions[upload_idx].action = ActionType::RenameRemote;
            actions[upload_idx].rename_to = Some(renamed_to.clone());
            actions[upload_idx].path = renamed_from.clone();
            actions[delete_idx].action = ActionType::Skip;
            actions[delete_idx].rename_to = None;
        }
    }
}

fn resolve_one(
    path: PathBuf,
    local: Option<&FileMeta>,
    remote: Option<&FileMeta>,
    indexed: Option<&FileMeta>,
) -> Result<SyncAction, ReconcileError> {
    let l_present = local.map(|m| !m.deleted).unwrap_or(false);
    let l_tomb = local.map(|m| m.deleted).unwrap_or(false);
    let r_present = remote.map(|m| !m.deleted).unwrap_or(false);
    let r_tomb = remote.map(|m| m.deleted).unwrap_or(false);
    let i_present = indexed.map(|m| !m.deleted).unwrap_or(false);
    let i_tomb = indexed.map(|m| m.deleted).unwrap_or(false);

    let make = |action: ActionType| SyncAction {
        path: path.clone(),
        action,
        server_version: remote.cloned(),
        conflict: None,
        rename_to: None,
    };

    let make_with_conflict = |action: ActionType, kind: ConflictKind| {
        let mut a = make(action);
        a.conflict = Some(ConflictReport {
            kind,
            local_hash: local.map(|m| m.content_hash),
            remote_hash: remote.map(|m| m.content_hash),
            base_hash: indexed.map(|m| m.content_hash),
        });
        a
    };

    // Scenarios 1-2: created on one side only, no index entry.
    if l_present && remote.is_none() && indexed.is_none() {
        return Ok(make(ActionType::Upload));
    }
    if local.is_none() && r_present && indexed.is_none() {
        return Ok(make(ActionType::Download));
    }

    // Scenarios 3-4: created on both sides with no shared base.
    if l_present && r_present && indexed.is_none() {
        return if hashes_eq(local, remote) {
            Ok(make(ActionType::Skip))
        } else {
            Ok(make_with_conflict(
                ActionType::ConflictFork,
                ConflictKind::Concurrent,
            ))
        };
    }

    // Scenarios 5-8: both sides have a record + we have a base index entry.
    if l_present && r_present && i_present {
        let l_changed = !hashes_eq(local, indexed);
        let r_changed = !hashes_eq(remote, indexed);

        return match (l_changed, r_changed) {
            (false, false) => Ok(make(ActionType::Skip)), // both still match base
            (true, false) => Ok(make(ActionType::Upload)), // scenario 5
            (false, true) => Ok(make(ActionType::Download)), // scenario 6
            (true, true) => {
                if hashes_eq(local, remote) {
                    Ok(make(ActionType::Skip)) // scenario 7 — identical edits
                } else {
                    // Hashes diverge. Use vector clock to disambiguate; when
                    // clocks are absent/equal we have no causal info, so emit
                    // a fork (scenarios 8 / 30 in the conflict matrix).
                    match clock_compare(local, remote) {
                        Causality::Before => Ok(make(ActionType::Download)),
                        Causality::After => Ok(make(ActionType::Upload)),
                        Causality::Equal | Causality::Concurrent => Ok(make_with_conflict(
                            ActionType::ConflictFork,
                            ConflictKind::Concurrent,
                        )),
                    }
                }
            }
        };
    }

    // Scenarios 9-13: tombstone interactions with index.
    if l_tomb && r_present && i_present {
        // Local deleted, remote unchanged from index → propagate delete.
        if hashes_eq(remote, indexed) {
            return Ok(make(ActionType::DeleteRemote));
        }
        // Remote modified → modified-wins, restore locally + flag fork.
        return Ok(make_with_conflict(
            ActionType::Download,
            ConflictKind::ModifiedDeleted,
        ));
    }
    if l_present && r_tomb && i_present {
        if hashes_eq(local, indexed) {
            return Ok(make(ActionType::DeleteLocal));
        }
        return Ok(make_with_conflict(
            ActionType::Upload,
            ConflictKind::ModifiedDeleted,
        ));
    }
    if l_tomb && r_tomb {
        return Ok(make(ActionType::Skip));
    }

    // Scenarios 24-26: recreate with tombstone in the index.
    if l_present && remote.is_none() && i_tomb {
        // Compare new content with what was tombstoned. Same hash → recovered;
        // different hash → fresh upload.
        if hashes_eq(local, indexed) {
            return Ok(make(ActionType::Skip));
        }
        return Ok(make(ActionType::Upload));
    }
    if local.is_none() && r_present && i_tomb {
        return Ok(make(ActionType::Download));
    }
    // Scenario 35: three-client recreate-after-delete.
    // C's baseline is a tombstone (i_tomb), local is C's pre-delete live copy,
    // remote is the server's recreated live file.
    // Server recreate wins; if hashes differ, preserve C's bytes in ConflictReport.
    if l_present && r_present && i_tomb {
        if hashes_eq(local, remote) {
            return Ok(make(ActionType::Skip)); // byte-identical → lossless no-op
        }
        return Ok(make_with_conflict(
            ActionType::Download,
            ConflictKind::ModifiedDeleted, // server recreate wins; C's divergent local preserved
        ));
    }

    // Scenarios 36-39: residual triples where one side is live and the other is
    // a tombstone with no matching i_present baseline (DISK-0048).
    //
    // (P,T,None) — C has live bytes, server tomb, no shared history.
    // C's content is unknown to the server; preserve both sides as a conflict.
    if l_present && r_tomb && indexed.is_none() {
        return Ok(make_with_conflict(
            ActionType::Upload,
            ConflictKind::ModifiedDeleted,
        ));
    }
    // (P,T,T) — C re-created the file after a prior delete; server hasn't seen the recreate.
    // Treat C's recreate as authoritative and flag the divergence.
    if l_present && r_tomb && i_tomb {
        return Ok(make_with_conflict(
            ActionType::Upload,
            ConflictKind::ModifiedDeleted,
        ));
    }
    // (T,P,None) — C tomb/none, server live, no shared history.
    // Server's live file wins; preserve both sides in ConflictReport.
    if l_tomb && r_present && indexed.is_none() {
        return Ok(make_with_conflict(
            ActionType::Download,
            ConflictKind::ModifiedDeleted,
        ));
    }
    // (T,P,T) — pure lagging recreate: C tomb, server live, baseline tomb.
    // C holds no divergent live bytes; plain Download is safe, no spurious conflict.
    if l_tomb && r_present && i_tomb {
        return Ok(make(ActionType::Download));
    }

    // Mixed tomb/None: one side has a tombstone, the other has nothing.
    if local.is_none() && r_tomb {
        // Remote propagated a delete; local lost track (e.g. directory move).
        // Treat as accept-delete: there is nothing to remove locally, but the
        // index entry should be cleared at the next save.
        return Ok(make(ActionType::DeleteLocal));
    }
    if l_tomb && remote.is_none() && i_tomb {
        // Both sides agree the file is gone (server=tomb, client=absent, indexed=tomb).
        // The client already processed this delete on a prior sync pass — stabilise.
        return Ok(make(ActionType::Skip));
    }
    if l_tomb && remote.is_none() {
        // Local deleted; remote never saw the file. Propagate the tombstone
        // upstream so the server can record it.
        return Ok(make(ActionType::DeleteRemote));
    }

    // Path was indexed but has disappeared from both sides — drop record.
    if local.is_none() && remote.is_none() {
        return Ok(make(ActionType::Skip));
    }

    // Scenarios 27 / mixed dir-state: when one side is missing entirely and
    // the other side has an entry without an indexed base. Rare but covered:
    // create on the side that has it.
    if l_present && remote.is_none() && i_present {
        // Remote-side delete; local still has content matching index → DeleteLocal.
        if hashes_eq(local, indexed) {
            return Ok(make(ActionType::DeleteLocal));
        }
        return Ok(make_with_conflict(
            ActionType::Upload,
            ConflictKind::ModifiedDeleted,
        ));
    }
    if local.is_none() && r_present && i_present {
        if hashes_eq(remote, indexed) {
            return Ok(make(ActionType::DeleteRemote));
        }
        return Ok(make_with_conflict(
            ActionType::Download,
            ConflictKind::ModifiedDeleted,
        ));
    }

    Err(ReconcileError::Inconsistent {
        path: path.display().to_string(),
        reason: format!(
            "unhandled triple state: l_present={l_present} l_tomb={l_tomb} r_present={r_present} r_tomb={r_tomb} i_present={i_present} i_tomb={i_tomb}"
        ),
    })
}

fn hashes_eq(a: Option<&FileMeta>, b: Option<&FileMeta>) -> bool {
    match (a, b) {
        (Some(x), Some(y)) => x.content_hash == y.content_hash,
        _ => false,
    }
}

fn clock_compare(a: Option<&FileMeta>, b: Option<&FileMeta>) -> Causality {
    match (a, b) {
        (Some(x), Some(y)) => x.vector_clock.compare(&y.vector_clock),
        _ => Causality::Concurrent,
    }
}
