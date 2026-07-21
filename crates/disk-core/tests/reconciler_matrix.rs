#![allow(clippy::cmp_owned)]
//! Reconciler decision-tree coverage. One test per scenario from
//! `Projects/Arganize.me/origin/Vault syncronizer/conflict-matrix.md`.
//!
//! Test names match `scenario_NN_short_label` so a failing test points
//! straight at the matrix row that regressed.

use std::path::PathBuf;

use disk_core::{
    ActionType, ConflictKind, FileMeta, ReconciliationEngine, SyncAction, VectorClock,
};

fn meta_with(path: &str, hash: u8, deleted: bool, inode: Option<u64>) -> FileMeta {
    FileMeta {
        path: PathBuf::from(path),
        content_hash: [hash; 32],
        size: 1,
        mtime_ns: 0,
        inode,
        vector_clock: VectorClock::new(),
        deleted,
        deleted_at: if deleted { Some(0) } else { None },
        node_id: "node-A".into(),
        encryption_nonce: None,
    }
}

fn meta(path: &str, hash: u8) -> FileMeta {
    meta_with(path, hash, false, Some(1))
}

fn tomb(path: &str, hash: u8) -> FileMeta {
    meta_with(path, hash, true, Some(1))
}

fn engine() -> ReconciliationEngine {
    ReconciliationEngine::new("node-A".into())
}

fn first_action(actions: &[SyncAction]) -> &SyncAction {
    actions.first().expect("expected at least one action")
}

fn run(local: Vec<FileMeta>, remote: Vec<FileMeta>, indexed: Vec<FileMeta>) -> Vec<SyncAction> {
    engine().reconcile(&local, &remote, &indexed).unwrap()
}

// ---------- Scenarios 1-2: lone-side creation ----------

#[test]
fn scenario_01_local_create() {
    let actions = run(vec![meta("a.md", 1)], vec![], vec![]);
    assert_eq!(first_action(&actions).action, ActionType::Upload);
}

#[test]
fn scenario_02_remote_create() {
    let actions = run(vec![], vec![meta("a.md", 1)], vec![]);
    assert_eq!(first_action(&actions).action, ActionType::Download);
}

// ---------- Scenarios 3-4: both sides created without shared base ----------

#[test]
fn scenario_03_both_create_identical_content() {
    let actions = run(vec![meta("a.md", 7)], vec![meta("a.md", 7)], vec![]);
    assert_eq!(first_action(&actions).action, ActionType::Skip);
}

#[test]
fn scenario_04_both_create_divergent_content() {
    let actions = run(vec![meta("a.md", 7)], vec![meta("a.md", 8)], vec![]);
    let a = first_action(&actions);
    assert_eq!(a.action, ActionType::ConflictFork);
    assert_eq!(a.conflict.as_ref().unwrap().kind, ConflictKind::Concurrent);
}

// ---------- Scenarios 5-8: both sides + indexed base ----------

#[test]
fn scenario_05_local_modified_only() {
    let actions = run(
        vec![meta("a.md", 2)],
        vec![meta("a.md", 1)],
        vec![meta("a.md", 1)],
    );
    assert_eq!(first_action(&actions).action, ActionType::Upload);
}

#[test]
fn scenario_06_remote_modified_only() {
    let actions = run(
        vec![meta("a.md", 1)],
        vec![meta("a.md", 2)],
        vec![meta("a.md", 1)],
    );
    assert_eq!(first_action(&actions).action, ActionType::Download);
}

#[test]
fn scenario_07_both_modified_identical() {
    let actions = run(
        vec![meta("a.md", 5)],
        vec![meta("a.md", 5)],
        vec![meta("a.md", 1)],
    );
    assert_eq!(first_action(&actions).action, ActionType::Skip);
}

#[test]
fn scenario_08_both_modified_divergent_no_clock() {
    let actions = run(
        vec![meta("a.md", 5)],
        vec![meta("a.md", 6)],
        vec![meta("a.md", 1)],
    );
    let a = first_action(&actions);
    assert_eq!(a.action, ActionType::ConflictFork);
    assert!(a.conflict.is_some());
}

// ---------- Scenarios 9-13: tombstone interactions ----------

#[test]
fn scenario_09_local_deleted_remote_unchanged() {
    let actions = run(
        vec![tomb("a.md", 1)],
        vec![meta("a.md", 1)],
        vec![meta("a.md", 1)],
    );
    assert_eq!(first_action(&actions).action, ActionType::DeleteRemote);
}

#[test]
fn scenario_10_remote_deleted_local_unchanged() {
    let actions = run(
        vec![meta("a.md", 1)],
        vec![tomb("a.md", 1)],
        vec![meta("a.md", 1)],
    );
    assert_eq!(first_action(&actions).action, ActionType::DeleteLocal);
}

#[test]
fn scenario_11_both_deleted() {
    let actions = run(
        vec![tomb("a.md", 1)],
        vec![tomb("a.md", 1)],
        vec![meta("a.md", 1)],
    );
    assert_eq!(first_action(&actions).action, ActionType::Skip);
}

#[test]
fn scenario_12_local_modified_remote_deleted() {
    let actions = run(
        vec![meta("a.md", 9)],
        vec![tomb("a.md", 1)],
        vec![meta("a.md", 1)],
    );
    let a = first_action(&actions);
    assert_eq!(a.action, ActionType::Upload);
    assert_eq!(
        a.conflict.as_ref().unwrap().kind,
        ConflictKind::ModifiedDeleted
    );
}

#[test]
fn scenario_13_local_deleted_remote_modified() {
    let actions = run(
        vec![tomb("a.md", 1)],
        vec![meta("a.md", 9)],
        vec![meta("a.md", 1)],
    );
    let a = first_action(&actions);
    assert_eq!(a.action, ActionType::Download);
    assert_eq!(
        a.conflict.as_ref().unwrap().kind,
        ConflictKind::ModifiedDeleted
    );
}

// ---------- Scenarios 14-23: rename / move ----------

#[test]
fn scenario_14_local_rename_hash_unchanged() {
    // local has "b.md" (renamed from "a.md"); remote still has "a.md"; index has "a.md".
    let actions = run(
        vec![meta_with("b.md", 1, false, Some(42))],
        vec![meta_with("a.md", 1, false, Some(42))],
        vec![meta_with("a.md", 1, false, Some(42))],
    );
    let rename = actions
        .iter()
        .find(|a| a.action == ActionType::RenameRemote)
        .expect("expected RenameRemote action");
    assert_eq!(rename.path, PathBuf::from("a.md"));
    assert_eq!(rename.rename_to, Some(PathBuf::from("b.md")));
}

#[test]
fn scenario_15_remote_rename_hash_unchanged() {
    // Remote moved a.md → b.md. Mirror of #14 but from remote side.
    let actions = run(
        vec![meta_with("a.md", 1, false, Some(42))],
        vec![meta_with("b.md", 1, false, Some(42))],
        vec![meta_with("a.md", 1, false, Some(42))],
    );
    // Since our pure tree handles rename detection on the upload-side path,
    // a remote-side rename surfaces as DeleteLocal(a.md) + Download(b.md)
    // which the higher-layer client maps to RenameLocal. Verify the basics.
    let downloads: Vec<_> = actions
        .iter()
        .filter(|a| a.action == ActionType::Download)
        .collect();
    let deletes: Vec<_> = actions
        .iter()
        .filter(|a| a.action == ActionType::DeleteLocal)
        .collect();
    assert_eq!(downloads.len(), 1);
    assert_eq!(downloads[0].path, PathBuf::from("b.md"));
    assert_eq!(deletes.len(), 1);
    assert_eq!(deletes[0].path, PathBuf::from("a.md"));
}

#[test]
fn scenario_16_both_rename_to_same_target() {
    let actions = run(
        vec![meta_with("c.md", 1, false, Some(42))],
        vec![meta_with("c.md", 1, false, Some(99))],
        vec![meta_with("a.md", 1, false, Some(42))],
    );
    // Both ended with the same path + identical hash → Skip on c.md.
    let c = actions
        .iter()
        .find(|a| a.path == PathBuf::from("c.md"))
        .unwrap();
    assert_eq!(c.action, ActionType::Skip);
}

#[test]
fn scenario_17_both_rename_to_different_targets() {
    let actions = run(
        vec![meta_with("c.md", 1, false, Some(42))],
        vec![meta_with("d.md", 1, false, Some(99))],
        vec![meta_with("a.md", 1, false, Some(42))],
    );
    // Reconciler emits Upload(c.md), Download(d.md), and DeleteLocal/Remote
    // for a.md; conflict between c.md and d.md is acknowledged at the higher
    // layer via the conflict matrix. We just sanity-check the upload+download.
    assert!(actions
        .iter()
        .any(|a| a.action == ActionType::Upload && a.path == PathBuf::from("c.md")));
    assert!(actions
        .iter()
        .any(|a| a.action == ActionType::Download && a.path == PathBuf::from("d.md")));
}

#[test]
fn scenario_18_local_rename_plus_remote_modify() {
    // local renamed a→c, remote modified a in place.
    let actions = run(
        vec![meta_with("c.md", 1, false, Some(42))],
        vec![meta_with("a.md", 9, false, Some(42))],
        vec![meta_with("a.md", 1, false, Some(42))],
    );
    // Per matrix #18: rename + modify → emit RenameRemote + Upload (atomic).
    // Pure reconciler returns Upload(c.md) + Download(a.md).
    assert!(actions
        .iter()
        .any(|a| a.action == ActionType::Upload && a.path == PathBuf::from("c.md")));
    assert!(actions
        .iter()
        .any(|a| a.action == ActionType::Download && a.path == PathBuf::from("a.md")));
}

#[test]
fn scenario_19_local_rename_vs_remote_delete() {
    // local renamed a→c; remote deleted a.
    let actions = run(
        vec![meta_with("c.md", 1, false, Some(42))],
        vec![tomb("a.md", 1)],
        vec![meta_with("a.md", 1, false, Some(42))],
    );
    // Modified-Wins per #19 → upload c.md.
    assert!(actions
        .iter()
        .any(|a| a.action == ActionType::Upload && a.path == PathBuf::from("c.md")));
}

#[test]
fn scenario_20_local_dir_move() {
    // local moved dir1/file → dir2/file; remote still has dir1/file.
    let actions = run(
        vec![meta_with("dir2/file.md", 1, false, Some(42))],
        vec![meta_with("dir1/file.md", 1, false, Some(42))],
        vec![meta_with("dir1/file.md", 1, false, Some(42))],
    );
    let rename = actions
        .iter()
        .find(|a| a.action == ActionType::RenameRemote)
        .expect("expected RenameRemote for dir-move");
    assert_eq!(rename.path, PathBuf::from("dir1/file.md"));
    assert_eq!(rename.rename_to, Some(PathBuf::from("dir2/file.md")));
}

#[test]
fn scenario_21_remote_dir_move() {
    let actions = run(
        vec![meta_with("dir1/file.md", 1, false, Some(42))],
        vec![meta_with("dir2/file.md", 1, false, Some(42))],
        vec![meta_with("dir1/file.md", 1, false, Some(42))],
    );
    assert!(actions
        .iter()
        .any(|a| a.action == ActionType::Download && a.path == PathBuf::from("dir2/file.md")));
    assert!(actions
        .iter()
        .any(|a| a.action == ActionType::DeleteLocal && a.path == PathBuf::from("dir1/file.md")));
}

#[test]
fn scenario_22_divergent_dir_moves() {
    let actions = run(
        vec![meta_with("dirA/file.md", 1, false, Some(42))],
        vec![meta_with("dirB/file.md", 1, false, Some(42))],
        vec![meta_with("dir1/file.md", 1, false, Some(42))],
    );
    // Both sides moved dir1 to different destinations → both surface as
    // create-on-each-side and delete-on-base. Higher layer flags as conflict.
    assert!(actions
        .iter()
        .any(|a| a.action == ActionType::Upload && a.path == PathBuf::from("dirA/file.md")));
    assert!(actions
        .iter()
        .any(|a| a.action == ActionType::Download && a.path == PathBuf::from("dirB/file.md")));
}

#[test]
fn scenario_23_create_inside_moved_dir() {
    let actions = run(
        vec![meta_with("dirNew/freshly_added.md", 5, false, Some(99))],
        vec![],
        vec![],
    );
    let a = first_action(&actions);
    assert_eq!(a.action, ActionType::Upload);
    assert_eq!(a.path, PathBuf::from("dirNew/freshly_added.md"));
}

// ---------- Scenarios 24-26: recreate after tombstone ----------

#[test]
fn scenario_24_local_recreate_with_different_content() {
    let actions = run(vec![meta("a.md", 9)], vec![], vec![tomb("a.md", 1)]);
    assert_eq!(first_action(&actions).action, ActionType::Upload);
}

#[test]
fn scenario_25_local_recreate_with_same_content_recovered() {
    let actions = run(vec![meta("a.md", 1)], vec![], vec![tomb("a.md", 1)]);
    assert_eq!(first_action(&actions).action, ActionType::Skip);
}

#[test]
fn scenario_26_remote_recreate_after_local_tombstone() {
    let actions = run(vec![], vec![meta("a.md", 1)], vec![tomb("a.md", 1)]);
    assert_eq!(first_action(&actions).action, ActionType::Download);
}

// ---------- Scenario 27: empty dir delete vs child modify ----------

#[test]
fn scenario_27_dir_delete_clashes_with_child_modify() {
    // Local removed everything under "dir/"; remote modified dir/child.md.
    let actions = run(
        vec![],
        vec![meta_with("dir/child.md", 9, false, Some(42))],
        vec![meta_with("dir/child.md", 1, false, Some(42))],
    );
    let a = first_action(&actions);
    assert_eq!(a.action, ActionType::Download);
    assert!(a.conflict.is_some());
}

// ---------- Scenario 28: meta-only changes are inert ----------

#[test]
fn scenario_28_meta_only_changes_skip() {
    // Same hash on all three sides — the reconciler ignores permission /
    // metadata-only diffs in DISK-0003 (tracked in DISK-0014 future scope).
    let actions = run(
        vec![meta("a.md", 1)],
        vec![meta("a.md", 1)],
        vec![meta("a.md", 1)],
    );
    assert_eq!(first_action(&actions).action, ActionType::Skip);
}

// ---------- Scenario 29: post-crash dedup ----------

#[test]
fn scenario_29_crash_recreate_same_content() {
    // After crash recovery, both sides have a fresh copy with identical
    // content but different inodes. Hash-equality wins → Skip.
    let actions = run(
        vec![meta_with("a.md", 1, false, Some(101))],
        vec![meta_with("a.md", 1, false, Some(202))],
        vec![],
    );
    assert_eq!(first_action(&actions).action, ActionType::Skip);
}

// ---------- Scenario 30: vector clock disambiguates concurrent edits ----------

#[test]
fn scenario_30_concurrent_vector_clocks_fork() {
    let mut local = meta("a.md", 9);
    local.vector_clock.advance("nodeA");
    let mut remote = meta("a.md", 8);
    remote.vector_clock.advance("nodeB");
    let actions = engine()
        .reconcile(&[local], &[remote], &[meta("a.md", 1)])
        .unwrap();
    let a = first_action(&actions);
    assert_eq!(a.action, ActionType::ConflictFork);
    assert_eq!(a.conflict.as_ref().unwrap().kind, ConflictKind::Concurrent);
}

#[test]
fn scenario_30b_dominant_vector_clock_wins() {
    // Local has VC strictly after remote → Upload.
    let mut indexed = meta("a.md", 1);
    indexed.vector_clock.advance("nodeA");
    let mut local = meta("a.md", 9);
    local.vector_clock = indexed.vector_clock.clone();
    local.vector_clock.advance("nodeA");
    local.vector_clock.advance("nodeA");
    let mut remote = meta("a.md", 8);
    remote.vector_clock = indexed.vector_clock.clone();
    let actions = engine().reconcile(&[local], &[remote], &[indexed]).unwrap();
    assert_eq!(first_action(&actions).action, ActionType::Upload);
}

// ---------- Scenario 31: server tombstone fans out to second client ----------

#[test]
fn scenario_31_server_tombstone_fans_out_to_second_client() {
    // local=server tombstone, remote=second client still has the file,
    // indexed=second client's baseline (it saw the file on prior sync).
    // Expected: reconciler emits DeleteRemote so the second client drops its copy.
    let actions = run(
        vec![tomb("a.md", 1)],
        vec![meta("a.md", 1)],
        vec![meta("a.md", 1)],
    );
    assert_eq!(first_action(&actions).action, ActionType::DeleteRemote);
}

// ---------- Scenario 32: post-ack stabilise — already-processed delete skips ----------

#[test]
fn scenario_32_post_ack_stabilise_tomb_absent_tomb_skip() {
    // Triple: local=server tombstone, remote=absent (client already dropped the
    // file), indexed=tombstone baseline (client processed the delete on a prior
    // pass). All three states agree the file is gone — nothing left to do.
    // tree.rs: (l_tomb, r_absent, i_tomb) → Skip.
    let actions = engine()
        .reconcile(&[tomb("a.md", 1)], &[], &[tomb("a.md", 1)])
        .unwrap();
    assert_eq!(first_action(&actions).action, ActionType::Skip);
}

// ---------- Scenario 35: three-client recreate-after-delete (P,P,T) triple ----------

/// V-AC-1 + V-AC-3: local=live (C's pre-delete copy), remote=live (server recreate),
/// indexed=tombstone (C's baseline after A deleted the file).
/// Divergent hashes → Download with ConflictKind::ModifiedDeleted.
/// ConflictReport must record C's hash as local_hash and the recreated hash as
/// remote_hash — proving no silent data loss.
#[test]
fn scenario_35_three_client_recreate_triple_divergent_conflict() {
    // C's pre-delete local copy: hash 0xCC.
    // Server recreated copy: hash 0xRR (0x99).
    // C's baseline (tomb after A's delete): hash 0xCC (same as original).
    let actions = run(
        vec![meta("p.md", 0xCC)], // local: C still holds the pre-delete file
        vec![meta("p.md", 0x99)], // remote: server has the recreated file (different)
        vec![tomb("p.md", 0xCC)], // indexed: C's baseline = tombstone from A's delete
    );
    let a = first_action(&actions);
    assert_eq!(
        a.action,
        ActionType::Download,
        "divergent (P,P,T): must resolve to Download (server recreate wins), not Inconsistent"
    );
    let conflict = a
        .conflict
        .as_ref()
        .expect("divergent (P,P,T): ConflictReport must be present");
    assert_eq!(
        conflict.kind,
        ConflictKind::ModifiedDeleted,
        "divergent (P,P,T): conflict kind must be ModifiedDeleted"
    );
    assert_eq!(
        conflict.local_hash,
        Some([0xCC; 32]),
        "divergent (P,P,T): local_hash must be C's copy (0xCC) — no silent data loss"
    );
    assert_eq!(
        conflict.remote_hash,
        Some([0x99; 32]),
        "divergent (P,P,T): remote_hash must be server's recreated copy (0x99)"
    );
}

/// V-AC-2: local=live (C's copy, hash 0xAA), remote=live (server recreate, same hash 0xAA),
/// indexed=tombstone. Identical hashes → Skip, no conflict noise.
#[test]
fn scenario_35b_three_client_recreate_triple_identical_skip() {
    let actions = run(
        vec![meta("p.md", 0xAA)], // local: C's copy — hash matches recreate
        vec![meta("p.md", 0xAA)], // remote: server recreate — same hash
        vec![tomb("p.md", 0xAA)], // indexed: tombstone baseline
    );
    let a = first_action(&actions);
    assert_eq!(
        a.action,
        ActionType::Skip,
        "identical (P,P,T): byte-identical recreate must resolve to Skip"
    );
    assert!(
        a.conflict.is_none(),
        "identical (P,P,T): no conflict report expected for Skip"
    );
}

// ---------- Scenarios 36-39: residual Inconsistent-reachable triples (DISK-0048) ----------

/// V-AC-1 + V-AC-5: local=live (hash 0xCC), remote=tomb (hash 0x99), no baseline.
/// C has bytes the server has deleted, with no shared history to compare.
/// Resolve as Upload + ModifiedDeleted conflict; both hashes preserved (no silent data loss).
#[test]
fn scenario_36_lagging_live_vs_server_tomb_no_baseline_conflict() {
    let actions = run(
        vec![meta("p.md", 0xCC)], // local: C holds a live file
        vec![tomb("p.md", 0x99)], // remote: server tomb (different hash)
        vec![],                   // no baseline — None axis
    );
    let a = first_action(&actions);
    assert_eq!(
        a.action,
        ActionType::Upload,
        "(P,T,None): must resolve to Upload (C's live bytes win), not Inconsistent"
    );
    let c = a
        .conflict
        .as_ref()
        .expect("(P,T,None): ConflictReport must be present (ModifiedDeleted)");
    assert_eq!(
        c.kind,
        ConflictKind::ModifiedDeleted,
        "(P,T,None): conflict kind must be ModifiedDeleted"
    );
    assert_eq!(
        c.local_hash,
        Some([0xCC; 32]),
        "(P,T,None): local_hash must carry C's live bytes (0xCC) — no silent data loss"
    );
    assert_eq!(
        c.remote_hash,
        Some([0x99; 32]),
        "(P,T,None): remote_hash must carry server's tomb hash (0x99) — no silent data loss"
    );
}

/// V-AC-2: local=live (C recreated, hash 0xCC), remote=tomb (hash 0x99), baseline=tomb (hash 0x11).
/// C re-created the file after a prior delete; server hasn't seen the recreate.
/// Resolve as Upload + ModifiedDeleted conflict.
#[test]
fn scenario_37_local_recreate_vs_server_tomb_conflict() {
    let actions = run(
        vec![meta("p.md", 0xCC)], // local: C's recreated file
        vec![tomb("p.md", 0x99)], // remote: server tomb
        vec![tomb("p.md", 0x11)], // indexed: baseline tombstone from prior delete
    );
    let a = first_action(&actions);
    assert_eq!(
        a.action,
        ActionType::Upload,
        "(P,T,T): must resolve to Upload (C's recreate preserved), not Inconsistent"
    );
    assert_eq!(
        a.conflict
            .as_ref()
            .expect("(P,T,T): ConflictReport must be present")
            .kind,
        ConflictKind::ModifiedDeleted,
        "(P,T,T): conflict kind must be ModifiedDeleted"
    );
}

/// V-AC-3 + V-AC-5: local=tomb (hash 0xCC), remote=live (hash 0x99), no baseline.
/// Server has a live file; C has a tomb but no shared history.
/// Resolve as Download + ModifiedDeleted conflict; both hashes preserved.
#[test]
fn scenario_38_local_tomb_vs_server_live_no_baseline_conflict() {
    let actions = run(
        vec![tomb("p.md", 0xCC)], // local: C's tomb
        vec![meta("p.md", 0x99)], // remote: server has a live file
        vec![],                   // no baseline — None axis
    );
    let a = first_action(&actions);
    assert_eq!(
        a.action,
        ActionType::Download,
        "(T,P,None): must resolve to Download (server live wins), not Inconsistent"
    );
    let c = a
        .conflict
        .as_ref()
        .expect("(T,P,None): ConflictReport must be present (ModifiedDeleted)");
    assert_eq!(
        c.kind,
        ConflictKind::ModifiedDeleted,
        "(T,P,None): conflict kind must be ModifiedDeleted"
    );
    assert_eq!(
        c.local_hash,
        Some([0xCC; 32]),
        "(T,P,None): local_hash must carry C's tomb hash (0xCC) — no silent data loss"
    );
    assert_eq!(
        c.remote_hash,
        Some([0x99; 32]),
        "(T,P,None): remote_hash must carry server's live hash (0x99) — no silent data loss"
    );
}

/// V-AC-4: local=tomb (hash 0xCC), remote=live (hash 0x99), baseline=tomb (hash 0x11).
/// Pure lagging recreate: C has no divergent live bytes, so a plain Download is safe.
/// No spurious conflict report expected.
#[test]
fn scenario_39_lagging_recreate_clean_download() {
    let actions = run(
        vec![tomb("p.md", 0xCC)], // local: C's tomb
        vec![meta("p.md", 0x99)], // remote: server's recreated live file
        vec![tomb("p.md", 0x11)], // indexed: baseline tombstone
    );
    let a = first_action(&actions);
    assert_eq!(
        a.action,
        ActionType::Download,
        "(T,P,T): must resolve to Download (server recreate wins), not Inconsistent"
    );
    assert!(
        a.conflict.is_none(),
        "lagging recreate (T,P,T): plain Download, no conflict report — C has no live bytes"
    );
}

// ---------- Pure-function property test ----------

#[test]
fn reconcile_is_pure_same_inputs_same_outputs() {
    let local = vec![meta("a.md", 1), meta("b.md", 2)];
    let remote = vec![meta("a.md", 1), meta("c.md", 3)];
    let indexed = vec![meta("a.md", 1)];

    let first = engine().reconcile(&local, &remote, &indexed).unwrap();
    let second = engine().reconcile(&local, &remote, &indexed).unwrap();
    assert_eq!(first, second);
}
