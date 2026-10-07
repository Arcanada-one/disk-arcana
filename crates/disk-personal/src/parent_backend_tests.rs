use super::*;
#[path = "../sqlite-abi/src/test_vfs.rs"]
mod test_vfs;
use test_vfs::MemoryVfs;
fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("../tests/fixtures/parent-native.json")).unwrap()
}
fn request(cleanup: bool) -> Request {
    let f = fixture();
    Request::parse(
        &serde_json::to_vec(&f["descriptor"]).unwrap(),
        if cleanup {
            None
        } else {
            f["descriptor"]["parts"][0]["partId"].as_str()
        },
    )
    .unwrap()
}
fn context(r: &Request, name: &str, disposition: OriginalDisposition) -> NativeCommitContext {
    let o = Outcome::parse(&serde_json::to_vec(&fixture()[name]).unwrap()).unwrap();
    let lease = serde_json::from_str(if name == "stored" {
        "\"00000000-0000-4000-8000-000000000091\""
    } else {
        "\"00000000-0000-4000-8000-000000000092\""
    })
    .unwrap();
    NativeCommitContext::from_control_readback(
        lease,
        o.clone(),
        o.original_identity(),
        r,
        disposition,
    )
    .unwrap()
}
fn backend(vfs: MemoryVfs, create: bool) -> SqliteBackend {
    SqliteBackend::initialize(Connection::open(vfs, create).unwrap(), create).unwrap()
}
#[test]
fn actual_sqlite_native_atomic_commit_exact_retry_and_reopen() {
    let vfs = MemoryVfs::default();
    let db = backend(vfs.clone(), true);
    let r = request(false);
    let e = context(&r, "stored", OriginalDisposition::FencedNoCommit);
    let body = vec![b'A'; 4096];
    assert!(matches!(
        db.observe_context(&e, &r).unwrap(),
        Observation::Unseen
    ));
    let outcome = db.stage_context(&e, &r, &body).unwrap().unwrap();
    assert_eq!(
        outcome.registration_json().unwrap(),
        e.proposal.registration_json().unwrap()
    );
    assert_eq!(db.read_context(&e, &r, 4096).unwrap(), body);
    assert!(db.stage_context(&e, &r, &vec![b'B'; 4096]).is_err());
    drop(db);
    let db = backend(vfs, false);
    let original = context(&r, "stored", OriginalDisposition::ExistingOrUnknown);
    assert!(matches!(
        db.observe_context(&original, &r).unwrap(),
        Observation::Durable { .. }
    ));
    assert!(db.stage_context(&original, &r, &body).unwrap().is_some());
    assert_eq!(
        db.query("SELECT count(*) FROM owner_journal", &[]).unwrap(),
        vec![vec![Value::Integer(1)]]
    );
}
#[test]
fn prepared_and_unknown_never_replay_after_reopen() {
    let vfs = MemoryVfs::default();
    let db = backend(vfs.clone(), true);
    let r = request(false);
    let e = context(&r, "stored", OriginalDisposition::ExistingOrUnknown);
    assert!(matches!(
        db.observe_context(&e, &r).unwrap(),
        Observation::Unknown
    ));
    assert!(matches!(
        db.stage_context(&e, &r, &vec![b'A'; 4096]),
        Err(Refusal::Pending)
    ));
    db.query(
        "INSERT INTO attempts(resource,lease,proposal,state) VALUES(?1,?2,?3,'prepared')",
        &[
            text(r.resource_identity()),
            text(e.lease.as_str()),
            text(String::from_utf8(e.proposal.registration_json().unwrap()).unwrap()),
        ],
    )
    .unwrap();
    drop(db);
    let db = backend(vfs, false);
    let fresh = context(&r, "stored", OriginalDisposition::FencedNoCommit);
    assert!(matches!(
        db.observe_context(&fresh, &r).unwrap(),
        Observation::Prepared
    ));
    assert!(matches!(
        db.stage_context(&fresh, &r, &vec![b'A'; 4096]),
        Err(Refusal::Pending)
    ));
    assert_eq!(
        db.query("SELECT count(*) FROM objects", &[]).unwrap(),
        vec![vec![Value::Integer(0)]]
    );
}
#[test]
fn real_sqlite_sync_error_retains_uncertainty_and_diagnostics() {
    let vfs = MemoryVfs::default();
    let db = backend(vfs.clone(), true);
    let r = request(false);
    let e = context(&r, "stored", OriginalDisposition::FencedNoCommit);
    vfs.fail_next_sync();
    assert!(db.stage_context(&e, &r, &vec![b'A'; 4096]).is_err());
    assert!(db.last_io_error().is_some());
    assert!(matches!(db.observe_context(&e, &r), Err(Refusal::Pending)));
}
#[test]
fn exact_cancelled_tombstone_precedes_atomic_byte_removal_and_original_cleaned() {
    let vfs = MemoryVfs::default();
    let db = backend(vfs.clone(), true);
    let r = request(false);
    let e = context(&r, "stored", OriginalDisposition::FencedNoCommit);
    db.stage_context(&e, &r, &vec![b'A'; 4096]).unwrap();
    let cleanup = request(true);
    let ce = context(&cleanup, "cleaned", OriginalDisposition::ExistingOrUnknown);
    let c = CancelledResource::parse(
        &serde_json::to_vec(&fixture()["cleanup_resolution"]["grant"]["resource"]).unwrap(),
        &cleanup,
    )
    .unwrap();
    let keys = c.objects(&cleanup).unwrap();
    assert!(db.cleanup_context(&ce, &cleanup, &keys, &c).is_err());
    db.tombstone_context(&ce, &cleanup, &keys, &c).unwrap();
    assert!(db.read_context(&e, &r, 4096).is_err());
    let wrong = &keys[..keys.len() - 1];
    assert!(db.cleanup_context(&ce, &cleanup, wrong, &c).is_err());
    assert!(db
        .cleanup_context(&ce, &cleanup, &keys, &c)
        .unwrap()
        .is_some());
    drop(db);
    let db = backend(vfs, false);
    assert!(db
        .cleanup_context(&ce, &cleanup, &keys, &c)
        .unwrap()
        .is_some());
    assert_eq!(
        db.query("SELECT count(*) FROM objects WHERE body IS NOT NULL", &[])
            .unwrap(),
        vec![vec![Value::Integer(0)]]
    );
    assert_eq!(
        db.query("SELECT count(*) FROM owner_journal", &[]).unwrap(),
        vec![vec![Value::Integer(2)]]
    );
}
#[test]
fn altered_body_and_descriptor_never_pass_native_readback() {
    let db = backend(MemoryVfs::default(), true);
    let r = request(false);
    let e = context(&r, "stored", OriginalDisposition::FencedNoCommit);
    db.stage_context(&e, &r, &vec![b'A'; 4096]).unwrap();
    db.query(
        "UPDATE objects SET body=?1 WHERE resource=?2",
        &[Value::Blob(vec![b'B'; 4096]), text(r.resource_identity())],
    )
    .unwrap();
    assert!(db.read_context(&e, &r, 4096).is_err());
    let mut f = fixture();
    f["descriptor"]["parts"][0]["objectRevision"] =
        serde_json::json!("00000000-0000-4000-8000-000000000077");
    let changed = Request::parse(
        &serde_json::to_vec(&f["descriptor"]).unwrap(),
        f["descriptor"]["parts"][0]["partId"].as_str(),
    )
    .unwrap();
    assert!(db.observe_context(&e, &changed).is_err());
}
#[test]
fn actual_descriptor_sqlite_source_fixture_retains_native_io_failure() {
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    let p = std::env::temp_dir().join(format!("disk-native-sqlite-source-{}", std::process::id()));
    fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(p.clone());
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(p.join("writer.lock"))
        .unwrap();
    let dir = File::open(&p).unwrap();
    let m = dir.metadata().unwrap();
    let id = DirectoryIdentity {
        device: m.dev(),
        inode: m.ino(),
        uid: m.uid(),
    };
    let db = SqliteBackend::from_admitted_handle(dir, id, true).unwrap();
    let r = request(false);
    let e = context(&r, "stored", OriginalDisposition::FencedNoCommit);
    db.stage_context(&e, &r, &vec![b'A'; 4096]).unwrap();
    assert_eq!(db.read_context(&e, &r, 4096).unwrap(), vec![b'A'; 4096]);
    // Second process-equivalent open description cannot acquire writer lock.
    let error = match SqliteBackend::from_admitted_handle(File::open(&p).unwrap(), id, false) {
        Ok(_) => panic!("second writer admitted"),
        Err(e) => e,
    };
    assert!(error.contains("temporarily unavailable"));
    drop(db);
    let reopened = SqliteBackend::from_admitted_handle(File::open(&p).unwrap(), id, false).unwrap();
    assert!(matches!(
        reopened.observe_context(&e, &r).unwrap(),
        Observation::Durable { .. }
    ));
}

#[test]
fn panic_mid_transaction_poison_and_rollback_without_promotion() {
    let db = backend(MemoryVfs::default(), true);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: Result<()> = db.transaction(|| {
            db.query(
                "INSERT INTO captures(id,descriptor,cancelled) VALUES('owned','fixture',NULL)",
                &[],
            )?;
            panic!("controlled transaction interruption")
        });
    }));
    assert!(result.is_err());
    assert!(matches!(db.ready(), Err(Refusal::Pending)));
    assert_eq!(
        db.db
            .borrow_mut()
            .query("SELECT count(*) FROM captures", &[])
            .unwrap(),
        vec![vec![Value::Integer(0)]]
    );
}

#[test]
fn missing_or_changed_original_journal_is_corrupt_not_durable() {
    let db = backend(MemoryVfs::default(), true);
    let r = request(false);
    let e = context(&r, "stored", OriginalDisposition::FencedNoCommit);
    db.stage_context(&e, &r, &vec![b'A'; 4096]).unwrap();
    db.query("DELETE FROM owner_journal", &[]).unwrap();
    assert!(matches!(
        db.observe_context(&e, &r).unwrap(),
        Observation::Corrupt
    ));
    assert!(db.read_context(&e, &r, 4096).is_err());
}

#[test]
fn sync_fault_matrix_keeps_bytes_inventory_and_owner_journal_atomic() {
    let mut prepared_seen = false;
    let mut committed_seen = false;
    let baseline = MemoryVfs::default();
    let control = backend(baseline.clone(), true);
    let before = baseline.sync_count();
    let r = request(false);
    let e = context(&r, "stored", OriginalDisposition::FencedNoCommit);
    assert!(control
        .stage_context(&e, &r, &vec![b'A'; 4096])
        .unwrap()
        .is_some());
    let actual_syncs = baseline.sync_count() - before;
    assert!(actual_syncs > 0 && actual_syncs < 32);
    drop(control);
    println!(
        "actual stage sync boundaries={actual_syncs}; fault cases plus no-fault boundary={}",
        actual_syncs + 1
    );
    for skip in 0..=actual_syncs {
        let vfs = MemoryVfs::default();
        let db = backend(vfs.clone(), true);
        let r = request(false);
        let e = context(&r, "stored", OriginalDisposition::FencedNoCommit);
        vfs.fail_after_syncs(skip);
        let result = db.stage_context(&e, &r, &vec![b'A'; 4096]);
        if matches!(result, Ok(Some(_))) {
            assert_eq!(db.read_context(&e, &r, 4096).unwrap(), vec![b'A'; 4096]);
        } else {
            assert!(db.uncertain.get());
        }
        drop(db);
        let db = backend(vfs, false);
        let objects = db.query("SELECT count(*) FROM objects", &[]).unwrap();
        let journal = db.query("SELECT count(*) FROM owner_journal", &[]).unwrap();
        assert_eq!(objects, journal, "split transaction at sync fault {skip}");
        let observation = db.observe_context(&e, &r).unwrap();
        match observation {
            Observation::Prepared => {
                prepared_seen = true;
                assert_eq!(objects, vec![vec![Value::Integer(0)]]);
            }
            Observation::Durable { .. } => {
                committed_seen = true;
                assert_eq!(db.read_context(&e, &r, 4096).unwrap(), vec![b'A'; 4096]);
            }
            Observation::Unseen => assert_eq!(objects, vec![vec![Value::Integer(0)]]),
            _ => panic!("incoherent state after controlled sync fault {skip}"),
        }
    }
    assert!(prepared_seen);
    assert!(committed_seen);
}

// These controls change trusted original-effect lineage, never the descriptor,
// bytes, persisted outcome, or existing journal. Fixtures do not confer authority.
fn changed_lineage(r: &Request, name: &str, field: &str) -> NativeCommitContext {
    let mut value = fixture()[name].clone();
    value[field] = match field {
        "deployment_generation" | "process_generation" => serde_json::json!("2"),
        _ => serde_json::json!("00000000-0000-4000-8000-000000000099"),
    };
    let outcome = Outcome::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
    NativeCommitContext::from_control_readback(
        context(r, name, OriginalDisposition::ExistingOrUnknown).lease,
        outcome.clone(),
        outcome.original_identity(),
        r,
        OriginalDisposition::ExistingOrUnknown,
    )
    .unwrap()
}
fn lineage_snapshot(db: &SqliteBackend) -> Vec<Vec<Vec<Value>>> {
    [
        "SELECT * FROM captures",
        "SELECT * FROM attempts",
        "SELECT * FROM objects",
        "SELECT * FROM owner_journal",
    ]
    .iter()
    .map(|sql| db.query(sql, &[]).unwrap())
    .collect()
}
#[test]
fn review_r1_stored_success_and_readback_require_original_lineage() {
    let db = backend(MemoryVfs::default(), true);
    let r = request(false);
    let e = context(&r, "stored", OriginalDisposition::FencedNoCommit);
    let body = vec![b'A'; 4096];
    db.stage_context(&e, &r, &body).unwrap();
    let before = lineage_snapshot(&db);
    for field in [
        "owner_commit_id",
        "operation_id",
        "process_generation",
        "deployment_generation",
    ] {
        let changed = changed_lineage(&r, "stored", field);
        assert!(db.observe_context(&changed, &r).is_err(), "{field}");
        assert!(db.stage_context(&changed, &r, &body).is_err(), "{field}");
        assert!(db.read_context(&changed, &r, 4096).is_err(), "{field}");
        assert_eq!(lineage_snapshot(&db), before, "{field}");
    }
    assert!(matches!(
        db.observe_context(&e, &r).unwrap(),
        Observation::Durable { .. }
    ));
    assert!(db.stage_context(&e, &r, &body).unwrap().is_some());
    assert_eq!(db.read_context(&e, &r, 4096).unwrap(), body);
    assert_eq!(lineage_snapshot(&db), before);
}
#[test]
fn review_r1_cleaned_observation_requires_original_lineage_and_cancellation() {
    let db = backend(MemoryVfs::default(), true);
    let r = request(true);
    let e = context(&r, "cleaned", OriginalDisposition::ExistingOrUnknown);
    let c = CancelledResource::parse(
        &serde_json::to_vec(&fixture()["cleanup_resolution"]["grant"]["resource"]).unwrap(),
        &r,
    )
    .unwrap();
    let keys = c.objects(&r).unwrap();
    db.tombstone_context(&e, &r, &keys, &c).unwrap();
    db.cleanup_context(&e, &r, &keys, &c).unwrap();
    let before = lineage_snapshot(&db);
    for field in [
        "owner_commit_id",
        "operation_id",
        "process_generation",
        "deployment_generation",
    ] {
        let changed = changed_lineage(&r, "cleaned", field);
        assert!(db.observe_context(&changed, &r).is_err(), "{field}");
        assert!(
            db.cleanup_context(&changed, &r, &keys, &c).is_err(),
            "{field}"
        );
        assert_eq!(lineage_snapshot(&db), before, "{field}");
    }
    assert!(matches!(
        db.observe_context(&e, &r).unwrap(),
        Observation::CancelledCleaned { .. }
    ));
    assert!(db.cleanup_context(&e, &r, &keys, &c).unwrap().is_some());
    assert_eq!(lineage_snapshot(&db), before);
    let mut changed = serde_json::to_value(&c).unwrap();
    changed["owner_outcome_id"] = serde_json::json!("00000000-0000-4000-8000-000000000099");
    db.query(
        "UPDATE captures SET cancelled=?1",
        &[text(serde_json::to_string(&changed).unwrap())],
    )
    .unwrap();
    let corrupt = lineage_snapshot(&db);
    assert!(db.observe_context(&e, &r).is_err());
    assert_eq!(lineage_snapshot(&db), corrupt);
}
#[test]
fn review_r2_orphan_journal_and_incoherent_attempt_refuse_before_prepared() {
    for state in ["orphan", "committed", "prepared"] {
        let db = backend(MemoryVfs::default(), true);
        let r = request(false);
        let e = context(&r, "stored", OriginalDisposition::FencedNoCommit);
        let body = vec![b'A'; 4096];
        assert!(matches!(
            db.observe_context(&e, &r).unwrap(),
            Observation::Unseen
        ));
        db.stage_context(&e, &r, &body).unwrap();
        db.query("DELETE FROM objects", &[]).unwrap();
        match state {
            "orphan" => {
                db.query("DELETE FROM attempts", &[]).unwrap();
            }
            "prepared" => {
                db.query("UPDATE attempts SET state='prepared'", &[])
                    .unwrap();
            }
            _ => (),
        }
        let before = lineage_snapshot(&db);
        assert!(
            matches!(db.observe_context(&e, &r).unwrap(), Observation::Corrupt),
            "{state}"
        );
        let unknown = context(&r, "stored", OriginalDisposition::ExistingOrUnknown);
        assert!(
            matches!(
                db.observe_context(&unknown, &r).unwrap(),
                Observation::Corrupt
            ),
            "{state}"
        );
        assert!(db.stage_context(&e, &r, &body).is_err());
        assert_eq!(lineage_snapshot(&db), before, "{state}");
    }
}
