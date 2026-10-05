use super::*;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{symlink, DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "disk-personal-fixture-native-journal-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(p.join("writer.lock"))
            .unwrap();
        Self(p)
    }
    fn journal(&self) -> Journal {
        let f = File::open(&self.0).unwrap();
        let m = f.metadata().unwrap();
        Journal::from_admitted_handle(
            f,
            DirectoryIdentity {
                device: m.dev(),
                inode: m.ino(),
                uid: m.uid(),
            },
        )
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn outcome() -> Outcome {
    let f: serde_json::Value =
        serde_json::from_str(include_str!("../tests/fixtures/parent-native.json")).unwrap();
    Outcome::parse(&serde_json::to_vec(&f["stored"]).unwrap()).unwrap()
}
fn lease(n: u8) -> Id {
    serde_json::from_str(&format!("\"00000000-0000-4000-8000-0000000000{n:02x}\"")).unwrap()
}
#[test]
fn actual_native_journal_sync_reopen_and_exact_retry() {
    let f = Fixture::new();
    let o = outcome();
    let j = f.journal();
    assert!(matches!(
        j.record(&lease(1), &o, &o.original_identity()).unwrap(),
        RecordResult::Recorded
    ));
    drop(j);
    let reopened = f.journal();
    let records = reopened.inspect().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].effect_lease_id(), &lease(1));
    assert_eq!(
        records[0].outcome().registration_json().unwrap(),
        o.registration_json().unwrap()
    );
    assert!(matches!(
        reopened
            .record(&lease(1), &o, &o.original_identity())
            .unwrap(),
        RecordResult::Existing
    ));
    assert!(matches!(
        reopened.record(&lease(2), &o, &o.original_identity()),
        Err(JournalError::Conflict)
    ));
}
#[test]
fn actual_partial_journal_is_retained_not_promoted_or_replaced() {
    let f = Fixture::new();
    let path = f.0.join(format!("{}.pending", lease(1).as_str()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    file.write_all(b"partial").unwrap();
    file.sync_all().unwrap();
    let j = f.journal();
    let o = outcome();
    let result = j.record(&lease(1), &o, &o.original_identity());
    assert!(
        matches!(result, Err(JournalError::Pending)),
        "unexpected error: {:?}",
        result.err()
    );
    assert_eq!(fs::read(path).unwrap(), b"partial");
}
#[test]
fn actual_corruption_and_hardlink_never_become_a_record() {
    let f = Fixture::new();
    let name = f.0.join(format!("{}.json", lease(1).as_str()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&name)
        .unwrap();
    file.write_all(b"{}").unwrap();
    let result = f.journal().inspect();
    assert!(
        matches!(result, Err(JournalError::Corrupt)),
        "unexpected error: {:?}",
        result.err()
    );
    fs::hard_link(&name, f.0.join("other")).unwrap();
    assert!(matches!(
        f.journal()
            .read(name.file_name().unwrap().to_str().unwrap()),
        Err(JournalError::UnsafeEntry)
    ));
}
#[test]
fn actual_lock_symlink_refuses_without_following() {
    let f = Fixture::new();
    fs::remove_file(f.0.join("writer.lock")).unwrap();
    symlink("missing", f.0.join("writer.lock")).unwrap();
    match f.journal().inspect() {
        Err(JournalError::Io(e)) => assert_eq!(e.raw_os_error(), Some(40)),
        _ => panic!("expected no-follow refusal"),
    }
    assert!(!f.0.join("missing").exists());
}
#[test]
fn actual_directory_substitution_identity_and_mode_refuse_before_open() {
    let f = Fixture::new();
    let file = File::open(&f.0).unwrap();
    let m = file.metadata().unwrap();
    let wrong = DirectoryIdentity {
        device: m.dev(),
        inode: m.ino() + 1,
        uid: m.uid(),
    };
    assert!(matches!(
        Journal::from_admitted_handle(file, wrong),
        Err(JournalError::UnsafeDirectory)
    ));
    fs::set_permissions(&f.0, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        Journal::from_admitted_handle(
            File::open(&f.0).unwrap(),
            DirectoryIdentity {
                device: m.dev(),
                inode: m.ino(),
                uid: m.uid()
            }
        ),
        Err(JournalError::UnsafeDirectory)
    ));
}
#[test]
fn exact_native_identity_conflict_refuses_before_any_journal_access() {
    let f = Fixture::new();
    let o = outcome();
    let mut wrong = o.original_identity();
    wrong.operation_id = lease(99);
    assert!(matches!(
        f.journal().record(&lease(1), &o, &wrong),
        Err(JournalError::Conflict)
    ));
    assert_eq!(fs::read_dir(&f.0).unwrap().count(), 1);
}
