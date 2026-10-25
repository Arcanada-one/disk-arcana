#![cfg(target_os = "linux")]
mod common;
use common::*;
use disk_personal::fixture_support::{Error, Fixture, Kind};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[tokio::test]
async fn actual_sqlite_bytes_and_evidence_survive_reopen() {
    let (_parent, path) = root().await;
    for (seed, size, kind) in [
        (1, 0, Kind::Attachment),
        (2, 4096, Kind::Note),
        (3, 65_536, Kind::Note),
        (4, 1_048_576, Kind::Attachment),
    ] {
        let bytes = vec![b'x'; size];
        let req = request(seed, &bytes, kind);
        let mut fixture = Fixture::open(&path, &binding()).await.unwrap();
        let commit = fixture.stage(&req, &bytes).await.unwrap();
        fixture.close().await.unwrap();
        let mut fixture = Fixture::open(&path, &binding()).await.unwrap();
        assert_eq!(fixture.read(&req).await.unwrap(), bytes);
        assert_eq!(fixture.stage(&req, &bytes).await.unwrap(), commit);
        let inspected = fixture.inspect().await.unwrap();
        assert_eq!(inspected.prepared, 0);
        assert!(inspected
            .sqlite_policy
            .contains(&("synchronous".to_owned(), 2)));
        assert!(inspected
            .sqlite_policy
            .contains(&("temp_store".to_owned(), 2)));
        fixture.close().await.unwrap();
    }
}

#[tokio::test]
async fn bad_body_and_invalid_identity_never_reserve() {
    let (_parent, path) = root().await;
    let mut fixture = Fixture::open(&path, &binding()).await.unwrap();
    let mut req = request(1, b"abc", Kind::Note);
    assert!(fixture.stage(&req, b"ab").await.is_err());
    assert!(fixture.stage(&req, b"abcd").await.is_err());
    req.sha256 = "0".repeat(64);
    assert!(fixture.stage(&req, b"abc").await.is_err());
    req = request(2, &[255], Kind::Note);
    assert!(fixture.stage(&req, &[255]).await.is_err());
    req = request(3, b"abc", Kind::Attachment);
    req.expected_len = u64::MAX;
    assert!(fixture.stage(&req, b"abc").await.is_err());
    req = request(4, b"abc", Kind::Note);
    req.object_id = "../elsewhere".to_owned();
    assert!(fixture.stage(&req, b"abc").await.is_err());
    let inspected = fixture.inspect().await.unwrap();
    assert_eq!(inspected.prepared, 0);
    assert!(inspected.durable.is_empty());
    fixture.close().await.unwrap();
}

#[tokio::test]
async fn immutable_retry_and_collision_never_overwrite() {
    let (_parent, path) = root().await;
    let mut fixture = Fixture::open(&path, &binding()).await.unwrap();
    let req = request(1, b"abc", Kind::Note);
    let original = fixture.stage(&req, b"abc").await.unwrap();
    assert_eq!(fixture.stage(&req, b"abc").await.unwrap(), original);
    let mut changed = request(1, b"xyz", Kind::Note);
    assert!(matches!(
        fixture.stage(&changed, b"xyz").await,
        Err(Error::Conflict)
    ));
    changed = request(2, b"xyz", Kind::Note);
    changed.object_id = req.object_id.clone();
    changed.revision_id = req.revision_id.clone();
    assert!(matches!(
        fixture.stage(&changed, b"xyz").await,
        Err(Error::Conflict)
    ));
    assert_eq!(fixture.read(&req).await.unwrap(), b"abc");
    fixture.close().await.unwrap();
}

#[tokio::test]
async fn real_sql_rejection_rolls_back_final_inventory_then_explicit_retry_succeeds() {
    let (_parent, path) = root().await;
    sql(&path, "CREATE TRIGGER reject_commit BEFORE UPDATE ON attempts WHEN NEW.state = 'DURABLE' BEGIN SELECT RAISE(ABORT, 'fixture final commit rejection'); END;").await;
    let req = request(1, b"abc", Kind::Note);
    let mut fixture = Fixture::open(&path, &binding()).await.unwrap();
    assert!(matches!(
        fixture.stage(&req, b"abc").await,
        Err(Error::Sql(_))
    ));
    let state = fixture.inspect().await.unwrap();
    assert_eq!(state.prepared, 1);
    assert!(state.durable.is_empty());
    fixture.close().await.unwrap();
    assert_eq!(std::fs::read(object_path(&path, &req)).unwrap(), b"abc");
    sql(&path, "DROP TRIGGER reject_commit;").await;
    let mut fixture = Fixture::open(&path, &binding()).await.unwrap();
    assert_eq!(fixture.inspect().await.unwrap().prepared, 1);
    assert_eq!(fixture.stage(&req, b"abc").await.unwrap().sequence, 1);
    fixture.close().await.unwrap();
}

#[tokio::test]
async fn partial_staging_is_retained_and_never_guessed_or_truncated() {
    let (_parent, path) = root().await;
    let bytes = vec![b'x'; 8192];
    let req = request(1, &bytes, Kind::Attachment);
    let mut fixture = Fixture::open(&path, &binding()).await.unwrap();
    let result = fixture
        .stage_with_checkpoint(&req, &bytes, &mut |name| {
            if name == "after_partial_write" {
                Err(Error::Injected(name))
            } else {
                Ok(())
            }
        })
        .await;
    assert!(result.is_err());
    fixture.close().await.unwrap();
    let stage = path
        .join("staging")
        .join(format!("{}.part", req.attempt_id));
    let retained = std::fs::read(&stage).unwrap();
    assert_eq!(retained.len(), 4096);
    let mut fixture = Fixture::open(&path, &binding()).await.unwrap();
    assert!(matches!(
        fixture.stage(&req, &bytes).await,
        Err(Error::UnresolvedPrepared)
    ));
    assert_eq!(fixture.inspect().await.unwrap().prepared, 1);
    assert_eq!(std::fs::read(stage).unwrap(), retained);
    fixture.close().await.unwrap();
}

#[tokio::test]
async fn poison_survives_restart_and_rejects_unrelated_writes() {
    let (_parent, path) = root().await;
    let req = request(1, b"abc", Kind::Note);
    let mut fixture = Fixture::open(&path, &binding()).await.unwrap();
    fixture.stage(&req, b"abc").await.unwrap();
    std::fs::write(object_path(&path, &req), b"bad").unwrap();
    assert!(matches!(fixture.read(&req).await, Err(Error::Poisoned)));
    let other = request(2, b"new", Kind::Note);
    assert!(matches!(
        fixture.stage(&other, b"new").await,
        Err(Error::Poisoned)
    ));
    fixture.close().await.unwrap();
    assert!(path.join("POISON").is_file());
    assert!(matches!(
        Fixture::open(&path, &binding()).await,
        Err(Error::Poisoned)
    ));
    assert!(!object_path(&path, &other).exists());
}

#[tokio::test]
async fn startup_detects_missing_durable_bytes_before_unrelated_operation() {
    let (_parent, path) = root().await;
    let req = request(1, b"abc", Kind::Note);
    let mut fixture = Fixture::open(&path, &binding()).await.unwrap();
    fixture.stage(&req, b"abc").await.unwrap();
    fixture.close().await.unwrap();
    std::fs::remove_file(object_path(&path, &req)).unwrap();
    assert!(matches!(
        Fixture::open(&path, &binding()).await,
        Err(Error::Poisoned)
    ));
    assert!(path.join("POISON").is_file());
}

#[tokio::test]
async fn existing_orphan_cannot_acquire_a_reservation_then_be_adopted() {
    let (_parent, path) = root().await;
    let req = request(1, b"abc", Kind::Note);
    let object = object_path(&path, &req);
    std::fs::create_dir(object.parent().unwrap()).unwrap();
    std::fs::set_permissions(
        object.parent().unwrap(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    std::fs::write(&object, b"abc").unwrap();
    std::fs::set_permissions(&object, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut fixture = Fixture::open(&path, &binding()).await.unwrap();
    for _ in 0..2 {
        assert!(matches!(
            fixture.stage(&req, b"abc").await,
            Err(Error::Conflict)
        ));
    }
    assert_eq!(fixture.inspect().await.unwrap().prepared, 0);
    assert_eq!(std::fs::read(object).unwrap(), b"abc");
    fixture.close().await.unwrap();
}

#[tokio::test]
async fn preexisting_database_sidecars_locks_and_markers_cannot_follow_links() {
    for name in [
        "inventory.sqlite",
        "inventory.sqlite-wal",
        "inventory.sqlite-shm",
        "inventory.sqlite-journal",
        "writer.lock",
        "fixture.json",
        "POISON",
    ] {
        for hard in [false, true] {
            let (parent, path) = root().await;
            let victim = parent.path().join("victim");
            std::fs::write(&victim, b"untouched").unwrap();
            std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();
            let target = path.join(name);
            if target.exists() {
                std::fs::remove_file(&target).unwrap();
            }
            if hard {
                std::fs::hard_link(&victim, &target).unwrap();
            } else {
                std::os::unix::fs::symlink(&victim, &target).unwrap();
            }
            assert!(
                Fixture::open(&path, &binding()).await.is_err(),
                "{name} hard={hard}"
            );
            assert_eq!(std::fs::read(victim).unwrap(), b"untouched");
        }
    }
}

#[tokio::test]
async fn schema_binding_root_mode_and_writer_gate_fail_closed() {
    let (_parent, path) = root().await;
    let fixture = Fixture::open(&path, &binding()).await.unwrap();
    assert!(matches!(
        Fixture::open(&path, &binding()).await,
        Err(Error::WriterBusy)
    ));
    fixture.close().await.unwrap();
    let mut wrong = binding();
    wrong.realm_id = "10000000-0000-4000-8000-000000000002".to_owned();
    assert!(Fixture::open(&path, &wrong).await.is_err());
    sql(&path, "PRAGMA user_version = 9;").await;
    assert!(matches!(
        Fixture::open(&path, &binding()).await,
        Err(Error::Schema)
    ));
    assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o700);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        Fixture::open(&path, &binding()).await,
        Err(Error::UnsafePath)
    ));
}

#[tokio::test]
async fn filesystem_error_points_never_report_a_durable_commit() {
    // Injected EIO/ENOSPC before each named syscall, not a claim that the OS
    // itself produced those errors on this filesystem.
    for errno in [5, 28] {
        for target in [
            "before_write",
            "before_file_sync",
            "before_rename",
            "before_directory_sync",
            "before_staging_directory_sync",
            "before_destination_directory_sync",
            "before_objects_directory_sync",
            "before_root_directory_sync",
        ] {
            let (_parent, path) = root().await;
            let req = request(1, b"abc", Kind::Note);
            let mut fixture = Fixture::open(&path, &binding()).await.unwrap();
            assert!(fixture
                .stage_with_checkpoint(&req, b"abc", &mut |name| {
                    if name == target {
                        Err(Error::Io(std::io::Error::from_raw_os_error(errno)))
                    } else {
                        Ok(())
                    }
                })
                .await
                .is_err());
            assert!(fixture.inspect().await.unwrap().durable.is_empty());
            fixture.close().await.unwrap();
        }
    }
}

#[tokio::test]
async fn required_schema_change_is_rejected_without_a_version_change() {
    let (_parent, path) = root().await;
    sql(&path, "DROP TRIGGER immutable_allocation;").await;
    assert!(matches!(
        Fixture::open(&path, &binding()).await,
        Err(Error::Schema)
    ));
}

#[tokio::test]
async fn extra_or_disguised_mutating_trigger_cannot_invalidate_a_commit() {
    for name in ["delete_commit", "reject_commit"] {
        let (_parent, path) = root().await;
        sql(&path, &format!("CREATE TRIGGER {name} AFTER UPDATE ON attempts WHEN NEW.state = 'DURABLE' BEGIN DELETE FROM attempts WHERE operation_id=NEW.operation_id; END;")).await;
        assert!(matches!(
            Fixture::open(&path, &binding()).await,
            Err(Error::Schema)
        ));
    }
}

#[tokio::test]
async fn blob_and_staging_links_and_fifo_are_rejected_without_following() {
    for location in ["staging", "object"] {
        for kind in ["symlink", "hardlink", "fifo"] {
            let (parent, path) = root().await;
            let req = request(1, b"abc", Kind::Note);
            let target = if location == "staging" {
                path.join("staging")
                    .join(format!("{}.part", req.attempt_id))
            } else {
                let target = object_path(&path, &req);
                std::fs::create_dir(target.parent().unwrap()).unwrap();
                std::fs::set_permissions(
                    target.parent().unwrap(),
                    std::fs::Permissions::from_mode(0o700),
                )
                .unwrap();
                target
            };
            let victim = parent.path().join("victim");
            std::fs::write(&victim, b"untouched").unwrap();
            std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();
            match kind {
                "symlink" => std::os::unix::fs::symlink(&victim, &target).unwrap(),
                "hardlink" => std::fs::hard_link(&victim, &target).unwrap(),
                _ => {
                    let dir = std::fs::File::open(target.parent().unwrap()).unwrap();
                    rustix::fs::mkfifoat(
                        &dir,
                        target.file_name().unwrap(),
                        rustix::fs::Mode::from_raw_mode(0o600),
                    )
                    .unwrap();
                }
            }
            let mut fixture = Fixture::open(&path, &binding()).await.unwrap();
            assert!(
                fixture.stage(&req, b"abc").await.is_err(),
                "{location} {kind}"
            );
            assert_eq!(fixture.inspect().await.unwrap().prepared, 0);
            fixture.close().await.unwrap();
            assert_eq!(std::fs::read(victim).unwrap(), b"untouched");
        }
    }
}

#[tokio::test]
async fn reserved_count_and_byte_limits_do_not_depend_on_completed_files() {
    for (count, bytes) in [(128, Vec::new()), (64, vec![b'x'; 1_048_576])] {
        let (_parent, path) = root().await;
        let mut fixture = Fixture::open(&path, &binding()).await.unwrap();
        for seed in 1..=count {
            let req = request(seed, &bytes, Kind::Attachment);
            assert!(matches!(
                fixture
                    .stage_with_checkpoint(&req, &bytes, &mut |name| {
                        if name == "after_prepare" {
                            Err(Error::Injected(name))
                        } else {
                            Ok(())
                        }
                    })
                    .await,
                Err(Error::Injected("after_prepare"))
            ));
        }
        let req = request(count + 1, &bytes, Kind::Attachment);
        assert!(matches!(
            fixture.stage(&req, &bytes).await,
            Err(Error::Capacity)
        ));
        assert_eq!(fixture.inspect().await.unwrap().prepared, count as usize);
        fixture.close().await.unwrap();
    }
}
