#![cfg(target_os = "linux")]
mod common;
use common::*;
use disk_personal::{
    capture_binding::CaptureDescriptor,
    fixture_support::{CaptureFixture, Fixture, Kind},
};
use serde_json::{json, Value};
use sqlx::{Connection, SqliteConnection};
fn descriptor() -> Value {
    serde_json::from_str::<Value>(include_str!("fixtures/capture-canonical.json")).unwrap()
        ["descriptor"]
        .clone()
}
fn validated(v: &Value) -> CaptureDescriptor {
    CaptureDescriptor::parse(&serde_json::to_vec(v).unwrap()).unwrap()
}
fn part() -> &'static str {
    "0000000b-0000-4000-8000-000000000001"
}
async fn fresh() -> (tempfile::TempDir, std::path::PathBuf) {
    let p = tempfile::tempdir().unwrap();
    let path = p.path().join("disk-personal-fixture-capture");
    CaptureFixture::initialize(&path, &binding()).await.unwrap();
    (p, path)
}
async fn counts(path: &std::path::Path) -> (i64, i64) {
    let opts = sqlx::sqlite::SqliteConnectOptions::new().filename(path.join("inventory.sqlite"));
    let mut db = SqliteConnection::connect_with(&opts).await.unwrap();
    let a = sqlx::query_scalar("SELECT COUNT(*) FROM attempts")
        .fetch_one(&mut db)
        .await
        .unwrap();
    let b = sqlx::query_scalar("SELECT COUNT(*) FROM capture_binding")
        .fetch_one(&mut db)
        .await
        .unwrap();
    db.close().await.unwrap();
    (a, b)
}
#[tokio::test]
async fn v2_durable_bytes_reopen_and_unchanged_retry() {
    let (_p, path) = fresh().await;
    let r = request(1, b"abc", Kind::Note);
    let d = validated(&descriptor());
    let mut f = CaptureFixture::open(&path, &binding()).await.unwrap();
    let receipt = f.stage(&d, part(), &r, b"abc").await.unwrap();
    f.close().await.unwrap();
    let mut f = CaptureFixture::open(&path, &binding()).await.unwrap();
    assert_eq!(f.read(&d, part(), &r).await.unwrap(), b"abc");
    assert_eq!(f.stage(&d, part(), &r, b"abc").await.unwrap(), receipt);
    f.close().await.unwrap();
    assert_eq!(counts(&path).await, (1, 1));
}
#[tokio::test]
async fn legacy_root_cannot_be_adopted_and_fresh_root_cannot_be_reinitialized() {
    let (_p, path) = root().await;
    assert!(CaptureFixture::open(&path, &binding()).await.is_err());
    assert!(CaptureFixture::initialize(&path, &binding()).await.is_err());
    Fixture::open(&path, &binding())
        .await
        .unwrap()
        .close()
        .await
        .unwrap();
    let (_p, path) = fresh().await;
    assert!(Fixture::open(&path, &binding()).await.is_err());
    assert!(CaptureFixture::initialize(&path, &binding()).await.is_err());
}
#[tokio::test]
async fn full_descriptor_retry_and_read_reject_substitution() {
    let (_p, path) = fresh().await;
    let r = request(1, b"abc", Kind::Note);
    let d = validated(&descriptor());
    let mut f = CaptureFixture::open(&path, &binding()).await.unwrap();
    f.stage(&d, part(), &r, b"abc").await.unwrap();
    for key in ["captureId", "messageId", "idempotencyKey"] {
        let mut other = descriptor();
        other[key] = json!("000000ff-0000-4000-8000-000000000001");
        let other = validated(&other);
        assert!(f.stage(&other, part(), &r, b"abc").await.is_err());
        assert!(f.read(&other, part(), &r).await.is_err());
    }
    f.close().await.unwrap();
    assert_eq!(counts(&path).await, (1, 1));
}
#[tokio::test]
async fn competing_capture_reservation_rolls_back_attempt_and_binding() {
    let (_p, path) = fresh().await;
    let r = request(1, b"abc", Kind::Note);
    let d = validated(&descriptor());
    let mut f = CaptureFixture::open(&path, &binding()).await.unwrap();
    f.stage(&d, part(), &r, b"abc").await.unwrap();
    let r2 = request(2, b"abc", Kind::Note);
    let mut other = descriptor();
    other["parts"][0]["objectId"] = json!(r2.object_id);
    other["parts"][0]["objectRevision"] = json!(r2.revision_id);
    assert!(f
        .stage(&validated(&other), part(), &r2, b"abc")
        .await
        .is_err());
    f.close().await.unwrap();
    assert_eq!(counts(&path).await, (1, 1));
    assert!(!object_path(&path, &r2).exists());
}
#[tokio::test]
async fn invalid_body_and_cross_realm_do_not_reserve() {
    let (_p, path) = fresh().await;
    let r = request(1, b"abc", Kind::Note);
    let d = validated(&descriptor());
    let mut f = CaptureFixture::open(&path, &binding()).await.unwrap();
    assert!(f.stage(&d, part(), &r, b"xyz").await.is_err());
    assert!(f
        .stage(&d, "000000ff-0000-4000-8000-000000000001", &r, b"abc")
        .await
        .is_err());
    f.close().await.unwrap();
    let mut b = binding();
    b.realm_id = "10000000-0000-4000-8000-000000000002".into();
    assert!(CaptureFixture::open(&path, &b).await.is_err());
    assert_eq!(counts(&path).await, (0, 0));
}
#[tokio::test]
async fn lost_ack_retains_both_rows_and_stable_retry() {
    let (_p, path) = fresh().await;
    let r = request(1, b"abc", Kind::Note);
    let d = validated(&descriptor());
    let mut f = CaptureFixture::open(&path, &binding()).await.unwrap();
    assert!(f
        .stage_with_checkpoint(&d, part(), &r, b"abc", &mut |at| if at == "after_commit" {
            Err(disk_personal::fixture_support::Error::Injected(
                "after_commit",
            ))
        } else {
            Ok(())
        })
        .await
        .is_err());
    f.close().await.unwrap();
    let mut f = CaptureFixture::open(&path, &binding()).await.unwrap();
    f.stage(&d, part(), &r, b"abc").await.unwrap();
    f.close().await.unwrap();
    assert_eq!(counts(&path).await, (1, 1));
}
#[tokio::test]
async fn unavailable_startup_denies_even_existing_root() {
    let (_p, path) = fresh().await;
    assert!(
        CaptureFixture::open_without_trusted_startup(&path, &binding())
            .await
            .is_err()
    );
    assert_eq!(counts(&path).await, (0, 0));
}

#[tokio::test]
async fn actual_database_cannot_mutate_or_delete_binding() {
    let (_p, path) = fresh().await;
    let r = request(1, b"abc", Kind::Note);
    let mut f = CaptureFixture::open(&path, &binding()).await.unwrap();
    f.stage(&validated(&descriptor()), part(), &r, b"abc")
        .await
        .unwrap();
    f.close().await.unwrap();
    let opts = sqlx::sqlite::SqliteConnectOptions::new().filename(path.join("inventory.sqlite"));
    let mut db = SqliteConnection::connect_with(&opts).await.unwrap();
    assert!(
        sqlx::query("UPDATE capture_binding SET cancellation_generation = 1")
            .execute(&mut db)
            .await
            .is_err()
    );
    assert!(sqlx::query("DELETE FROM capture_binding")
        .execute(&mut db)
        .await
        .is_err());
    db.close().await.unwrap();
    CaptureFixture::open(&path, &binding())
        .await
        .unwrap()
        .close()
        .await
        .unwrap();
}

#[tokio::test]
async fn competing_v2_open_cannot_acquire_a_second_writer() {
    let (_p, path) = fresh().await;
    let b = binding();
    let (a, c) = tokio::join!(
        CaptureFixture::open(&path, &b),
        CaptureFixture::open(&path, &b)
    );
    assert_ne!(a.is_ok(), c.is_ok());
    if let Ok(f) = a {
        f.close().await.unwrap();
    }
    if let Ok(f) = c {
        f.close().await.unwrap();
    }
}
