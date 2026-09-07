#![allow(dead_code)]
use disk_personal::fixture_support::{digest, Binding, Fixture, Kind, Request};
use sqlx::{Connection, SqliteConnection};
use std::path::{Path, PathBuf};

pub fn binding() -> Binding {
    Binding {
        realm_id: "10000000-0000-4000-8000-000000000001".to_owned(),
        deployment_id: "20000000-0000-4000-8000-000000000001".to_owned(),
    }
}

pub fn request(seed: u64, bytes: &[u8], kind: Kind) -> Request {
    Request {
        operation_id: format!("30000000-0000-4000-8000-{seed:012x}"),
        attempt_id: format!("40000000-0000-4000-8000-{seed:012x}"),
        object_id: format!("50000000-0000-4000-8000-{seed:012x}"),
        revision_id: format!("60000000-0000-4000-8000-{seed:012x}"),
        kind,
        expected_len: bytes.len() as u64,
        sha256: digest(bytes),
    }
}

pub async fn root() -> (tempfile::TempDir, PathBuf) {
    let parent = tempfile::tempdir().unwrap();
    let path = parent.path().join("disk-personal-fixture-test");
    Fixture::initialize(&path, &binding()).await.unwrap();
    (parent, path)
}

pub async fn sql(path: &Path, statement: &str) {
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(path.join("inventory.sqlite"))
        .create_if_missing(false);
    let mut db = SqliteConnection::connect_with(&options).await.unwrap();
    sqlx::raw_sql(statement).execute(&mut db).await.unwrap();
    db.close().await.unwrap();
}

pub fn object_path(root: &Path, request: &Request) -> PathBuf {
    root.join("objects")
        .join(&request.object_id)
        .join(format!("{}.blob", request.revision_id))
}
