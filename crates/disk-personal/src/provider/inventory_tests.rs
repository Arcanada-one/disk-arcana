use super::super::types::Kind;
use super::*;
use serde_json::{json, Value};

fn binding() -> Binding {
    Binding {
        realm_id: "10000000-0000-4000-8000-000000000001".into(),
        deployment_id: "20000000-0000-4000-8000-000000000001".into(),
    }
}

fn request(seed: u64, kind: Kind) -> Request {
    Request {
        operation_id: format!("30000000-0000-4000-8000-{seed:012x}"),
        attempt_id: format!("40000000-0000-4000-8000-{seed:012x}"),
        object_id: format!("50000000-0000-4000-8000-{seed:012x}"),
        revision_id: format!("60000000-0000-4000-8000-{seed:012x}"),
        kind,
        expected_len: 3,
        sha256: digest(b"abc"),
    }
}

fn descriptor() -> Value {
    let mut d =
        serde_json::from_str::<Value>(include_str!("../../tests/fixtures/capture-canonical.json"))
            .unwrap()["descriptor"]
            .clone();
    let mut attachment = d["parts"][0].clone();
    attachment["partId"] = json!("0000000c-0000-4000-8000-000000000001");
    attachment["role"] = json!("attachment");
    attachment["objectId"] = json!(request(2, Kind::Attachment).object_id);
    attachment["objectRevision"] = json!(request(2, Kind::Attachment).revision_id);
    d["parts"].as_array_mut().unwrap().push(attachment);
    let parts: Vec<_> = d["parts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| json!([p["role"], p["sha256"], p["sizeBytes"], p["mediaType"]]))
        .collect();
    d["requestFingerprint"] = json!(digest(
        json!([
            d["schemaVersion"],
            d["realmId"],
            d["operation"],
            d["conversationId"],
            d["expectedConversationRevision"],
            parts
        ])
        .to_string()
        .as_bytes()
    ));
    d
}

fn parsed(d: &Value) -> CaptureDescriptor {
    CaptureDescriptor::parse(&serde_json::to_vec(d).unwrap()).unwrap()
}

async fn database(path: &std::path::Path) -> SqliteConnection {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Full)
        .foreign_keys(true)
        .disable_statement_logging();
    SqliteConnection::connect_with(&options).await.unwrap()
}

// Exercise the actual file-backed SQL reservation layer independently of the
// provider's Linux openat2 boundary. These tests grant no filesystem admission.
#[tokio::test]
async fn changed_descriptor_on_second_part_leaves_no_reservation() {
    for committed in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("inventory.sqlite");
        let mut db = database(&path).await;
        initialize(&mut db, &binding(), true).await.unwrap();
        let d = descriptor();
        let first = request(1, Kind::Note);
        let second = request(2, Kind::Attachment);
        reserve(
            &mut db,
            &first,
            Some((&parsed(&d), d["parts"][0]["partId"].as_str().unwrap())),
        )
        .await
        .unwrap();
        if committed {
            commit(&mut db, &first).await.unwrap();
        }
        db.close().await.unwrap();
        let mut db = database(&path).await;
        for field in ["messageId", "idempotencyKey"] {
            let mut changed = d.clone();
            changed[field] = json!("000000ff-0000-4000-8000-000000000001");
            let result = reserve(
                &mut db,
                &second,
                Some((
                    &parsed(&changed),
                    changed["parts"][1]["partId"].as_str().unwrap(),
                )),
            )
            .await;
            assert!(
                matches!(result, Err(Error::Conflict)),
                "{field}, committed={committed}: {result:?}"
            );
            assert_eq!(records(&mut db).await.unwrap().len(), 1);
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM capture_binding")
                .fetch_one(&mut db)
                .await
                .unwrap();
            assert_eq!(count, 1);
        }
        db.close().await.unwrap();
    }
}

#[tokio::test]
async fn matching_parts_and_exact_retry_survive_inventory_reopen() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("inventory.sqlite");
    let mut db = database(&path).await;
    initialize(&mut db, &binding(), true).await.unwrap();
    let d = descriptor();
    let parsed = parsed(&d);
    let requests = [request(1, Kind::Note), request(2, Kind::Attachment)];
    let mut commits = Vec::new();
    for (i, r) in requests.iter().enumerate() {
        let part = d["parts"][i]["partId"].as_str().unwrap();
        assert_eq!(
            reserve(&mut db, r, Some((&parsed, part))).await.unwrap(),
            (false, None)
        );
        commits.push(commit(&mut db, r).await.unwrap());
    }
    db.close().await.unwrap();
    let mut db = database(&path).await;
    verify_binding(&mut db, &binding(), true).await.unwrap();
    for (i, r) in requests.iter().enumerate() {
        let part = d["parts"][i]["partId"].as_str().unwrap();
        assert_eq!(
            reserve(&mut db, r, Some((&parsed, part))).await.unwrap(),
            (true, Some(commits[i].clone()))
        );
    }
    assert_eq!(records(&mut db).await.unwrap().len(), 2);
    db.close().await.unwrap();
}

#[tokio::test]
async fn retained_conflicting_capture_is_refused_before_byte_scan() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("inventory.sqlite");
    let mut db = database(&path).await;
    initialize(&mut db, &binding(), true).await.unwrap();
    let d = descriptor();
    let first = request(1, Kind::Note);
    let second = request(2, Kind::Attachment);
    reserve(
        &mut db,
        &first,
        Some((&parsed(&d), d["parts"][0]["partId"].as_str().unwrap())),
    )
    .await
    .unwrap();
    // Reproduce an inventory the old reservation path could persist. This is
    // synthetic setup, not an alternate provider or a production repair API.
    reserve(&mut db, &second, None).await.unwrap();
    let mut changed = d.clone();
    changed["messageId"] = json!("000000ff-0000-4000-8000-000000000001");
    let changed = parsed(&changed);
    sqlx::query("INSERT INTO capture_binding VALUES (?, ?, ?, ?, ?, ?)")
        .bind(&second.operation_id)
        .bind(changed.realm())
        .bind(changed.capture())
        .bind(d["parts"][1]["partId"].as_str().unwrap())
        .bind(changed.generation())
        .bind(changed.descriptor_identity())
        .execute(&mut db)
        .await
        .unwrap();
    db.close().await.unwrap();
    let mut db = database(&path).await;
    assert!(matches!(
        verify_binding(&mut db, &binding(), true).await,
        Err(Error::Schema)
    ));
    assert_eq!(records(&mut db).await.unwrap().len(), 2);
    let distinct: i64 =
        sqlx::query_scalar("SELECT COUNT(DISTINCT descriptor_identity) FROM capture_binding")
            .fetch_one(&mut db)
            .await
            .unwrap();
    assert_eq!(
        distinct, 2,
        "conflicting evidence must not be repaired or deleted"
    );
    db.close().await.unwrap();
}
