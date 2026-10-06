use super::fs::Root;
use super::types::{
    digest, Binding, Error, LocalCommit, Request, Result, MAX_RECORDS, MAX_RESERVED_BYTES,
};
use crate::capture_binding::CaptureDescriptor;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqliteSynchronous};
use sqlx::{ConnectOptions, Connection, Row, SqliteConnection};
use std::time::Duration;

pub(crate) struct Record {
    pub request: Request,
    pub committed: Option<LocalCommit>,
}

pub(crate) async fn connect(root: &Root) -> Result<SqliteConnection> {
    root.validate()?;
    let options = SqliteConnectOptions::new()
        .filename(root.path.join("inventory.sqlite"))
        .create_if_missing(false)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Full)
        .foreign_keys(true)
        .pragma("temp_store", "MEMORY")
        .pragma("cache_size", "-2048")
        .pragma("trusted_schema", "OFF")
        .busy_timeout(Duration::ZERO)
        .disable_statement_logging();
    let mut db = SqliteConnection::connect_with(&options).await?;
    if let Err(error) = root.validate() {
        db.close().await?;
        return Err(error);
    }
    verify_policy(&mut db).await?;
    Ok(db)
}

pub(crate) async fn initialize(
    db: &mut SqliteConnection,
    binding: &Binding,
    capture: bool,
) -> Result<()> {
    let mut tx = db.begin().await?;
    sqlx::raw_sql(migration(capture)).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO fixture_binding VALUES (1, ?, ?, ?)")
        .bind(&binding.realm_id)
        .bind(&binding.deployment_id)
        .bind(if capture { 2_i64 } else { 1_i64 })
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

fn migration(capture: bool) -> &'static str {
    if capture {
        include_str!("../../migrations/0002_capture_fresh.sql")
    } else {
        include_str!("../../migrations/0001_provider.sql")
    }
}

pub(crate) async fn verify_binding(
    db: &mut SqliteConnection,
    binding: &Binding,
    capture: bool,
) -> Result<()> {
    let version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(&mut *db)
        .await?;
    if version != if capture { 2 } else { 1 } {
        return Err(Error::Schema);
    }
    verify_schema(db, capture).await?;
    let rows =
        sqlx::query("SELECT realm_id, deployment_id, schema_version FROM fixture_binding LIMIT 2")
            .fetch_all(&mut *db)
            .await?;
    if rows.len() != 1
        || rows[0].try_get::<String, _>("realm_id")? != binding.realm_id
        || rows[0].try_get::<String, _>("deployment_id")? != binding.deployment_id
        || rows[0].try_get::<i64, _>("schema_version")? != if capture { 2 } else { 1 }
    {
        return Err(Error::Schema);
    }
    if capture {
        // Admission precedes this function. Still refuse incomplete allocations
        // before consistency can hydrate any durable object bytes.
        let broken: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM attempts a LEFT JOIN capture_binding c ON c.operation_id = a.operation_id WHERE c.operation_id IS NULL OR c.realm_id != ?")
            .bind(&binding.realm_id).fetch_one(&mut *db).await?;
        let orphaned: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM capture_binding c LEFT JOIN attempts a ON a.operation_id = c.operation_id WHERE a.operation_id IS NULL")
            .fetch_one(&mut *db).await?;
        if broken != 0 || orphaned != 0 {
            return Err(Error::Schema);
        }
    }
    Ok(())
}

async fn verify_schema(db: &mut SqliteConnection, capture: bool) -> Result<()> {
    let objects = sqlx::query("SELECT type, name, tbl_name, sql FROM sqlite_schema LIMIT 16")
        .fetch_all(&mut *db)
        .await?;
    if objects.len() > if capture { 14 } else { 9 } {
        return Err(Error::Schema);
    }
    for object in &objects {
        let kind: String = object.try_get("type")?;
        let name: String = object.try_get("name")?;
        let table: String = object.try_get("tbl_name")?;
        let sql: Option<String> = object.try_get("sql")?;
        let allowed = match (kind.as_str(), name.as_str()) {
            ("table", "fixture_binding") => table == "fixture_binding",
            ("table", "attempts") => table == "attempts",
            ("table", "capture_binding") if capture => table == "capture_binding",
            ("trigger", "immutable_capture_update" | "immutable_capture_delete") if capture => {
                table == "capture_binding"
            }
            (
                "index",
                "sqlite_autoindex_capture_binding_1" | "sqlite_autoindex_capture_binding_2",
            ) if capture => table == "capture_binding" && sql.is_none(),
            ("trigger", "immutable_allocation") => table == "attempts",
            ("trigger", "reject_commit") => {
                let exact = "CREATE TRIGGER reject_commit BEFORE UPDATE ON attempts WHEN NEW.state = 'DURABLE' BEGIN SELECT RAISE(ABORT, 'fixture final commit rejection'); END";
                table == "attempts"
                    && sql
                        .as_deref()
                        .map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "))
                        == Some(exact.to_owned())
            }
            ("index", name) => {
                table == "attempts"
                    && sql.is_none()
                    && (1..=5).any(|i| name == format!("sqlite_autoindex_attempts_{i}"))
            }
            _ => false,
        };
        if !allowed {
            return Err(Error::Schema);
        }
    }
    // Extract each whole statement, including trigger bodies, from the exact
    // versioned schema. Names and automatic indexes above remain allowlisted.
    let source = migration(capture);
    let mut names = vec!["fixture_binding", "attempts", "immutable_allocation"];
    if capture {
        names.extend([
            "capture_binding",
            "immutable_capture_update",
            "immutable_capture_delete",
        ]);
    }
    for name in names {
        let prefix = if name.starts_with("immutable_") {
            "CREATE TRIGGER "
        } else {
            "CREATE TABLE "
        };
        let marker = format!("{prefix}{name} ");
        let begin = source.find(&marker).ok_or(Error::Schema)?;
        let rest = &source[begin..];
        let end = if name.starts_with("immutable_") {
            rest.find("END;").ok_or(Error::Schema)? + 3
        } else {
            rest.find(';').ok_or(Error::Schema)?
        };
        let expected = &rest[..end];
        let actual: Option<String> =
            sqlx::query_scalar("SELECT sql FROM sqlite_schema WHERE name = ?")
                .bind(name)
                .fetch_optional(&mut *db)
                .await?;
        let normalize = |sql: &str| sql.split_whitespace().collect::<Vec<_>>().join(" ");
        if actual.as_deref().map(normalize) != Some(normalize(expected)) {
            return Err(Error::Schema);
        }
    }
    let indexes: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_index_list('attempts') WHERE \"unique\" = 1",
    )
    .fetch_one(&mut *db)
    .await?;
    if indexes != 5 {
        return Err(Error::Schema);
    }
    Ok(())
}

pub(crate) async fn verify_policy(db: &mut SqliteConnection) -> Result<Vec<(String, i64)>> {
    let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(&mut *db)
        .await?;
    if mode != "wal" {
        return Err(Error::Schema);
    }
    let mut result = Vec::new();
    for (name, value) in [
        ("synchronous", 2),
        ("foreign_keys", 1),
        ("temp_store", 2),
        ("cache_size", -2048),
        ("trusted_schema", 0),
    ] {
        // Name is selected only from the fixed list above, never caller input.
        let actual: i64 = sqlx::query_scalar(&format!("PRAGMA {name}"))
            .fetch_one(&mut *db)
            .await?;
        if actual != value {
            return Err(Error::Schema);
        }
        result.push((name.to_owned(), actual));
    }
    Ok(result)
}

pub(crate) async fn records(db: &mut SqliteConnection) -> Result<Vec<Record>> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM attempts")
        .fetch_one(&mut *db)
        .await?;
    if count > MAX_RECORDS {
        return Err(Error::Capacity);
    }
    let rows = sqlx::query("SELECT * FROM attempts ORDER BY operation_id LIMIT 129")
        .fetch_all(&mut *db)
        .await?;
    let mut records = Vec::new();
    for row in rows {
        let text: String = row.try_get("request_json")?;
        if text.len() > 2048 {
            return Err(Error::Schema);
        }
        let request: Request = serde_json::from_str(&text)?;
        request.validate()?;
        for (name, expected) in [
            ("operation_id", &request.operation_id),
            ("attempt_id", &request.attempt_id),
            ("object_id", &request.object_id),
            ("revision_id", &request.revision_id),
        ] {
            if row.try_get::<String, _>(name)? != *expected {
                return Err(Error::Schema);
            }
        }
        if row.try_get::<i64, _>("expected_len")?
            != i64::try_from(request.expected_len).map_err(|_| Error::InvalidInput)?
        {
            return Err(Error::Schema);
        }
        let id: Option<String> = row.try_get("local_commit_id")?;
        let sequence: Option<i64> = row.try_get("sequence")?;
        let state: String = row.try_get("state")?;
        let committed = match (state.as_str(), id, sequence) {
            ("PREPARED", None, None) => None,
            ("DURABLE", Some(id), Some(sequence)) if sequence > 0 && id == commit_id(&request)? => {
                Some(LocalCommit {
                    local_commit_id: id,
                    sequence,
                    request: request.clone(),
                })
            }
            _ => return Err(Error::Schema),
        };
        records.push(Record { request, committed });
    }
    Ok(records)
}

pub(crate) async fn reserve(
    db: &mut SqliteConnection,
    request: &Request,
    capture: Option<(&CaptureDescriptor, &str)>,
) -> Result<(bool, Option<LocalCommit>)> {
    let records = records(db).await?;
    for record in &records {
        if record.request.operation_id == request.operation_id {
            if record.request != *request {
                return Err(Error::Conflict);
            }
            if let Some((descriptor, part)) = capture {
                verify_capture(db, request, descriptor, part).await?;
            }
            return Ok((true, record.committed.clone()));
        }
        if record.request.attempt_id == request.attempt_id
            || (record.request.object_id == request.object_id
                && record.request.revision_id == request.revision_id)
        {
            return Err(Error::Conflict);
        }
    }
    let reserved: u64 = records.iter().map(|r| r.request.expected_len).sum();
    if records.len() >= MAX_RECORDS as usize
        || reserved + request.expected_len > MAX_RESERVED_BYTES as u64
    {
        return Err(Error::Capacity);
    }
    let mut tx = db.begin().await?;
    sqlx::query("INSERT INTO attempts (operation_id, attempt_id, object_id, revision_id, request_json, expected_len, state) VALUES (?, ?, ?, ?, ?, ?, 'PREPARED')")
        .bind(&request.operation_id).bind(&request.attempt_id).bind(&request.object_id).bind(&request.revision_id)
        .bind(serde_json::to_string(request)?).bind(i64::try_from(request.expected_len).map_err(|_| Error::InvalidInput)?)
        .execute(&mut *tx).await?;
    if let Some((d, part)) = capture {
        sqlx::query("INSERT INTO capture_binding (operation_id, realm_id, capture_id, part_id, cancellation_generation, descriptor_identity) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(&request.operation_id).bind(d.realm()).bind(d.capture()).bind(part)
            .bind(d.generation()).bind(d.descriptor_identity()).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok((false, None))
}

fn commit_id(request: &Request) -> Result<String> {
    Ok(format!("local-{}", digest(&serde_json::to_vec(request)?)))
}

pub(crate) async fn commit(db: &mut SqliteConnection, request: &Request) -> Result<LocalCommit> {
    let mut tx = db.begin().await?;
    let sequence: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(sequence), 0) + 1 FROM attempts")
        .fetch_one(&mut *tx)
        .await?;
    let id = commit_id(request)?;
    let update = sqlx::query("UPDATE attempts SET state = 'DURABLE', local_commit_id = ?, sequence = ? WHERE operation_id = ? AND state = 'PREPARED' AND request_json = ?")
        .bind(&id).bind(sequence).bind(&request.operation_id).bind(serde_json::to_string(request)?)
        .execute(&mut *tx).await?;
    if update.rows_affected() != 1 {
        return Err(Error::Conflict);
    }
    tx.commit().await?;
    Ok(LocalCommit {
        local_commit_id: id,
        sequence,
        request: request.clone(),
    })
}

pub(crate) async fn verify_capture(
    db: &mut SqliteConnection,
    request: &Request,
    d: &CaptureDescriptor,
    part: &str,
) -> Result<()> {
    let row = sqlx::query("SELECT realm_id, capture_id, part_id, cancellation_generation, descriptor_identity FROM capture_binding WHERE operation_id = ?")
        .bind(&request.operation_id).fetch_optional(&mut *db).await?.ok_or(Error::Conflict)?;
    if row.try_get::<String, _>("realm_id")? != d.realm()
        || row.try_get::<String, _>("capture_id")? != d.capture()
        || row.try_get::<String, _>("part_id")? != part
        || row.try_get::<i64, _>("cancellation_generation")? != d.generation()
        || row.try_get::<String, _>("descriptor_identity")? != d.descriptor_identity()
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
