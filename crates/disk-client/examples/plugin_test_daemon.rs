//! Disposable real-daemon fixture for the Obsidian integration suite.
//!
//! It intentionally uses the production Axum router, SQLite `MetaDb`, and
//! filesystem conflict operations while binding only to 127.0.0.1:9444.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use disk_client::rest_api::{serve, DaemonState, ShareSnapshot};
use disk_client::sync_loop::LoopState;
use disk_core::types::ConflictRecord;
use disk_core::MetaDb;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let root = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("usage: plugin_test_daemon <isolated-temp-root>"))?;
    if !root.is_absolute() {
        anyhow::bail!("fixture root must be absolute");
    }
    let canonical_parent = root
        .parent()
        .ok_or_else(|| anyhow::anyhow!("fixture root has no parent"))?
        .canonicalize()?;
    std::fs::create_dir_all(&root)?;
    let canonical_root = root.canonicalize()?;
    if canonical_root.parent() != Some(canonical_parent.as_path()) {
        anyhow::bail!("fixture root changed parent during canonicalization");
    }

    let state_dir = canonical_root.join("state");
    let wiki = canonical_root.join("wiki");
    let docs = canonical_root.join("docs");
    std::fs::create_dir_all(state_dir.as_path())?;
    std::fs::create_dir_all(wiki.join("notes"))?;
    std::fs::create_dir_all(docs.join("notes"))?;
    std::fs::write(wiki.join("notes/todo.md"), b"wiki untouched\n")?;
    std::fs::write(docs.join("notes/todo.md"), b"local version\n")?;
    std::fs::write(docs.join("notes/todo.remote.md"), b"remote version\n")?;

    let db_path = state_dir.join("meta.db");
    let db = MetaDb::open(&db_path).await?;
    db.create_conflict(&ConflictRecord {
        id: None,
        vault_id: "docs".into(),
        path: "notes/todo.md".into(),
        conflict_type: "Concurrent".into(),
        local_hash: None,
        remote_hash: None,
        base_hash: None,
        resolution: None,
        fork_path: Some("notes/todo.remote.md".into()),
        resolved: false,
        created_at: 0,
        resolved_at: None,
    })
    .await?;

    let (state, _, _) = DaemonState::new("obsidian-integration", "test-v1");
    let roots = HashMap::from([("wiki".to_string(), wiki), ("docs".to_string(), docs)]);
    let state = state.with_meta_db(db).with_vault_roots(roots);
    state
        .set_shares(vec![ShareSnapshot {
            name: "docs".into(),
            path: canonical_root.join("docs").display().to_string(),
            declared_direction: disk_client::config::Direction::Bidirectional,
            server_confirmed_role: Some(disk_client::config::Direction::Bidirectional),
            state: LoopState::Idle,
            last_success_at: None,
            last_error: None,
            bytes_sent_session: 0,
            bytes_received_session: 0,
            pending_local_changes: 0,
        }])
        .await;

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9444);
    let (_shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    serve(state, addr, async move {
        let _ = shutdown_rx.await;
    })
    .await?;
    println!("plugin-test-daemon ready on http://127.0.0.1:9444");
    tokio::signal::ctrl_c().await?;
    Ok(())
}
