//! DISK-0006 R9 — Hot config reload integration tests.
//!
//! Plan §Test Plan `it_hot_reload`: edit `disk.toml` add new share → daemon
//! picks up within 10 s without restart (PRD AC #15).
//!
//! These tests spin up a real `notify` watcher on a tmpdir, write a valid
//! initial config, rewrite the file in-place to add a new `[[share]]`
//! section, and assert the `ConfigSnapshot` flips to the new content.
//!
//! A second test rewrites the file with an invalid TOML payload and asserts
//! the snapshot stays pinned to the previous valid version while
//! `ReloadStatus::get()` surfaces the parse error — the «previous active
//! config продолжает работать» contract from the plan.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use disk_client::config::{spawn_config_watcher, DiskConfig};

#[cfg(not(windows))]
const INITIAL: &str = r#"
[node]
id = "dev"
[node.default]
intended_direction = "receive_only"

[server]
address = "host:9443"
client_cert = "/etc/disk-arcana/client.crt"
client_key  = "/etc/disk-arcana/client.key"
"#;

#[cfg(windows)]
const INITIAL: &str = r#"
[node]
id = "dev"
[node.default]
intended_direction = "receive_only"

[server]
address = "host:9443"
client_cert = "C:\\ProgramData\\disk-arcana\\client.crt"
client_key  = "C:\\ProgramData\\disk-arcana\\client.key"
"#;

#[cfg(not(windows))]
const ADDED_SHARE: &str = r#"
[node]
id = "dev"
[node.default]
intended_direction = "receive_only"

[server]
address = "host:9443"
client_cert = "/etc/disk-arcana/client.crt"
client_key  = "/etc/disk-arcana/client.key"

[[share]]
name = "hermes-artefacts"
path = "/var/disk-arcana/hermes"
intended_direction = "bidirectional"
"#;

#[cfg(windows)]
const ADDED_SHARE: &str = r#"
[node]
id = "dev"
[node.default]
intended_direction = "receive_only"

[server]
address = "host:9443"
client_cert = "C:\\ProgramData\\disk-arcana\\client.crt"
client_key  = "C:\\ProgramData\\disk-arcana\\client.key"

[[share]]
name = "hermes-artefacts"
path = "C:\\var\\disk-arcana\\hermes"
intended_direction = "bidirectional"
"#;

const BROKEN: &str = r#"
[node
id = "dev"
"#;

/// Poll the snapshot up to `deadline`, returning `Some(cfg)` as soon as
/// the predicate matches. Used because notify event delivery is async and
/// the apply path runs on the spawned task — we can't `assert_eq!` right
/// after `tokio::fs::write` returns.
async fn wait_for<F: Fn(&DiskConfig) -> bool>(
    snap: &disk_client::config::ConfigSnapshot,
    predicate: F,
    timeout: Duration,
) -> Option<Arc<DiskConfig>> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let cur = snap.current();
        if predicate(&cur) {
            return Some(cur);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

fn write_config(path: &PathBuf, body: &str) {
    std::fs::write(path, body).expect("write config");
}

fn init_logs() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("disk_client=debug")
        .try_init();
}

#[tokio::test]
async fn hot_reload_picks_up_added_share_within_10s() {
    init_logs();
    let tmp = tempfile::tempdir().unwrap();
    let cfg_path = tmp.path().join("disk.toml");
    write_config(&cfg_path, INITIAL);

    let initial: DiskConfig = INITIAL.parse().unwrap();
    let watcher = spawn_config_watcher(
        cfg_path.clone(),
        Arc::new(initial),
        None,
        Some(Duration::from_millis(100)),
    )
    .expect("spawn watcher");

    // Sanity: starts with zero shares.
    assert_eq!(watcher.snapshot.current().shares.len(), 0);
    assert_eq!(watcher.status.get(), None);

    // Rewrite the file with an added share.
    write_config(&cfg_path, ADDED_SHARE);

    let updated = wait_for(
        &watcher.snapshot,
        |c| c.shares.len() == 1 && c.shares[0].name == "hermes-artefacts",
        Duration::from_secs(10),
    )
    .await
    .expect("config should reload within 10 s");

    assert_eq!(updated.shares.len(), 1);
    assert_eq!(updated.shares[0].name, "hermes-artefacts");
    assert_eq!(watcher.status.get(), None);

    watcher.abort();
}

#[tokio::test]
async fn hot_reload_keeps_previous_on_validation_error() {
    init_logs();
    let tmp = tempfile::tempdir().unwrap();
    let cfg_path = tmp.path().join("disk.toml");
    write_config(&cfg_path, INITIAL);

    let initial: DiskConfig = INITIAL.parse().unwrap();
    let watcher = spawn_config_watcher(
        cfg_path.clone(),
        Arc::new(initial.clone()),
        None,
        Some(Duration::from_millis(100)),
    )
    .expect("spawn watcher");

    // Write a syntactically-broken file → reload must fail and the old
    // snapshot must stay.
    write_config(&cfg_path, BROKEN);

    // Wait for the error to surface.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut got_err: Option<String> = None;
    while Instant::now() < deadline {
        if let Some(msg) = watcher.status.get() {
            got_err = Some(msg);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let err_msg = got_err.expect("status.last_error should surface within 10 s");
    assert!(
        err_msg.contains("parse failed") || err_msg.contains("validation failed"),
        "unexpected error message: {err_msg}"
    );

    // Snapshot must still hold the initial valid config — «previous active
    // config продолжает работать».
    let snap = watcher.snapshot.current();
    assert_eq!(snap.node.id, initial.node.id);

    // Recovery: rewrite a valid config → snapshot updates and error clears.
    write_config(&cfg_path, ADDED_SHARE);
    let recovered = wait_for(
        &watcher.snapshot,
        |c| c.shares.len() == 1,
        Duration::from_secs(10),
    )
    .await
    .expect("recovery write should propagate");
    assert_eq!(recovered.shares[0].name, "hermes-artefacts");
    assert_eq!(
        watcher.status.get(),
        None,
        "last_error must clear after successful reload"
    );

    watcher.abort();
}

#[tokio::test]
async fn explicit_reload_signal_triggers_apply() {
    init_logs();
    let tmp = tempfile::tempdir().unwrap();
    let cfg_path = tmp.path().join("disk.toml");
    write_config(&cfg_path, INITIAL);

    let (reload_tx, reload_rx) = tokio::sync::mpsc::channel::<()>(4);

    let initial: DiskConfig = INITIAL.parse().unwrap();
    let watcher = spawn_config_watcher(
        cfg_path.clone(),
        Arc::new(initial),
        Some(reload_rx),
        Some(Duration::from_millis(100)),
    )
    .expect("spawn watcher");

    // Rewrite file BEFORE sending the signal — REST POST /config/reload
    // is the explicit «I edited it, pick it up now» path.
    write_config(&cfg_path, ADDED_SHARE);
    reload_tx.send(()).await.expect("send reload signal");

    let updated = wait_for(
        &watcher.snapshot,
        |c| c.shares.len() == 1,
        Duration::from_secs(10),
    )
    .await
    .expect("explicit signal must drive reload");
    assert_eq!(updated.shares[0].name, "hermes-artefacts");

    watcher.abort();
}
