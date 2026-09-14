#![cfg(target_os = "linux")]
mod common;
use common::*;
use disk_personal::fixture_support::{Error, Fixture, Kind};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn(input: &Value) -> OwnedChild {
    let mut child = Command::new(env!("CARGO_BIN_EXE_disk-personal-fixture-worker"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    serde_json::to_writer(&mut stdin, input).unwrap();
    stdin.flush().unwrap();
    drop(stdin);
    OwnedChild(child)
}

fn run(input: &Value) -> (bool, Value) {
    let mut child = spawn(input);
    let stdout = child.0.stdout.take().unwrap();
    let (send, recv) = mpsc::channel();
    std::thread::spawn(move || {
        let value = serde_json::from_reader::<_, Value>(stdout);
        let _ = send.send(value);
    });
    let value = recv
        .recv_timeout(Duration::from_secs(20))
        .expect("worker output deadline");
    let success = child.0.wait().unwrap().success();
    (success, value.unwrap_or(Value::Null))
}

fn wait_checkpoint(child: &mut OwnedChild, expected: &str) {
    let stdout = child.0.stdout.take().unwrap();
    let (send, recv) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let read = BufReader::new(stdout).read_line(&mut line);
        let _ = send.send((read, line));
    });
    let (read, line) = recv
        .recv_timeout(Duration::from_secs(20))
        .expect("checkpoint deadline");
    read.unwrap();
    assert_eq!(line.trim(), format!("CHECKPOINT {expected}"));
}

#[tokio::test]
async fn deterministic_sigkill_boundaries_keep_truthful_local_state() {
    let checkpoints = [
        "before_prepare",
        "after_prepare",
        "after_create",
        "after_partial_write",
        "after_write",
        "after_file_sync",
        "after_rename",
        "after_directory_sync",
        "before_commit",
        "after_commit",
    ];
    for checkpoint in checkpoints {
        let (_parent, path) = root().await;
        let bytes = vec![b'x'; 8192];
        let request = request(1, &bytes, Kind::Attachment);
        let mut input = json!({"action":"stage", "root":path, "binding":binding(), "request":request,
            "data_hex":"78".repeat(bytes.len()), "pause_at":checkpoint});
        let mut child = spawn(&input);
        let stdout = child.0.stdout.take().unwrap();
        let (send, recv) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let result = BufReader::new(stdout).read_line(&mut line);
            let _ = send.send((result, line));
        });
        let (read, line) = recv
            .recv_timeout(Duration::from_secs(20))
            .expect("checkpoint deadline");
        read.unwrap();
        assert_eq!(line.trim(), format!("CHECKPOINT {checkpoint}"));
        child.0.kill().unwrap();
        assert!(!child.0.wait().unwrap().success());
        let (ok, state) = run(&json!({"action":"inspect", "root":path, "binding":binding()}));
        assert!(ok, "{checkpoint}: inspect");
        let committed = checkpoint == "after_commit";
        assert_eq!(
            state["durable"].as_array().unwrap().len(),
            usize::from(committed),
            "{checkpoint}"
        );
        assert_eq!(
            state["prepared"].as_u64().unwrap(),
            u64::from(checkpoint != "before_prepare" && !committed)
        );
        input["pause_at"] = Value::Null;
        let (retry_ok, retried) = run(&input);
        if matches!(checkpoint, "after_create" | "after_partial_write") {
            assert!(!retry_ok, "partial attempt cannot resume: {checkpoint}");
            let stage = path
                .join("staging")
                .join(format!("{}.part", request.attempt_id));
            assert_eq!(
                std::fs::metadata(stage).unwrap().len(),
                if checkpoint == "after_create" {
                    0
                } else {
                    4096
                }
            );
        } else {
            assert!(
                retry_ok,
                "complete or absent attempt may be explicitly restaged: {checkpoint}"
            );
            assert_eq!(std::fs::read(object_path(&path, &request)).unwrap(), bytes);
            if committed {
                assert_eq!(retried, state["durable"][0]);
            }
        }
    }
}

#[tokio::test]
async fn another_process_cannot_write_while_first_process_holds_the_root() {
    let (_parent, path) = root().await;
    let request = request(1, b"abc", Kind::Note);
    let input = json!({"action":"stage", "root":path, "binding":binding(), "request":request, "data_hex":"616263", "pause_at":"after_prepare"});
    let mut child = spawn(&input);
    wait_checkpoint(&mut child, "after_prepare");
    let (ok, _) = run(&json!({"action":"inspect", "root":path, "binding":binding()}));
    assert!(!ok);
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    assert!(run(&json!({"action":"inspect", "root":path, "binding":binding()})).0);
}

#[tokio::test]
async fn actual_paused_sqlite_worker_drop_and_cancel_keep_lock_until_process_exit() {
    for action in ["abandon_worker", "cancel_close"] {
        let (_parent, path) = root().await;
        let mut child = spawn(&json!({"action":action, "root":path, "binding":binding()}));
        wait_checkpoint(&mut child, action);
        // The child has abandoned a connection or cancelled close while a real
        // SQLite progress callback remains paused in its worker thread.
        assert!(!run(&json!({"action":"inspect", "root":path, "binding":binding()})).0);
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        assert!(run(&json!({"action":"inspect", "root":path, "binding":binding()})).0);
    }
}

#[tokio::test]
async fn poison_is_provider_wide_in_new_processes() {
    for injected_marker_failure in [false, true] {
        let (_parent, path) = root().await;
        let req = request(1, b"abc", Kind::Note);
        let other = request(2, b"xyz", Kind::Note);
        let mut fixture = Fixture::open(&path, &binding()).await.unwrap();
        fixture.stage(&req, b"abc").await.unwrap();
        std::fs::write(object_path(&path, &req), b"bad").unwrap();
        if injected_marker_failure {
            fixture.fail_poison_persistence();
            assert!(matches!(
                fixture.read(&req).await,
                Err(Error::PoisonUncertain)
            ));
            assert!(!path.join("POISON").exists());
        } else {
            assert!(matches!(fixture.read(&req).await, Err(Error::Poisoned)));
            assert!(path.join("POISON").exists());
        }
        assert!(matches!(
            fixture.stage(&other, b"xyz").await,
            Err(Error::Poisoned)
        ));
        fixture.close().await.unwrap();
        // Fresh process must rediscover corruption even if marker persistence
        // was injected to fail; it does not inherit an in-memory poison flag.
        assert!(!run(&json!({"action":"inspect", "root":path, "binding":binding()})).0);
        assert!(path.join("POISON").exists());
        assert!(!run(&json!({"action":"stage", "root":path, "binding":binding(), "request":other, "data_hex":"78797a"})).0);
        assert!(!object_path(&path, &other).exists());
        assert_eq!(std::fs::read(object_path(&path, &req)).unwrap(), b"bad");
    }
}
