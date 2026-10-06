//! Fresh-process configuration probes. This module is included only by tests.
use serde_json::Value;
use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const CASE_ENV: &str = "DISK_CONFIG_PROBE_CASE";

fn emit_case_ok(id: &str) {
    // println! is captured by libtest for passing tests. Write only the
    // synthetic fixture ID directly so ordinary CI retains each observation.
    writeln!(std::io::stdout().lock(), "CONFIG_PROBE_CASE_OK {id}")
        .expect("retain synthetic configuration case marker");
}

#[test]
fn marker_visibility_child() {
    if std::env::var(CASE_ENV).as_deref() == Ok("marker-visibility-control") {
        emit_case_ok("C00-marker-visibility-control");
    }
}

#[test]
fn case_marker_survives_default_libtest_capture() {
    let module = module_path!().split_once("::").map(|(_, path)| path);
    let child = match module {
        Some(path) => format!("{path}::marker_visibility_child"),
        None => "marker_visibility_child".to_string(),
    };
    let output = Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", &child])
        .env_clear()
        .env(CASE_ENV, "marker-visibility-control")
        .output()
        .expect("run owned marker visibility control");
    assert!(output.status.success(), "marker child failed");
    let stdout = String::from_utf8(output.stdout).expect("synthetic marker UTF-8");
    assert!(stdout.contains("test result: ok. 1 passed; 0 failed;"));
    assert!(stdout
        .lines()
        .any(|line| { line.trim_end() == "CONFIG_PROBE_CASE_OK C00-marker-visibility-control" }));
}

struct OwnedChild(Option<Child>);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub fn expected() -> Option<Value> {
    std::env::var(CASE_ENV)
        .ok()
        .map(|s| serde_json::from_str(&s).expect("synthetic probe envelope"))
}

pub fn check(actual: Value, expected: Value) {
    let fields = expected.as_object().expect("expected field projection");
    assert!(!fields.is_empty(), "empty projection is not a probe");
    for (key, value) in fields {
        assert_eq!(actual.get(key), Some(value), "configuration field {key}");
    }
    println!("CONFIG_PROBE_CHILD_OK");
}

pub fn run(child_name: &str, fixtures: &str) {
    let cases: Value = serde_json::from_str(fixtures).expect("fixture JSON");
    let cases = cases.as_array().expect("fixture cases");
    assert!(!cases.is_empty());
    for case in cases {
        let id = case["id"].as_str().expect("case id");
        let mut command = Command::new(std::env::current_exe().expect("test executable"));
        command
            .args(["--exact", child_name, "--nocapture"])
            .env_clear()
            .env(CASE_ENV, case["expected"].to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in case["env"].as_object().expect("fixture env") {
            assert!(
                key != CASE_ENV && (key.starts_with("DISK_") || key == "OPS_BOT_URL"),
                "non-config environment key"
            );
            command.env(key, value.as_str().expect("synthetic string"));
        }
        let mut owned = OwnedChild(Some(command.spawn().expect("spawn isolated probe")));
        let child = owned.0.as_mut().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if child.try_wait().expect("poll owned child").is_some() {
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("configuration probe {id} timed out");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = owned
            .0
            .take()
            .unwrap()
            .wait_with_output()
            .expect("collect probe");
        // Only this scrubbed child's synthetic assertion output is reported.
        assert!(
            output.status.success(),
            "configuration probe {id}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("CONFIG_PROBE_CHILD_OK"),
            "probe {id} did not execute its reader"
        );
        assert!(
            stdout.contains("test result: ok. 1 passed; 0 failed;"),
            "probe {id} did not run exactly one test"
        );
        emit_case_ok(id);
    }
}
