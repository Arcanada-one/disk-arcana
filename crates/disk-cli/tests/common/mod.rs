//! Shared helpers for disk-cli integration tests.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::ChildStderr;

/// Parse `disk daemon listening on 127.0.0.1:NNNNN` from a log line.
pub fn parse_port_from_listening_line(line: &str) -> Option<u16> {
    let tail = line.rsplit_once(':')?.1;
    tail.trim().parse::<u16>().ok()
}

/// Read the ephemeral REST port from stderr, then keep draining stderr so
/// tracing/log lines cannot SIGPIPE the daemon when the test harness closes
/// pipes early (llvm-cov / parallel `cargo test` race class).
pub async fn read_daemon_listen_port(stderr: ChildStderr) -> u16 {
    let mut reader = BufReader::new(stderr).lines();
    loop {
        let line = tokio::time::timeout(Duration::from_secs(30), reader.next_line())
            .await
            .expect("daemon must emit listening line within 30 s")
            .expect("stderr read failed")
            .expect("listening line absent before stderr closed");
        if let Some(port) = parse_port_from_listening_line(&line) {
            tokio::spawn(async move { while let Ok(Some(_)) = reader.next_line().await {} });
            return port;
        }
    }
}

/// Like [`read_daemon_listen_port`], but also append stderr lines to `log` for
/// failure diagnostics (ring-buffer capped at 16 KiB).
pub async fn read_daemon_listen_port_with_log(stderr: ChildStderr, log: Arc<Mutex<String>>) -> u16 {
    let mut reader = BufReader::new(stderr).lines();
    loop {
        let line = tokio::time::timeout(Duration::from_secs(30), reader.next_line())
            .await
            .expect("daemon must emit listening line within 30 s")
            .expect("stderr read failed")
            .expect("listening line absent before stderr closed");
        {
            let mut buf = log.lock().expect("daemon log lock");
            buf.push_str(&line);
            buf.push('\n');
            if buf.len() > 16_384 {
                let drain = buf.len() - 8_192;
                buf.drain(..drain);
            }
        }
        if parse_port_from_listening_line(&line).is_some() {
            let log_bg = Arc::clone(&log);
            tokio::spawn(async move {
                while let Ok(Some(line)) = reader.next_line().await {
                    let mut buf = log_bg.lock().expect("daemon log lock");
                    buf.push_str(&line);
                    buf.push('\n');
                    if buf.len() > 16_384 {
                        let drain = buf.len() - 8_192;
                        buf.drain(..drain);
                    }
                }
            });
            return parse_port_from_listening_line(&line).expect("just matched");
        }
    }
}
