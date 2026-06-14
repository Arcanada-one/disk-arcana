//! DISK-0039 — `disk status` / `disk config validate` / `disk config reload`
//! CLI shortcuts over the R7 loopback REST surface (`127.0.0.1:9444`) and the
//! existing static config validator.
//!
//! These are thin wrappers: `status` and `config reload` are HTTP calls to the
//! running daemon's loopback REST API; `config validate` reuses
//! [`DiskConfig::load`] — the very same load+parse+validate the daemon runs at
//! startup — so it needs no daemon and binds nothing.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use disk_client::config::DiskConfig;
use disk_client::{AcceptedResponse, StatusResponse, DEFAULT_PORT};

/// Default loopback address for the REST surface (`127.0.0.1:9444`).
fn default_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], DEFAULT_PORT))
}

/// Maximum number of connect-retry attempts before giving up.
///
/// 40 attempts × 50 ms ≈ 2 s total.  This covers the brief window between the
/// daemon logging its "listening on …" line and the tokio accept loop
/// processing its first connection.  The total budget is acceptable for the
/// absent-daemon error path too: it will exhaust all attempts and still exit
/// non-zero as required.
const CONNECT_MAX_ATTEMPTS: u32 = 40;

/// Delay between successive connect-retry attempts.
const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(50);

/// Send a request built by `make_request` with bounded connect-retry.
///
/// Retries only on connection errors (`e.is_connect()` — ECONNREFUSED,
/// connection-reset, etc.).  Any other error kind (DNS, TLS, decode) is
/// propagated immediately without retrying; successful HTTP responses
/// (including 4xx/5xx) are returned as-is.  `make_request` is re-invoked for
/// every attempt because a `RequestBuilder` is consumed by `send()`.
async fn send_with_retry(
    addr: SocketAddr,
    mut make_request: impl FnMut() -> reqwest::RequestBuilder,
) -> Result<reqwest::Response> {
    let mut last_err: Option<reqwest::Error> = None;
    for _ in 0..CONNECT_MAX_ATTEMPTS {
        match make_request().send().await {
            Ok(resp) => return Ok(resp),
            Err(e) if e.is_connect() => {
                last_err = Some(e);
                tokio::time::sleep(CONNECT_RETRY_DELAY).await;
            }
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("connect to daemon at {addr} (is `disk daemon` running?)")
                });
            }
        }
    }
    Err(last_err.expect("loop ran at least once"))
        .with_context(|| format!("connect to daemon at {addr} (is `disk daemon` running?)"))
}

/// `disk status [--addr <ip:port>]` — GET `/status` and pretty-print.
pub async fn run_status(addr: Option<SocketAddr>) -> Result<()> {
    let addr = addr.unwrap_or_else(default_addr);
    let url = format!("http://{addr}/status");
    let client = reqwest::Client::new();
    let resp = send_with_retry(addr, || client.get(&url)).await?;
    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("GET /status returned HTTP {status}");
    }
    let body: StatusResponse = resp.json().await.context("decode /status JSON")?;
    print_status(&body);
    Ok(())
}

/// Render a human-readable snapshot of the daemon status.
fn print_status(s: &StatusResponse) {
    println!("node:           {}", s.node);
    println!("config_version: {}", s.config_version);
    println!("uptime:         {}s", s.daemon_uptime_s);
    if s.shares.is_empty() {
        println!("shares:         (none)");
        return;
    }
    println!("shares:");
    for sh in &s.shares {
        println!("  - {} [{}]", sh.name, sh.state);
        println!("      path:      {}", sh.path);
        println!("      direction: {}", sh.declared_direction);
        if let Some(role) = &sh.server_confirmed_role {
            println!("      role:      {role}");
        }
        if let Some(ts) = &sh.last_success_at {
            println!("      last_ok:   {ts}");
        }
        if let Some(err) = &sh.last_error {
            println!("      last_err:  {err}");
        }
        println!(
            "      bytes:     sent={} recv={} pending={}",
            sh.bytes_sent_session, sh.bytes_received_session, sh.pending_local_changes
        );
    }
}

/// `disk config validate [--file <path>]` — static load + validate, no daemon.
///
/// Defaults to the production config path so a bare `disk config validate`
/// checks the deployed file. Any [`disk_client::config::ConfigError`] is
/// surfaced verbatim and the process exits non-zero (the `?` propagation in
/// `main`).
pub fn run_config_validate(file: Option<PathBuf>) -> Result<()> {
    let path = file.unwrap_or_else(|| PathBuf::from("/etc/disk-arcana/disk.toml"));
    let cfg = DiskConfig::load(&path).with_context(|| format!("validate {}", path.display()))?;
    println!(
        "{} is valid ({} share(s))",
        path.display(),
        cfg.shares.len()
    );
    Ok(())
}

/// `disk config reload [--addr <ip:port>]` — POST `/config/reload`.
pub async fn run_config_reload(addr: Option<SocketAddr>) -> Result<()> {
    let addr = addr.unwrap_or_else(default_addr);
    let url = format!("http://{addr}/config/reload");
    let client = reqwest::Client::new();
    let resp = send_with_retry(addr, || client.post(&url)).await?;
    let status = resp.status();
    let body: AcceptedResponse = resp.json().await.context("decode /config/reload JSON")?;
    if body.queued {
        println!("config reload queued");
        Ok(())
    } else {
        anyhow::bail!("daemon did not queue the reload (HTTP {status}, queued=false)")
    }
}

/// `disk conflicts list [--addr <ip:port>]` — GET `/conflicts`.
pub async fn run_conflicts_list(addr: Option<SocketAddr>) -> Result<()> {
    let addr = addr.unwrap_or_else(default_addr);
    let url = format!("http://{addr}/conflicts");
    let client = reqwest::Client::new();
    let resp = send_with_retry(addr, || client.get(&url)).await?;
    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("GET /conflicts returned HTTP {status}");
    }
    let items: Vec<disk_client::ConflictListItem> =
        resp.json().await.context("decode /conflicts JSON")?;
    if items.is_empty() {
        println!("no unresolved conflicts");
        return Ok(());
    }
    println!("{:<6}  {:<50}  type", "id", "path");
    println!("{}", "-".repeat(80));
    for item in &items {
        println!("{:<6}  {:<50}  {}", item.id, item.path, item.conflict_type);
        if let Some(fork) = &item.fork_path {
            println!("       fork: {fork}");
        }
    }
    Ok(())
}

/// `disk conflicts resolve` — POST `/conflicts/{path}` or loop for `--all`.
pub async fn run_conflicts_resolve(
    addr: Option<SocketAddr>,
    path: Option<String>,
    all: bool,
    action: &str,
) -> Result<()> {
    let addr = addr.unwrap_or_else(default_addr);
    let client = reqwest::Client::new();

    if all {
        // Fetch all unresolved conflicts then resolve each.
        let list_url = format!("http://{addr}/conflicts");
        let resp = send_with_retry(addr, || client.get(&list_url)).await?;
        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!("GET /conflicts returned HTTP {status}");
        }
        let items: Vec<disk_client::ConflictListItem> =
            resp.json().await.context("decode /conflicts JSON")?;
        if items.is_empty() {
            println!("no unresolved conflicts");
            return Ok(());
        }
        for item in &items {
            resolve_one(addr, &item.path, action, &client).await?;
        }
        println!(
            "resolved {} conflict(s) with action '{action}'",
            items.len()
        );
    } else if let Some(p) = path {
        resolve_one(addr, &p, action, &client).await?;
        println!("resolved conflict at '{p}' with action '{action}'");
    } else {
        anyhow::bail!("either --path <path> or --all is required");
    }
    Ok(())
}

/// POST `/conflicts/{path}` with the given action.
async fn resolve_one(
    addr: SocketAddr,
    path: &str,
    action: &str,
    client: &reqwest::Client,
) -> Result<()> {
    let encoded_path = percent_encode(path);
    let url = format!("http://{addr}/conflicts/{encoded_path}");
    let body = serde_json::json!({ "action": action });
    let resp = send_with_retry(addr, || client.post(&url).json(&body)).await?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("POST /conflicts/{path} returned HTTP {status}: {text}");
    }
    Ok(())
}

/// Percent-encode a vault-relative path for use in a URL segment.
///
/// Only encodes characters that would be misinterpreted in URL paths
/// (primarily `/` → `%2F`).
fn percent_encode(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            if c == '/' {
                vec!['%', '2', 'F']
            } else {
                vec![c]
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener as StdTcpListener;
    use std::time::Instant;

    /// Reserve an OS-assigned loopback port, then release it so a connect to it
    /// initially refuses (nothing is listening) until the delayed server below
    /// claims it. This is exactly the cold-start window `send_with_retry` exists
    /// to bridge.
    fn reserve_port() -> SocketAddr {
        let l = StdTcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let addr = l.local_addr().expect("local_addr");
        drop(l);
        addr
    }

    /// `send_with_retry` must keep retrying across an initial `ECONNREFUSED`
    /// and succeed once a server starts listening, rather than failing on the
    /// first cold connect. Regression guard for the daemon cold-start race.
    #[tokio::test]
    async fn send_with_retry_bridges_initial_connection_refused() {
        let addr = reserve_port();
        let url = format!("http://{addr}/ping");

        // Confirm the port refuses right now (no listener yet).
        assert!(
            tokio::net::TcpStream::connect(addr).await.is_err(),
            "precondition: reserved port must initially refuse connections"
        );

        // Start an HTTP listener after a delay long enough to force ≥1 retry
        // (several CONNECT_RETRY_DELAY cycles) but well within the total budget.
        let server = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .expect("bind delayed server");
            let (mut sock, _) = listener.accept().await.expect("accept");
            // Minimal HTTP/1.1 200 so reqwest gets a real response.
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await;
            let _ = sock.flush().await;
        });

        let client = reqwest::Client::new();
        let started = Instant::now();
        let resp = send_with_retry(addr, || client.get(&url))
            .await
            .expect("send_with_retry must succeed once the server comes up");

        assert!(
            resp.status().is_success(),
            "expected 200 from delayed server"
        );
        // It must have actually waited for the server (i.e. retried), not
        // succeeded instantly — proves the retry path engaged.
        assert!(
            started.elapsed() >= Duration::from_millis(200),
            "expected at least one retry cycle before success (retry path engaged)"
        );

        server.await.expect("server task");
    }

    /// A non-connect failure path: a fully-absent daemon (port that nothing will
    /// ever claim) must still exhaust the bounded retries and return an error
    /// rather than hanging — the absent-daemon contract.
    #[tokio::test]
    async fn send_with_retry_gives_up_on_permanently_absent_daemon() {
        let addr = reserve_port(); // released, nothing will re-bind it
        let url = format!("http://{addr}/status");
        let client = reqwest::Client::new();

        let started = Instant::now();
        let result = send_with_retry(addr, || client.get(&url)).await;

        assert!(result.is_err(), "absent daemon must yield an error");
        // Bounded: must give up near the configured budget, not hang forever.
        let budget = CONNECT_RETRY_DELAY * CONNECT_MAX_ATTEMPTS;
        assert!(
            started.elapsed() < budget * 4,
            "retry must be bounded (gave up within a small multiple of the budget)"
        );
    }
}
