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
    let path = file.unwrap_or_else(|| PathBuf::from(crate::paths::DEFAULT_CONFIG));
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

/// `disk lan peers [--addr <ip:port>]` — GET `/lan/peers`.
pub async fn run_lan_peers(addr: Option<SocketAddr>) -> Result<()> {
    let addr = addr.unwrap_or_else(default_addr);
    let url = format!("http://{addr}/lan/peers");
    let client = reqwest::Client::new();
    let resp = send_with_retry(addr, || client.get(&url)).await?;
    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("GET /lan/peers returned HTTP {status}");
    }
    let body: serde_json::Value = resp.json().await.context("decode /lan/peers JSON")?;
    if !body["enabled"].as_bool().unwrap_or(false) {
        println!("lan_sync: disabled (set [lan_sync] enabled = true in disk.toml)");
        return Ok(());
    }
    let peers = body["peers"].as_array().cloned().unwrap_or_default();
    if peers.is_empty() {
        println!("lan_sync: enabled — no peers discovered yet");
        return Ok(());
    }
    println!("lan_sync: {} peer(s)", peers.len());
    for peer in peers {
        let node_id = peer["node_id"].as_str().unwrap_or("?");
        let host = peer["host"].as_str().unwrap_or("?");
        let port = peer["port"].as_u64().unwrap_or(0);
        let tenant = peer["tenant_id"].as_str().unwrap_or("—");
        let seen = peer["last_seen_unix"].as_i64().unwrap_or(0);
        println!("  {node_id}  {host}:{port}  tenant={tenant}  seen={seen}");
    }
    Ok(())
}

/// `disk conflicts list [--vault <name>] [--addr <ip:port>]`.
pub async fn run_conflicts_list(
    addr: Option<SocketAddr>,
    vault_filter: Option<&str>,
) -> Result<()> {
    let addr = addr.unwrap_or_else(default_addr);
    let url = format!("http://{addr}/conflicts");
    let client = reqwest::Client::new();
    let resp = send_with_retry(addr, || client.get(&url)).await?;
    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("GET /conflicts returned HTTP {status}");
    }
    let mut items: Vec<disk_client::ConflictListItem> =
        resp.json().await.context("decode /conflicts JSON")?;
    if let Some(vault) = vault_filter {
        items.retain(|item| item.vault_id == vault);
    }
    if items.is_empty() {
        println!("no unresolved conflicts");
        return Ok(());
    }
    println!("{:<6}  {:<12}  {:<40}  type", "id", "vault", "path");
    println!("{}", "-".repeat(80));
    for item in &items {
        println!(
            "{:<6}  {:<12}  {:<40}  {}",
            item.id, item.vault_id, item.path, item.conflict_type
        );
        if let Some(fork) = &item.fork_path {
            println!("       fork: {fork}");
        }
    }
    Ok(())
}

/// `disk conflicts resolve` — POST share-qualified `/conflicts/{vault}/{path}` or loop for `--all`.
pub async fn run_conflicts_resolve(
    addr: Option<SocketAddr>,
    vault: Option<String>,
    path: Option<String>,
    all: bool,
    action: &str,
) -> Result<()> {
    let addr = addr.unwrap_or_else(default_addr);
    let client = reqwest::Client::new();

    if all {
        // Fetch all unresolved conflicts then resolve each with its vault_id.
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
            resolve_one(
                addr,
                Some(item.vault_id.as_str()),
                &item.path,
                action,
                &client,
            )
            .await?;
        }
        println!(
            "resolved {} conflict(s) with action '{action}'",
            items.len()
        );
    } else if let Some(p) = path {
        resolve_one(addr, vault.as_deref(), &p, action, &client).await?;
        let vault_hint = vault
            .as_deref()
            .map(|v| format!(" (vault '{v}')"))
            .unwrap_or_default();
        println!("resolved conflict at '{p}'{vault_hint} with action '{action}'");
    } else {
        anyhow::bail!("either --path <path> or --all is required");
    }
    Ok(())
}

/// `disk conflicts show --path <path> [--vault <name>] [--addr <ip:port>]` — side-by-side diff.
pub async fn run_conflicts_show(
    addr: Option<SocketAddr>,
    vault: Option<&str>,
    path: &str,
) -> Result<()> {
    let addr = addr.unwrap_or_else(default_addr);
    let api_path = conflict_api_path(vault, path, "/diff");
    let url = format!("http://{addr}{api_path}");
    let client = reqwest::Client::new();
    let resp = send_with_retry(addr, || client.get(&url)).await?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("GET /conflicts/{path}/diff returned HTTP {status}: {text}");
    }
    let body: serde_json::Value = resp.json().await.context("decode /conflicts diff JSON")?;

    // Extract local and fork content from the JSON response.
    let local_content = body
        .get("local_content")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let fork_content = body
        .get("fork_content")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let fork_path = body
        .get("fork_path")
        .and_then(|v| v.as_str())
        .unwrap_or("<unknown>");
    let local_error = body.get("local_error").and_then(|v| v.as_str());
    let fork_error = body.get("fork_error").and_then(|v| v.as_str());

    println!("conflict: {path}");
    println!("fork:     {fork_path}");
    println!("{}", "─".repeat(80));

    if let Some(e) = local_error {
        println!("LOCAL ERROR: {e}");
    } else if let Some(e) = fork_error {
        println!("FORK ERROR:  {e}");
    } else {
        // Render a side-by-side diff using prettydiff.
        let local_lines: Vec<&str> = local_content.lines().collect();
        let fork_lines: Vec<&str> = fork_content.lines().collect();
        let diff = prettydiff::diff_lines(local_content, fork_content);
        println!(
            "─── local ({} lines) vs fork ({} lines) ───",
            local_lines.len(),
            fork_lines.len()
        );
        println!("{diff}");
    }

    Ok(())
}

/// POST `/conflicts/{vault}/{path}` (or legacy `/conflicts/{path}`) with the given action.
async fn resolve_one(
    addr: SocketAddr,
    vault_id: Option<&str>,
    path: &str,
    action: &str,
    client: &reqwest::Client,
) -> Result<()> {
    let api_path = conflict_api_path(vault_id, path, "");
    let url = format!("http://{addr}{api_path}");
    let body = serde_json::json!({ "action": action });
    let resp = send_with_retry(addr, || client.post(&url).json(&body)).await?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        let vault_hint = vault_id
            .map(|v| format!(" vault='{v}'"))
            .unwrap_or_default();
        anyhow::bail!("POST {api_path} ({path}{vault_hint}) returned HTTP {status}: {text}");
    }
    Ok(())
}

/// Build the REST path for conflict resolve or diff endpoints.
///
/// When `vault_id` is present the share-qualified route is used so file ops
/// resolve against the correct share root in multi-share daemons.
pub fn conflict_api_path(vault_id: Option<&str>, path: &str, suffix: &str) -> String {
    let encoded_path = percent_encode(path);
    match vault_id {
        Some(vault) => {
            let encoded_vault = percent_encode(vault);
            format!("/conflicts/{encoded_vault}/{encoded_path}{suffix}")
        }
        None => format!("/conflicts/{encoded_path}{suffix}"),
    }
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

    #[test]
    fn conflict_api_path_share_qualified() {
        assert_eq!(
            conflict_api_path(Some("docs"), "notes/todo.md", ""),
            "/conflicts/docs/notes%2Ftodo.md"
        );
        assert_eq!(
            conflict_api_path(Some("wiki"), "a.md", "/diff"),
            "/conflicts/wiki/a.md/diff"
        );
    }

    #[test]
    fn conflict_api_path_legacy_unqualified() {
        assert_eq!(
            conflict_api_path(None, "notes/todo.md", ""),
            "/conflicts/notes%2Ftodo.md"
        );
    }

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
    #[cfg(not(windows))]
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
            started.elapsed() < budget * if cfg!(windows) { 10 } else { 4 },
            "retry must be bounded (gave up within a small multiple of the budget)"
        );
    }
}
