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

/// GET `url` with bounded connect-retry.
///
/// Retries only on connection errors (`e.is_connect()` — ECONNREFUSED,
/// connection-reset, etc.).  Any other error kind (DNS, TLS, decode) is
/// propagated immediately without retrying; successful HTTP responses
/// (including 4xx/5xx) are returned as-is.
async fn get_with_retry(
    client: &reqwest::Client,
    url: &str,
    addr: SocketAddr,
) -> Result<reqwest::Response> {
    let mut last_err: Option<reqwest::Error> = None;
    for _ in 0..CONNECT_MAX_ATTEMPTS {
        match client.get(url).send().await {
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

/// POST `url` (no body) with bounded connect-retry.  Mirrors [`get_with_retry`].
async fn post_with_retry(
    client: &reqwest::Client,
    url: &str,
    addr: SocketAddr,
) -> Result<reqwest::Response> {
    let mut last_err: Option<reqwest::Error> = None;
    for _ in 0..CONNECT_MAX_ATTEMPTS {
        match client.post(url).send().await {
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
    let resp = get_with_retry(&client, &url, addr).await?;
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
    let resp = post_with_retry(&client, &url, addr).await?;
    let status = resp.status();
    let body: AcceptedResponse = resp.json().await.context("decode /config/reload JSON")?;
    if body.queued {
        println!("config reload queued");
        Ok(())
    } else {
        anyhow::bail!("daemon did not queue the reload (HTTP {status}, queued=false)")
    }
}
