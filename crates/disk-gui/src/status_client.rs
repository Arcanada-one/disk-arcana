//! Async HTTP client for the daemon's `GET /status` endpoint.
//!
//! This module is cross-platform: the async runtime (tokio) and the HTTP
//! client (reqwest) are both available on Linux for testing; the macOS GUI
//! calls this function from within the eframe polling loop.
//!
//! ## Error contract
//!
//! Every path that could cause a panic is converted to `Err`. The caller
//! (the GUI) renders "daemon not running" on any `Err` variant — it must
//! not crash on a network failure, a stale daemon, or a malformed response.

use anyhow::{Context, Result};
use disk_client::StatusResponse;
use tracing::debug;

/// Fetch and deserialise the daemon status from `http://{host}:{port}/status`.
///
/// Returns `Err` on any I/O error, connection refused, timeout, or JSON
/// parse failure.
pub async fn fetch_status(host: &str, port: u16) -> Result<StatusResponse> {
    let url = format!("http://{host}:{port}/status");
    debug!(url = %url, "fetching daemon status");

    let raw = reqwest::get(&url)
        .await
        .with_context(|| format!("GET {url}"))?
        .text()
        .await
        .context("read response body")?;

    crate::parse_status_json(&raw)
}

// ---------------------------------------------------------------------------
// Unit tests — exercise parse behaviour; network I/O is integration-only
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use disk_client::StatusResponse;

    /// The async runtime is used to call `fetch_status`; we test parse
    /// behaviour inline (no real network) by calling `parse_status_json`
    /// directly — consistent with the test plan in the plan doc.
    #[test]
    fn parse_valid_response_via_lib() {
        let json = r#"{
            "node": "my-node",
            "daemon_uptime_s": 120,
            "config_version": "abc",
            "shares": []
        }"#;
        let result: Result<StatusResponse> = crate::parse_status_json(json);
        let resp = result.expect("should parse valid JSON");
        assert_eq!(resp.node, "my-node");
        assert_eq!(resp.daemon_uptime_s, 120);
    }

    #[test]
    fn parse_error_on_bad_json_via_lib() {
        let result = crate::parse_status_json("{bad}");
        assert!(result.is_err());
    }
}
