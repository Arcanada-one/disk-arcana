//! disk-gui — cross-platform library layer.
//!
//! This module contains all pure, platform-independent logic that does not
//! require the windowing stack (eframe). The macOS-specific GUI code lives
//! in `gui.rs` and `main.rs`, both gated with `#[cfg(target_os = "macos")]`.
//!
//! ## Cross-platform surface (unit-tested on all platforms)
//!
//! - [`GuiSettings`] — user-facing settings persisted to
//!   `~/Library/Application Support/Disk Arcana/settings.toml`.
//! - [`parse_status_json`] — deserialise a raw `/status` JSON body into
//!   [`StatusResponse`], returning `Err` on any malformed input.
//! - [`format_status`] — format a `StatusResponse` into a [`StatusDisplay`]
//!   suitable for rendering in egui labels.
//! - [`fetch_status`] — async HTTP client wrapper used by both the GUI and
//!   tests (with a wiremock/local-server fixture in tests).

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

pub mod settings;
pub mod status_client;

pub use settings::GuiSettings;
pub use status_client::fetch_status;

use anyhow::{Context, Result};
use disk_client::{StatusResponse, StatusShare};

// Re-export for consumers of this crate.
pub use disk_client::DEFAULT_PORT;

// ---------------------------------------------------------------------------
// DTO formatting — cross-platform
// ---------------------------------------------------------------------------

/// Human-readable representation of a single share suitable for UI labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareDisplay {
    pub name: String,
    pub path: String,
    pub direction: String,
    pub state: String,
    pub last_success_at: Option<String>,
    pub last_error: Option<String>,
    pub pending_changes: u64,
}

/// Human-readable representation of the full daemon status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusDisplay {
    pub node: String,
    pub daemon_uptime: String,
    pub config_version: String,
    pub shares: Vec<ShareDisplay>,
}

/// Format an uptime value in seconds into a compact "Xd Xh Xm Xs" string.
///
/// Any component that is zero is omitted, except when the total is less than a
/// second (returns "0s").
pub fn format_uptime(secs: u64) -> String {
    if secs == 0 {
        return "0s".to_string();
    }
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let minutes = (secs % 3_600) / 60;
    let seconds = secs % 60;

    let mut parts = Vec::with_capacity(4);
    if days > 0 {
        parts.push(format!("{days}d"));
    }
    if hours > 0 {
        parts.push(format!("{hours}h"));
    }
    if minutes > 0 {
        parts.push(format!("{minutes}m"));
    }
    if seconds > 0 {
        parts.push(format!("{seconds}s"));
    }
    parts.join(" ")
}

/// Convert a [`StatusResponse`] into display-ready strings.
pub fn format_status(resp: &StatusResponse) -> StatusDisplay {
    let shares = resp.shares.iter().map(format_share).collect::<Vec<_>>();

    StatusDisplay {
        node: resp.node.clone(),
        daemon_uptime: format_uptime(resp.daemon_uptime_s),
        config_version: resp.config_version.clone(),
        shares,
    }
}

fn format_share(s: &StatusShare) -> ShareDisplay {
    ShareDisplay {
        name: s.name.clone(),
        path: s.path.clone(),
        direction: s.declared_direction.clone(),
        state: s.state.clone(),
        last_success_at: s.last_success_at.clone(),
        last_error: s.last_error.clone(),
        pending_changes: s.pending_local_changes,
    }
}

/// Deserialise a raw JSON string from the daemon's `GET /status` endpoint
/// into a [`StatusResponse`].
///
/// Returns `Err` for any malformed JSON, missing required fields, or wrong
/// field types. The GUI must call this function and handle `Err` by displaying
/// "daemon not running / parse error" — it must never panic on bad input.
pub fn parse_status_json(raw: &str) -> Result<StatusResponse> {
    serde_json::from_str(raw).context("failed to parse /status response")
}

// ---------------------------------------------------------------------------
// Unit tests — run on all platforms including Linux CI
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // format_uptime
    // -----------------------------------------------------------------------

    #[test]
    fn uptime_zero_seconds() {
        assert_eq!(format_uptime(0), "0s");
    }

    #[test]
    fn uptime_seconds_only() {
        assert_eq!(format_uptime(45), "45s");
    }

    #[test]
    fn uptime_minutes_and_seconds() {
        assert_eq!(format_uptime(3661), "1h 1m 1s");
    }

    #[test]
    fn uptime_days_hours_minutes_seconds() {
        let secs = 2 * 86_400 + 3 * 3_600 + 4 * 60 + 5;
        assert_eq!(format_uptime(secs), "2d 3h 4m 5s");
    }

    #[test]
    fn uptime_exactly_one_day() {
        assert_eq!(format_uptime(86_400), "1d");
    }

    #[test]
    fn uptime_skips_zero_components() {
        // 1 day + 1 second (no hours or minutes)
        assert_eq!(format_uptime(86_401), "1d 1s");
    }

    // -----------------------------------------------------------------------
    // parse_status_json
    // -----------------------------------------------------------------------

    fn valid_status_json() -> &'static str {
        r#"{
            "node": "test-node",
            "daemon_uptime_s": 3661,
            "config_version": "v1.0",
            "shares": [
                {
                    "name": "vault",
                    "path": "/Users/user/vault",
                    "declared_direction": "bidirectional",
                    "state": "idle",
                    "last_success_at": null,
                    "last_error": null,
                    "bytes_sent_session": 0,
                    "bytes_received_session": 0,
                    "pending_local_changes": 3
                }
            ]
        }"#
    }

    #[test]
    fn parse_valid_status_json_succeeds() {
        let resp = parse_status_json(valid_status_json()).expect("should parse");
        assert_eq!(resp.node, "test-node");
        assert_eq!(resp.daemon_uptime_s, 3661);
        assert_eq!(resp.config_version, "v1.0");
        assert_eq!(resp.shares.len(), 1);
        assert_eq!(resp.shares[0].name, "vault");
        assert_eq!(resp.shares[0].pending_local_changes, 3);
    }

    #[test]
    fn parse_malformed_json_returns_err() {
        let result = parse_status_json("{not valid json}");
        assert!(result.is_err(), "malformed JSON must return Err");
    }

    #[test]
    fn parse_missing_required_field_returns_err() {
        // Missing "node" field
        let raw = r#"{"daemon_uptime_s": 0, "config_version": "v1", "shares": []}"#;
        let result = parse_status_json(raw);
        assert!(result.is_err(), "missing 'node' must return Err");
    }

    #[test]
    fn parse_empty_string_returns_err() {
        assert!(parse_status_json("").is_err());
    }

    // -----------------------------------------------------------------------
    // format_status
    // -----------------------------------------------------------------------

    #[test]
    fn format_status_basic() {
        let resp = parse_status_json(valid_status_json()).expect("should parse");
        let display = format_status(&resp);
        assert_eq!(display.node, "test-node");
        assert_eq!(display.daemon_uptime, "1h 1m 1s");
        assert_eq!(display.config_version, "v1.0");
        assert_eq!(display.shares.len(), 1);
        assert_eq!(display.shares[0].pending_changes, 3);
        assert_eq!(display.shares[0].direction, "bidirectional");
    }

    #[test]
    fn format_status_empty_shares() {
        let resp = StatusResponse {
            node: "n".to_string(),
            daemon_uptime_s: 0,
            config_version: "v0".to_string(),
            shares: vec![],
        };
        let d = format_status(&resp);
        assert!(d.shares.is_empty());
        assert_eq!(d.daemon_uptime, "0s");
    }

    #[test]
    fn format_status_share_last_error_propagated() {
        let json = r#"{
            "node": "n",
            "daemon_uptime_s": 10,
            "config_version": "v1",
            "shares": [{
                "name": "s",
                "path": "/p",
                "declared_direction": "send",
                "state": "error",
                "last_success_at": null,
                "last_error": "connection refused",
                "bytes_sent_session": 0,
                "bytes_received_session": 0,
                "pending_local_changes": 0
            }]
        }"#;
        let resp = parse_status_json(json).expect("should parse");
        let d = format_status(&resp);
        assert_eq!(
            d.shares[0].last_error.as_deref(),
            Some("connection refused")
        );
    }
}
