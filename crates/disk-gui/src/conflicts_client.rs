//! Async HTTP client for the daemon's `/conflicts` REST surface.
//!
//! Mirrors [`crate::status_client`]: the async runtime (tokio) and HTTP
//! client (reqwest) are both available on Linux for testing; the macOS GUI
//! calls these functions from within the eframe polling loop.
//!
//! ## Error contract
//!
//! Every path that could cause a panic is converted to `Err`. The caller
//! (the GUI) renders "conflicts unavailable" on any `Err` variant — it must
//! not crash on a network failure, a stale daemon, or a malformed response.

use anyhow::{Context, Result};
use disk_client::{ConflictListItem, ResolveRequest};

/// Fetch the list of unresolved conflicts from `GET http://{host}:{port}/conflicts`.
pub async fn fetch_conflicts(host: &str, port: u16) -> Result<Vec<ConflictListItem>> {
    let url = format!("http://{host}:{port}/conflicts");

    let raw = reqwest::get(&url)
        .await
        .with_context(|| format!("GET {url}"))?
        .text()
        .await
        .context("read response body")?;

    parse_conflicts_json(&raw)
}

/// Resolve a single conflict via `POST http://{host}:{port}/conflicts/{path}`.
///
/// `path` is the vault-relative conflict path exactly as returned by
/// [`fetch_conflicts`] (unencoded); it is percent-encoded internally before
/// being placed in the URL.
pub async fn resolve_conflict(host: &str, port: u16, path: &str, action: &str) -> Result<()> {
    let encoded = percent_encode_path(path);
    let url = format!("http://{host}:{port}/conflicts/{encoded}");
    let body = ResolveRequest {
        action: action.to_string(),
    };

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;

    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("POST {url} returned HTTP {status}: {text}");
    }
    Ok(())
}

/// Deserialise a raw JSON string from the daemon's `GET /conflicts` endpoint
/// into a list of [`ConflictListItem`].
///
/// Returns `Err` for any malformed JSON or wrong field types.
pub fn parse_conflicts_json(raw: &str) -> Result<Vec<ConflictListItem>> {
    serde_json::from_str(raw).context("failed to parse /conflicts response")
}

/// Percent-encode a vault-relative path for use in a URL segment.
///
/// Only encodes characters that would be misinterpreted in URL paths
/// (primarily `/` → `%2F`). Mirrors `disk-cli`'s `percent_encode`.
pub fn percent_encode_path(s: &str) -> String {
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

// ---------------------------------------------------------------------------
// Unit tests — exercise parse/encode behaviour; network I/O is integration-only
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_list() {
        let items = parse_conflicts_json("[]").expect("should parse");
        assert!(items.is_empty());
    }

    #[test]
    fn parse_single_conflict() {
        let json = r#"[{
            "id": 1,
            "path": "notes/todo.md",
            "conflict_type": "Concurrent",
            "fork_path": "notes/todo.md.sync-conflict-abc",
            "created_at": 1234
        }]"#;
        let items = parse_conflicts_json(json).expect("should parse");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].path, "notes/todo.md");
        assert_eq!(items[0].conflict_type, "Concurrent");
        assert_eq!(
            items[0].fork_path.as_deref(),
            Some("notes/todo.md.sync-conflict-abc")
        );
    }

    #[test]
    fn parse_conflict_without_fork_path() {
        let json = r#"[{
            "id": 2,
            "path": "a.md",
            "conflict_type": "DeleteRemoteModifyLocal",
            "fork_path": null,
            "created_at": 0
        }]"#;
        let items = parse_conflicts_json(json).expect("should parse");
        assert_eq!(items[0].fork_path, None);
    }

    #[test]
    fn parse_malformed_json_returns_err() {
        assert!(parse_conflicts_json("{not valid json}").is_err());
    }

    #[test]
    fn parse_missing_required_field_returns_err() {
        // Missing "path" field.
        let raw =
            r#"[{"id": 1, "conflict_type": "Concurrent", "fork_path": null, "created_at": 0}]"#;
        assert!(parse_conflicts_json(raw).is_err());
    }

    #[test]
    fn percent_encode_path_escapes_slash() {
        assert_eq!(percent_encode_path("notes/todo.md"), "notes%2Ftodo.md");
    }

    #[test]
    fn percent_encode_path_nested_dirs() {
        assert_eq!(percent_encode_path("a/b/c.md"), "a%2Fb%2Fc.md");
    }

    #[test]
    fn percent_encode_path_no_slash_unchanged() {
        assert_eq!(percent_encode_path("file.txt"), "file.txt");
    }
}
