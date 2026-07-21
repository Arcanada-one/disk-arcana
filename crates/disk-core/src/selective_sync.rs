//! Per-device selective sync path matching (DISK-0023).

/// Normalize a user-supplied folder prefix for storage and matching.
///
/// Strips leading/trailing slashes, rejects `..` segments, and lowercases nothing
/// (paths are case-sensitive on Linux servers).
pub fn normalize_include_prefix(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim().replace('\\', "/");
    if trimmed.is_empty() {
        return Err("include prefix must not be empty".into());
    }
    if trimmed.contains("..") {
        return Err("include prefix must not contain '..'".into());
    }
    let normalized = trimmed.trim_matches('/').to_string();
    if normalized.is_empty() {
        return Err("include prefix must not be empty".into());
    }
    Ok(normalized)
}

/// `true` when `rel_path` should sync for the given include list.
///
/// An empty list means sync the full vault (no selective restriction).
pub fn path_matches_includes(rel_path: &str, includes: &[String]) -> bool {
    if includes.is_empty() {
        return true;
    }
    let path = rel_path.trim().replace('\\', "/");
    let path = path.trim_matches('/');
    if path.is_empty() {
        return false;
    }
    includes.iter().any(|prefix| {
        path == prefix.as_str() || path.starts_with(&format!("{}/", prefix)) || prefix.is_empty()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_slashes() {
        assert_eq!(normalize_include_prefix("/docs/").unwrap(), "docs");
        assert_eq!(
            normalize_include_prefix("photos/2024").unwrap(),
            "photos/2024"
        );
    }

    #[test]
    fn normalize_rejects_traversal() {
        assert!(normalize_include_prefix("../secret").is_err());
    }

    #[test]
    fn empty_includes_matches_all() {
        assert!(path_matches_includes("a/b.txt", &[]));
    }

    #[test]
    fn prefix_match_includes_descendants() {
        let includes = vec!["docs".into()];
        assert!(path_matches_includes("docs/readme.md", &includes));
        assert!(path_matches_includes("docs", &includes));
        assert!(!path_matches_includes("wiki/page.md", &includes));
    }
}
