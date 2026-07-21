//! Path filter that decides which scanned entries enter the metadata index.
//!
//! Combines three layers:
//! 1. A non-overridable hardcoded deny list (e.g. `.git`, `.disk-archive`).
//! 2. An optional extension whitelist.
//! 3. A user-provided list of glob patterns (gitignore-style semantics).
//!
//! The hardcoded deny list is intentionally not exposed in [`FilterRules`] —
//! callers may extend the deny list, but they cannot remove core entries.

use std::path::{Component, Path};

use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};

use crate::error::FilterError;

/// Folder / file segments that are *always* excluded.
///
/// `.dreamer` — Agent Dreamer runtime state (DISK-0011 / ADR-0001 workflow exclusion).
const HARDCODED_DENY_SEGMENTS: &[&str] = &[".git", ".disk-archive", ".dreamer"];

/// User-tunable filter rules.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FilterRules {
    /// If non-empty, only files whose extension (lowercased, no dot) is in
    /// the set will be scanned.
    pub extensions_whitelist: Vec<String>,
    /// Additional segments to deny (in addition to the hardcoded list).
    pub deny_segments: Vec<String>,
    /// gitignore-style glob patterns. Matched against the relative path.
    pub ignore_globs: Vec<String>,
}

/// Compiled filter ready for fast lookup. Build with [`Filter::from_config`].
#[derive(Debug, Clone)]
pub struct Filter {
    extensions_whitelist: Vec<String>,
    deny_segments: Vec<String>,
    ignore: GlobSet,
}

impl Filter {
    /// Compile a [`FilterRules`] into an executable [`Filter`].
    pub fn from_config(cfg: &FilterRules) -> Result<Self, FilterError> {
        let mut builder = GlobSetBuilder::new();
        for raw in &cfg.ignore_globs {
            let glob = Glob::new(raw).map_err(|e| FilterError::InvalidGlob {
                pattern: raw.clone(),
                reason: e.to_string(),
            })?;
            builder.add(glob);
        }
        let ignore = builder.build().map_err(|e| FilterError::InvalidGlob {
            pattern: "<aggregate>".into(),
            reason: e.to_string(),
        })?;

        let extensions_whitelist = cfg
            .extensions_whitelist
            .iter()
            .map(|s| s.trim_start_matches('.').to_ascii_lowercase())
            .collect();

        Ok(Self {
            extensions_whitelist,
            deny_segments: cfg.deny_segments.clone(),
            ignore,
        })
    }

    /// `true` when `rel_path` must be skipped by the scanner.
    pub fn is_excluded(&self, rel_path: &Path) -> bool {
        for component in rel_path.components() {
            if let Component::Normal(segment) = component {
                let segment_str = segment.to_string_lossy();
                if HARDCODED_DENY_SEGMENTS
                    .iter()
                    .any(|s| segment_str.eq_ignore_ascii_case(s))
                {
                    return true;
                }
                if self
                    .deny_segments
                    .iter()
                    .any(|s| segment_str.eq_ignore_ascii_case(s))
                {
                    return true;
                }
            }
        }

        if !self.extensions_whitelist.is_empty() {
            let ext = rel_path
                .extension()
                .and_then(|e| e.to_str())
                .map(|s| s.to_ascii_lowercase());
            match ext {
                Some(e) if self.extensions_whitelist.contains(&e) => {}
                _ => return true,
            }
        }

        if self.ignore.is_match(rel_path) {
            return true;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules_with_whitelist(exts: &[&str]) -> FilterRules {
        FilterRules {
            extensions_whitelist: exts.iter().map(|s| (*s).to_string()).collect(),
            deny_segments: vec![],
            ignore_globs: vec![],
        }
    }

    #[test]
    fn hardcoded_deny_excludes_dot_dreamer() {
        let f = Filter::from_config(&FilterRules::default()).unwrap();
        assert!(f.is_excluded(Path::new("wiki/.dreamer/state.json")));
        assert!(f.is_excluded(Path::new(".dreamer/cache/images/x.png")));
    }

    #[test]
    fn hardcoded_deny_excludes_dot_git() {
        let f = Filter::from_config(&FilterRules::default()).unwrap();
        assert!(f.is_excluded(Path::new("repo/.git/HEAD")));
    }

    #[test]
    fn hardcoded_deny_cannot_be_overridden_by_extension_whitelist() {
        let cfg = rules_with_whitelist(&["md", "HEAD"]);
        let f = Filter::from_config(&cfg).unwrap();
        // .git appears in path, deny wins regardless of whitelist match.
        assert!(f.is_excluded(Path::new(".git/HEAD")));
    }

    #[test]
    fn extension_whitelist_excludes_other_extensions() {
        let cfg = rules_with_whitelist(&["md"]);
        let f = Filter::from_config(&cfg).unwrap();
        assert!(f.is_excluded(Path::new("notes/x.txt")));
        assert!(!f.is_excluded(Path::new("notes/x.md")));
    }

    #[test]
    fn empty_whitelist_allows_all_extensions() {
        let f = Filter::from_config(&FilterRules::default()).unwrap();
        assert!(!f.is_excluded(Path::new("a/b.txt")));
        assert!(!f.is_excluded(Path::new("a/b.md")));
    }

    #[test]
    fn ignore_glob_excludes_match() {
        let cfg = FilterRules {
            ignore_globs: vec!["**/secret/**".into()],
            ..FilterRules::default()
        };
        let f = Filter::from_config(&cfg).unwrap();
        assert!(f.is_excluded(Path::new("a/secret/x.md")));
        assert!(!f.is_excluded(Path::new("a/notes/x.md")));
    }

    #[test]
    fn invalid_glob_returns_error() {
        let cfg = FilterRules {
            ignore_globs: vec!["[invalid".into()],
            ..FilterRules::default()
        };
        let err = Filter::from_config(&cfg).unwrap_err();
        assert!(matches!(err, FilterError::InvalidGlob { .. }));
    }

    #[test]
    fn extension_whitelist_is_case_insensitive() {
        let cfg = rules_with_whitelist(&["md"]);
        let f = Filter::from_config(&cfg).unwrap();
        assert!(!f.is_excluded(Path::new("a/b.MD")));
    }

    #[test]
    fn user_deny_segment_excludes_match() {
        let cfg = FilterRules {
            deny_segments: vec!["node_modules".into()],
            ..FilterRules::default()
        };
        let f = Filter::from_config(&cfg).unwrap();
        assert!(f.is_excluded(Path::new("project/node_modules/x.js")));
    }
}
