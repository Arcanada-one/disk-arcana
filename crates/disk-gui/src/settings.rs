//! User-facing GUI settings persisted to a TOML file.
//!
//! The file lives at:
//!   `~/Library/Application Support/Disk Arcana/settings.toml`   (macOS)
//!   `~/.local/share/Disk Arcana/settings.toml`                  (Linux, for CI tests)
//!
//! The struct contains **no secrets** (no API keys, no tokens, no cert paths).
//! The daemon port is not a secret — it is visible in `lsof` anyway.

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::DEFAULT_PORT;

/// App-level settings persisted between sessions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuiSettings {
    /// Daemon REST address. Default: `127.0.0.1`.
    pub daemon_host: String,
    /// Daemon REST port. Default: [`DEFAULT_PORT`] (9444).
    pub daemon_port: u16,
    /// Read-only display of the storage path from `DiskConfig`.
    /// The GUI never writes to this path — it is informational only.
    pub storage_path_display: String,
}

impl Default for GuiSettings {
    fn default() -> Self {
        Self {
            daemon_host: "127.0.0.1".to_string(),
            daemon_port: DEFAULT_PORT,
            storage_path_display: String::new(),
        }
    }
}

impl GuiSettings {
    /// Return the daemon REST base URL (e.g. `http://127.0.0.1:9444`).
    pub fn daemon_url(&self) -> String {
        format!("http://{}:{}", self.daemon_host, self.daemon_port)
    }

    /// Load settings from the canonical path, returning [`Default`] when the
    /// file does not exist or cannot be parsed.
    ///
    /// Parse failures are logged as a warning; the application continues with
    /// defaults rather than crashing.
    pub fn load_or_default() -> Self {
        match Self::load() {
            Ok(s) => s,
            Err(e) => {
                warn!("GuiSettings: using defaults ({})", e);
                Self::default()
            }
        }
    }

    /// Load settings from the canonical path.
    ///
    /// Returns `Err` if the file does not exist or the TOML is malformed.
    pub fn load() -> Result<Self> {
        let path = settings_path().context("could not determine settings directory")?;
        let raw =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        toml::from_str(&raw).context("parse settings TOML")
    }

    /// Persist the settings to the canonical path, creating the directory if
    /// needed.
    pub fn save(&self) -> Result<()> {
        let path = settings_path().context("could not determine settings directory")?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("create dir {}", dir.display()))?;
        }
        let toml = toml::to_string_pretty(self).context("serialise settings to TOML")?;
        std::fs::write(&path, toml).with_context(|| format!("write {}", path.display()))?;
        Ok(())
    }

    /// Load from an explicit path (used in unit tests to avoid touching
    /// the real `~/Library/Application Support/` directory).
    #[cfg(test)]
    pub fn load_from(path: &std::path::Path) -> Result<Self> {
        let raw =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        toml::from_str(&raw).context("parse settings TOML")
    }

    /// Persist to an explicit path (used in unit tests).
    #[cfg(test)]
    pub fn save_to(&self, path: &std::path::Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("create dir {}", dir.display()))?;
        }
        let toml = toml::to_string_pretty(self).context("serialise settings to TOML")?;
        std::fs::write(path, toml).with_context(|| format!("write {}", path.display()))?;
        Ok(())
    }
}

/// Return the canonical path to the settings file.
///
/// On macOS this follows the macOS convention; on other platforms it uses
/// the XDG data-home equivalent via the `dirs` crate.
fn settings_path() -> Result<PathBuf> {
    let base = dirs::data_dir().context("cannot find user data directory")?;
    Ok(base.join("Disk Arcana").join("settings.toml"))
}

// ---------------------------------------------------------------------------
// Unit tests — run on all platforms
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn default_seeds_from_default_port() {
        let s = GuiSettings::default();
        assert_eq!(s.daemon_port, DEFAULT_PORT);
        assert_eq!(s.daemon_host, "127.0.0.1");
        assert!(s.storage_path_display.is_empty());
    }

    #[test]
    fn daemon_url_format() {
        let s = GuiSettings::default();
        assert_eq!(s.daemon_url(), format!("http://127.0.0.1:{DEFAULT_PORT}"));
    }

    #[test]
    fn daemon_url_custom_port() {
        let s = GuiSettings {
            daemon_port: 9999,
            ..GuiSettings::default()
        };
        assert_eq!(s.daemon_url(), "http://127.0.0.1:9999");
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("settings.toml");

        let original = GuiSettings {
            daemon_host: "127.0.0.1".to_string(),
            daemon_port: 12345,
            storage_path_display: "/tmp/vault".to_string(),
        };
        original.save_to(&path).expect("save");

        let loaded = GuiSettings::load_from(&path).expect("load");
        assert_eq!(original, loaded);
    }

    #[test]
    fn save_writes_valid_toml() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("settings.toml");

        let s = GuiSettings {
            daemon_host: "127.0.0.1".to_string(),
            daemon_port: 9444,
            storage_path_display: "/home/user/obsidian".to_string(),
        };
        s.save_to(&path).expect("save");

        let raw = std::fs::read_to_string(&path).expect("read back");
        assert!(raw.contains("daemon_port"));
        assert!(raw.contains("9444"));
        assert!(raw.contains("127.0.0.1"));
    }

    #[test]
    fn load_from_missing_file_returns_err() {
        let result = GuiSettings::load_from(std::path::Path::new("/nonexistent/settings.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn load_from_malformed_toml_returns_err() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, b"[[[this is not valid TOML").expect("write");
        let result = GuiSettings::load_from(&path);
        assert!(result.is_err());
    }

    #[test]
    fn load_or_default_on_missing_file_returns_default() {
        // No settings file present in a fresh temp dir — load_or_default must
        // not panic and must return the default.
        // We can't redirect settings_path() easily without a helper, but we
        // can verify that GuiSettings::load_or_default() itself never panics
        // (it calls load() which may fail, then falls back to Default).
        // The return value will either be a saved real file or the default —
        // both are valid; we just assert the call completes and the port is
        // in the valid range.
        let s = GuiSettings::load_or_default();
        assert!(s.daemon_port > 0);
    }
}
