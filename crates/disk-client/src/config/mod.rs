//! `disk.toml` config — schema + validator + loader (DISK-0006 R3).
//!
//! PRD-DISK-0001 §4.11.3 Per-Host Directional Policy.
//!
//! Loader contract: [`DiskConfig::load`] reads the file at `path`, parses
//! the TOML, runs [`validate`], and returns a fully-checked `DiskConfig`.
//! Any failure surfaces as [`ConfigError`] without mutating state — callers
//! that hold a previous valid config keep using it (the eventual hot-reload
//! loop in R9 relies on this property).

pub mod reload;
pub mod schema;
pub mod validate;

use std::path::Path;
use std::str::FromStr;

pub use reload::{spawn_config_watcher, ConfigSnapshot, ConfigWatcher, ReloadStatus};
pub use schema::{
    Direction, DiskConfig, FilterMode, FilterSection, NodeDefault, NodeSection, PublisherSection,
    ServerSection, ShareSection,
};
pub use validate::{validate, ConfigError};

impl DiskConfig {
    /// Load + parse + validate a `disk.toml` file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path)?;
        raw.parse()
    }
}

impl FromStr for DiskConfig {
    type Err = ConfigError;

    /// Parse + validate from a TOML string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let cfg: DiskConfig = toml::from_str(s)?;
        validate(&cfg)?;
        Ok(cfg)
    }
}

impl DiskConfig {
    /// Resolve the effective direction for a share by name, applying
    /// `node.default.intended_direction` fallback.
    pub fn share_direction(&self, name: &str) -> Option<Direction> {
        self.shares
            .iter()
            .find(|s| s.name == name)
            .and_then(|s| s.effective_direction(self.node.default.intended_direction))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
[node]
id = "dev-server"
[node.default]
intended_direction = "receive_only"

[server]
address = "disk.arcanada.ai:9443"
client_cert = "/etc/disk-arcana/client.crt"
client_key  = "/etc/disk-arcana/client.key"
"#;

    const FULL: &str = r#"
[node]
id = "arcana-ai"
display_name = "Arcana AI server"
[node.default]
intended_direction = "bidirectional"

[server]
address = "disk.arcanada.ai:9443"
tls = "auto"
client_cert = "/etc/disk-arcana/client.crt"
client_key  = "/etc/disk-arcana/client.key"
server_ca   = "/etc/disk-arcana/server-ca.crt"

[[share]]
name = "hermes-artefacts"
path = "/home/hermes/.hermes/cache"
intended_direction = "publisher"
[share.filter]
mode = "whitelist"
extensions = ["png", "jpg", "pdf", "md"]
include = ["images/**", "documents/**"]
exclude = [".env", "logs/**"]
[share.publisher]
sign_key_ref = "vault:transit/disk-arcana/arcana-ai-publisher"
quarantine_on_failure = true

[[share]]
name = "wiki"
path = "/home/operator/wiki"
[share.filter]
mode = "whitelist"
extensions = ["md", "txt", "json"]
"#;

    #[test]
    fn parses_minimal() {
        let cfg = DiskConfig::from_str(MINIMAL).unwrap();
        assert_eq!(cfg.node.id, "dev-server");
        assert_eq!(
            cfg.node.default.intended_direction,
            Some(Direction::ReceiveOnly)
        );
        assert_eq!(cfg.server.address, "disk.arcanada.ai:9443");
        assert_eq!(cfg.server.tls, "auto"); // default applied
        assert!(cfg.shares.is_empty());
    }

    #[test]
    fn parses_full() {
        let cfg = DiskConfig::from_str(FULL).unwrap();
        assert_eq!(cfg.node.id, "arcana-ai");
        assert_eq!(cfg.node.display_name.as_deref(), Some("Arcana AI server"));
        assert_eq!(cfg.shares.len(), 2);

        let hermes = &cfg.shares[0];
        assert_eq!(hermes.name, "hermes-artefacts");
        assert_eq!(hermes.intended_direction, Some(Direction::Publisher));
        assert!(hermes.publisher.is_some());

        let wiki = &cfg.shares[1];
        assert_eq!(wiki.name, "wiki");
        // No explicit direction → inherits node default (bidirectional).
        assert_eq!(wiki.intended_direction, None);
        assert_eq!(
            wiki.effective_direction(cfg.node.default.intended_direction),
            Some(Direction::Bidirectional)
        );
    }

    #[test]
    fn share_direction_resolves_via_node_default() {
        let cfg = DiskConfig::from_str(FULL).unwrap();
        assert_eq!(cfg.share_direction("wiki"), Some(Direction::Bidirectional));
        assert_eq!(
            cfg.share_direction("hermes-artefacts"),
            Some(Direction::Publisher)
        );
        assert_eq!(cfg.share_direction("nonexistent"), None);
    }

    #[test]
    fn rejects_missing_node_section() {
        let bad = r#"
[server]
address = "host:9443"
client_cert = "/a"
client_key = "/b"
"#;
        let err = DiskConfig::from_str(bad).unwrap_err();
        assert!(matches!(err, ConfigError::Toml(_)));
    }

    #[test]
    fn rejects_unknown_direction_value() {
        let bad = r#"
[node]
id = "x"
[node.default]
intended_direction = "sideways"
[server]
address = "host:9443"
client_cert = "/a"
client_key = "/b"
"#;
        let err = DiskConfig::from_str(bad).unwrap_err();
        assert!(matches!(err, ConfigError::Toml(_)));
    }

    #[test]
    fn rejects_invalid_node_id() {
        let bad = r#"
[node]
id = "Bad-Id"
[server]
address = "host:9443"
client_cert = "/a"
client_key = "/b"
"#;
        let err = DiskConfig::from_str(bad).unwrap_err();
        match err {
            ConfigError::Validation(msg) => assert!(msg.contains("lowercase")),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn rejects_relative_share_path() {
        let bad = r#"
[node]
id = "x"
[node.default]
intended_direction = "bidirectional"
[server]
address = "host:9443"
client_cert = "/a"
client_key = "/b"
[[share]]
name = "rel"
path = "relative/path"
"#;
        let err = DiskConfig::from_str(bad).unwrap_err();
        match err {
            ConfigError::Validation(msg) => assert!(msg.contains("absolute")),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn rejects_publisher_without_section() {
        let bad = r#"
[node]
id = "x"
[server]
address = "host:9443"
client_cert = "/a"
client_key = "/b"
[[share]]
name = "no-pub"
path = "/data"
intended_direction = "publisher"
"#;
        let err = DiskConfig::from_str(bad).unwrap_err();
        match err {
            ConfigError::Validation(msg) => assert!(msg.contains("publisher")),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn rejects_publisher_section_without_direction_publisher() {
        let bad = r#"
[node]
id = "x"
[server]
address = "host:9443"
client_cert = "/a"
client_key = "/b"
[[share]]
name = "stray"
path = "/data"
intended_direction = "bidirectional"
[share.publisher]
sign_key_ref = "vault:foo"
"#;
        let err = DiskConfig::from_str(bad).unwrap_err();
        match err {
            ConfigError::Validation(msg) => {
                assert!(msg.contains("publisher") && msg.contains("not publisher"))
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn rejects_whitelist_with_no_patterns() {
        let bad = r#"
[node]
id = "x"
[node.default]
intended_direction = "bidirectional"
[server]
address = "host:9443"
client_cert = "/a"
client_key = "/b"
[[share]]
name = "empty-filter"
path = "/data"
[share.filter]
mode = "whitelist"
"#;
        let err = DiskConfig::from_str(bad).unwrap_err();
        match err {
            ConfigError::Validation(msg) => assert!(msg.contains("whitelist")),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn rejects_duplicate_share_names() {
        let bad = r#"
[node]
id = "x"
[node.default]
intended_direction = "bidirectional"
[server]
address = "host:9443"
client_cert = "/a"
client_key = "/b"
[[share]]
name = "dup"
path = "/a"
[[share]]
name = "dup"
path = "/b"
"#;
        let err = DiskConfig::from_str(bad).unwrap_err();
        match err {
            ConfigError::Validation(msg) => assert!(msg.contains("dup") && msg.contains("twice")),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn rejects_share_without_any_direction() {
        let bad = r#"
[node]
id = "x"
[server]
address = "host:9443"
client_cert = "/a"
client_key = "/b"
[[share]]
name = "orphan"
path = "/data"
"#;
        let err = DiskConfig::from_str(bad).unwrap_err();
        match err {
            ConfigError::Validation(msg) => assert!(msg.contains("intended_direction")),
            other => panic!("expected Validation, got {other:?}"),
        }
    }
}
