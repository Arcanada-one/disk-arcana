//! Validation rules for `DiskConfig` — runs after TOML deserialisation.
//!
//! Validation is intentionally separate from schema deserialisation so
//! that operators can see all validation errors at once (collected via
//! `ConfigError::Multi`), rather than failing on the first issue.

use std::collections::HashSet;

use thiserror::Error;

use super::schema::{Direction, DiskConfig, FilterMode, ShareSection};

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("toml parse: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("validation: {0}")]
    Validation(String),
}

/// Validate every rule against the parsed config. Returns the first
/// failure (cheap-to-read errors over completeness).
pub fn validate(cfg: &DiskConfig) -> Result<(), ConfigError> {
    validate_node_id(&cfg.node.id)?;
    validate_server_address(&cfg.server.address)?;
    validate_share_names_unique(&cfg.shares)?;

    for share in &cfg.shares {
        validate_share(share, cfg.node.default.intended_direction)?;
    }
    Ok(())
}

/// `node.id` MUST match `^[a-z][a-z0-9-]{0,62}$` (DNS-label-style).
pub fn validate_node_id(id: &str) -> Result<(), ConfigError> {
    if id.is_empty() {
        return Err(err("node.id must not be empty"));
    }
    if id.len() > 63 {
        return Err(err(format!(
            "node.id is {} chars; max 63 allowed",
            id.len()
        )));
    }
    let mut chars = id.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_lowercase() {
        return Err(err(format!(
            "node.id must start with lowercase ASCII letter, got {first:?}"
        )));
    }
    if id.ends_with('-') {
        return Err(err("node.id must not end with a hyphen"));
    }
    for c in id.chars() {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
            return Err(err(format!(
                "node.id may contain [a-z0-9-] only, found {c:?}"
            )));
        }
    }
    Ok(())
}

/// `server.address` MUST contain a host and a port separated by `:`.
/// We do not require resolution — DNS lookup is a runtime concern.
pub fn validate_server_address(addr: &str) -> Result<(), ConfigError> {
    let Some((host, port)) = addr.rsplit_once(':') else {
        return Err(err(format!("server.address {addr:?} must be host:port")));
    };
    if host.is_empty() {
        return Err(err(format!("server.address {addr:?} has empty host")));
    }
    let parsed: Result<u16, _> = port.parse();
    if parsed.is_err() || parsed.unwrap_or(0) == 0 {
        return Err(err(format!(
            "server.address {addr:?} port {port:?} must be 1..=65535"
        )));
    }
    Ok(())
}

fn validate_share_names_unique(shares: &[ShareSection]) -> Result<(), ConfigError> {
    let mut seen = HashSet::new();
    for s in shares {
        if !seen.insert(s.name.as_str()) {
            return Err(err(format!("share.name {:?} declared twice", s.name)));
        }
    }
    Ok(())
}

fn validate_share(
    share: &ShareSection,
    node_default: Option<Direction>,
) -> Result<(), ConfigError> {
    if share.name.is_empty() {
        return Err(err("share.name must not be empty"));
    }
    if !share.path.is_absolute() {
        return Err(err(format!(
            "share[{}].path must be absolute, got {}",
            share.name,
            share.path.display()
        )));
    }
    let direction = share.effective_direction(node_default).ok_or_else(|| {
        err(format!(
            "share[{}].intended_direction missing and no node.default.intended_direction",
            share.name
        ))
    })?;

    if direction == Direction::Publisher && share.publisher.is_none() {
        return Err(err(format!(
            "share[{}] has direction=publisher but no [share.publisher] section",
            share.name
        )));
    }
    if direction != Direction::Publisher && share.publisher.is_some() {
        return Err(err(format!(
            "share[{}] has [share.publisher] but direction is not publisher",
            share.name
        )));
    }

    if let Some(f) = &share.filter {
        if matches!(f.mode, FilterMode::Whitelist)
            && f.extensions.is_empty()
            && f.include.is_empty()
        {
            return Err(err(format!(
                "share[{}].filter.mode=whitelist requires non-empty extensions or include",
                share.name
            )));
        }
    }

    if let Some(p) = &share.publisher {
        if p.sign_key_ref.is_empty() {
            return Err(err(format!(
                "share[{}].publisher.sign_key_ref must not be empty",
                share.name
            )));
        }
    }
    Ok(())
}

fn err(msg: impl Into<String>) -> ConfigError {
    ConfigError::Validation(msg.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_id_valid_simple() {
        assert!(validate_node_id("arcana-ai").is_ok());
        assert!(validate_node_id("a").is_ok());
        assert!(validate_node_id("node1").is_ok());
    }

    #[test]
    fn node_id_rejects_invalid() {
        assert!(validate_node_id("").is_err());
        assert!(validate_node_id("1abc").is_err()); // starts with digit
        assert!(validate_node_id("Arcana").is_err()); // uppercase
        assert!(validate_node_id("foo_bar").is_err()); // underscore
        assert!(validate_node_id("foo-").is_err()); // trailing hyphen
        let too_long = "a".repeat(64);
        assert!(validate_node_id(&too_long).is_err());
    }

    #[test]
    fn server_address_valid() {
        assert!(validate_server_address("disk.arcanada.ai:9443").is_ok());
        assert!(validate_server_address("127.0.0.1:9443").is_ok());
        assert!(validate_server_address("localhost:9443").is_ok());
    }

    #[test]
    fn server_address_invalid() {
        assert!(validate_server_address("no-port").is_err());
        assert!(validate_server_address(":9443").is_err());
        assert!(validate_server_address("host:0").is_err());
        assert!(validate_server_address("host:abc").is_err());
        assert!(validate_server_address("host:99999").is_err());
    }
}
