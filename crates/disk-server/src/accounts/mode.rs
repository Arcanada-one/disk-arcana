//! User auth mode from environment.

use crate::config::ConfigError;

/// How the server exposes SaaS account endpoints (DISK-0016).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// Self-hosted default — no `/auth/*` routes.
    Disabled,
    /// Signup/login/JWT on the health HTTP listener.
    Enforce,
}

impl AuthMode {
    pub fn parse(raw: &str) -> Result<Self, ConfigError> {
        match raw.to_ascii_lowercase().as_str() {
            "disabled" | "" => Ok(Self::Disabled),
            "enforce" | "local" => Ok(Self::Enforce),
            other => Err(ConfigError::InvalidValue(
                "DISK_AUTH_MODE",
                format!("unknown value '{other}'; expected disabled or enforce"),
            )),
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Self::Enforce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_modes() {
        assert_eq!(AuthMode::parse("disabled").unwrap(), AuthMode::Disabled);
        assert_eq!(AuthMode::parse("enforce").unwrap(), AuthMode::Enforce);
    }
}
