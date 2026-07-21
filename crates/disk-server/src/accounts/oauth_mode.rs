//! OAuth mode from environment (DISK-0016 slice 2).

use crate::config::ConfigError;

/// How the server exposes social/OIDC login endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthMode {
    /// Password signup/login only (slice 1).
    Disabled,
    /// Deterministic dev/test OAuth without external IdP.
    Stub,
    /// OIDC authorization-code flow via Auth Arcana (interim RP).
    AuthArcana,
}

impl OAuthMode {
    pub fn parse(raw: &str) -> Result<Self, ConfigError> {
        match raw.to_ascii_lowercase().as_str() {
            "disabled" | "" => Ok(Self::Disabled),
            "stub" | "dev" => Ok(Self::Stub),
            "auth_arcana" | "oidc" => Ok(Self::AuthArcana),
            other => Err(ConfigError::InvalidValue(
                "DISK_OAUTH_MODE",
                format!("unknown value '{other}'; expected disabled, stub, or auth_arcana"),
            )),
        }
    }

    pub fn is_active(self) -> bool {
        !matches!(self, Self::Disabled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_modes() {
        assert_eq!(OAuthMode::parse("disabled").unwrap(), OAuthMode::Disabled);
        assert_eq!(OAuthMode::parse("stub").unwrap(), OAuthMode::Stub);
        assert_eq!(
            OAuthMode::parse("auth_arcana").unwrap(),
            OAuthMode::AuthArcana
        );
    }
}
