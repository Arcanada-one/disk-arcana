//! JWT verification mode from environment (DISK-0016 slice 4).

use crate::config::ConfigError;

/// How bearer access tokens are issued and verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtMode {
    /// Interim HS256 local signing (slice 1 default).
    Local,
    /// Auth Arcana JWKS only — password issue disabled; OAuth passthrough.
    AuthArcana,
    /// Accept Auth Arcana JWKS or interim HS256 during migration.
    Dual,
}

impl JwtMode {
    pub fn parse(raw: &str) -> Result<Self, ConfigError> {
        match raw.to_ascii_lowercase().as_str() {
            "local" | "" => Ok(Self::Local),
            "auth_arcana" | "jwks" | "oidc" => Ok(Self::AuthArcana),
            "dual" => Ok(Self::Dual),
            other => Err(ConfigError::InvalidValue(
                "DISK_JWT_MODE",
                format!("unknown value '{other}'; expected local, auth_arcana, or dual"),
            )),
        }
    }

    pub fn allows_local_issue(self) -> bool {
        matches!(self, Self::Local | Self::Dual)
    }

    pub fn allows_jwks_verify(self) -> bool {
        matches!(self, Self::AuthArcana | Self::Dual)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_modes() {
        assert_eq!(JwtMode::parse("local").unwrap(), JwtMode::Local);
        assert_eq!(JwtMode::parse("auth_arcana").unwrap(), JwtMode::AuthArcana);
        assert_eq!(JwtMode::parse("dual").unwrap(), JwtMode::Dual);
    }
}
