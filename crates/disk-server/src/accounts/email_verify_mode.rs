//! Email verification mode from environment (DISK-0016 slice 3).

use crate::config::ConfigError;

/// How the server delivers email verification tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailVerifyMode {
    /// No verification endpoints; signup leaves `email_verified=false`.
    Disabled,
    /// Return verification token/URL in API responses (CI/dev).
    Stub,
    /// Log verification URL via `tracing` (operator/dev).
    Log,
}

impl EmailVerifyMode {
    pub fn parse(raw: &str) -> Result<Self, ConfigError> {
        match raw.to_ascii_lowercase().as_str() {
            "disabled" | "" => Ok(Self::Disabled),
            "stub" | "dev" => Ok(Self::Stub),
            "log" => Ok(Self::Log),
            other => Err(ConfigError::InvalidValue(
                "DISK_EMAIL_VERIFY_MODE",
                format!("unknown value '{other}'; expected disabled, stub, or log"),
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
        assert_eq!(
            EmailVerifyMode::parse("disabled").unwrap(),
            EmailVerifyMode::Disabled
        );
        assert_eq!(
            EmailVerifyMode::parse("stub").unwrap(),
            EmailVerifyMode::Stub
        );
        assert_eq!(EmailVerifyMode::parse("log").unwrap(), EmailVerifyMode::Log);
    }
}
