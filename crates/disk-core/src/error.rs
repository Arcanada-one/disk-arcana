//! Error types for `disk-core`. Phase 1 introduced [`ConfigError`] and
//! [`MetaDbError`]; Phase 2 (DISK-0003) adds scanner / reconciler /
//! path-guard / filter errors.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse TOML: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid configuration: {0}")]
    Validation(String),
}

#[derive(Debug, Error)]
pub enum MetaDbError {
    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("serde_json error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("invalid metadata: {0}")]
    Invalid(String),
}

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("proto encode error: {0}")]
    Encode(String),
    #[error("proto decode error: {0}")]
    Decode(String),
}

#[derive(Debug, Error)]
pub enum IoError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("path not found: {0}")]
    PathNotFound(String),
}

/// Reasons [`crate::path_guard::validate`] may reject a candidate path.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PathGuardError {
    #[error("path resolves outside the configured sync root")]
    OutsideRoot,
    #[error("path contains a NUL byte")]
    NullByte,
    #[error("path is not valid UTF-8")]
    InvalidUtf8,
    #[error("path contains `..` segment")]
    RelativeWithDotDot,
    #[error("symlink target points outside the sync root")]
    SymlinkOutsideRoot,
    #[error("path exceeds platform PATH_MAX")]
    PathTooLong,
}

/// Configuration / runtime errors produced by the file [`crate::filter::Filter`].
#[derive(Debug, Error)]
pub enum FilterError {
    #[error("invalid glob pattern `{pattern}`: {reason}")]
    InvalidGlob { pattern: String, reason: String },
}

/// Errors produced by the [`crate::scanner::FileScanner`].
#[derive(Debug, Error)]
pub enum ScannerError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    PathGuard(#[from] PathGuardError),
    #[error(transparent)]
    Filter(#[from] FilterError),
    #[error("walkdir error: {0}")]
    Walk(String),
}

/// Errors produced by [`crate::reconciler::ReconciliationEngine`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReconcileError {
    #[error("inconsistent triple at path `{path}`: {reason}")]
    Inconsistent { path: String, reason: String },
}
