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
