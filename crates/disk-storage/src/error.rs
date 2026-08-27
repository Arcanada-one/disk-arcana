use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("metadata store: {0}")]
    Metadata(String),

    #[error("object not found: {path}")]
    NotFound { path: String },

    #[error("object already exists: {path}")]
    AlreadyExists { path: String },

    #[error("invalid path: {0}")]
    InvalidPath(String),

    #[error("backend I/O: {0}")]
    Io(#[from] std::io::Error),

    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),

    #[error("s3 transient: {0}")]
    S3Transient(String),

    #[error("unsupported operation: {0}")]
    Unsupported(String),
}
