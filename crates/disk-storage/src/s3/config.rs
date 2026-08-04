//! Shared S3-compatible client configuration (DISK-0076 B2 + DISK-0080 R2).

use crate::StorageError;

/// S3-compatible endpoint configuration used by B2, R2, MinIO, etc.
#[derive(Debug, Clone)]
pub struct S3BackendConfig {
    pub endpoint_url: String,
    pub region: String,
    pub bucket: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    /// Path-style addressing (required by some S3-compatible stores).
    pub force_path_style: bool,
}

impl S3BackendConfig {
    /// Backblaze B2 via S3-compatible API.
    ///
    /// Env: `DISK_B2_BUCKET`, `DISK_B2_KEY_ID`, `DISK_B2_APP_KEY`,
    /// optional `DISK_B2_ENDPOINT` (default `https://s3.us-west-004.backblazeb2.com`),
    /// optional `DISK_B2_REGION` (default `us-west-004`).
    pub fn backblaze_from_env() -> Result<Self, StorageError> {
        Ok(Self {
            endpoint_url: std::env::var("DISK_B2_ENDPOINT")
                .unwrap_or_else(|_| "https://s3.us-west-004.backblazeb2.com".into()),
            region: std::env::var("DISK_B2_REGION").unwrap_or_else(|_| "us-west-004".into()),
            bucket: require_env("DISK_B2_BUCKET")?,
            access_key_id: require_env("DISK_B2_KEY_ID")?,
            secret_access_key: require_env("DISK_B2_APP_KEY")?,
            force_path_style: true,
        })
    }

    /// Cloudflare R2 via S3-compatible API.
    ///
    /// Env: `DISK_R2_ACCOUNT_ID`, `DISK_R2_BUCKET`, `DISK_R2_ACCESS_KEY_ID`,
    /// `DISK_R2_SECRET_ACCESS_KEY`, optional `DISK_R2_ENDPOINT` override.
    pub fn cloudflare_r2_from_env() -> Result<Self, StorageError> {
        let account_id = require_env("DISK_R2_ACCOUNT_ID")?;
        let endpoint_url = std::env::var("DISK_R2_ENDPOINT").unwrap_or_else(|_| {
            format!("https://{account_id}.r2.cloudflarestorage.com")
        });
        Ok(Self {
            endpoint_url,
            region: std::env::var("DISK_R2_REGION").unwrap_or_else(|_| "auto".into()),
            bucket: require_env("DISK_R2_BUCKET")?,
            access_key_id: require_env("DISK_R2_ACCESS_KEY_ID")?,
            secret_access_key: require_env("DISK_R2_SECRET_ACCESS_KEY")?,
            force_path_style: false,
        })
    }
}

fn require_env(name: &str) -> Result<String, StorageError> {
    std::env::var(name).map_err(|_| StorageError::Metadata(format!("missing env {name}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r2_endpoint_default_uses_account_id() {
        std::env::set_var("DISK_R2_ACCOUNT_ID", "abc123");
        std::env::set_var("DISK_R2_BUCKET", "videos");
        std::env::set_var("DISK_R2_ACCESS_KEY_ID", "key");
        std::env::set_var("DISK_R2_SECRET_ACCESS_KEY", "secret");
        let cfg = S3BackendConfig::cloudflare_r2_from_env().unwrap();
        assert!(cfg.endpoint_url.contains("abc123"));
        assert_eq!(cfg.bucket, "videos");
        std::env::remove_var("DISK_R2_ACCOUNT_ID");
        std::env::remove_var("DISK_R2_BUCKET");
        std::env::remove_var("DISK_R2_ACCESS_KEY_ID");
        std::env::remove_var("DISK_R2_SECRET_ACCESS_KEY");
    }
}
