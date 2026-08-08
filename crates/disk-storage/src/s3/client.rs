use std::time::Duration;

use aws_sdk_s3::config::{Builder as S3ConfigBuilder, Credentials, Region};
use aws_sdk_s3::error::ProvideErrorMetadata;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client;

use crate::s3::config::S3BackendConfig;
use crate::StorageError;

pub(crate) async fn build_client(config: &S3BackendConfig) -> Result<Client, StorageError> {
    let creds = Credentials::new(
        &config.access_key_id,
        &config.secret_access_key,
        None,
        None,
        "disk-storage",
    );
    let s3_config = S3ConfigBuilder::new()
        .endpoint_url(&config.endpoint_url)
        .region(Region::new(config.region.clone()))
        .credentials_provider(creds)
        .force_path_style(config.force_path_style)
        .build();
    Ok(Client::from_conf(s3_config))
}

pub(crate) async fn with_retry<T, F, Fut>(mut operation: F) -> Result<T, StorageError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, StorageError>>,
{
    let mut delay = Duration::from_millis(200);
    let mut last_err = None;
    for attempt in 0..5 {
        match operation().await {
            Ok(v) => return Ok(v),
            Err(e) if is_transient(&e) && attempt < 4 => {
                tracing::warn!(attempt, error = %e, "s3 transient error, retrying");
                last_err = Some(e);
                tokio::time::sleep(delay).await;
                delay *= 2;
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err.unwrap_or_else(|| StorageError::Unsupported("retry exhausted".into())))
}

fn is_transient(err: &StorageError) -> bool {
    matches!(err, StorageError::S3Transient(_))
}

pub(crate) async fn put_object(
    client: &Client,
    bucket: &str,
    key: &str,
    data: &[u8],
) -> Result<(), StorageError> {
    with_retry(|| async {
        client
            .put_object()
            .bucket(bucket)
            .key(key)
            .body(ByteStream::from(data.to_vec()))
            .send()
            .await
            .map_err(map_sdk_error)?;
        Ok(())
    })
    .await
}

pub(crate) async fn get_object(
    client: &Client,
    bucket: &str,
    key: &str,
) -> Result<Vec<u8>, StorageError> {
    with_retry(|| async {
        let out = client
            .get_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .map_err(map_sdk_error)?;
        let bytes = out
            .body
            .collect()
            .await
            .map_err(|e| StorageError::S3Transient(e.to_string()))?
            .into_bytes();
        Ok(bytes.to_vec())
    })
    .await
}

pub(crate) async fn delete_object(
    client: &Client,
    bucket: &str,
    key: &str,
) -> Result<(), StorageError> {
    with_retry(|| async {
        client
            .delete_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .map_err(map_sdk_error)?;
        Ok(())
    })
    .await
}

pub(crate) fn map_sdk_error<E: std::error::Error + ProvideErrorMetadata>(err: E) -> StorageError {
    let code = err.code().unwrap_or("unknown");
    let msg = format!("{code}: {err}");
    if matches!(
        code,
        "InternalError" | "ServiceUnavailable" | "SlowDown" | "RequestTimeout"
    ) || msg.contains("503")
        || msg.contains("429")
    {
        StorageError::S3Transient(msg)
    } else {
        StorageError::Metadata(msg)
    }
}
