//! JWKS fetch + in-memory cache for Auth Arcana token verification (DISK-0016 slice 4).

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::DecodingKey;
use serde::Deserialize;

const DEFAULT_CACHE_TTL_SECS: u64 = 300;

pub struct JwksCache {
    uri: String,
    ttl: Duration,
    inner: RwLock<Option<CachedJwks>>,
    http: reqwest::Client,
}

struct CachedJwks {
    fetched_at: Instant,
    keys: HashMap<String, DecodingKey>,
}

#[derive(Deserialize)]
struct JwksDocument {
    keys: Vec<Jwk>,
}

impl JwksCache {
    pub fn new(uri: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            ttl: Duration::from_secs(DEFAULT_CACHE_TTL_SECS),
            inner: RwLock::new(None),
            http: reqwest::Client::new(),
        }
    }

    pub fn with_ttl_secs(mut self, secs: u64) -> Self {
        self.ttl = Duration::from_secs(secs);
        self
    }

    pub async fn decoding_key(&self, kid: &str) -> Result<DecodingKey, JwksError> {
        if let Some(key) = self.cached_key(kid) {
            return Ok(key);
        }
        self.refresh().await?;
        self.cached_key(kid)
            .ok_or_else(|| JwksError::UnknownKid(kid.to_owned()))
    }

    fn cached_key(&self, kid: &str) -> Option<DecodingKey> {
        let guard = self.inner.read().ok()?;
        let cached = guard.as_ref()?;
        if cached.fetched_at.elapsed() > self.ttl {
            return None;
        }
        cached.keys.get(kid).cloned()
    }

    async fn refresh(&self) -> Result<(), JwksError> {
        let body: JwksDocument = self
            .http
            .get(&self.uri)
            .send()
            .await
            .map_err(JwksError::Fetch)?
            .error_for_status()
            .map_err(JwksError::Fetch)?
            .json()
            .await
            .map_err(JwksError::Fetch)?;

        let mut keys = HashMap::new();
        for jwk in body.keys {
            let kid = jwk
                .common
                .key_id
                .clone()
                .ok_or(JwksError::InvalidDocument)?;
            let key = DecodingKey::from_jwk(&jwk).map_err(|_| JwksError::InvalidDocument)?;
            keys.insert(kid, key);
        }
        if keys.is_empty() {
            return Err(JwksError::InvalidDocument);
        }

        let mut guard = self.inner.write().map_err(|_| JwksError::InvalidDocument)?;
        *guard = Some(CachedJwks {
            fetched_at: Instant::now(),
            keys,
        });
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum JwksError {
    #[error("jwks fetch failed: {0}")]
    Fetch(#[from] reqwest::Error),

    #[error("jwks document invalid")]
    InvalidDocument,

    #[error("unknown jwk kid: {0}")]
    UnknownKid(String),
}
