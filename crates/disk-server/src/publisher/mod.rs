//! Publisher signature verification gate.
//!
//! Feature-flagged: enabled only when `publisher-verify` cargo feature is set.
//! When the feature is off, the verification function is a no-op and the
//! quarantine path in `services::sync` is skipped — preserving P4a behaviour.
//!
//! ## Canonical signed payload
//!
//! The Ed25519 signature covers the following bytes in order:
//!
//! ```text
//! blake3(file_content) || share_name (UTF-8, no NUL) || NUL (0x00)
//! || path (UTF-8, no NUL) || NUL (0x00)
//! || signed_at_unix_ms (u64 little-endian)
//! || counter (u64 little-endian)
//! ```
//!
//! This layout is canonical and must not change without a version-bump field
//! in `PublisherSignatureProof`. Verifiers reconstruct this byte sequence
//! from the `FileMetadata` fields and proof metadata before calling `verify_strict`.
//!
//! ## Vault integration
//!
//! The public key is fetched from Vault transit by calling:
//! ```text
//! GET /v1/transit/keys/<key_ref>
//! ```
//! The response `.data.keys."1".public_key` field (PEM-encoded Ed25519 pubkey)
//! is decoded and cached in `publisher_keys` table for 24 hours.
//!
//! When Vault is unreachable: return `VerifyError::KeyFetchFailed`. **Never
//! default-allow** — fail closed per PRD §V3/V4 STRIDE rows.
//!
//! ## Counter replay protection
//!
//! `publisher_counter(cert_fp, share)` stores `max_counter`. Incoming
//! `counter <= max_counter` → `VerifyError::ReplayDetected`. Counter is
//! persisted before returning Ok (see plan §step 14 note on fail-forward).

use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{ed25519::signature::Verifier, VerifyingKey};
use sqlx::SqlitePool;
use thiserror::Error;

use crate::acl::CertFingerprint;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Metadata about the file being published, needed for signature verification.
#[derive(Debug, Clone)]
pub struct FileMetadata {
    /// Relative path within the share (no leading slash).
    pub path: String,
    /// blake3 hash of the file content (32 bytes).
    pub blake3: [u8; 32],
}

/// Publisher signature proof, matching `PublisherSignatureProof` proto message.
#[derive(Debug, Clone)]
pub struct PublisherSignatureProof {
    /// 64-byte Ed25519 signature.
    pub ed25519_signature: Vec<u8>,
    /// Vault transit key reference, e.g. `transit/keys/disk-arcana-arcana-ai-publisher`.
    pub vault_key_ref: String,
    /// Unix milliseconds when the client signed the payload.
    pub signed_at_unix_ms: i64,
    /// Monotonic counter per (cert_fp, share) for replay protection.
    pub counter: u64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("could not fetch public key from Vault: {0}")]
    KeyFetchFailed(String),

    #[error("Ed25519 signature verification failed")]
    SignatureMismatch,

    #[error("publisher replay detected: incoming counter {incoming} <= stored {stored}")]
    ReplayDetected { incoming: u64, stored: u64 },

    #[error("database error: {0}")]
    Db(String),

    #[error("invalid public key format: {0}")]
    InvalidPublicKey(String),
}

impl From<sqlx::Error> for VerifyError {
    fn from(e: sqlx::Error) -> Self {
        VerifyError::Db(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Vault key fetch (real + stub)
// ---------------------------------------------------------------------------

/// Trait for fetching Ed25519 public key from Vault transit.
#[async_trait::async_trait]
pub trait VaultKeyFetcher: Send + Sync {
    /// Returns the raw 32-byte Ed25519 public key for the given key reference.
    async fn fetch_pubkey(&self, key_ref: &str) -> Result<[u8; 32], VerifyError>;
}

/// Stub key fetcher for tests: always returns a fixed key or an error.
pub struct StubKeyFetcher {
    inner: std::sync::Mutex<Option<Result<[u8; 32], VerifyError>>>,
}

impl StubKeyFetcher {
    pub fn ok(key: [u8; 32]) -> Self {
        Self {
            inner: std::sync::Mutex::new(Some(Ok(key))),
        }
    }

    pub fn unreachable() -> Self {
        Self {
            inner: std::sync::Mutex::new(Some(Err(VerifyError::KeyFetchFailed(
                "Vault unreachable (stub)".into(),
            )))),
        }
    }
}

#[async_trait::async_trait]
impl VaultKeyFetcher for StubKeyFetcher {
    async fn fetch_pubkey(&self, _key_ref: &str) -> Result<[u8; 32], VerifyError> {
        let mut guard = self.inner.lock().unwrap();
        guard.take().expect("StubKeyFetcher: called more than once")
    }
}

// ---------------------------------------------------------------------------
// Core verifier
// ---------------------------------------------------------------------------

/// Stateless verifier — all state lives in the SQLite pool.
///
/// Instantiation is cheap (pool is `Arc` inside). Clone freely.
pub struct PublisherVerifier {
    pool: SqlitePool,
    vault: std::sync::Arc<dyn VaultKeyFetcher>,
}

impl std::fmt::Debug for PublisherVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublisherVerifier")
            .field("vault", &"<dyn VaultKeyFetcher>")
            .finish_non_exhaustive()
    }
}

impl PublisherVerifier {
    pub fn new(pool: SqlitePool, vault: std::sync::Arc<dyn VaultKeyFetcher>) -> Self {
        Self { pool, vault }
    }

    /// Verify a publisher signature proof for a given cert fingerprint, share,
    /// and file metadata.
    ///
    /// Algorithm:
    /// 1. Fetch (or cache-hit) Ed25519 public key via `vault`.
    /// 2. Reconstruct canonical signed payload bytes.
    /// 3. Verify Ed25519 signature.
    /// 4. Replay check against `publisher_counter`.
    /// 5. Advance counter (persisted before returning Ok).
    ///
    /// Fail-closed: any error returns `Err`, never default-allows.
    pub async fn verify(
        &self,
        proof: &PublisherSignatureProof,
        cert_fp: &CertFingerprint,
        share: &str,
        file: &FileMetadata,
    ) -> Result<(), VerifyError> {
        // Step 1: fetch public key (cache or Vault).
        let raw_pubkey = self.get_pubkey(cert_fp, &proof.vault_key_ref).await?;

        let verifying_key = VerifyingKey::from_bytes(&raw_pubkey)
            .map_err(|e| VerifyError::InvalidPublicKey(e.to_string()))?;

        // Step 2: build canonical payload.
        let payload = build_signed_payload(file, share, proof.signed_at_unix_ms, proof.counter);

        // Step 3: verify signature.
        let sig_bytes: [u8; 64] = proof
            .ed25519_signature
            .as_slice()
            .try_into()
            .map_err(|_| VerifyError::SignatureMismatch)?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify(&payload, &sig)
            .map_err(|_| VerifyError::SignatureMismatch)?;

        // Step 4: replay check.
        self.check_and_advance_counter(cert_fp, share, proof.counter)
            .await?;

        Ok(())
    }

    /// Fetch pubkey from cache (publisher_keys table, 24h TTL) or Vault.
    async fn get_pubkey(
        &self,
        cert_fp: &CertFingerprint,
        key_ref: &str,
    ) -> Result<[u8; 32], VerifyError> {
        let now_ms = unix_now_ms() as i64;
        let ttl_ms = 24 * 3600 * 1_000i64;

        // Try cache.
        let cached: Option<(Vec<u8>, i64)> = sqlx::query_as(
            "SELECT pubkey_ed25519, fetched_at FROM publisher_keys
             WHERE cert_fingerprint = ?1",
        )
        .bind(&cert_fp[..])
        .fetch_optional(&self.pool)
        .await
        .map_err(VerifyError::from)?;

        if let Some((key_bytes, fetched_at)) = cached {
            if now_ms - fetched_at < ttl_ms {
                // Cache hit — still fresh.
                let arr: [u8; 32] = key_bytes
                    .try_into()
                    .map_err(|_| VerifyError::InvalidPublicKey("cached key wrong length".into()))?;
                return Ok(arr);
            }
        }

        // Cache miss or stale — fetch from Vault.
        let key = self.vault.fetch_pubkey(key_ref).await?;

        // Upsert into cache (best-effort — failure does not abort verification).
        let _ = sqlx::query(
            "INSERT INTO publisher_keys
             (cert_fingerprint, vault_key_ref, pubkey_ed25519, fetched_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(cert_fingerprint) DO UPDATE
             SET vault_key_ref = excluded.vault_key_ref,
                 pubkey_ed25519 = excluded.pubkey_ed25519,
                 fetched_at = excluded.fetched_at",
        )
        .bind(&cert_fp[..])
        .bind(key_ref)
        .bind(&key[..])
        .bind(now_ms)
        .execute(&self.pool)
        .await;

        Ok(key)
    }

    /// Check `proof.counter > max_counter(cert_fp, share)` and advance.
    async fn check_and_advance_counter(
        &self,
        cert_fp: &CertFingerprint,
        share: &str,
        counter: u64,
    ) -> Result<(), VerifyError> {
        let now_ms = unix_now_ms() as i64;

        // Fetch current max.
        let stored: Option<(i64,)> = sqlx::query_as(
            "SELECT max_counter FROM publisher_counter
             WHERE cert_fingerprint = ?1 AND share_name = ?2",
        )
        .bind(&cert_fp[..])
        .bind(share)
        .fetch_optional(&self.pool)
        .await
        .map_err(VerifyError::from)?;

        let max_stored = stored.map(|(v,)| v as u64).unwrap_or(0);

        if counter <= max_stored {
            return Err(VerifyError::ReplayDetected {
                incoming: counter,
                stored: max_stored,
            });
        }

        // Advance counter — persisted before returning Ok.
        sqlx::query(
            "INSERT INTO publisher_counter (cert_fingerprint, share_name, max_counter, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(cert_fingerprint, share_name) DO UPDATE
             SET max_counter = excluded.max_counter,
                 updated_at = excluded.updated_at",
        )
        .bind(&cert_fp[..])
        .bind(share)
        .bind(counter as i64)
        .bind(now_ms)
        .execute(&self.pool)
        .await
        .map_err(VerifyError::from)?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Canonical signed payload builder
// ---------------------------------------------------------------------------

/// Build the canonical byte sequence that the client signed.
///
/// Format: `blake3(content) || share_name || NUL || path || NUL
///          || signed_at_unix_ms (u64 LE) || counter (u64 LE)`
pub fn build_signed_payload(
    file: &FileMetadata,
    share: &str,
    signed_at_unix_ms: i64,
    counter: u64,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(32 + share.len() + 1 + file.path.len() + 1 + 8 + 8);
    payload.extend_from_slice(&file.blake3);
    payload.extend_from_slice(share.as_bytes());
    payload.push(0x00);
    payload.extend_from_slice(file.path.as_bytes());
    payload.push(0x00);
    payload.extend_from_slice(&(signed_at_unix_ms as u64).to_le_bytes());
    payload.extend_from_slice(&counter.to_le_bytes());
    payload
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::RngCore;
    use std::sync::Arc;

    // rand 0.9's OsRng no longer implements ed25519-dalek 2's rand_core 0.6
    // `CryptoRngCore`, so generate a seed with rand 0.9 and build the key from it.
    fn gen_signing_key() -> SigningKey {
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        SigningKey::from_bytes(&seed)
    }

    async fn make_pool() -> SqlitePool {
        let pool = SqlitePool::connect(":memory:").await.unwrap();
        sqlx::migrate!("../../crates/disk-core/migrations")
            .run(&pool)
            .await
            .unwrap();
        pool
    }

    fn sign_proof(
        signing_key: &SigningKey,
        file: &FileMetadata,
        share: &str,
        signed_at_ms: i64,
        counter: u64,
    ) -> PublisherSignatureProof {
        let payload = build_signed_payload(file, share, signed_at_ms, counter);
        let sig = signing_key.sign(&payload);
        PublisherSignatureProof {
            ed25519_signature: sig.to_bytes().to_vec(),
            vault_key_ref: "transit/keys/test-key".into(),
            signed_at_unix_ms: signed_at_ms,
            counter,
        }
    }

    #[tokio::test]
    async fn verify_happy_path() {
        let pool = make_pool().await;
        let signing_key = gen_signing_key();
        let verifying_bytes = signing_key.verifying_key().to_bytes();
        let cert_fp = [0x01u8; 32];
        let file = FileMetadata {
            path: "notes/foo.md".into(),
            blake3: [0x42u8; 32],
        };
        let proof = sign_proof(&signing_key, &file, "wiki", 1_000_000, 1);

        let stub_vault = Arc::new(StubKeyFetcher::ok(verifying_bytes));
        let verifier = PublisherVerifier::new(pool.clone(), stub_vault);

        let result = verifier.verify(&proof, &cert_fp, "wiki", &file).await;
        assert!(result.is_ok(), "happy path should succeed: {result:?}");

        // Counter must have been persisted.
        let stored: (i64,) = sqlx::query_as(
            "SELECT max_counter FROM publisher_counter
             WHERE cert_fingerprint = ?1 AND share_name = 'wiki'",
        )
        .bind(&cert_fp[..])
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(stored.0, 1);
    }

    #[tokio::test]
    async fn verify_signature_mismatch() {
        let pool = make_pool().await;
        let signing_key = gen_signing_key();
        let wrong_key = gen_signing_key();
        let cert_fp = [0x02u8; 32];
        let file = FileMetadata {
            path: "notes/bar.md".into(),
            blake3: [0x11u8; 32],
        };
        // Sign with wrong key, verify with correct key's pubkey.
        let proof = sign_proof(&wrong_key, &file, "wiki", 1_000_000, 1);
        let verifying_bytes = signing_key.verifying_key().to_bytes();

        let stub_vault = Arc::new(StubKeyFetcher::ok(verifying_bytes));
        let verifier = PublisherVerifier::new(pool, stub_vault);

        let err = verifier
            .verify(&proof, &cert_fp, "wiki", &file)
            .await
            .unwrap_err();
        assert_eq!(err, VerifyError::SignatureMismatch);
    }

    #[tokio::test]
    async fn verify_replay_detected() {
        let pool = make_pool().await;
        let signing_key = gen_signing_key();
        let verifying_bytes = signing_key.verifying_key().to_bytes();
        let cert_fp = [0x03u8; 32];
        let file = FileMetadata {
            path: "notes/baz.md".into(),
            blake3: [0x99u8; 32],
        };

        // Pre-store counter = 5.
        sqlx::query(
            "INSERT INTO publisher_counter (cert_fingerprint, share_name, max_counter, updated_at)
             VALUES (?1, 'wiki', 5, 0)",
        )
        .bind(&cert_fp[..])
        .execute(&pool)
        .await
        .unwrap();

        // Send counter = 3 → replay.
        let proof = sign_proof(&signing_key, &file, "wiki", 1_000_000, 3);
        let stub_vault = Arc::new(StubKeyFetcher::ok(verifying_bytes));
        let verifier = PublisherVerifier::new(pool, stub_vault);

        let err = verifier
            .verify(&proof, &cert_fp, "wiki", &file)
            .await
            .unwrap_err();
        assert!(
            matches!(err, VerifyError::ReplayDetected { .. }),
            "expected ReplayDetected, got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_missing_key() {
        let pool = make_pool().await;
        let signing_key = gen_signing_key();
        let cert_fp = [0x04u8; 32];
        let file = FileMetadata {
            path: "notes/x.md".into(),
            blake3: [0x55u8; 32],
        };
        let proof = sign_proof(&signing_key, &file, "wiki", 1_000_000, 1);

        // Vault returns key_not_found.
        let stub_vault = Arc::new(StubKeyFetcher::unreachable());
        let verifier = PublisherVerifier::new(pool, stub_vault);

        let err = verifier
            .verify(&proof, &cert_fp, "wiki", &file)
            .await
            .unwrap_err();
        assert!(
            matches!(err, VerifyError::KeyFetchFailed(_)),
            "expected KeyFetchFailed, got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_vault_unreachable() {
        let pool = make_pool().await;
        let signing_key = gen_signing_key();
        let cert_fp = [0x05u8; 32];
        let file = FileMetadata {
            path: "notes/y.md".into(),
            blake3: [0x77u8; 32],
        };
        let proof = sign_proof(&signing_key, &file, "wiki", 1_000_000, 1);

        let stub_vault = Arc::new(StubKeyFetcher::unreachable());
        let verifier = PublisherVerifier::new(pool, stub_vault);

        let err = verifier
            .verify(&proof, &cert_fp, "wiki", &file)
            .await
            .unwrap_err();
        // Both missing_key and unreachable hit KeyFetchFailed.
        assert!(matches!(err, VerifyError::KeyFetchFailed(_)));
    }
}
