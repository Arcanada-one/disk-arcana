//! Integration test — publisher signature failure → quarantine path.
//!
//! Step 19 P4b: a bad signature must:
//! 1. Not commit any delta (DeltaUpload handler returns PermissionDenied).
//! 2. Write bytes to `<root>/.quarantine/<share>/<short_fp>/<path>`.
//! 3. Emit `publisher.signature_failure` audit row.
//!
//! This test runs without the `publisher-verify` feature — it exercises
//! the `PublisherVerifier` directly (library-level), not the gRPC handler.
//! The gRPC quarantine path is covered by `publisher_signature_success.rs`
//! which uses the feature gate.

use std::sync::Arc;

use disk_server::publisher::{
    FileMetadata, PublisherSignatureProof, PublisherVerifier, StubKeyFetcher, VerifyError,
};
use sqlx::SqlitePool;

async fn make_pool() -> SqlitePool {
    let pool = SqlitePool::connect(":memory:").await.unwrap();
    sqlx::migrate!("../../crates/disk-core/migrations")
        .run(&pool)
        .await
        .unwrap();
    pool
}

#[tokio::test]
async fn bad_signature_returns_signature_mismatch() {
    let pool = make_pool().await;

    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    let correct_key = SigningKey::generate(&mut OsRng);
    let wrong_key = SigningKey::generate(&mut OsRng);
    let verifying_bytes = correct_key.verifying_key().to_bytes();
    let cert_fp = [0xBBu8; 32];

    let file = FileMetadata {
        path: "docs/bad.md".into(),
        blake3: [0x12u8; 32],
    };
    let payload = disk_server::publisher::build_signed_payload(&file, "wiki", 1_000_000, 1);
    let sig = wrong_key.sign(&payload); // wrong key!

    let proof = PublisherSignatureProof {
        ed25519_signature: sig.to_bytes().to_vec(),
        vault_key_ref: "transit/keys/test".into(),
        signed_at_unix_ms: 1_000_000,
        counter: 1,
    };

    let verifier = PublisherVerifier::new(pool, Arc::new(StubKeyFetcher::ok(verifying_bytes)));
    let err = verifier
        .verify(&proof, &cert_fp, "wiki", &file)
        .await
        .unwrap_err();

    assert_eq!(err, VerifyError::SignatureMismatch);
}

#[tokio::test]
async fn replay_counter_returns_replay_detected() {
    let pool = make_pool().await;

    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    let key = SigningKey::generate(&mut OsRng);
    let verifying_bytes = key.verifying_key().to_bytes();
    let cert_fp = [0xCCu8; 32];

    // Pre-seed counter = 10.
    sqlx::query(
        "INSERT INTO publisher_counter (cert_fingerprint, share_name, max_counter, updated_at)
         VALUES (?1, 'wiki', 10, 0)",
    )
    .bind(&cert_fp[..])
    .execute(&pool)
    .await
    .unwrap();

    let file = FileMetadata {
        path: "docs/stale.md".into(),
        blake3: [0x34u8; 32],
    };
    let payload = disk_server::publisher::build_signed_payload(&file, "wiki", 1_000_000, 5); // counter 5 < 10
    let sig = key.sign(&payload);

    let proof = PublisherSignatureProof {
        ed25519_signature: sig.to_bytes().to_vec(),
        vault_key_ref: "transit/keys/test".into(),
        signed_at_unix_ms: 1_000_000,
        counter: 5,
    };

    let verifier = PublisherVerifier::new(pool, Arc::new(StubKeyFetcher::ok(verifying_bytes)));
    let err = verifier
        .verify(&proof, &cert_fp, "wiki", &file)
        .await
        .unwrap_err();

    assert!(
        matches!(
            err,
            VerifyError::ReplayDetected {
                incoming: 5,
                stored: 10
            }
        ),
        "expected ReplayDetected(5, 10), got {err:?}"
    );
}
