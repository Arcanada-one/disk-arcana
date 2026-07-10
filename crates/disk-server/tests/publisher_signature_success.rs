//! Integration test — publisher signature success path.
//!
//! Step 19 P4b: generate Ed25519 keypair, sign a delta, mock Vault to return
//! the pubkey, verify success, and assert counter advances.

use std::sync::Arc;

use disk_server::publisher::{
    FileMetadata, PublisherSignatureProof, PublisherVerifier, StubKeyFetcher,
};
use sqlx::SqlitePool;

fn gen_signing_key() -> ed25519_dalek::SigningKey {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    ed25519_dalek::SigningKey::from_bytes(&seed)
}

async fn make_pool() -> SqlitePool {
    let pool = SqlitePool::connect(":memory:").await.unwrap();
    sqlx::migrate!("../../crates/disk-core/migrations")
        .run(&pool)
        .await
        .unwrap();
    pool
}

#[tokio::test]
async fn valid_signature_succeeds_and_advances_counter() {
    use ed25519_dalek::Signer;

    let pool = make_pool().await;
    let key = gen_signing_key();
    let verifying_bytes = key.verifying_key().to_bytes();
    let cert_fp = [0xAAu8; 32];

    let file = FileMetadata {
        path: "vault/note.md".into(),
        blake3: [0x55u8; 32],
    };
    let payload = disk_server::publisher::build_signed_payload(&file, "main", 9_000_000, 1);
    let sig = key.sign(&payload);

    let proof = PublisherSignatureProof {
        ed25519_signature: sig.to_bytes().to_vec(),
        vault_key_ref: "transit/keys/publisher".into(),
        signed_at_unix_ms: 9_000_000,
        counter: 1,
    };

    let verifier =
        PublisherVerifier::new(pool.clone(), Arc::new(StubKeyFetcher::ok(verifying_bytes)));
    verifier
        .verify(&proof, &cert_fp, "main", &file)
        .await
        .expect("valid signature must succeed");

    // Counter must be persisted.
    let stored: (i64,) = sqlx::query_as(
        "SELECT max_counter FROM publisher_counter
         WHERE cert_fingerprint = ?1 AND share_name = 'main'",
    )
    .bind(&cert_fp[..])
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(stored.0, 1, "counter must advance to 1");
}

#[tokio::test]
async fn counter_advances_on_second_valid_upload() {
    use ed25519_dalek::Signer;

    let pool = make_pool().await;
    let key = gen_signing_key();
    let verifying_bytes = key.verifying_key().to_bytes();
    let cert_fp = [0xDDu8; 32];

    for counter in [1u64, 2u64] {
        let file = FileMetadata {
            path: format!("vault/note-{counter}.md"),
            blake3: [(counter as u8).wrapping_mul(17); 32],
        };
        let payload =
            disk_server::publisher::build_signed_payload(&file, "docs", 9_000_000, counter);
        let sig = key.sign(&payload);
        let proof = PublisherSignatureProof {
            ed25519_signature: sig.to_bytes().to_vec(),
            vault_key_ref: "transit/keys/publisher".into(),
            signed_at_unix_ms: 9_000_000,
            counter,
        };
        let verifier =
            PublisherVerifier::new(pool.clone(), Arc::new(StubKeyFetcher::ok(verifying_bytes)));
        verifier
            .verify(&proof, &cert_fp, "docs", &file)
            .await
            .unwrap();
    }

    let stored: (i64,) = sqlx::query_as(
        "SELECT max_counter FROM publisher_counter
         WHERE cert_fingerprint = ?1 AND share_name = 'docs'",
    )
    .bind(&cert_fp[..])
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored.0, 2, "counter must be 2 after two uploads");
}
