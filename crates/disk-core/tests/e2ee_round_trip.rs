//! DISK-0015 — E2EE integration smoke (client-side only).

use disk_core::e2ee::{decrypt, encrypt, random_salt, VaultKey};

#[test]
fn encrypted_blob_content_hash_is_over_ciphertext() {
    let salt = random_salt();
    let key = VaultKey::derive_from_passphrase(b"vault-password", &salt).unwrap();
    let plaintext = b"# Obsidian note\n\nSecret content.";
    let blob = encrypt(plaintext, &key).unwrap();

    let ciphertext_hash = blake3::hash(&blob.ciphertext);
    let roundtrip = decrypt(&blob, &key).unwrap();
    assert_eq!(roundtrip, plaintext);
    assert_ne!(
        ciphertext_hash.as_bytes(),
        blake3::hash(plaintext).as_bytes(),
        "ciphertext hash must differ from plaintext hash"
    );
    assert_eq!(blob.nonce.len(), disk_core::e2ee::NONCE_LEN);
}
