# DISK-0015 — E2EE scaffold

**Status:** slice 2 on DEVS — optional encrypt-on-upload + MetaDb nonce persistence.  
**Parent:** DISK-0001 §4.7 (future paid / SaaS feature).  
**Tracking:** DISK-0015 in Datarim backlog.

## Scope

| Slice | In scope | Out of scope |
|-------|----------|--------------|
| 1 (merged #57) | `disk_core::e2ee` primitives, unit tests | Wire integration |
| 2 (this PR) | `UploadPayload`, `delta_upload`, `[vault] e2ee_enabled`, env key load, MetaDb `encryption_nonce` | Keychain UX, ExchangeState ciphertext-hash reconcile |
| 3+ | `disk vault unlock`, multi-device escrow | SaaS billing |

## Crypto contract

- **Algorithm:** XChaCha20-Poly1305 (24-byte random nonce per blob).
- **Key derivation:** Argon2id (`m=19456`, `t=2`, `p=1`) from passphrase + 16-byte salt.
- **Vault key:** 32-byte secret; lives in OS keychain or operator-local config — never on server.
- **Wire hint:** `FileMetadata.encryption_nonce` (proto field 10). When non-empty:
  - Delta bytes on the wire are ciphertext.
  - `content_hash` = `blake3(ciphertext)`, not plaintext.
- **Server:** stores opaque bytes; zero-knowledge — no decrypt path in `disk-server`.

## Operator config (slice 2)

```toml
[vault]
e2ee_enabled = true
```

```bash
export DISK_VAULT_PASSPHRASE='operator-chosen-secret'
export DISK_VAULT_SALT='00112233445566778899aabbccddeeff'  # 16-byte hex
```

When `e2ee_enabled = true` but env vars are missing or invalid, the daemon logs a warning and uploads remain plaintext.

## Known gap (documented deferral)

Local `ExchangeState` scan still indexes **plaintext** `content_hash` from disk. Encrypted uploads send **ciphertext** hash on the wire. Reconciler alignment (overlay MetaDb or post-scan rewrite) is a follow-up slice — not blocking encrypt-on-upload.

## API (`crates/disk-core/src/e2ee/`)

```rust
UploadPayload::from_plaintext(bytes)
UploadPayload::from_plaintext_encrypted(bytes, &VaultKey) -> Result<UploadPayload, E2eeError>
VaultKey::derive_from_passphrase(passphrase, salt) -> Result<VaultKey, E2eeError>
encrypt(plaintext, &key) -> Result<EncryptedBlob, E2eeError>
decrypt(&blob, &key) -> Result<Vec<u8>, E2eeError>
```

Client env loader: `disk_client::load_vault_key_from_env()`.

## Tests

- `crates/disk-core/src/e2ee/` — unit tests
- `crates/disk-core/tests/e2ee_round_trip.rs` — ciphertext vs plaintext hash contract
- `crates/disk-client/src/vault_key.rs` — env derivation
- `crates/disk-core/tests/metadata_lifecycle.rs` — `encryption_nonce` MetaDb round-trip

## References

- `proto/disk.proto` — `FileMetadata.encryption_nonce`
- `CONTRIBUTING.md` — forward-compat field rules
- `SECURITY.md` — never log `encryption_nonce` or keys
