# DISK-0015 — E2EE scaffold (first slice)

**Status:** scaffold on DEVS — crypto primitives only; wire integration deferred.  
**Parent:** DISK-0001 §4.7 (future paid / SaaS feature).  
**Tracking:** DISK-0015 in Datarim backlog.

## Scope (this slice)

| In scope | Out of scope (follow-ups) |
|----------|---------------------------|
| `disk_core::e2ee` — Argon2id key derivation, XChaCha20-Poly1305 encrypt/decrypt | Daemon opt-in encrypt on upload |
| Unit + integration tests | Keychain / `disk.toml` vault unlock UX |
| Design contract for `encryption_nonce` + `content_hash` | Multi-device key escrow, SaaS billing |

## Crypto contract

- **Algorithm:** XChaCha20-Poly1305 (24-byte random nonce per blob).
- **Key derivation:** Argon2id (`m=19456`, `t=2`, `p=1`) from passphrase + 16-byte salt.
- **Vault key:** 32-byte secret; lives in OS keychain or operator-local config — never on server.
- **Wire hint:** `FileMetadata.encryption_nonce` (proto field 10). When non-empty:
  - Delta bytes on the wire are ciphertext.
  - `content_hash` = `blake3(ciphertext)`, not plaintext.
- **Server:** stores opaque bytes; zero-knowledge — no decrypt path in `disk-server`.

## API (`crates/disk-core/src/e2ee/`)

```rust
VaultKey::derive_from_passphrase(passphrase, salt) -> Result<VaultKey, E2eeError>
encrypt(plaintext, &key) -> Result<EncryptedBlob, E2eeError>
decrypt(&blob, &key) -> Result<Vec<u8>, E2eeError>
```

## Tests

- `crates/disk-core/src/e2ee/mod.rs` — unit tests
- `crates/disk-core/tests/e2ee_round_trip.rs` — ciphertext vs plaintext hash contract

## Follow-up slices

1. Client daemon: optional `[vault] e2ee = true` + encrypt before `DeltaUpload`.
2. MetaDb: persist `encryption_nonce` column (already forward-compat in `001_init.sql`).
3. CLI: `disk vault unlock` / keychain integration.
4. PRD amendment + operator key-recovery runbook.

## References

- `proto/disk.proto` — `FileMetadata.encryption_nonce`
- `CONTRIBUTING.md` — forward-compat field rules
- `SECURITY.md` — never log `encryption_nonce` or keys
