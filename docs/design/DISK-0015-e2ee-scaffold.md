# DISK-0015 — E2EE scaffold

**Status:** slice 3 on DEVS — ExchangeState ciphertext overlay + MetaDb wire index.  
**Parent:** DISK-0001 §4.7 (future paid / SaaS feature).  
**Tracking:** DISK-0015 in Datarim backlog.

## Scope

| Slice | In scope | Out of scope |
|-------|----------|--------------|
| 1 (merged #57) | `disk_core::e2ee` primitives, unit tests | Wire integration |
| 2 (merged #58) | `UploadPayload`, encrypt-on-upload, MetaDb `encryption_nonce` | ExchangeState reconcile |
| 3 (this PR) | `overlay_scanned_meta`, MetaDb + in-memory wire cache, stable ciphertext hash across cycles | Keychain UX, multi-device escrow |
| 4+ | `disk vault unlock`, SaaS billing | — |

## Crypto contract

- **Algorithm:** XChaCha20-Poly1305 (24-byte random nonce per blob).
- **Key derivation:** Argon2id (`m=19456`, `t=2`, `p=1`) from passphrase + 16-byte salt.
- **Vault key:** 32-byte secret; lives in OS keychain or operator-local config — never on server.
- **Wire hint:** `FileMetadata.encryption_nonce` (proto field 10). When non-empty:
  - Delta bytes on the wire are ciphertext.
  - `content_hash` = `blake3(ciphertext)`, not plaintext.
- **Server:** stores opaque bytes; zero-knowledge — no decrypt path in `disk-server`.

## Operator config

```toml
[vault]
e2ee_enabled = true
```

```bash
export DISK_VAULT_PASSPHRASE='operator-chosen-secret'
export DISK_VAULT_SALT='00112233445566778899aabbccddeeff'  # 16-byte hex
```

When `e2ee_enabled = true` but env vars are missing or invalid, the daemon logs a warning and uploads remain plaintext.

## ExchangeState overlay (slice 3)

Local scan indexes **plaintext** `content_hash`. Because XChaCha20 uses a random nonce, re-encrypting unchanged files would rotate the ciphertext hash every cycle.

Before `ExchangeState`, when E2EE is active:

1. Load wire index from MetaDb (`files.encryption_nonce` rows) and an in-memory cache.
2. For each scanned file, if `(mtime_ns, plaintext size)` matches the cache → reuse stored `(content_hash, encryption_nonce)`.
3. Otherwise read plaintext, encrypt once, and update MetaDb + cache.

Upload path persists the same `(mtime_ns, plaintext size, ciphertext hash, nonce)` tuple.

## API (`crates/disk-core/src/e2ee/`)

```rust
UploadPayload::from_plaintext(bytes)
UploadPayload::from_plaintext_encrypted(bytes, &VaultKey) -> Result<UploadPayload, E2eeError>
overlay_scanned_meta(scanned, &VaultKey, cached, plaintext) -> Result<Option<E2eeCachedWire>, E2eeError>
VaultKey::derive_from_passphrase(passphrase, salt) -> Result<VaultKey, E2eeError>
```

Client env loader: `disk_client::load_vault_key_from_env()`.

## Tests

- `crates/disk-core/src/e2ee/exchange_overlay.rs` — cache hit/miss unit tests
- `crates/disk-core/src/e2ee/` — encrypt unit tests
- `crates/disk-core/tests/e2ee_round_trip.rs` — ciphertext vs plaintext hash contract
- `crates/disk-client/src/vault_key.rs` — env derivation
- `crates/disk-core/tests/metadata_lifecycle.rs` — `encryption_nonce` MetaDb round-trip

## References

- `proto/disk.proto` — `FileMetadata.encryption_nonce`
- `CONTRIBUTING.md` — forward-compat field rules
- `SECURITY.md` — never log `encryption_nonce` or keys
