# DISK-0015 — E2EE scaffold

**Status:** slice 4 on DEVS — `disk vault unlock` / keychain UX.  
**Parent:** DISK-0001 §4.7 (future paid / SaaS feature).  
**Tracking:** DISK-0015 in Datarim backlog.

## Scope

| Slice | In scope | Out of scope |
|-------|----------|--------------|
| 1 (merged #57) | `disk_core::e2ee` primitives | Wire integration |
| 2 (merged #58) | encrypt-on-upload, MetaDb nonce | ExchangeState reconcile |
| 3 (merged #59) | ExchangeState ciphertext overlay | Keychain UX |
| 4 (merged #60) | `disk vault unlock|lock|status`, keychain store, daemon `resolve_vault_key` | SaaS billing, multi-device escrow |
| 5+ | Multi-device escrow | Billing → DISK-0018 |

## Operator workflow (slice 4)

```toml
[vault]
e2ee_enabled = true
```

```bash
# One-time (or after lock): derive key and store in OS keychain / {state_dir}/keys fallback
disk vault unlock --passphrase 'your-secret'

# Check state
disk vault status

# Remove key material from keychain
disk vault lock
```

Dev/CI override (unchanged): `DISK_VAULT_PASSPHRASE` + `DISK_VAULT_SALT` env vars take precedence over keychain.

## Crypto contract

- **Algorithm:** XChaCha20-Poly1305 (24-byte random nonce per blob).
- **Key derivation:** Argon2id from passphrase + 16-byte salt.
- **Key storage:** derived 32-byte key + salt in OS keychain (`e2ee.<node_id>`) or `{state_dir}/keys/` file fallback — never the raw passphrase.
- **Wire:** `content_hash` = `blake3(ciphertext)` when `encryption_nonce` is set.

## ExchangeState overlay (slice 3)

Before `ExchangeState`, unchanged files reuse cached `(ciphertext hash, nonce)` from MetaDb / in-memory cache when `(mtime_ns, plaintext size)` match.

## API

```rust
disk vault unlock|lock|status   // CLI
resolve_vault_key(node_id, state_dir) -> Option<VaultKey>
unlock_vault_key(passphrase, node_id, state_dir, salt_override)
overlay_scanned_meta(...)       // slice 3
```

## Tests

- `crates/disk-client/src/vault_key.rs` — unlock/lock round-trip
- `crates/disk-cli/tests/it_vault_unlock.rs` — CLI integration
- `crates/disk-core/src/e2ee/exchange_overlay.rs` — overlay unit tests

## References

- `crates/disk-client/src/keychain.rs` — `KeyStore` / `detect_or_file`
- `SECURITY.md` — never log passphrases, keys, or `encryption_nonce`
