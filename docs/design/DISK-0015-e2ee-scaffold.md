# DISK-0015 — E2EE scaffold

**Status:** slices 1–4 shipped on `main` (PRs #57–#60). Slice 5+ deferred (multi-device escrow, download decrypt).  
**Parent:** DISK-0001 §4.7 (future paid / SaaS feature).  
**Tracking:** DISK-0015 — **done** (MVP scaffold) in Datarim backlog.

## Scope

| Slice | In scope | Out of scope |
|-------|----------|--------------|
| 1 (merged #57) | `disk_core::e2ee` primitives | Wire integration |
| 2 (merged #58) | encrypt-on-upload, MetaDb nonce | ExchangeState reconcile |
| 3 (merged #59) | ExchangeState ciphertext overlay | Keychain UX |
| 4 (merged #60) | `disk vault unlock|lock|status`, keychain store, daemon `resolve_vault_key` | SaaS billing, multi-device escrow |
| 5+ | Multi-device escrow; download-path decrypt on pull | Billing → DISK-0018 |

## Remaining gaps vs full zero-knowledge sync (post–slice 4)

| Gap | Status | Notes |
|-----|--------|-------|
| Upload encrypt + wire `encryption_nonce` | **Shipped** | `wire.rs` upload path + MetaDb persistence |
| ExchangeState ciphertext overlay | **Shipped** | `overlay_e2ee_exchange_files` |
| `disk vault unlock\|lock\|status` + keychain | **Shipped** | `it_vault_unlock.rs` |
| Download decrypt (pull → plaintext on disk) | **Open** | `decrypt()` exists in `disk_core::e2ee`; sync download path not wired |
| Multi-device key escrow | **Open** | Slice 5+; out of MVP scaffold |

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
