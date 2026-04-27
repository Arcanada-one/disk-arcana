# Contributing to Disk Arcana

Thanks for your interest. This document is the source of truth for setup and
PR rules during the open-source self-hosted phase (Foundation → v1.0).

## Dev setup

1. Install Rust stable via [rustup](https://rustup.rs).
2. Install `protoc`:
   - macOS: `brew install protobuf`
   - Ubuntu/Debian: `sudo apt-get install protobuf-compiler`
3. Clone and build:
   ```sh
   git clone https://github.com/Arcanada-one/disk-arcana
   cd disk-arcana
   cargo build --workspace --all-features
   cargo test  --workspace --all-features
   ```
4. Optional cross-compile (matches CI matrix):
   ```sh
   cargo install cross --locked
   cross build --release --target aarch64-unknown-linux-gnu --workspace
   ```

## PR checklist

Before opening a PR, verify locally:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test  --workspace --all-features
```

CI also runs `cargo audit`, `cargo deny check licenses`, and gitleaks. Fix any
finding rather than silencing it.

## Proto3 compatibility rules

The `proto/disk.proto` schema is a public wire-format contract once
`v1.0` ships. Until then we treat it as if it already were locked.

1. **Never delete a field.** Replace it with `reserved <tag>`.
2. **Never change a field's type** (e.g. `string` → `bytes`). Add a new field
   under a new tag instead.
3. **Tag numbers 1–15** are 1-byte on the wire — reserve them for hot-path
   fields. Use 16+ for rare fields.
4. **Forward-compat fields** (DISK-0015 / DISK-0017 / DISK-0020) are populated
   with the proto3 default in self-hosted v1.0. Do not gate them behind a
   feature flag — they must be present on every node.
5. **Service version negotiation** lands in DISK-0004 via the first RPC of
   `ExchangeState`. Do not add per-RPC version fields meanwhile.

## SQLite migration rules

1. **Append-only.** Never edit a migration file once it lands on `main`. Add a
   new `00X_description.sql` instead.
2. **Backfill safely.** When adding a `NOT NULL` column to an existing table,
   ship a default first, then drop the default in a follow-up migration once
   all clients have upgraded.
3. **Forward-compat columns** (`tenant_id`, `vault_id`, `user_id`,
   `version_id`, `parent_version_id`, `encryption_nonce`) live on every table
   from day one and stay nullable / defaulted in self-hosted v1.0.

## Logging discipline

Never log raw `api_key`, `session_token`, file content, or `encryption_nonce`.
PR review will reject violations.

## License

By submitting a PR you agree to license your contribution under MIT, the
license of the rest of this repository.
