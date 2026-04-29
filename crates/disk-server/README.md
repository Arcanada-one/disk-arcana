# disk-server

gRPC server crate for Disk Arcana Phase 3 (DISK-0004).

Implements two tonic services over TLS 1.3:

| Service       | RPC               | Auth required | Notes                              |
|---------------|-------------------|---------------|------------------------------------|
| AuthService   | RegisterNode      | No            | Issues `arc_disk_*` API keys       |
| AuthService   | Authenticate      | No            | Returns `arc_disk_sess_*` tokens   |
| SyncService   | DeltaDownload     | Bearer token  | Server-streaming, zstd compressed  |
| SyncService   | DeltaUpload       | Bearer token  | Client-streaming, blake3 verified  |
| SyncService   | SyncState         | Bearer token  | Bidi-streaming with replay guard   |

## Security controls

- **TLS 1.3 only** — `rustls 0.23` server config, ALPN `h2`.
- **Bearer token auth** — every `SyncService` RPC checks `Authorization: Bearer arc_disk_sess_*`.
- **Path traversal guard** — any path containing `..` is rejected with `InvalidArgument`.
- **Anti-replay** — monotonic `sequence_id` per (node, stream); duplicates rejected.
- **Decompression bomb guard** — 4 MiB / 16 MiB / 256 MiB caps.
- **Log redaction** — `ApiKey` and `SessionToken` mask themselves in `Display`/`Debug`.

See [SECURITY.md](../../SECURITY.md) for the full Phase 3 threat model.

## Public API

```rust
use disk_server::{
    AuthServiceImpl, AuthStore, SyncServiceImpl,
    CertProvider, DevSelfSignedProvider, StaticPemProvider,
    ApiKey, SessionToken,
    middleware::replay::ReplayGuard,
    middleware::bomb_guard::{compress, decompress_guarded},
};
```

## TLS providers

```rust
// Development: ephemeral self-signed cert (rcgen).
let (server_cfg, cert_der) = DevSelfSignedProvider::generate()?;

// Production: pre-provisioned PEM files.
let provider = StaticPemProvider::from_files("cert.pem", "key.pem");
let server_cfg = provider.server_config()?;
```

## Minimum example (test harness)

See `tests/two_node_round_trip.rs` for a complete two-node loopback example
that exercises register → authenticate → delta_download in a single test.
