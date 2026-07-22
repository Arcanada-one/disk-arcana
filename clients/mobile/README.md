# Disk Arcana — Mobile Clients (DISK-0014)

Commercial v2.0 track: native iOS and Android apps for read-mostly vault access,
offline cache, and push notifications for agent webhooks.

## Status

**Scaffold only** — no store binaries yet. Rust core (`disk-core`, `disk-client`)
is the shared sync engine; mobile shells are thin native UI layers.

## Layout

```
clients/mobile/
  README.md          # this file
  ios/               # SwiftUI shell (DISK-0014 slice 1)
  android/           # Kotlin / Jetpack Compose shell (DISK-0014 slice 2)
  shared/            # Cross-platform contract notes (gRPC + REST loopback parity)
```

## Planned slices

| Slice | Platform | In scope |
|-------|----------|----------|
| 1 | iOS | Xcode project, Auth Arcana OIDC, read-only share browser |
| 2 | Android | Gradle module, same API surface as iOS |
| 3 | Both | Background delta sync, E2EE unlock via escrow (DISK-0015 slice 6) |
| 4+ | Both | Write path, billing gate (DISK-0018), App Store / Play release |

## API dependencies

- gRPC mTLS sync (`disk-client` Rust FFI or gRPC-Swift / grpc-java)
- Loopback REST for status/conflicts when co-installed with daemon (optional)
- Enrollment `:9445` per `DISK-RB-001`

## References

- Parent epic: DISK-0001
- E2EE: `docs/design/DISK-0015-e2ee-scaffold.md`
- Billing tiers: `docs/design/DISK-0018-billing-scaffold.md`
