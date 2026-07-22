# Disk Arcana iOS (DISK-0014 scaffold)

SwiftUI application shell. Implementation slices are tracked under DISK-0014.

## Bootstrap (operator)

```bash
# Future: xcodegen or swift package init in this directory
open clients/mobile/ios/README.md
```

## Minimum viable surface

- Sign in via Auth Arcana OIDC (`auth.arcanada.ai`)
- List shares from daemon REST or embedded `disk-client` FFI
- Read-only file browser for synced vault paths

## Not in scaffold

- App Store signing, TestFlight, background URLSession sync (slice 2+)
