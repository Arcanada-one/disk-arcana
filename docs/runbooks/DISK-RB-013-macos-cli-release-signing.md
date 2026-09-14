# DISK-RB-013 — macOS CLI release signing and notarization

Gatekeeper trust for the public `disk` CLI binary (v0.1.0+). Operators run this on a **Mac** or configure GitHub Secrets for the `build-macos-client` release job.

**Hard gate:** never open RB-011 (`:9445` WAN enrollment). This runbook covers **client binary distribution** only.

## Packaging path (arcana-devs / release)

| Stage | Path | Notes |
|-------|------|-------|
| Install script | `scripts/install.sh` | Downloads `disk-macos-arm64` or `disk-macos-x86_64` from GitHub Releases |
| Release assets | `disk-macos-{arm64,x86_64}` | **Missing on v0.1.0** — only `disk-arcana-server` was attached; re-tag after signing |
| Local Mac build | `target/{aarch64,x86_64}-apple-darwin/release/disk` | `scripts/build-macos-release.sh` |
| Install target | `/usr/local/bin/disk` | `scripts/install-macos.sh --binary <path>` |
| CI job | `.github/workflows/release-deploy.yml` → `build-macos-client` | Tag push `v*.*.*`, `macos-14` runner |

arcana-devs is **Linux-only** — codesign/notarytool cannot run there. On DEVS, verify **packaging only**:

```bash
# From disk-arcana repo on arcana-devs (or any Linux host)
./scripts/verify-macos-release-assets.sh              # list assets on latest tag
DISK_VERSION=v0.1.0 ./scripts/verify-macos-release-assets.sh --download  # + Mach-O probe
```

Build/sign on operator Mac or macOS CI (`build-macos-client` job, `macos-14` runner).

## Operator prerequisites (stop if any missing)

### Required for codesign

1. **Apple Developer Program** membership (paid).
2. **Developer ID Application** certificate in the Mac login keychain (export from developer.apple.com → Certificates).
3. Identity string, e.g. `Developer ID Application: Pavel Valentov (ABCDE12345)`:

```bash
security find-identity -v -p codesigning
export DISK_SIGN_IDENTITY="Developer ID Application: … (TEAMID)"
```

### Required for Gatekeeper (notarization — strongly recommended)

4. **App-specific password** (appleid.apple.com → Sign-In and Security → App-Specific Passwords) **or** App Store Connect API key (`.p8`).
5. **Team ID** (developer.apple.com → Membership).
6. Store notarytool credentials once per Mac:

```bash
xcrun notarytool store-credentials disk-notary \
  --apple-id "you@example.com" \
  --team-id "TEAMID" \
  --password "xxxx-xxxx-xxxx-xxxx"

export DISK_NOTARY_KEYCHAIN_PROFILE="disk-notary"
```

### Required for GitHub Actions release job

Configure repository secrets on `Arcanada-one/disk-arcana`:

| Secret | Purpose |
|--------|---------|
| `DISK_MACOS_CERT_P12` | Base64 of `.p12` export (Developer ID Application cert + private key) |
| `DISK_MACOS_CERT_PASSWORD` | Password used when exporting the `.p12` |
| `DISK_SIGN_IDENTITY` | Full codesign identity string |
| `DISK_NOTARY_APPLE_ID` | Apple ID email for notarytool |
| `DISK_NOTARY_TEAM_ID` | 10-character Team ID |
| `DISK_NOTARY_PASSWORD` | App-specific password |
| `DISK_NOTARY_KEYCHAIN_PROFILE` | Profile name (e.g. `disk-notary`) — created in CI before sign |

**Current status (2026-08-05):** none of these secrets are configured; CI signing will fail until the operator adds them.

## Procedure — operator Mac (manual v0.1.0 resign)

```bash
git clone https://github.com/Arcanada-one/disk-arcana.git
cd disk-arcana
git checkout v0.1.0   # or main

# Build both architectures (on Apple Silicon Mac)
export DISK_SIGN_IDENTITY="Developer ID Application: … (TEAMID)"
export DISK_NOTARY_KEYCHAIN_PROFILE="disk-notary"

./scripts/build-macos-release.sh
# outputs: dist/macos/disk-macos-arm64, dist/macos/disk-macos-x86_64
```

Or sign a single binary:

```bash
cargo build --release -p disk-cli --bin disk
./scripts/sign-macos-cli.sh ./target/release/disk
```

## Verification (expect ALLOW / accepted)

```bash
disk=./dist/macos/disk-macos-arm64   # or signed target/release/disk

codesign --verify --strict -vvv "$disk"
# expect: valid on disk; satisfies its Designated Requirement

spctl --assess --type execute -vv "$disk"
# expect: accepted (source=Notarized Developer ID when notarized)

spctl -a -vv -t install "$disk"
# expect: accepted (install/quarantine context)

./"$disk" --help
```

After download via browser/curl, Gatekeeper also checks quarantine xattr; notarized+stapled binaries pass `spctl` on the file itself.

## Attach to GitHub Release

After verification:

```bash
gh release upload v0.1.0 dist/macos/disk-macos-arm64 dist/macos/disk-macos-x86_64 \
  --repo Arcanada-one/disk-arcana
```

Then `curl -fsSL https://disk.arcanada.ai/install.sh | sh` on macOS will fetch a signed asset.

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `DISK_SIGN_IDENTITY is not set` | Export identity; see prerequisites §1–3 |
| `signing identity not found` | Import `.p12` into login keychain; unlock keychain |
| `notarytool profile not found` | Run `notarytool store-credentials` |
| `spctl: rejected` | Notarize + staple; or check hardened runtime (`--options runtime`) |
| `cannot run on Linux` | Use operator Mac — arcana-devs cannot sign |

## Related

- `scripts/verify-macos-release-assets.sh` — DEVS/Linux release asset probe (no codesign)
- `scripts/sign-macos-cli.sh` — sign + optional notarize + verify
- `scripts/build-macos-release.sh` — dual-arch release build
- `scripts/install.sh` — public installer (expects signed release assets)
- DISK-RB-001 — enroll after install
