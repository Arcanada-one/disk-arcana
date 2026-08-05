#!/usr/bin/env bash
# Sign (and optionally notarize) the public `disk` CLI binary for macOS Gatekeeper.
#
# Requires macOS with Xcode CLT. Never runs on Linux CI hosts.
#
# Environment:
#   DISK_SIGN_IDENTITY          Developer ID Application identity (required)
#   DISK_NOTARY_KEYCHAIN_PROFILE  notarytool keychain profile (optional; enables notarize+staple)
#
# Usage:
#   export DISK_SIGN_IDENTITY="Developer ID Application: … (TEAMID)"
#   export DISK_NOTARY_KEYCHAIN_PROFILE="disk-notary"   # optional
#   ./scripts/sign-macos-cli.sh ./target/aarch64-apple-darwin/release/disk
#
# Verification (exit 0 = Gatekeeper-ready):
#   codesign --verify --strict -vvv <binary>
#   spctl -a -vv -t install <binary>   # expect: accepted (source=Notarized Developer ID or Developer ID)

set -euo pipefail

BINARY="${1:-}"
if [[ -z "$BINARY" || ! -f "$BINARY" ]]; then
  echo "usage: $0 <path/to/disk-binary>" >&2
  exit 2
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: codesign/notarytool require macOS (got $(uname -s))" >&2
  exit 1
fi

for tool in codesign security spctl xcrun; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: missing macOS tool: $tool (install Xcode Command Line Tools)" >&2
    exit 1
  fi
done

SIGN_IDENTITY="${DISK_SIGN_IDENTITY:-${APPLE_SIGNING_IDENTITY:-}}"
NOTARY_PROFILE="${DISK_NOTARY_KEYCHAIN_PROFILE:-${APPLE_NOTARY_KEYCHAIN_PROFILE:-}}"

if [[ -z "$SIGN_IDENTITY" ]]; then
  echo "error: DISK_SIGN_IDENTITY is not set" >&2
  echo >&2
  echo "Missing operator prerequisites:" >&2
  echo "  1. Apple Developer Program membership (paid)" >&2
  echo "  2. 'Developer ID Application' certificate installed in login keychain" >&2
  echo "     (Keychain Access → My Certificates, or import .p12 from developer.apple.com)" >&2
  echo "  3. Export identity string, e.g.:" >&2
  echo '       export DISK_SIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)"' >&2
  echo "     List candidates:" >&2
  echo "       security find-identity -v -p codesigning" >&2
  exit 1
fi

if ! security find-identity -v -p codesigning 2>/dev/null | grep -Fq "$SIGN_IDENTITY"; then
  echo "error: signing identity not found in keychain: $SIGN_IDENTITY" >&2
  echo "Available Developer ID / codesigning identities:" >&2
  security find-identity -v -p codesigning 2>/dev/null | grep -E 'Developer ID|Apple Development' || true
  exit 1
fi

chmod +x "$BINARY"

echo "==> codesign (hardened runtime + timestamp): $BINARY"
codesign --force --options runtime --timestamp \
  --sign "$SIGN_IDENTITY" \
  "$BINARY"

echo "==> codesign --verify --strict"
codesign --verify --strict -vvv "$BINARY"

if [[ -n "$NOTARY_PROFILE" ]]; then
  if ! xcrun notarytool history --keychain-profile "$NOTARY_PROFILE" >/dev/null 2>&1; then
    echo "error: notarytool keychain profile '$NOTARY_PROFILE' not found" >&2
    echo >&2
    echo "Missing operator prerequisites for notarization:" >&2
    echo "  1. App-specific password OR App Store Connect API key (recommended)" >&2
    echo "  2. Store credentials once:" >&2
    echo "       xcrun notarytool store-credentials \"$NOTARY_PROFILE\" \\" >&2
    echo "         --apple-id \"you@example.com\" \\" >&2
    echo "         --team-id \"TEAMID\" \\" >&2
    echo "         --password \"app-specific-password\"" >&2
    echo "     Or API key: --key /path/to/AuthKey.p8 --key-id … --issuer …" >&2
    echo "  3. export DISK_NOTARY_KEYCHAIN_PROFILE=\"$NOTARY_PROFILE\"" >&2
    exit 1
  fi

  workdir="$(mktemp -d "${TMPDIR:-/tmp}/disk-notarize.XXXXXX")"
  trap 'rm -rf "$workdir"' EXIT INT TERM
  zip_path="${workdir}/disk.zip"
  bin_name="$(basename "$BINARY")"
  cp "$BINARY" "${workdir}/${bin_name}"
  (
    cd "$workdir"
    zip -q "$zip_path" "$bin_name"
  )

  echo "==> notarytool submit (profile=$NOTARY_PROFILE)"
  xcrun notarytool submit "$zip_path" --keychain-profile "$NOTARY_PROFILE" --wait

  echo "==> stapler staple"
  xcrun stapler staple "$BINARY"
else
  echo "==> skipping notarization (DISK_NOTARY_KEYCHAIN_PROFILE unset)"
  echo "    Gatekeeper may still block downloaded binaries without notarization on modern macOS."
fi

echo "==> spctl --assess --type execute -vv"
if ! spctl --assess --type execute -vv "$BINARY" 2>&1 | tee /dev/stderr | grep -qiE 'accepted|allow'; then
  echo "error: spctl --assess did not report accepted/allow" >&2
  exit 1
fi

echo "==> spctl -a -t install -vv (download/install context)"
spctl -a -vv -t install "$BINARY" 2>&1 | tee /dev/stderr || true

echo "==> OK: $BINARY is signed (and notarized when profile was set)"
