#!/usr/bin/env bash
# Verify macOS CLI release assets from GitHub (runs on Linux / arcana-devs — no codesign).
#
# Checks packaging contract for scripts/install.sh:
#   disk-macos-arm64, disk-macos-x86_64
#
# Full Gatekeeper trust (codesign --verify, spctl --assess) requires macOS — see
# scripts/sign-macos-cli.sh and docs/runbooks/DISK-RB-013-macos-cli-release-signing.md.
#
# Usage:
#   ./scripts/verify-macos-release-assets.sh
#   DISK_VERSION=v0.1.0 ./scripts/verify-macos-release-assets.sh
#   ./scripts/verify-macos-release-assets.sh --download   # fetch + Mach-O probe

set -euo pipefail

REPO="${DISK_RELEASE_REPO:-Arcanada-one/disk-arcana}"
VERSION="${DISK_VERSION:-}"
DOWNLOAD=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --download) DOWNLOAD=1; shift ;;
    -h|--help)
      sed -n '2,14p' "$0"
      exit 0
      ;;
    *)
      echo "unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$VERSION" ]]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])')"
fi

echo "==> release ${REPO} tag ${VERSION}"

release_json="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/tags/${VERSION}")"

missing=0
for asset in disk-macos-arm64 disk-macos-x86_64; do
  url="$(printf '%s' "$release_json" | ASSET="$asset" python3 -c '
import json, os, sys
data = json.load(sys.stdin)
want = os.environ["ASSET"]
for a in data.get("assets", []):
    if a.get("name") == want:
        print(a["browser_download_url"])
        break
')"
  if [[ -z "$url" ]]; then
    echo "MISSING asset: $asset"
    missing=$((missing + 1))
    continue
  fi
  size="$(printf '%s' "$release_json" | ASSET="$asset" python3 -c '
import json, os, sys
data = json.load(sys.stdin)
want = os.environ["ASSET"]
for a in data.get("assets", []):
    if a.get("name") == want:
        print(a.get("size", 0))
        break
')"
  echo "OK asset listed: $asset (${size} bytes)"

  if [[ "$DOWNLOAD" -eq 1 ]]; then
    tmp="$(mktemp)"
    curl -fsSL "$url" -o "$tmp"
    chmod +x "$tmp"
    if command -v file >/dev/null 2>&1; then
      kind="$(file -b "$tmp")"
      echo "    file: $kind"
      if [[ "$kind" != *"Mach-O"* ]]; then
        echo "    ERROR: expected Mach-O executable for $asset" >&2
        missing=$((missing + 1))
      fi
    else
      magic="$(head -c 4 "$tmp" | od -An -tx1 | tr -d ' \n')"
      if [[ "$magic" != "cffaedfe" ]]; then
        echo "    ERROR: bad Mach-O magic for $asset (got $magic)" >&2
        missing=$((missing + 1))
      else
        echo "    Mach-O magic OK (cffaedfe)"
      fi
    fi
    rm -f "$tmp"
  fi
done

# install.sh contract cross-check
install_asset="$(printf '%s' "$release_json" | python3 -c '
import json, sys
data = json.load(sys.stdin)
names = {a.get("name") for a in data.get("assets", [])}
for p, a in [("linux", "x86_64"), ("linux", "aarch64"), ("macos", "arm64"), ("macos", "x86_64")]:
    n = f"disk-{p}-{a}"
    status = "present" if n in names else "missing"
    print(f"{n}: {status}")
')"

echo ""
echo "==> install.sh asset matrix (${VERSION}):"
echo "$install_asset"

if [[ "$missing" -gt 0 ]]; then
  echo ""
  echo "FAIL: $missing macOS asset(s) missing or invalid on ${VERSION}" >&2
  echo "Signing/notarization runs on macOS CI or operator Mac — not on arcana-devs." >&2
  echo "See docs/runbooks/DISK-RB-013-macos-cli-release-signing.md" >&2
  exit 1
fi

echo ""
echo "PASS: macOS release assets present for ${VERSION}"
echo "Next (macOS only): codesign --verify --strict -vvv <binary>"
echo "                   spctl --assess --type execute -vv <binary>   # expect: ALLOW"
