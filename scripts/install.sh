#!/usr/bin/env sh
# DISK-0010 — curl | sh client installer (Linux / macOS).
#
# Downloads the `disk` CLI from GitHub Releases when a matching asset exists,
# otherwise prints build-from-source instructions.
#
# Usage:
#   curl -fsSL https://disk.arcanada.ai/install.sh | sh
#   DISK_VERSION=v0.1.0 sh install.sh

set -eu

REPO="Arcanada-one/disk-arcana"
PREFIX="${DISK_INSTALL_PREFIX:-/usr/local/bin}"
VERSION="${DISK_VERSION:-}"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch="x86_64" ;;
  aarch64|arm64) arch="aarch64" ;;
  *)
    echo "error: unsupported architecture: $arch" >&2
    exit 1
    ;;
esac

case "$os" in
  linux) platform="linux" ;;
  darwin) platform="macos" ;;
  *)
    echo "error: unsupported OS: $os (use Windows zip from GitHub Releases)" >&2
    exit 1
    ;;
esac

asset_name="disk-${platform}-${arch}"

if [ -z "$VERSION" ]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])')"
fi

if [ -z "$VERSION" ]; then
  echo "error: could not resolve latest release tag" >&2
  exit 1
fi

echo "==> Disk Arcana client installer (${platform}/${arch}, ${VERSION})"

release_json="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/tags/${VERSION}")"
download_url="$(printf '%s' "$release_json" | ASSET="$asset_name" python3 -c '
import json, os, sys
data = json.load(sys.stdin)
want = os.environ["ASSET"]
for a in data.get("assets", []):
    if a.get("name") == want:
        print(a["browser_download_url"])
        break
')"

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/disk-install.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT INT TERM

if [ -n "$download_url" ]; then
  echo "==> downloading ${asset_name} from ${VERSION}"
  curl -fsSL "$download_url" -o "${tmpdir}/disk"
  chmod +x "${tmpdir}/disk"
  mkdir -p "$PREFIX"
  if [ -w "$PREFIX" ]; then
    install -m 0755 "${tmpdir}/disk" "${PREFIX}/disk"
  else
    echo "==> installing to ${PREFIX}/disk (sudo)"
    sudo install -m 0755 "${tmpdir}/disk" "${PREFIX}/disk"
  fi
  if "${PREFIX}/disk" --version >/dev/null 2>&1; then
    "${PREFIX}/disk" --version
  else
    echo "==> installed ${PREFIX}/disk"
  fi
  echo
  echo "Next: configure and enroll — see docs/installation.md"
  exit 0
fi

cat <<EOF
No prebuilt binary '${asset_name}' on release ${VERSION}.

Build from source:
  git clone https://github.com/${REPO}.git
  cd disk-arcana
  cargo build --release -p disk-cli
EOF

if [ "$platform" = "linux" ]; then
  cat <<EOF
  sudo ./scripts/install-linux.sh --binary ./target/release/disk
EOF
else
  cat <<EOF
  sudo ./scripts/install-macos.sh --binary ./target/release/disk
EOF
fi

exit 1
