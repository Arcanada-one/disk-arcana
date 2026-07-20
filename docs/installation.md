# Installation

Disk Arcana ships a **client** (`disk` CLI + daemon) and a **server** (`disk-arcana-server`).
This guide covers the client; server deployment is operator-run on Linux.

## Quick install (Linux x86_64)

When a release asset is published:

```bash
curl -fsSL https://disk.arcanada.ai/install.sh | sh
```

Or download the script and inspect before running:

```bash
curl -fsSL https://disk.arcanada.ai/install.sh -o install.sh
less install.sh
sh install.sh
```

Environment variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `DISK_INSTALL_PREFIX` | `/usr/local/bin` | Binary destination |
| `DISK_VERSION` | latest GitHub release | Pin a tag (e.g. `v0.1.0`) |

## Build from source

Requirements: Rust stable, `protoc` 25+.

```bash
git clone https://github.com/Arcanada-one/disk-arcana.git
cd disk-arcana
cargo build --release -p disk-cli
sudo ./scripts/install-linux.sh --binary ./target/release/disk
```

## macOS

```bash
cargo build --release -p disk-cli
sudo ./scripts/install-macos.sh --binary ./target/release/disk
```

## Windows

Download `disk-arcana-windows-x86_64.zip` from [GitHub Releases](https://github.com/Arcanada-one/disk-arcana/releases)
or build locally, then follow `docs/runbooks/DISK-RB-008-windows-vm-e2e.md`.

## After install

1. Copy `disk.toml.example` → `/etc/disk-arcana/disk.toml` (Linux) or edit the seeded file.
2. Enroll: see operator runbook DISK-RB-001 (token + `disk enroll`).
3. Check status: `curl -sf http://127.0.0.1:9444/status | jq .`

## Uninstall

- Linux: `scripts/uninstall-linux.sh` (when present) or disable `disk-arcana.service` and remove unit.
- Windows: `scripts/uninstall-windows.ps1` (portable zip).

## Related

- [README](../README.md)
- [Windows platform notes](windows-platform-notes.md)
- [OWASP gRPC checklist](security/OWASP-gRPC-audit.md)
