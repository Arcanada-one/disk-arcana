# Disk Arcana

> Open-source self-hosted file synchronisation engine for AI knowledge bases.
> Built for Obsidian-style vaults where mass file-sync products (Syncthing,
> Dropbox, iCloud) corrupt code subprojects, embedding stores, and AI agent
> state.

**Status:** Active development — mTLS bidirectional sync is functional (as of
DISK-0056). The server and client daemons exchange deltas over gRPC with mutual
TLS (Disk-mesh CA), GPG-signed ACL, and per-node blake3 cert fingerprint
identity. The production deployment path (Disk-mesh CA provisioning, systemd +
launchd bring-up, and canon migration) is covered by DISK-0057.
Earlier phases landed the crate skeleton, wire format, SQLite schema, sync
engine, conflict resolution, and CI gate that these daemons build on.

## Architecture

```
+----------------------------------------+        +----------------------------+
|              disk-client               |  gRPC  |        disk-server         |
|  (file watcher, scanner, reconciler)   | <----> | (multi-node coordinator,   |
|                                        |        |  conflict broker, store)   |
+----------------------------------------+        +----------------------------+
                |                                              |
                v                                              v
          local SQLite                                   server SQLite
          (files, tombstones,                             + nodes table
           sync_queue, conflicts)
```

Crates:

- `disk-proto`   — generated tonic bindings, single source of truth for the wire format.
- `disk-core`    — types, errors, config, metadata DB, sync traits.
- `disk-server`  — server daemon binary.
- `disk-client`  — client daemon binary.
- `disk-cli`     — operator CLI (`disk init`, `disk status`, ...).

## Phase Roadmap

| Phase        | Tasks            | Status |
| ------------ | ---------------- | ------ |
| Foundation   | DISK-0002        | done |
| Core sync    | DISK-0003        | done |
| Transport    | DISK-0004        | done |
| Server       | DISK-0005        | done |
| Client       | DISK-0006        | done |
| Conflicts    | DISK-0007        | done |
| Prod sync    | DISK-0057        | in-progress (config phase done; rollout operator-gated) |
| v1.0 MVP     | DISK-0008..0014  | planned |
| v1.5 / SaaS  | DISK-0015..0030  | planned |

The full backlog and PRD live in the upstream Datarim project.

## Build

Requirements: Rust stable (`rustup install stable`), `protoc` 25+
(`brew install protobuf` / `apt-get install protobuf-compiler`).

```sh
cargo build --workspace --all-features
cargo test  --workspace --all-features
```

The daemons are fully functional. Example:

```sh
cargo run --bin disk-arcana-server -- --help
cargo run --bin disk               -- --help
```

For a local end-to-end test (self-signed stub CA, no real mTLS cert needed):

```sh
./scripts/dev-local-e2e.sh
```

## Configuration

Copy `disk.toml.example` → `disk.toml`. The schema is consumed by `disk-core`
in Phase 1 and by the daemons starting from DISK-0006.

## Security

See [`SECURITY.md`](SECURITY.md) for responsible disclosure. The Phase 1 attack
surface is empty (no daemon, no network, no user data) but the proto/SQLite
schema is locked in here — contributing rules in
[`CONTRIBUTING.md`](CONTRIBUTING.md) preserve forward compatibility.

## License

[MIT](LICENSE).
