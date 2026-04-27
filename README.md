# Disk Arcana

> Open-source self-hosted file synchronisation engine for AI knowledge bases.
> Built for Obsidian-style vaults where mass file-sync products (Syncthing,
> Dropbox, iCloud) corrupt code subprojects, embedding stores, and AI agent
> state.

**Status:** Phase 1 scaffold (`v0.0.1-phase1`). No functional sync yet — the
crate skeleton, wire format, SQLite schema, and CI gate land here so subsequent
phases (DISK-0003 sync engine, DISK-0004 transport, ...) build on a stable
foundation.

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
| Foundation   | DISK-0002        | in-progress (this scaffold) |
| Core sync    | DISK-0003        | planned |
| Transport    | DISK-0004        | planned |
| Server       | DISK-0005        | planned |
| Client       | DISK-0006        | planned |
| Conflicts    | DISK-0007        | planned |
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

The Phase 1 binaries are stubs that print their version and exit:

```sh
cargo run --bin disk-server
# disk-server v0.0.1 (Phase 1 stub)
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
