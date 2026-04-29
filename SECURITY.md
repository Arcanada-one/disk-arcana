# Security Policy

## Reporting a vulnerability

Send a private email to **security@arcanada.one** with:

- a description of the issue,
- reproduction steps (proof-of-concept welcome),
- the affected commit / tag,
- your contact for follow-up.

Please **do not** open a public GitHub issue or PR for security findings. We
will acknowledge receipt within **5 business days** and aim to provide a fix
or mitigation timeline within **14 days**.

## Supported versions

Until `v1.0` only the current `main` branch is supported. After `v1.0` we will
publish a support matrix in this file.

## Hardening commitments (Phase 1+)

- All Rust code in `disk-core` and `disk-server` enforces `#![forbid(unsafe_code)]`.
- CI runs `cargo audit --deny warnings`, `cargo deny check licenses`, and gitleaks on every push.
- Coverage gate: `cargo llvm-cov --workspace --fail-under-lines 80` (DISK-0032) — build fails if line coverage drops below 80 %.
- No secrets land in git history — `.gitignore` excludes `.env` / `disk.toml`
  / `*.db`, and gitleaks gates the lint job.
- Logs MUST NOT contain `api_key`, `session_token`, `encryption_nonce`, or raw
  file content. `ApiKey` and `SessionToken` types mask themselves in `Display`
  and `Debug` (`arc_disk_***` / `arc_disk_sess_***`). Reviewers will reject PRs
  that violate this rule.

## Phase 3 threat model (gRPC transport, DISK-0004)

| ID   | Threat                         | Mitigation                                                                   |
|------|--------------------------------|------------------------------------------------------------------------------|
| V-7  | Clean-sync data loss           | Two-node integration test (TLS loopback, byte equality assertion)            |
| V-8  | TLS downgrade (1.2)            | `rustls 0.23` TLS 1.3-only `ServerConfig`; ALPN `h2`; test rejects TLS 1.2 client |
| V-9  | Replay / out-of-order chunks   | `ReplayGuard`: per-(node, stream) monotonic `sequence_id`; duplicates → `InvalidArgument` |
| V-11 | Path traversal                 | `path_guard` rejects any path containing `..` → `InvalidArgument`           |
| V-12 | Unauthenticated sync access    | Bearer token required on every `SyncService` RPC; missing/invalid → `Unauthenticated` |
| V-13 | Decompression bomb             | `BombGuard`: 4 MiB compressed / 16 MiB decompressed / 256 MiB stream caps   |
| V-14 | Secret leak in logs            | `ApiKey`/`SessionToken` masked in `Display`/`Debug`                          |

## Known suppressed advisories

`cargo audit` ignores two advisories at the workspace level (rationale in
[`.audit.toml`](.audit.toml) and [`deny.toml`](deny.toml)):

- **RUSTSEC-2023-0071** (`rsa` — Marvin Attack timing side-channel). Pulled
  in via `sqlx-mysql`, which is locked into `Cargo.lock` because cargo
  records every optional sqlx feature. Disk Arcana ships `sqlite`-only, so
  the MySQL driver — and therefore the vulnerable code path — is never
  instantiated. Tracked: <https://github.com/launchbadge/sqlx/issues/2876>.
- ~~**RUSTSEC-2025-0134**~~ (`rustls-pemfile` — unmaintained). Was transitive
  through `tonic` 0.12. Resolved: upgraded to `tonic` 0.13 in DISK-0004.
