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

## Dependency advisory policy

Both `cargo audit` and `cargo deny check` run on every CI build and must pass
with no `--ignore` flags on the command line. A suppression is a last resort: an
advisory is closed by upgrading, replacing or feature-gating the crate, and only
when none of those is possible does it get an entry — with a dated rationale, an
exploitability argument, and a retirement condition — in
[`.cargo/audit.toml`](.cargo/audit.toml) or [`deny.toml`](deny.toml).

Note that cargo-audit reads only `.cargo/audit.toml`; a root `.audit.toml` is
silently ignored. The repo carried such a file until DISK-0066, and because CI
duplicated its entries as command-line flags, its rationale went stale without
anyone noticing.

### Currently suppressed

- **RUSTSEC-2023-0071** (`rsa` — Marvin Attack timing side-channel). Pulled in
  via `sqlx-mysql`, which is recorded in `Cargo.lock` because cargo records every
  optional sqlx feature. Disk Arcana ships `sqlite`-only, so the MySQL driver —
  and therefore the vulnerable code path — is never compiled into a shipped
  binary. Visible to cargo-audit (lockfile scan) but not cargo-deny (feature
  graph), so it is suppressed only in `.cargo/audit.toml`. Retire on the sqlx 0.9
  upgrade. Tracked: <https://github.com/launchbadge/sqlx/issues/2876>.

### Closed by remediation in DISK-0066 (ARCA-0194 R6-17)

None of the following is suppressed — each was fixed in the dependency graph, so
a regression would fail CI rather than pass silently:

- **RUSTSEC-2026-0194 / RUSTSEC-2026-0195** (`quick-xml` 0.39.4, two high-severity
  DoS vectors). Fixed by `wayland-scanner` 0.31.11, which requires
  `quick-xml ^0.41` — a semver-compatible lockfile bump. The previous note here
  claimed the bump was blocked behind an egui-stack upgrade; that was wrong.
- **RUSTSEC-2026-0192** (`ttf-parser` unmaintained, no fixed release). Fixed by
  upgrading `eframe` 0.29 → 0.34: epaint 0.34 replaced `ab_glyph`
  (→ `owned_ttf_parser` → `ttf-parser`) with `skrifa`, the maintained crate the
  advisory itself recommends. `ttf-parser` is no longer in the tree.
- **Yanked `spin` 0.9.8** (reached via `flume` → `sqlx-sqlite` and `mdns-sd`).
  Fixed by pinning the unyanked `spin` 0.9.9, which satisfies flume's `^0.9.8`
  requirement — no sqlx upgrade needed. `deny.toml` keeps `yanked = "warn"`.
