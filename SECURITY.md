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

- All Rust code in `disk-core` enforces `#![forbid(unsafe_code)]`.
- CI runs `cargo audit`, `cargo deny check licenses`, and gitleaks on every push.
- No secrets land in git history — `.gitignore` excludes `.env` / `disk.toml`
  / `*.db`, and gitleaks gates the lint job.
- Logs MUST NOT contain `api_key`, `session_token`, `encryption_nonce`, or raw
  file content. Reviewers will reject PRs that violate this rule.

## Known suppressed advisories

`cargo audit` ignores two advisories at the workspace level (rationale in
[`.audit.toml`](.audit.toml) and [`deny.toml`](deny.toml)):

- **RUSTSEC-2023-0071** (`rsa` — Marvin Attack timing side-channel). Pulled
  in via `sqlx-mysql`, which is locked into `Cargo.lock` because cargo
  records every optional sqlx feature. Disk Arcana ships `sqlite`-only, so
  the MySQL driver — and therefore the vulnerable code path — is never
  instantiated. Tracked: <https://github.com/launchbadge/sqlx/issues/2876>.
- **RUSTSEC-2025-0134** (`rustls-pemfile` — unmaintained). Transitive
  through `tonic` 0.12. Removed in `tonic` 0.13; drops automatically when we
  upgrade.
