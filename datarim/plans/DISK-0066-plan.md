# DISK-0066 — Dependency remediation, R6-17 (plan)

**Status:** implemented; verification green on the real tree
**Branch:** `sec/DISK-0066-dependency-remediation` (PR #128)
**Epic:** ARCA-0194 R6-17

## Goal

Clear every vulnerable, unmaintained and yanked dependency from the workspace
**without weakening policy**. Suppressions may not be used to make warnings go
away; each advisory is closed by an upgrade, a replacement, or — only where
neither exists — a documented exception the policy already supports, carrying a
retirement condition.

Acceptance: `cargo audit` and `cargo deny check` both pass on the real tree.

## Findings

Baseline at `cffed52` — four items, none of which actually needed an exception:

| Item | Advisory | Reached via |
|---|---|---|
| `quick-xml` 0.39.4 | RUSTSEC-2026-0194, RUSTSEC-2026-0195 (7.5 high, DoS) | `wayland-scanner` (build-time, egui stack) |
| `ttf-parser` 0.25.1 | RUSTSEC-2026-0192 (unmaintained, no fixed release) | `ab_glyph` → `epaint` → `egui` → `eframe` |
| `spin` 0.9.8 | yanked | `flume` → `sqlx-sqlite`, `mdns-sd` |
| `rsa` 0.9.10 | RUSTSEC-2023-0071 (5.9 medium) | `sqlx-mysql` — feature never enabled |

The checked-in rationale asserted that quick-xml and ttf-parser were both
blocked behind "the whole egui 0.29 stack upgrade". Registry metadata
contradicted this on both counts.

## Approach

1. **quick-xml** — `wayland-scanner` 0.31.11 requires `quick-xml ^0.41`, and
   0.31.10 → 0.31.11 is semver-compatible. Lockfile-only, no manifest change.
2. **ttf-parser** — `epaint` 0.34 dropped `ab_glyph` (and with it
   `owned_ttf_parser` → `ttf-parser`) in favour of **skrifa**, precisely the
   maintained crate RUSTSEC-2026-0192 recommends. Bump `eframe` 0.29 → 0.34,
   the earliest release carrying the skrifa switch.

   This is a breaking GUI migration and cannot be avoided: 0.34 already replaces
   `App::update` with the required `App::ui`, and already ships the `Panel`
   redesign (`TopBottomPanel` is a deprecated alias, `show` → `show_inside`).
   0.35 was evaluated and rejected — it goes further still, removing
   `TopBottomPanel` outright, for no additional security benefit.

   Because the migration is unavoidable, its behavioural deltas must be reviewed
   rather than assumed. QA caught one: 0.34's `Panel::new` defaults `resizable`
   to `true` where 0.29's `TopBottomPanel::new` defaulted to `false`, which made
   the header and status bars user-draggable down to 20px. Both now pass
   `.resizable(false)` explicitly.
3. **spin** — 0.9.9 is unyanked and satisfies flume's `^0.9.8`. Pin it; no sqlx
   upgrade required. Restore `yanked = "warn"`.
4. **rsa** — the one item with no upstream fix. Keep the suppression, but in
   `.cargo/audit.toml` only, with an exploitability argument and a retirement
   condition (sqlx 0.9, Dependabot #34).

## Policy corrections (all tightenings)

- `deny.toml`: advisory `ignore` list emptied; `yanked` restored from `"allow"`
  to `"warn"`.
- Root `.audit.toml` **deleted**. cargo-audit reads only `.cargo/audit.toml`
  (verified empirically against 0.22.2 — an ignore in a root `.audit.toml` has
  no effect). Because CI duplicated the entries as `--ignore` flags, the dead
  file's rationale drifted unnoticed into being factually wrong. `.cargo/audit.toml`
  is now the single source of truth; the CI step runs bare `cargo audit`.
- CI runs full `cargo deny check` rather than licenses-only.
- `epaint_default_fonts` 0.34 re-expresses the same Ubuntu Font Licence under
  its now-standard SPDX id, so the crate-scoped exception moves
  `LicenseRef-UFL-1.0` → `Ubuntu-font-1.0`; the allowlist is not widened.

## Verification

The macOS-only GUI is compiled by no CI job, so the eframe migration would
otherwise have shipped unverified. Typechecked out-of-band for
`aarch64-apple-darwin` with `cargo-zigbuild` (full link is not possible without
a macOS SDK — `libobjc` is unavailable — but `cargo check` covers the migration).

| Gate | Result |
|---|---|
| `cargo audit` | exit 0, zero findings |
| `cargo deny check` | exit 0 — advisories / bans / licenses / sources all ok |
| `cargo fmt --all -- --check` | exit 0 |
| `cargo clippy --all-targets --all-features -- -D warnings` | exit 0 |
| `cargo test --workspace --all-features` | exit 0, 903 tests |
| macOS GUI typecheck (`aarch64-apple-darwin`) | exit 0, no warnings |

## Out of scope / follow-ups

- **sqlx 0.9** (Dependabot #34) — retires the last suppression (`rsa`, review
  date 2026-11-30) and the duplicate `flume` 0.11/0.12 entries.
- **eframe 0.35** — deferred, and genuinely optional: 0.34 already carries the
  skrifa switch this task needed. 0.35 removes `TopBottomPanel` entirely and
  reworks `App`/`Panel` further, so it warrants its own task.
- **Visual QA of the GUI on macOS hardware.** The eframe 0.34 migration was
  typechecked but never run — no macOS machine was available. The panel-resize
  regression was caught by code review, not by execution; a second pass on real
  hardware is warranted before the next release that ships the GUI.
- **Compile `disk-gui` in CI.** Nothing builds it today, which is why a GUI
  regression could reach a green pipeline at all. Adding
  `cargo-zigbuild check -p disk-gui --all-targets --target aarch64-apple-darwin`
  to the lint job closes this, but needs zig plus the `aarch64-apple-darwin`
  target on the self-hosted runner — a CI-infrastructure change, deliberately
  not bundled into a dependency-remediation PR.
- **`cargo deny` duplicate-version warnings** (axum 0.7/0.8, windows-sys, …)
  remain warnings under `multiple-versions = "warn"`; now visible in CI since
  the full check runs.
- **`license-not-encountered`** warnings for `OpenSSL` and `Unicode-DFS-2016`
  indicate dead allowlist entries; pruning them is a separate tightening.

## Execution note

This task was dispatched concurrently to a second agent (Cursor), which had
already opened PR #128 from the same branch using the suppression approach the
scope prohibits, and whose commit failed the CI lint gate on `dead_code`. Its
genuine contribution — the `mdns-sd` 0.13 → 0.20 upgrade — was preserved: this
work was built on top of that commit and fast-forwarded onto the same branch, so
nothing was discarded and PR #128 remains the single PR for the task.
