# Insights — Rust advisory tooling (DISK-0066 / ARCA-0194 R6-17)

Findings from remediating the Disk Arcana dependency advisories. Each was
verified against this workspace rather than taken from documentation.

## 1. cargo-audit reads only `.cargo/audit.toml`

A root `.audit.toml` is silently ignored. Verified against cargo-audit 0.22.2 by
placing the same `ignore` entry in each location in turn and re-running:

```
only .audit.toml        → advisory still reported
only .cargo/audit.toml  → advisory suppressed
```

Disk Arcana had carried a root `.audit.toml` since DISK-0005. Nothing ever read
it. CI masked the fact by repeating the suppressions as `--ignore` flags on the
command line, so the file degenerated into a comment block that drifted out of
sync with reality — by the time DISK-0066 opened it, its rationale claimed a
quick-xml bump was impossible when a semver-compatible one existed.

**Rule:** if a config file's effect is duplicated by a CLI flag, the file is
untested. Prefer bare `cargo audit` in CI so the config is exercised.

## 2. cargo-audit and cargo-deny do not see the same crates

They disagree by design, and the difference is not a bug in either:

- **cargo-audit** scans every crate recorded in `Cargo.lock`. Cargo records
  optional dependencies regardless of feature selection.
- **cargo-deny** walks the *resolved feature graph*.

So a crate reachable only through a disabled feature is visible to cargo-audit
alone. Here that is `rsa`, reachable only via `sqlx-mysql`, which the workspace
never enables: cargo-audit reports RUSTSEC-2023-0071, cargo-deny does not, and
listing it in `deny.toml` makes cargo-deny emit `advisory-not-detected`.

**Rule:** suppress such an advisory in `.cargo/audit.toml` only. A
`advisory-not-detected` warning means the entry belongs in the *other* tool's
config — or nowhere.

## 3. "No safe upgrade is available" ≠ no fix

RUSTSEC-2026-0192 marks `ttf-parser` unmaintained with no fixed release, and the
whole 0.25.x line is the latest. That says nothing about the *consumer*: epaint
0.34 replaced `ab_glyph` (→ `owned_ttf_parser` → `ttf-parser`) with **skrifa** —
the very crate the advisory recommends as the alternative. Bumping `eframe`
0.29 → 0.34 removed the crate from the tree outright.

**Rule:** when an advisory has no direct fix, walk *up* the dependency chain and
check whether an intermediate crate has already switched away. Query the
registry per version:

```
curl -s https://crates.io/api/v1/crates/<crate>/<version>/dependencies
```

Diffing that across versions is what surfaced both the epaint→skrifa switch and
`wayland-scanner` 0.31.11's move to `quick-xml ^0.41`.

## 4. A yanked crate often has an unyanked sibling in the same range

`spin` 0.9.8 was yanked; 0.9.9 exists, is not yanked, and satisfies flume's
`^0.9.8`. `cargo update -p spin --precise 0.9.9` cleared it with no upgrade to
flume or sqlx. Yanked status is per-version, and the crates.io API exposes it:

```
curl -s https://crates.io/api/v1/crates/spin | jq '.versions[]|{num,yanked}'
```

**Rule:** check for an unyanked patch release before concluding a yanked
transitive dependency is blocked behind a major upgrade.

## 5. macOS-only code can be typechecked on Linux with cargo-zigbuild

Disk Arcana's GUI is `[target.'cfg(target_os = "macos")'.dependencies]` and no
CI job builds macOS, so `crates/disk-gui` compiles nowhere in CI — an eframe
migration would ship unverified.

`cargo-zigbuild check --target aarch64-apple-darwin` (with zig on PATH) does
typecheck it, including C build scripts like `zstd-sys` and `libsqlite3-sys`
that plain `cargo check` cannot cross-compile (host `cc` rejects `-arch arm64`).

A full **link** still fails — zig does not ship `libobjc`, which needs the macOS
SDK — so use `check`, not `build`. That is enough to validate an API migration.

**Caveat:** `cargo <cmd> ... | tail` reports the *pipe's* exit status. An early
`cargo zigbuild | tail -15` looked like it passed (exit 0) while the build had
actually failed at link. Capture to a file and check `$?` on the cargo process.

## 6. Concurrent agents on one worktree

DISK-0066 was dispatched to two agents at once. The second (Cursor, `--yolo`)
was editing the same worktree, so files mutated mid-session with no visible
cause — `Cargo.toml` reverting, source files appearing — which initially looked
like a cargo bug.

Diagnosis that worked: walk `/proc/<pid>/cwd` for every process, not just the
ones matching the expected binary name. Scanning only for `claude` processes
missed it, because the writer was `agent` (Cursor's CLI).

Non-destructive resolution: branch from the other agent's commit, layer the
corrected work on top, and **fast-forward** its branch. Nothing is discarded,
its valid contribution (the `mdns-sd` 0.20 upgrade) survives, and the task keeps
a single PR. Force-pushing would have destroyed concurrent work.
