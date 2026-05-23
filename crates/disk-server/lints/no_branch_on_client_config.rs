#!/usr/bin/env rust-script
//! Grep-based lint: no server-side branching on `intended_direction` metadata
//! outside the `audit` module (P4a Step 10).
//!
//! The `intended_direction` field in client request metadata is an
//! informational hint from the client's `disk.toml`.  Server code MUST NOT
//! use it for auth or ACL decisions — that path leads to T-DIR-1 (direction-
//! spoofing).  Only the `audit` module is allowed to read it for logging.
//!
//! Run: `cargo run --manifest-path Cargo.toml -p disk-server
//!        --example lint_no_branch_on_client_config`
//! Or:  `crates/disk-server/lints/no_branch_on_client_config.sh`
//!
//! Exit codes:
//!   0 — no violations found.
//!   1 — one or more violations found (paths and line numbers printed).
//!
//! This file documents the lint rule; the executable is the companion shell
//! script `no_branch_on_client_config.sh`.

fn main() {
    // This file is documentation + the Rust entry point for
    // `cargo run --example` if desired.  The actual CI hook uses the
    // `.sh` companion to avoid requiring rust-script in CI.
    eprintln!("Use no_branch_on_client_config.sh for the lint check.");
    std::process::exit(0);
}
