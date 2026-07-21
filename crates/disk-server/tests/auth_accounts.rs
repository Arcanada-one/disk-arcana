//! Integration tests for SaaS account auth (DISK-0016).
//!
//! HTTP round-trips live in `accounts::routes::integration_tests` (lib) because
//! the `tests/` harness uses a different Tokio runtime wiring than in-crate tests.

#[test]
fn auth_integration_tests_live_in_lib() {}
