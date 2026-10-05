//! Local synthetic persistence mechanics. No personal service or authorization API.
#![forbid(unsafe_code)]

#[cfg(all(target_os = "linux", feature = "synthetic-fixtures"))]
mod provider;

/// Test-only access to task-owned synthetic storage. This is not an Auth adapter.
#[cfg(all(target_os = "linux", feature = "synthetic-fixtures"))]
pub mod fixture_support;

pub mod capture_binding;

pub mod startup;

/// Disabled parent orchestration; no registered production authority or storage.
pub mod parent_adapter;

/// Structural native reference/error codec; never an authorization boundary.
pub mod parent_wire;
