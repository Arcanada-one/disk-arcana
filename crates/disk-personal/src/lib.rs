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

/// Native startup/Auth binding checks around the authenticated control port.
pub mod parent_authority;
/// Concrete native type and storage binding; no production IO installed.
pub mod parent_native;

/// Linux handle-relative journal primitive; no mount or runtime admission.
#[cfg(target_os = "linux")]
pub mod parent_journal;

#[cfg(target_os = "linux")]
pub mod parent_inventory;
#[cfg(target_os = "linux")]
pub mod parent_vfs;

#[cfg(target_os = "linux")]
pub mod parent_sqlite;

#[cfg(target_os = "linux")]
pub mod parent_backend;
