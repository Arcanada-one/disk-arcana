//! gRPC service trait implementations.

pub mod auth;
pub mod sync;

pub use auth::AuthServiceImpl;
pub use sync::SyncServiceImpl;
