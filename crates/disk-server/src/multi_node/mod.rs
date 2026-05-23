//! Multi-node coordination: vector clocks + node lifecycle.

pub mod lifecycle;
pub mod vclock;

pub use lifecycle::{revoke_node, spawn_tombstone_publisher, LifecycleError};
pub use vclock::VClock;
