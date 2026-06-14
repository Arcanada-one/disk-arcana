//! Conflict-resolution utilities: fork naming and 3-way merge.

pub mod fork;
pub mod merge;

pub use fork::fork_filename;
pub use merge::{three_way_merge, MergeOutput, RefuseReason};
