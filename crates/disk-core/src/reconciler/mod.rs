//! Pure-function reconciliation engine. Given local + remote + indexed
//! snapshots of a vault, [`ReconciliationEngine::reconcile`] emits a
//! `Vec<SyncAction>` covering all 30 conflict-matrix scenarios.

mod tree;
mod triple;

pub use tree::ReconciliationEngine;
