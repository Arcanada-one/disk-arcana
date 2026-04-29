//! Delta-sync algorithm: rolling checksum, strong hash, fixed-block chunker,
//! and delta plan builder/applier.
//!
//! Introduced in Phase 3 (DISK-0004).

pub mod chunker;
pub mod reconcile;
pub mod rolling;
pub mod strong;

pub use chunker::{chunks, Chunk, BLOCK_SIZE};
pub use reconcile::{
    apply_plan, build_plan, build_plan_with_data, ChunkSig, DeltaEntry, DeltaPlan,
};
pub use rolling::{adler32_full, RollingChecksum};
pub use strong::{hash as blake3_hash, verify as blake3_verify};
