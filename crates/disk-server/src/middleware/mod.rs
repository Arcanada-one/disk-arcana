//! Server-side middleware: decompression-bomb guard and anti-replay protection.

pub mod bomb_guard;
pub mod peer_cert;
pub mod replay;

pub use bomb_guard::{compress, decompress_guarded, BombError};
pub use peer_cert::propagate_peer_cert;
pub use replay::{ReplayError, ReplayGuard};
