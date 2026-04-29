//! Delta plan: build and apply the minimal set of chunks required to
//! reconstruct the client's version of a file on the server side.
//!
//! **Algorithm** (rsync-inspired, fixed-block):
//!
//! 1. Client sends its chunk signatures `[ChunkSig]` (weak + strong + offset).
//! 2. Server holds its own chunk signatures for the same file.
//! 3. [`build_plan`] compares the two lists: chunks where both `weak` and
//!    `strong` match are *hits* (server already has them); mismatches are
//!    *misses* that must be uploaded.
//! 4. [`apply_plan`] assembles the reconstructed bytes from the base (server
//!    copy) for hits and the uploaded data for misses.
//!
//! **Invariant** (proptest § 5.1):
//! ```text
//! forall (base: Vec<u8>, edits: Vec<Edit>) {
//!     let client = apply_edits(&base, &edits);
//!     let plan   = build_plan(&chunks(client), &chunks(base));
//!     assert_eq!(apply_plan(&base, &plan), client);
//! }
//! ```

use super::chunker::{chunks, Chunk, BLOCK_SIZE};

/// Signature of a single block (sent by client in `SyncStateRequest`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkSig {
    pub offset: u64,
    pub weak: u32,
    pub strong: [u8; 32],
}

impl From<&Chunk> for ChunkSig {
    fn from(c: &Chunk) -> Self {
        ChunkSig {
            offset: c.offset,
            weak: c.weak,
            strong: c.strong,
        }
    }
}

/// One entry in a delta plan — either a cache hit (reuse server bytes) or a
/// miss (upload required, data carried inline for `apply_plan`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaEntry {
    /// Server already has these bytes at `server_offset`; copy `len` bytes.
    Hit { server_offset: u64, len: usize },
    /// Data not present on server; use these bytes verbatim.
    Miss { data: Vec<u8> },
}

/// An ordered sequence of [`DeltaEntry`] values that, when applied to a base
/// file via [`apply_plan`], produces the client's version.
#[derive(Debug, Clone, Default)]
pub struct DeltaPlan {
    pub entries: Vec<DeltaEntry>,
}

/// Build a delta plan that turns `base` (server view) into a file whose
/// chunk signatures match `client_sigs` (client view).
///
/// `client_sigs` must be in offset order.  Each entry in the plan corresponds
/// to exactly one client-side chunk.
pub fn build_plan(client_sigs: &[ChunkSig], base: &[u8]) -> DeltaPlan {
    // Build a lookup: (weak, strong) → offset in base.
    let base_chunks: Vec<Chunk> = chunks(base).map(|r| r.unwrap()).collect();
    let base_index: std::collections::HashMap<(u32, [u8; 32]), u64> = base_chunks
        .iter()
        .map(|c| ((c.weak, c.strong), c.offset))
        .collect();

    let mut entries = Vec::with_capacity(client_sigs.len());
    for sig in client_sigs {
        let key = (sig.weak, sig.strong);
        if let Some(&server_offset) = base_index.get(&key) {
            // Determine actual length from base_chunks at that offset.
            let len = base_chunks
                .iter()
                .find(|c| c.offset == server_offset)
                .map(|c| c.data.len())
                .unwrap_or(BLOCK_SIZE);
            entries.push(DeltaEntry::Hit { server_offset, len });
        } else {
            // Miss: placeholder — real data is filled in by the upload path.
            // For `apply_plan` tests we carry the data via a separate step;
            // here we emit a sentinel that apply_plan will panic on if called
            // without data.  In the live upload flow the data comes from
            // DeltaChunk.data on the wire.
            entries.push(DeltaEntry::Miss { data: Vec::new() });
        }
    }

    DeltaPlan { entries }
}

/// Build a delta plan with inline miss-data (for `apply_plan` tests).
///
/// `client_chunks` carries the full `Chunk` objects (with data).  For cache
/// hits the data is not included (base bytes are reused); for misses the
/// client's data is carried inline.
pub fn build_plan_with_data(client_chunks: &[Chunk], base: &[u8]) -> DeltaPlan {
    let base_chunks: Vec<Chunk> = chunks(base).map(|r| r.unwrap()).collect();
    let base_index: std::collections::HashMap<(u32, [u8; 32]), u64> = base_chunks
        .iter()
        .map(|c| ((c.weak, c.strong), c.offset))
        .collect();

    let mut entries = Vec::with_capacity(client_chunks.len());
    for chunk in client_chunks {
        let key = (chunk.weak, chunk.strong);
        if let Some(&server_offset) = base_index.get(&key) {
            let len = base_chunks
                .iter()
                .find(|c| c.offset == server_offset)
                .map(|c| c.data.len())
                .unwrap_or(chunk.data.len());
            entries.push(DeltaEntry::Hit { server_offset, len });
        } else {
            entries.push(DeltaEntry::Miss {
                data: chunk.data.clone(),
            });
        }
    }

    DeltaPlan { entries }
}

/// Apply a delta plan to `base`, producing the reconstructed client file.
///
/// Every `Hit` copies bytes from `base`; every `Miss` uses the inline data.
/// Returns `Err` if a `Hit` references out-of-bounds bytes in `base` or if a
/// `Miss` entry has no data (i.e. `build_plan` was used instead of
/// `build_plan_with_data`).
pub fn apply_plan(base: &[u8], plan: &DeltaPlan) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for entry in &plan.entries {
        match entry {
            DeltaEntry::Hit { server_offset, len } => {
                let start = *server_offset as usize;
                let end = start + len;
                if end > base.len() {
                    return Err(format!(
                        "Hit out of bounds: offset={server_offset} len={len} base_len={}",
                        base.len()
                    ));
                }
                out.extend_from_slice(&base[start..end]);
            }
            DeltaEntry::Miss { data } => {
                if data.is_empty() {
                    return Err("Miss entry has no data (use build_plan_with_data)".into());
                }
                out.extend_from_slice(data);
            }
        }
    }
    Ok(out)
}

// -----------------------------------------------------------------------
// Helper for tests: simple edit model
// -----------------------------------------------------------------------

/// An edit to apply to a byte vector (for proptest).
#[derive(Debug, Clone)]
pub struct Edit {
    /// Byte offset to start the edit.
    pub offset: usize,
    /// Replacement bytes (may be longer or shorter than the original range).
    pub replacement: Vec<u8>,
    /// Number of bytes to replace (0 = pure insertion).
    pub replace_len: usize,
}

/// Apply a list of edits to `data`, returning the modified version.
/// Edits are applied in reverse offset order to avoid shifting issues.
pub fn apply_edits(data: &[u8], edits: &[Edit]) -> Vec<u8> {
    let mut result = data.to_vec();
    // Sort edits by offset descending so each edit doesn't shift later ones.
    let mut sorted = edits.to_vec();
    sorted.sort_by(|a, b| b.offset.cmp(&a.offset));
    for edit in sorted {
        let start = edit.offset.min(result.len());
        let end = (edit.offset + edit.replace_len).min(result.len());
        result.splice(start..end, edit.replacement.iter().cloned());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delta::chunker::chunks;

    fn file_chunks(data: &[u8]) -> Vec<Chunk> {
        chunks(data).map(|r| r.unwrap()).collect()
    }

    // -----------------------------------------------------------------------
    // Deterministic unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn identical_files_all_hits() {
        let data: Vec<u8> = (0u8..=255u8).cycle().take(8192).collect();
        let client_chunks = file_chunks(&data);
        let plan = build_plan_with_data(&client_chunks, &data);
        assert!(plan
            .entries
            .iter()
            .all(|e| matches!(e, DeltaEntry::Hit { .. })));
        let reconstructed = apply_plan(&data, &plan).unwrap();
        assert_eq!(reconstructed, data);
    }

    #[test]
    fn completely_different_files_all_misses() {
        let base: Vec<u8> = vec![0u8; 4096];
        let client: Vec<u8> = vec![0xffu8; 4096];
        let client_chunks = file_chunks(&client);
        let plan = build_plan_with_data(&client_chunks, &base);
        assert!(plan
            .entries
            .iter()
            .all(|e| matches!(e, DeltaEntry::Miss { .. })));
        let reconstructed = apply_plan(&base, &plan).unwrap();
        assert_eq!(reconstructed, client);
    }

    #[test]
    fn single_block_changed_only_that_block_is_miss() {
        let base: Vec<u8> = (0u8..=255u8).cycle().take(8192).collect();
        let mut client = base.clone();
        // Flip every byte in block 1 (offset 4096..8192).
        for b in &mut client[4096..8192] {
            *b ^= 0xff;
        }
        let client_chunks = file_chunks(&client);
        let plan = build_plan_with_data(&client_chunks, &base);
        assert_eq!(plan.entries.len(), 2);
        assert!(matches!(plan.entries[0], DeltaEntry::Hit { .. }));
        assert!(matches!(plan.entries[1], DeltaEntry::Miss { .. }));
        let reconstructed = apply_plan(&base, &plan).unwrap();
        assert_eq!(reconstructed, client);
    }

    #[test]
    fn small_file_single_miss() {
        let base = b"hello world".to_vec();
        let client = b"hello rust!".to_vec();
        let client_chunks = file_chunks(&client);
        let plan = build_plan_with_data(&client_chunks, &base);
        let reconstructed = apply_plan(&base, &plan).unwrap();
        assert_eq!(reconstructed, client);
    }

    #[test]
    fn empty_client_empty_result() {
        let base = b"some data".to_vec();
        let plan = build_plan_with_data(&[], &base);
        let reconstructed = apply_plan(&base, &plan).unwrap();
        assert!(reconstructed.is_empty());
    }

    // -----------------------------------------------------------------------
    // proptest invariant: apply_edits → build_plan → apply_plan → original
    // -----------------------------------------------------------------------

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig {
            cases: 64,
            max_shrink_iters: 256,
            ..Default::default()
        })]

        #[test]
        fn delta_roundtrip_invariant(
            base in proptest::collection::vec(0u8..=255u8, 0..=16384usize),
            edits in proptest::collection::vec(
                (
                    0usize..=16383usize,  // offset
                    proptest::collection::vec(0u8..=255u8, 0..=128usize), // replacement
                    0usize..=128usize,   // replace_len
                ),
                0..=8usize,
            ),
        ) {
            let edit_list: Vec<Edit> = edits.into_iter().map(|(offset, replacement, replace_len)| {
                Edit { offset: offset.min(base.len()), replacement, replace_len }
            }).collect();
            let client = apply_edits(&base, &edit_list);
            let client_chunks = file_chunks(&client);
            let plan = build_plan_with_data(&client_chunks, &base);
            let reconstructed = apply_plan(&base, &plan).unwrap();
            proptest::prop_assert_eq!(reconstructed, client);
        }
    }
}
