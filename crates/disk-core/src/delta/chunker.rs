//! Fixed-block 4 KiB iterator for the delta-sync algorithm.
//!
//! Files smaller than 4 KiB are emitted as a single chunk.  Files ≥ 4 KiB are
//! split into sequential 4 KiB blocks; the final chunk carries the remainder
//! and may be shorter than 4 KiB.
//!
//! Each `Chunk` carries the block offset (bytes from file start), the Adler32
//! weak checksum, the blake3 strong hash, and the raw data bytes.

use std::io::{self, Read};

use super::{rolling::adler32_full, strong::hash as blake3_hash};

/// Fixed block size for delta chunking (4 KiB).
pub const BLOCK_SIZE: usize = 4096;

/// One chunk produced by [`chunks`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    /// Byte offset of the chunk within the original file.
    pub offset: u64,
    /// Adler32 weak checksum of the chunk data.
    pub weak: u32,
    /// Blake3 strong hash (32 bytes) of the chunk data.
    pub strong: [u8; 32],
    /// The raw bytes of this chunk.
    pub data: Vec<u8>,
}

/// Iterate over fixed-size 4 KiB chunks from `reader`.
///
/// Files smaller than [`BLOCK_SIZE`] produce exactly one chunk.
/// Empty readers produce zero chunks.
pub fn chunks(mut reader: impl Read) -> impl Iterator<Item = io::Result<Chunk>> {
    let mut buf = vec![0u8; BLOCK_SIZE];
    let mut offset: u64 = 0;
    let mut done = false;

    std::iter::from_fn(move || {
        if done {
            return None;
        }
        let mut total_read = 0usize;
        // Read exactly BLOCK_SIZE bytes (or until EOF).
        loop {
            match reader.read(&mut buf[total_read..]) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    total_read += n;
                    if total_read == BLOCK_SIZE {
                        break;
                    }
                }
                Err(e) => return Some(Err(e)),
            }
        }
        if total_read == 0 {
            done = true;
            return None;
        }
        let data = buf[..total_read].to_vec();
        let weak = adler32_full(&data);
        let strong = blake3_hash(&data);
        let chunk = Chunk {
            offset,
            weak,
            strong,
            data,
        };
        offset += total_read as u64;
        Some(Ok(chunk))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect_chunks(data: &[u8]) -> Vec<Chunk> {
        chunks(data).map(|r| r.unwrap()).collect()
    }

    #[test]
    fn empty_file_zero_chunks() {
        let result = collect_chunks(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn single_byte_one_chunk() {
        let result = collect_chunks(b"x");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].offset, 0);
        assert_eq!(result[0].data, b"x");
    }

    #[test]
    fn exactly_4095_bytes_one_chunk() {
        let data: Vec<u8> = (0u8..=255u8).cycle().take(4095).collect();
        let result = collect_chunks(&data);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].offset, 0);
        assert_eq!(result[0].data.len(), 4095);
    }

    #[test]
    fn exactly_4096_bytes_one_chunk() {
        let data: Vec<u8> = (0u8..=255u8).cycle().take(4096).collect();
        let result = collect_chunks(&data);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].offset, 0);
        assert_eq!(result[0].data.len(), 4096);
    }

    #[test]
    fn exactly_4097_bytes_two_chunks() {
        let data: Vec<u8> = (0u8..=255u8).cycle().take(4097).collect();
        let result = collect_chunks(&data);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].offset, 0);
        assert_eq!(result[0].data.len(), 4096);
        assert_eq!(result[1].offset, 4096);
        assert_eq!(result[1].data.len(), 1);
    }

    #[test]
    fn eight_mib_file_correct_chunk_count() {
        let size = 8 * 1024 * 1024; // 8 MiB
        let data: Vec<u8> = (0u8..=255u8).cycle().take(size).collect();
        let result = collect_chunks(&data);
        assert_eq!(result.len(), 2048, "8 MiB / 4 KiB = 2048 chunks");
        for (i, chunk) in result.iter().enumerate() {
            assert_eq!(chunk.offset, (i * BLOCK_SIZE) as u64);
            assert_eq!(chunk.data.len(), BLOCK_SIZE);
        }
    }

    #[test]
    fn chunk_weak_hash_matches_adler32_full() {
        let data: Vec<u8> = (0u8..=255u8).cycle().take(8500).collect();
        for chunk in collect_chunks(&data) {
            let expected_weak = adler32_full(&chunk.data);
            assert_eq!(chunk.weak, expected_weak);
        }
    }

    #[test]
    fn chunk_strong_hash_matches_blake3() {
        let data: Vec<u8> = (0u8..=255u8).cycle().take(5000).collect();
        for chunk in collect_chunks(&data) {
            let expected_strong = blake3_hash(&chunk.data);
            assert_eq!(chunk.strong, expected_strong);
        }
    }

    #[test]
    fn offsets_are_contiguous() {
        let data: Vec<u8> = (0u8..=255u8).cycle().take(12288 + 100).collect();
        let result = collect_chunks(&data);
        let mut expected_offset = 0u64;
        for chunk in &result {
            assert_eq!(chunk.offset, expected_offset);
            expected_offset += chunk.data.len() as u64;
        }
        assert_eq!(expected_offset, data.len() as u64);
    }
}
