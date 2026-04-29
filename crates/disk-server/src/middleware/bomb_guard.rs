//! Decompression-bomb guard for the zstd codec.
//!
//! Wraps a `zstd::Decoder` with byte counters that enforce:
//! - Compressed input cap: 4 MiB per message.
//! - Decompressed output cap: 16 MiB per message.
//! - Cumulative decompressed cap: 256 MiB per stream.
//!
//! Exceeding any cap returns `BombError::BombDetected` (T-DoS-Bomb, DISK-0004 § 6).

use std::io::{self, Read};

/// Per-message limits.
pub const MAX_COMPRESSED_BYTES: usize = 4 * 1024 * 1024; // 4 MiB
pub const MAX_DECOMPRESSED_BYTES: usize = 16 * 1024 * 1024; // 16 MiB
/// Per-stream cumulative decompressed cap.
pub const MAX_STREAM_DECOMPRESSED: usize = 256 * 1024 * 1024; // 256 MiB

/// Error variants for the bomb guard.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BombError {
    #[error("decompression bomb: compressed input exceeded {MAX_COMPRESSED_BYTES} bytes")]
    CompressedCapExceeded,
    #[error("decompression bomb: decompressed output exceeded {MAX_DECOMPRESSED_BYTES} bytes")]
    DecompressedCapExceeded,
    #[error("decompression bomb: stream cumulative cap exceeded {MAX_STREAM_DECOMPRESSED} bytes")]
    StreamCapExceeded,
}

/// Decompress `compressed` bytes, enforcing per-message and optional
/// per-stream limits.
///
/// `stream_decompressed_so_far` is updated on success to include bytes from
/// this call; on `BombError` the state is NOT updated (no partial commit).
pub fn decompress_guarded(
    compressed: &[u8],
    stream_decompressed_so_far: &mut usize,
) -> Result<Vec<u8>, BombError> {
    if compressed.len() > MAX_COMPRESSED_BYTES {
        return Err(BombError::CompressedCapExceeded);
    }

    // Decompress with output capped at MAX_DECOMPRESSED_BYTES + 1 to detect overflow.
    let cap = MAX_DECOMPRESSED_BYTES + 1;
    let mut out = Vec::with_capacity(compressed.len().min(MAX_DECOMPRESSED_BYTES));
    let mut decoder =
        zstd::Decoder::new(compressed).map_err(|_| BombError::DecompressedCapExceeded)?;
    let mut buf = [0u8; 16384];
    loop {
        match decoder.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if out.len() + n > cap {
                    return Err(BombError::DecompressedCapExceeded);
                }
                out.extend_from_slice(&buf[..n]);
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(_) => return Err(BombError::DecompressedCapExceeded),
        }
    }

    if out.len() > MAX_DECOMPRESSED_BYTES {
        return Err(BombError::DecompressedCapExceeded);
    }

    let new_total = *stream_decompressed_so_far + out.len();
    if new_total > MAX_STREAM_DECOMPRESSED {
        return Err(BombError::StreamCapExceeded);
    }

    *stream_decompressed_so_far = new_total;
    Ok(out)
}

/// Compress `data` with zstd level 3.
pub fn compress(data: &[u8], level: i32) -> io::Result<Vec<u8>> {
    zstd::encode_all(std::io::Cursor::new(data), level)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_small_message() {
        let data = b"hello disk arcana";
        let compressed = compress(data, 3).unwrap();
        let mut stream_bytes = 0;
        let decompressed = decompress_guarded(&compressed, &mut stream_bytes).unwrap();
        assert_eq!(decompressed, data);
        assert_eq!(stream_bytes, data.len());
    }

    #[test]
    fn compressed_cap_exceeded() {
        // Fabricate an input that exceeds the compressed cap.
        let large = vec![0u8; MAX_COMPRESSED_BYTES + 1];
        let mut stream_bytes = 0;
        let err = decompress_guarded(&large, &mut stream_bytes).unwrap_err();
        assert_eq!(err, BombError::CompressedCapExceeded);
        assert_eq!(stream_bytes, 0); // not updated on error
    }

    #[test]
    fn decompressed_cap_exceeded() {
        // Craft a highly compressible payload that expands beyond 16 MiB.
        // A zstd bomb: compress 17 MiB of zeros.
        let huge = vec![0u8; MAX_DECOMPRESSED_BYTES + 1];
        let compressed = compress(&huge, 22).unwrap();
        // Only trigger the bomb if compressed fits within compressed cap.
        if compressed.len() <= MAX_COMPRESSED_BYTES {
            let mut stream_bytes = 0;
            let err = decompress_guarded(&compressed, &mut stream_bytes).unwrap_err();
            assert_eq!(err, BombError::DecompressedCapExceeded);
        }
        // If the compressed form itself is > 4 MiB, the CompressedCapExceeded fires first.
    }

    #[test]
    fn stream_cap_enforced() {
        let data = vec![42u8; 1024];
        let compressed = compress(&data, 3).unwrap();
        // Simulate stream accumulation that brings us just over the cap.
        let mut stream_bytes = MAX_STREAM_DECOMPRESSED - 512;
        // The next call would push total to MAX_STREAM_DECOMPRESSED + 512.
        let err = decompress_guarded(&compressed, &mut stream_bytes).unwrap_err();
        assert_eq!(err, BombError::StreamCapExceeded);
    }
}
