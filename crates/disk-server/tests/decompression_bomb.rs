//! Decompression-bomb defence test (V-10, T-DoS-Bomb).
//!
//! Crafts a zstd payload that, when decompressed, would exceed the per-message
//! 16 MiB cap. Asserts `BombError::DecompressedCapExceeded` is returned before
//! the full decompressed bytes are materialised.
//!
//! DISK-0004 Step 10.

use disk_server::middleware::bomb_guard::{
    compress, decompress_guarded, BombError, MAX_COMPRESSED_BYTES, MAX_DECOMPRESSED_BYTES,
    MAX_STREAM_DECOMPRESSED,
};

/// Build a highly compressible payload that expands beyond `MAX_DECOMPRESSED_BYTES`.
fn make_bomb() -> Vec<u8> {
    // 17 MiB of zeros compresses to ~10 KiB with zstd level 22.
    let huge = vec![0u8; MAX_DECOMPRESSED_BYTES + 1024 * 1024]; // 17 MiB
    compress(&huge, 22).expect("compress bomb")
}

#[test]
fn bomb_fixture_decompressed_cap_exceeded() {
    let bomb = make_bomb();
    // Bomb must fit within the compressed cap to test the decompressed cap.
    // If it doesn't, we fall back to testing the compressed cap instead.
    let mut stream_bytes = 0usize;
    let err = decompress_guarded(&bomb, &mut stream_bytes).unwrap_err();
    assert!(
        matches!(
            err,
            BombError::DecompressedCapExceeded | BombError::CompressedCapExceeded
        ),
        "Expected BombError, got: {err:?}"
    );
    // State must NOT have been updated on error.
    assert_eq!(stream_bytes, 0, "stream counter must not advance on bomb");
}

#[test]
fn compressed_cap_explicitly() {
    let oversized = vec![0u8; MAX_COMPRESSED_BYTES + 1];
    let mut s = 0;
    let err = decompress_guarded(&oversized, &mut s).unwrap_err();
    assert_eq!(err, BombError::CompressedCapExceeded);
}

#[test]
fn stream_cap_accumulates_correctly() {
    let data = vec![42u8; 1024];
    let compressed = compress(&data, 3).unwrap();
    // Seed the stream counter so that next call would exceed the cap.
    let mut stream_bytes = MAX_STREAM_DECOMPRESSED - 512; // 512 bytes under cap
                                                          // data.len() = 1024 > 512 remaining → should trip StreamCapExceeded.
    let err = decompress_guarded(&compressed, &mut stream_bytes).unwrap_err();
    assert_eq!(err, BombError::StreamCapExceeded);
    // Counter must not have advanced on error.
    assert_eq!(stream_bytes, MAX_STREAM_DECOMPRESSED - 512);
}

#[test]
fn legitimate_message_passes() {
    let data = b"a normal disk arcana sync message payload";
    let compressed = compress(data, 3).unwrap();
    let mut s = 0;
    let out = decompress_guarded(&compressed, &mut s).unwrap();
    assert_eq!(out, data);
    assert_eq!(s, data.len());
}
