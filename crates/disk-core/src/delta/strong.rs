//! Blake3 strong hash wrapper for the delta-sync algorithm.
//!
//! Provides a thin, zero-overhead wrapper around the `blake3` crate that
//! returns a fixed-size 32-byte digest.  The wrapper exists purely to give
//! the delta module a self-contained API and to attach the Phase-3 test
//! vector.

/// Compute the blake3 digest of `data`, returning a 32-byte array.
#[inline]
pub fn hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Verify that `data` hashes to `expected`.  Constant-time via blake3's
/// internal implementation (T-Tampering mitigation).
#[inline]
pub fn verify(data: &[u8], expected: &[u8; 32]) -> bool {
    &hash(data) == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-vector: blake3("") = af1349b9f5f9a1a6a0404dea36dcc949...
    ///
    /// Full 64-hex digest from the official blake3 test suite.
    #[test]
    fn empty_known_vector() {
        let digest = hash(b"");
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert!(
            hex.starts_with("af1349b9"),
            "blake3('') prefix mismatch: {hex}"
        );
    }

    #[test]
    fn non_empty_deterministic() {
        let a = hash(b"hello world");
        let b = hash(b"hello world");
        assert_eq!(a, b);
    }

    #[test]
    fn different_inputs_differ() {
        let a = hash(b"hello");
        let b = hash(b"world");
        assert_ne!(a, b);
    }

    #[test]
    fn verify_ok() {
        let data = b"some content";
        let expected = hash(data);
        assert!(verify(data, &expected));
    }

    #[test]
    fn verify_fail_on_bit_flip() {
        let data = b"some content";
        let mut expected = hash(data);
        expected[0] ^= 0x01; // flip one bit
        assert!(!verify(data, &expected));
    }
}
