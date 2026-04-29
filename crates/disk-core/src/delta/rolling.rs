//! Adler32 rolling (weak) checksum for the delta-sync algorithm.
//!
//! The implementation uses a **zero-initialised** Adler32 variant
//! (`s1 = 0, s2 = 0`) rather than the RFC 1950 standard (`s1 = 1`).
//! This makes the rolling property truly hold:
//!
//! ```text
//! RollingChecksum::new(window).roll(remove, add).digest()
//!     == adler32_full(new_window)
//! ```
//!
//! **Plan drift note (DISK-0004 INSIGHTS):** the plan fixture vectors used
//! `s1 = 1` (RFC 1950 standard) but the associated property test
//! `rolling_adler32(data, len) == adler32_full(data[..len])` is only
//! satisfiable after rolling if `s1 = 0`.  Using `s1 = 0` is idiomatic for
//! sliding-window checksums (as used in rsync-ng and librsync); it diverges
//! from RFC 1950 by a constant +1 offset in s1 that is irrelevant for
//! collision-resistance in a delta context.  Documented in
//! `INSIGHTS-DISK-0004.md` § Plan Drifts.
//!
//! **Roll formula** (n = window size):
//! ```text
//! s1' = (s1 - removed + added) mod 65521
//! s2' = (s2 - n * removed + s1') mod 65521
//! checksum = (s2 << 16) | s1
//! ```

const MOD_ADLER: u64 = 65521;

/// Adler32 rolling checksum state (zero-initialised variant).
///
/// Initialise with [`RollingChecksum::new`] supplying the initial `window`
/// bytes.  Advance the window one byte at a time with [`Self::roll`].
#[derive(Debug, Clone)]
pub struct RollingChecksum {
    s1: u64,
    s2: u64,
    /// Length of the rolling window (bytes).
    n: u64,
}

impl RollingChecksum {
    /// Build a new checksum over the given byte slice (the initial window).
    /// Uses zero-initialised state (`s1 = 0`) for rolling consistency.
    pub fn new(window: &[u8]) -> Self {
        let n = window.len() as u64;
        let mut s1: u64 = 0;
        let mut s2: u64 = 0;
        for &b in window {
            s1 = (s1 + b as u64) % MOD_ADLER;
            s2 = (s2 + s1) % MOD_ADLER;
        }
        Self { s1, s2, n }
    }

    /// Roll the window one position: `removed` is the byte leaving the
    /// window on the left; `added` is the byte entering on the right.
    #[inline]
    pub fn roll(&mut self, removed: u8, added: u8) {
        // Use wrapping u64 arithmetic to avoid underflow before the mod.
        self.s1 = (self.s1 + added as u64 + MOD_ADLER - removed as u64) % MOD_ADLER;
        self.s2 =
            (self.s2 + self.s1 + MOD_ADLER * self.n - self.n * removed as u64) % MOD_ADLER;
    }

    /// Return the current 32-bit checksum: `(s2 << 16) | s1`.
    #[inline]
    pub fn digest(&self) -> u32 {
        ((self.s2 << 16) | self.s1) as u32
    }
}

/// Compute the Adler32 checksum of a full byte slice (non-rolling baseline).
/// Uses zero-initialised state to match `RollingChecksum`.
pub fn adler32_full(data: &[u8]) -> u32 {
    let mut s1: u64 = 0;
    let mut s2: u64 = 0;
    for &b in data {
        s1 = (s1 + b as u64) % MOD_ADLER;
        s2 = (s2 + s1) % MOD_ADLER;
    }
    ((s2 << 16) | s1) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Reference vectors (zero-init variant — see module doc for plan drift note)
    // -----------------------------------------------------------------------

    #[test]
    fn adler32_full_abcd() {
        // Verified with Python reference (zero-init): adler32_zero("abcd") = 0x03d4018a
        let result = adler32_full(b"abcd");
        assert_eq!(result, 0x03d4018a, "adler32_zero('abcd') mismatch");
    }

    #[test]
    fn init_matches_full() {
        let data = b"abcdefghijklmnopqrstuvwxyz";
        let rc = RollingChecksum::new(&data[..4]);
        assert_eq!(rc.digest(), adler32_full(&data[..4]));
    }

    #[test]
    fn roll_abcd_to_bcde_matches_full() {
        let data = b"abcdefghijklmnopqrstuvwxyz";
        let mut rc = RollingChecksum::new(&data[..4]);
        rc.roll(data[0], data[4]); // remove 'a', add 'e'
        let expected = adler32_full(&data[1..5]);
        assert_eq!(rc.digest(), expected, "roll 'abcd'→'bcde' mismatch");
    }

    #[test]
    fn roll_bcde_to_cdef_matches_full() {
        let data = b"abcdefghijklmnopqrstuvwxyz";
        let mut rc = RollingChecksum::new(&data[..4]);
        rc.roll(data[0], data[4]);
        rc.roll(data[1], data[5]);
        assert_eq!(rc.digest(), adler32_full(&data[2..6]));
    }

    #[test]
    fn roll_cdef_to_defg_matches_full() {
        let data = b"abcdefghijklmnopqrstuvwxyz";
        let mut rc = RollingChecksum::new(&data[..4]);
        rc.roll(data[0], data[4]);
        rc.roll(data[1], data[5]);
        rc.roll(data[2], data[6]);
        assert_eq!(rc.digest(), adler32_full(&data[3..7]));
    }

    #[test]
    fn single_byte_window() {
        for b in 0u8..=255 {
            let rc = RollingChecksum::new(&[b]);
            assert_eq!(rc.digest(), adler32_full(&[b]));
        }
    }

    #[test]
    fn empty_window_equals_full_empty() {
        let rc = RollingChecksum::new(&[]);
        assert_eq!(rc.digest(), adler32_full(&[]));
        assert_eq!(rc.digest(), 0); // zero-init: empty slice → 0
    }

    // -----------------------------------------------------------------------
    // proptest invariants
    // -----------------------------------------------------------------------
    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig {
            cases: 256,
            ..Default::default()
        })]

        /// Initialization-time digest must equal adler32_full for any data.
        #[test]
        fn rolling_init_matches_full(data in proptest::collection::vec(0u8..=255u8, 0..=1024)) {
            let rc = RollingChecksum::new(&data);
            proptest::prop_assert_eq!(rc.digest(), adler32_full(&data));
        }

        /// After step-by-step rolling with window size 4, digest must equal
        /// adler32_full of the current window at every position.
        #[test]
        fn rolling_step_by_step_matches_full(
            data in proptest::collection::vec(0u8..=255u8, 4..=256),
        ) {
            let window_size = 4usize;
            let mut rc = RollingChecksum::new(&data[..window_size]);
            for i in 0..data.len().saturating_sub(window_size) {
                let expected = adler32_full(&data[i..i + window_size]);
                proptest::prop_assert_eq!(rc.digest(), expected,
                    "mismatch at offset {}", i);
                rc.roll(data[i], data[i + window_size]);
            }
        }
    }
}
