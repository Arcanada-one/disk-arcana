//! Sync-loop state machine + exponential backoff (DISK-0006 R5 skeleton).
//!
//! Plan §FsWatcher + sync-loop state machine:
//!
//! ```text
//! Idle → trigger (event | 5 s timer) → Scan → Hash → Reconcile → gRPC
//!                                                              ↓ Err
//!                                                           Backoff
//! ```
//!
//! Backoff curve: base 1 s, exp grow, cap 60 s, jitter ±10 %. Triggers
//! that cause backoff: `share.unknown` (R-DIR-7), `transport.unavailable`.
//! Trigger that does NOT cause backoff: `acl.role_mismatch` — surfaced
//! to `/status` as a sticky state (no retry), per PRD §4.11 + R-DIR-6.
//!
//! R5 ships the pure state machine + the Backoff math. R6 wires the
//! Scan/Hash/Reconcile/gRPC sequence; R7 exposes `state` via the
//! `/status` REST endpoint. The skeleton is deliberately blocking-free
//! and clock-injectable so the curve UT can run against deterministic
//! sequences without sleeping.

use std::time::{Duration, Instant};

use rand::Rng;
use thiserror::Error;

/// Default polling tick — sync loop wakes every `POLL_INTERVAL` even
/// without inbound fs events to drive pull-side reconciliation.
pub const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Backoff floor.
pub const BACKOFF_BASE: Duration = Duration::from_secs(1);

/// Backoff ceiling (PRD §4.11 cap).
pub const BACKOFF_CAP: Duration = Duration::from_secs(60);

/// Jitter band (±10 %).
pub const BACKOFF_JITTER: f64 = 0.10;

/// Observable sync-loop state.
///
/// Mirrors `state` values surfaced in the `/status` JSON schema
/// (plan §Status endpoint contract): `idle | syncing | error |
/// acl_mismatch | server_unreachable`. `Backoff` covers the
/// `server_unreachable` and `share.unknown` paths during retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopState {
    Idle,
    Syncing,
    Backoff,
    AclMismatch,
    ServerUnreachable,
    Error,
}

/// Outcomes a sync attempt can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum LoopError {
    /// Server replied with `share.unknown` — share is not (yet)
    /// registered on the server side. Retry with backoff (R-DIR-7).
    #[error("share.unknown — server has no record of this share")]
    ShareUnknown,

    /// Transport-level failure (DNS, TCP refusal, TLS handshake). Retry
    /// with backoff.
    #[error("transport.unavailable — could not reach disk-arcana-server")]
    TransportUnavailable,

    /// Server replied with `acl.role_mismatch` — client's declared
    /// direction does not match the server-side ACL. Sticky failure;
    /// no retry until config or ACL is fixed (R-DIR-6).
    #[error("acl.role_mismatch — declared direction differs from server ACL")]
    AclRoleMismatch,
}

impl LoopError {
    /// Whether this error should trigger backoff-and-retry.
    /// `acl.role_mismatch` is the only non-retryable variant.
    pub fn should_backoff(&self) -> bool {
        match self {
            LoopError::ShareUnknown | LoopError::TransportUnavailable => true,
            LoopError::AclRoleMismatch => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Backoff
// ---------------------------------------------------------------------------

/// Exponential backoff with cap and ±jitter.
///
/// Public surface intentionally accepts an explicit RNG so tests can
/// pin a seeded source — the production sync loop will pass
/// `rand::thread_rng()` from the caller's context.
#[derive(Debug, Clone)]
pub struct Backoff {
    base: Duration,
    cap: Duration,
    jitter: f64,
    attempt: u32,
}

impl Backoff {
    /// Construct with explicit parameters.
    pub fn new(base: Duration, cap: Duration, jitter: f64) -> Self {
        assert!(
            (0.0..=1.0).contains(&jitter),
            "jitter must be within [0, 1]"
        );
        Self {
            base,
            cap,
            jitter,
            attempt: 0,
        }
    }

    /// Construct with [`BACKOFF_BASE`] / [`BACKOFF_CAP`] / [`BACKOFF_JITTER`].
    pub fn with_defaults() -> Self {
        Self::new(BACKOFF_BASE, BACKOFF_CAP, BACKOFF_JITTER)
    }

    /// Current attempt counter (0 = next call returns the floor delay).
    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    /// Compute the next delay and advance the attempt counter.
    ///
    /// Returns `base * 2^attempt` clamped to `cap`, with multiplicative
    /// jitter drawn from `[1 - jitter, 1 + jitter]`.
    pub fn next_delay<R: Rng + ?Sized>(&mut self, rng: &mut R) -> Duration {
        let exp_factor = 1u64.checked_shl(self.attempt).unwrap_or(u64::MAX);
        let unscaled_nanos = (self.base.as_nanos() as u64).saturating_mul(exp_factor);
        let capped = unscaled_nanos.min(self.cap.as_nanos() as u64);
        let jitter_scale = if self.jitter == 0.0 {
            1.0
        } else {
            1.0 + rng.gen_range(-self.jitter..=self.jitter)
        };
        // Bound the result so jitter cannot push past the cap.
        let jittered = ((capped as f64) * jitter_scale).max(0.0);
        let cap_nanos = self.cap.as_nanos() as f64;
        let final_nanos = jittered.min(cap_nanos);
        // Saturating cast — Duration accepts u64 nanos directly.
        let nanos = final_nanos as u64;
        self.attempt = self.attempt.saturating_add(1);
        Duration::from_nanos(nanos)
    }

    /// Reset the curve — call on a successful sync.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

// ---------------------------------------------------------------------------
// SyncLoop scaffold
// ---------------------------------------------------------------------------

/// Trigger that drove the loop's most recent iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopTrigger {
    FsEventBatch,
    Tick,
    Manual,
}

/// State-machine scaffold. R5 only models transitions and timers;
/// R6 wires Scan/Hash/Reconcile/gRPC into [`SyncLoop::begin_sync`].
#[derive(Debug, Clone)]
pub struct SyncLoop {
    state: LoopState,
    backoff: Backoff,
    poll_interval: Duration,
    /// When `state == Backoff`, the wall-clock instant at which the
    /// next sync attempt may begin. `None` in all other states.
    backoff_until: Option<Instant>,
    /// Last `LoopError`. Cleared on success.
    last_error: Option<LoopError>,
}

impl Default for SyncLoop {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncLoop {
    /// Construct with defaults from plan §FsWatcher.
    pub fn new() -> Self {
        Self {
            state: LoopState::Idle,
            backoff: Backoff::with_defaults(),
            poll_interval: POLL_INTERVAL,
            backoff_until: None,
            last_error: None,
        }
    }

    /// Override the poll interval (tests).
    pub fn with_poll_interval(mut self, poll: Duration) -> Self {
        self.poll_interval = poll;
        self
    }

    /// Current observable state.
    pub fn state(&self) -> LoopState {
        self.state
    }

    /// Last error encountered, if any.
    pub fn last_error(&self) -> Option<LoopError> {
        self.last_error
    }

    /// Polling tick interval (drives the 5 s timer wakeups).
    pub fn poll_interval(&self) -> Duration {
        self.poll_interval
    }

    /// Backoff dwell deadline. `Some` only while `state == Backoff`.
    pub fn backoff_until(&self) -> Option<Instant> {
        self.backoff_until
    }

    /// Read-only access to the internal backoff curve — exposed for
    /// observability (R7 status endpoint surfaces the attempt counter).
    pub fn backoff(&self) -> &Backoff {
        &self.backoff
    }

    /// Mark sync as in-flight. Returns `false` if the loop is currently
    /// dwelling in `Backoff` or pinned in `AclMismatch`.
    pub fn begin_sync(&mut self, now: Instant, _trigger: LoopTrigger) -> bool {
        match self.state {
            LoopState::AclMismatch => false,
            LoopState::Backoff => match self.backoff_until {
                Some(deadline) if now < deadline => false,
                _ => {
                    self.state = LoopState::Syncing;
                    self.backoff_until = None;
                    true
                }
            },
            _ => {
                self.state = LoopState::Syncing;
                true
            }
        }
    }

    /// Record the outcome of a sync attempt. Drives the state transition
    /// per plan §FsWatcher (success → Idle; retryable err → Backoff;
    /// AclRoleMismatch → AclMismatch sticky).
    pub fn finish_sync<R: Rng + ?Sized>(
        &mut self,
        outcome: Result<(), LoopError>,
        now: Instant,
        rng: &mut R,
    ) {
        match outcome {
            Ok(()) => {
                self.state = LoopState::Idle;
                self.backoff.reset();
                self.backoff_until = None;
                self.last_error = None;
            }
            Err(err) if err.should_backoff() => {
                let delay = self.backoff.next_delay(rng);
                self.state = match err {
                    LoopError::TransportUnavailable => LoopState::ServerUnreachable,
                    _ => LoopState::Backoff,
                };
                self.backoff_until = Some(now + delay);
                self.last_error = Some(err);
            }
            Err(err) => {
                // Sticky non-retryable failure (acl.role_mismatch).
                self.state = LoopState::AclMismatch;
                self.backoff_until = None;
                self.last_error = Some(err);
            }
        }
    }

    /// Clear a sticky `AclMismatch` — call when operator confirms
    /// config or ACL has been corrected (eventually wired to
    /// `POST /config/reload` in R9).
    pub fn clear_acl_mismatch(&mut self) {
        if self.state == LoopState::AclMismatch {
            self.state = LoopState::Idle;
            self.last_error = None;
            self.backoff.reset();
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn rng_seed() -> StdRng {
        StdRng::seed_from_u64(0xD15C_0006_0005_0000)
    }

    // ----------- LoopError classification -----------

    #[test]
    fn share_unknown_triggers_backoff() {
        assert!(LoopError::ShareUnknown.should_backoff());
    }

    #[test]
    fn transport_unavailable_triggers_backoff() {
        assert!(LoopError::TransportUnavailable.should_backoff());
    }

    #[test]
    fn acl_role_mismatch_does_not_backoff() {
        assert!(!LoopError::AclRoleMismatch.should_backoff());
    }

    // ----------- Backoff curve -----------

    #[test]
    fn backoff_zero_jitter_doubles_each_attempt() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(60), 0.0);
        let mut rng = rng_seed();
        let d0 = b.next_delay(&mut rng);
        let d1 = b.next_delay(&mut rng);
        let d2 = b.next_delay(&mut rng);
        let d3 = b.next_delay(&mut rng);
        let d4 = b.next_delay(&mut rng);
        assert_eq!(d0, Duration::from_secs(1));
        assert_eq!(d1, Duration::from_secs(2));
        assert_eq!(d2, Duration::from_secs(4));
        assert_eq!(d3, Duration::from_secs(8));
        assert_eq!(d4, Duration::from_secs(16));
    }

    #[test]
    fn backoff_caps_at_60_seconds() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(60), 0.0);
        let mut rng = rng_seed();
        // 2^6 = 64 → above cap.
        for _ in 0..6 {
            let _ = b.next_delay(&mut rng);
        }
        let d6 = b.next_delay(&mut rng);
        assert_eq!(d6, Duration::from_secs(60));
        // Far past the cap — still 60s.
        for _ in 0..20 {
            let d = b.next_delay(&mut rng);
            assert_eq!(d, Duration::from_secs(60), "must stay at cap");
        }
    }

    #[test]
    fn backoff_jitter_stays_within_band() {
        let mut b = Backoff::new(
            Duration::from_secs(1),
            Duration::from_secs(60),
            BACKOFF_JITTER,
        );
        let mut rng = rng_seed();
        // First attempt → 1s ±10% → [900ms, 1.1s].
        for _ in 0..200 {
            let mut b = b.clone();
            let d = b.next_delay(&mut rng);
            assert!(
                d >= Duration::from_millis(900) && d <= Duration::from_millis(1_100),
                "delay {d:?} outside ±10% band of 1s"
            );
        }
        // After saturating to 60s, jitter cannot push past the cap.
        for _ in 0..10 {
            let _ = b.next_delay(&mut rng);
        }
        for _ in 0..200 {
            let mut bb = b.clone();
            let d = bb.next_delay(&mut rng);
            assert!(
                d <= Duration::from_secs(60),
                "jitter must not exceed cap, got {d:?}"
            );
            assert!(
                d >= Duration::from_millis(54_000),
                "jittered cap floor: 60s -10% = 54s, got {d:?}"
            );
        }
    }

    #[test]
    fn backoff_reset_returns_to_floor() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(60), 0.0);
        let mut rng = rng_seed();
        for _ in 0..5 {
            let _ = b.next_delay(&mut rng);
        }
        assert_eq!(b.attempt(), 5);
        b.reset();
        assert_eq!(b.attempt(), 0);
        assert_eq!(b.next_delay(&mut rng), Duration::from_secs(1));
    }

    #[test]
    #[should_panic(expected = "jitter must be within")]
    fn backoff_rejects_jitter_out_of_band() {
        let _ = Backoff::new(Duration::from_secs(1), Duration::from_secs(60), 1.5);
    }

    // ----------- SyncLoop state machine -----------

    #[test]
    fn fresh_loop_is_idle() {
        let s = SyncLoop::new();
        assert_eq!(s.state(), LoopState::Idle);
        assert_eq!(s.poll_interval(), POLL_INTERVAL);
        assert!(s.last_error().is_none());
    }

    #[test]
    fn begin_sync_from_idle_transitions_to_syncing() {
        let mut s = SyncLoop::new();
        let now = Instant::now();
        assert!(s.begin_sync(now, LoopTrigger::Tick));
        assert_eq!(s.state(), LoopState::Syncing);
    }

    #[test]
    fn finish_sync_success_resets_to_idle() {
        let mut s = SyncLoop::new();
        let mut rng = rng_seed();
        let now = Instant::now();
        s.begin_sync(now, LoopTrigger::Tick);
        s.finish_sync(Ok(()), now, &mut rng);
        assert_eq!(s.state(), LoopState::Idle);
        assert_eq!(s.backoff().attempt(), 0);
        assert!(s.last_error().is_none());
    }

    #[test]
    fn share_unknown_enters_backoff_dwell() {
        let mut s = SyncLoop::new();
        let mut rng = rng_seed();
        let now = Instant::now();
        s.begin_sync(now, LoopTrigger::Tick);
        s.finish_sync(Err(LoopError::ShareUnknown), now, &mut rng);
        assert_eq!(s.state(), LoopState::Backoff);
        assert!(s.backoff_until().is_some());
        let deadline = s.backoff_until().unwrap();
        // First attempt floor delay is ~1s ±10% → between 900ms and 1.1s ahead.
        let elapsed = deadline.saturating_duration_since(now);
        assert!(
            elapsed >= Duration::from_millis(900) && elapsed <= Duration::from_millis(1_100),
            "first backoff dwell {elapsed:?} outside expected band"
        );
        assert_eq!(s.last_error(), Some(LoopError::ShareUnknown));
    }

    #[test]
    fn transport_unavailable_enters_server_unreachable_with_backoff() {
        let mut s = SyncLoop::new();
        let mut rng = rng_seed();
        let now = Instant::now();
        s.begin_sync(now, LoopTrigger::Tick);
        s.finish_sync(Err(LoopError::TransportUnavailable), now, &mut rng);
        assert_eq!(s.state(), LoopState::ServerUnreachable);
        assert!(s.backoff_until().is_some());
    }

    #[test]
    fn acl_role_mismatch_is_sticky_no_dwell_timer() {
        let mut s = SyncLoop::new();
        let mut rng = rng_seed();
        let now = Instant::now();
        s.begin_sync(now, LoopTrigger::Tick);
        s.finish_sync(Err(LoopError::AclRoleMismatch), now, &mut rng);
        assert_eq!(s.state(), LoopState::AclMismatch);
        assert!(s.backoff_until().is_none());
    }

    #[test]
    fn begin_sync_blocked_during_backoff_dwell() {
        let mut s = SyncLoop::new();
        let mut rng = rng_seed();
        let now = Instant::now();
        s.begin_sync(now, LoopTrigger::Tick);
        s.finish_sync(Err(LoopError::ShareUnknown), now, &mut rng);
        // Still in the dwell window — second begin_sync refuses.
        assert!(!s.begin_sync(now, LoopTrigger::FsEventBatch));
        assert_eq!(s.state(), LoopState::Backoff);
    }

    #[test]
    fn begin_sync_unblocks_after_dwell_passes() {
        let mut s = SyncLoop::new();
        let mut rng = rng_seed();
        let now = Instant::now();
        s.begin_sync(now, LoopTrigger::Tick);
        s.finish_sync(Err(LoopError::ShareUnknown), now, &mut rng);
        let later = s.backoff_until().unwrap() + Duration::from_millis(1);
        assert!(s.begin_sync(later, LoopTrigger::FsEventBatch));
        assert_eq!(s.state(), LoopState::Syncing);
    }

    #[test]
    fn begin_sync_blocked_during_acl_mismatch() {
        let mut s = SyncLoop::new();
        let mut rng = rng_seed();
        let now = Instant::now();
        s.begin_sync(now, LoopTrigger::Tick);
        s.finish_sync(Err(LoopError::AclRoleMismatch), now, &mut rng);
        assert!(!s.begin_sync(now + Duration::from_secs(3600), LoopTrigger::Manual));
        assert_eq!(s.state(), LoopState::AclMismatch);
    }

    #[test]
    fn clear_acl_mismatch_returns_loop_to_idle() {
        let mut s = SyncLoop::new();
        let mut rng = rng_seed();
        let now = Instant::now();
        s.begin_sync(now, LoopTrigger::Tick);
        s.finish_sync(Err(LoopError::AclRoleMismatch), now, &mut rng);
        s.clear_acl_mismatch();
        assert_eq!(s.state(), LoopState::Idle);
        assert!(s.last_error().is_none());
    }

    #[test]
    fn clear_acl_mismatch_is_noop_outside_that_state() {
        let mut s = SyncLoop::new();
        s.clear_acl_mismatch();
        assert_eq!(s.state(), LoopState::Idle);

        let mut rng = rng_seed();
        let now = Instant::now();
        s.begin_sync(now, LoopTrigger::Tick);
        s.finish_sync(Err(LoopError::ShareUnknown), now, &mut rng);
        s.clear_acl_mismatch(); // must not affect Backoff state
        assert_eq!(s.state(), LoopState::Backoff);
    }

    #[test]
    fn backoff_resets_after_success_following_failure() {
        let mut s = SyncLoop::new();
        let mut rng = rng_seed();
        let now = Instant::now();
        // Two failures bump the attempt counter.
        s.begin_sync(now, LoopTrigger::Tick);
        s.finish_sync(Err(LoopError::ShareUnknown), now, &mut rng);
        let later = s.backoff_until().unwrap() + Duration::from_millis(1);
        s.begin_sync(later, LoopTrigger::Tick);
        s.finish_sync(Err(LoopError::ShareUnknown), later, &mut rng);
        assert!(s.backoff().attempt() >= 2);
        // Now a success — counter resets.
        let later2 = s.backoff_until().unwrap() + Duration::from_millis(1);
        s.begin_sync(later2, LoopTrigger::Tick);
        s.finish_sync(Ok(()), later2, &mut rng);
        assert_eq!(s.state(), LoopState::Idle);
        assert_eq!(s.backoff().attempt(), 0);
    }
}
