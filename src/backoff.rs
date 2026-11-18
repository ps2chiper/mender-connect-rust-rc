//! Deterministic retry policy mirroring the upstream Go exponential backoff.
//!
//! Reference: `mender-connect/connectionmanager/exponentialbackoff.go`
//! (commit `ba393f11b6317f756bb86c5f3963061903728c01`).
//!
//! Attempt numbering matches `WaitForBackoff`: the counter is incremented
//! *before* the delay is computed, and the first attempt returns immediately.
//! For attempt `n >= 2` the base delay is `1s << (n / 3)` capped at 1800s,
//! plus caller-supplied jitter clamped to 5s.
//!
//! This module is pure: it never sleeps, reads the wall clock, or draws
//! randomness. The caller supplies jitter and performs cancellation-safe
//! sleeping.

use std::time::Duration;

/// Smallest backoff unit (1 second), matching the Go `smallestUnit`.
const SMALLEST_UNIT: Duration = Duration::from_secs(1);
/// Maximum base backoff (1800 seconds), matching the Go `maxBackoff`.
const MAX_BACKOFF: Duration = Duration::from_secs(1800);
/// Maximum jitter (5 seconds), matching the Go `randomInterval` bound.
const MAX_JITTER: Duration = Duration::from_secs(5);
/// Largest shift for which `SMALLEST_UNIT << shift` stays below `MAX_BACKOFF`.
///
/// `1s << 10 == 1024s < 1800s`, while `1s << 11 == 2048s > 1800s`. Using this
/// threshold avoids shift overflow for large attempt counts.
const MAX_SHIFT: u32 = 10;

/// Deterministic exponential backoff policy.
#[derive(Debug, Default)]
pub struct Backoff {
    attempts: u64,
}

impl Backoff {
    /// Compute the next delay, advancing the attempt counter.
    ///
    /// The first call returns [`Duration::ZERO`] and ignores `jitter`. Later
    /// calls return the capped exponential base plus `jitter` clamped to 5s.
    pub fn next_delay(&mut self, jitter: Duration) -> Duration {
        self.attempts = self.attempts.saturating_add(1);

        // First attempt returns immediately, matching `WaitForBackoff`.
        if self.attempts <= 1 {
            return Duration::ZERO;
        }

        let shift = self.attempts / 3;
        // Shift amounts are bounded by `MAX_SHIFT`; both the conversion to the
        // shift operand type and the shift itself are checked so that no
        // unchecked numeric cast or overflow can occur.
        let base = u32::try_from(shift)
            .ok()
            .filter(|shift| *shift <= MAX_SHIFT)
            .and_then(|shift| SMALLEST_UNIT.as_secs().checked_shl(shift))
            .map_or(MAX_BACKOFF, Duration::from_secs);

        base + jitter.min(MAX_JITTER)
    }

    /// Reset the policy so the next call is the immediate first attempt again.
    pub fn reset(&mut self) {
        self.attempts = 0;
    }
}
