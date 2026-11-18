//! Tests for the deterministic retry policy in `src/backoff.rs`.
//!
//! Attempt numbering follows the upstream Go reference
//! (`mender-connect/connectionmanager/exponentialbackoff.go`, commit
//! `ba393f11b6317f756bb86c5f3963061903728c01`):
//!
//! * `WaitForBackoff` increments the attempt counter *before* computing the
//!   delay.
//! * The first attempt (`attempts == 1`) returns immediately (zero delay).
//! * For `attempts >= 2`, the base delay is `1s << (attempts / 3)`, capped at
//!   1800s, plus caller-supplied jitter clamped to 5s.
//!
//! With zero jitter the successive delays are therefore
//! `[0, 1, 2, 2, 2, 4, 4, 4, 8, ...]` seconds.

use std::time::Duration;

use mender_connect_rust::backoff::Backoff;

const MAX_BACKOFF: Duration = Duration::from_secs(1800);
const MAX_JITTER: Duration = Duration::from_secs(5);

#[test]
fn reference_sequence_with_zero_jitter() {
    let mut backoff = Backoff::default();
    let expected_secs = [0u64, 1, 2, 2, 2, 4, 4, 4, 8, 8, 8, 16];
    for (step, &secs) in expected_secs.iter().enumerate() {
        let delay = backoff.next_delay(Duration::ZERO);
        assert_eq!(
            delay,
            Duration::from_secs(secs),
            "unexpected delay at step {step}"
        );
    }
}

#[test]
fn reset_returns_to_immediate_first_attempt() {
    let mut backoff = Backoff::default();
    for _ in 0..5 {
        backoff.next_delay(Duration::ZERO);
    }
    backoff.reset();
    assert_eq!(backoff.next_delay(Duration::ZERO), Duration::ZERO);
    assert_eq!(backoff.next_delay(Duration::ZERO), Duration::from_secs(1));
}

#[test]
fn saturates_at_cap_after_many_retries() {
    let mut backoff = Backoff::default();
    for _ in 0..10_000 {
        let delay = backoff.next_delay(Duration::ZERO);
        assert!(delay <= MAX_BACKOFF, "delay exceeded cap: {delay:?}");
    }
    assert_eq!(backoff.next_delay(Duration::ZERO), MAX_BACKOFF);
}

#[test]
fn jitter_is_added_and_clamped() {
    let mut backoff = Backoff::default();
    // First attempt ignores jitter entirely.
    assert_eq!(backoff.next_delay(Duration::from_secs(10)), Duration::ZERO);
    // Second attempt: base 1s + jitter 3s.
    assert_eq!(
        backoff.next_delay(Duration::from_secs(3)),
        Duration::from_secs(4)
    );
    // Third attempt: base 2s + oversize jitter clamped to 5s.
    assert_eq!(
        backoff.next_delay(Duration::from_secs(10)),
        Duration::from_secs(7)
    );
}

#[test]
fn jitter_bounds_are_respected() {
    let mut backoff = Backoff::default();
    // Skip the immediate first attempt.
    backoff.next_delay(Duration::ZERO);
    for _ in 0..100 {
        let delay = backoff.next_delay(MAX_JITTER);
        assert!(delay >= Duration::from_secs(1) + MAX_JITTER);
        assert!(delay <= MAX_BACKOFF + MAX_JITTER);
    }
}
