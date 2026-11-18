//! Pure, manual-clock rate-counter foundation.
//!
//! This module provides a typed, side-effect-free engine that reproduces the
//! upstream mender-connect file-transfer byte-counter semantics *without* a
//! global static, background ticker, threads or any I/O. The engine is driven
//! entirely by caller-supplied [`Instant`]s (a manual clock), which makes it
//! deterministic and trivially testable.
//!
//! # Ownership / wiring status (this batch is unwired)
//!
//! One engine instance is intended to be owned by the daemon supervisor and
//! shared across file managers and connections, e.g. as a
//! [`SharedRateCounter`] cloned via `Arc` into each worker. This batch does
//! **not** wire it into the daemon, configuration loader or transfer workers:
//! no static, no detached task, and no run-time enablement is introduced here.
//! Per-process scope is deliberate: the counters describe bytes moved by *this*
//! process only and are never shared across processes.
//!
//! Downstream wiring contract: the supervisor constructs exactly one engine
//! (with the process/daemon start [`Instant`]) and hands clones of the shared
//! handle to every file manager. The engine is **never reset** when a new file
//! manager or authentication reconnect occurs; totals accumulate monotonically
//! for the lifetime of the process.
//!
//! # Tick cadence and EMA meaning
//!
//! Upstream runs a ticker every 5 s and folds the bytes-since-last-tick into a
//! one-minute *soft* exponential moving average:
//!
//! ```text
//! decay = exp(-(5 s / 60 s))
//! weight = 1 - decay
//! avg  = weight * bytes_in_window + decay * avg_previous
//! ```
//!
//! Here the tick is explicit: [`RateEngine::advance`] (also invoked implicitly
//! by [`RateEngine::try_record_tx`] / [`RateEngine::try_record_rx`]) consumes
//! any whole 5 s ticks that elapsed since the previous advance. A long idle
//! window is folded in **O(1)** using the closed form `decay^(ticks-1)`; there
//! is no per-tick catch-up loop. The byte delta of the window is applied to the
//! first tick and the remaining idle ticks only decay, which is the smallest
//! faithful model of upstream that remains O(1).
//!
//! # Documented source quirks
//!
//! These are inherited on purpose from the upstream implementation:
//!
//! * **Units.** Despite the `Avg1m` name, the EMA value is *not* bytes per
//!   minute. For a steady rate `R` bytes/s it converges to `5 * R`, i.e. bytes
//!   per 5 s tick. The threshold comparison below preserves this unit meaning
//!   exactly.
//! * **Threshold truncation.** Upstream compares `uint64(avg) >= limit`.
//!   Because the limit is an integer, this is equivalent to `avg >= limit`,
//!   which is what we evaluate (without any lossy float-to-int cast).
//! * **Overflow guard.** Upstream only adds when `total < u64::MAX - n`, so a
//!   huge `n` may be dropped rather than saturating to `u64::MAX`. We keep that
//!   exact guard: counters never wrap.
//! * **Mutation order while denied.** A denied record still mutates the raw
//!   total; the decision is only advisory. We add first, then decide.
//!
//! # Soft EMA vs. hard rolling window
//!
//! The EMA is a *soft* limit: it lags and decays smoothly, so a burst can
//! transiently exceed the configured `*_per_minute` figure and a sustained rate
//! just under it is allowed. It is not a hard, exact rolling-window cap. Callers
//! that need a strict window must enforce it separately.
//!
//! # Disabled behavior
//!
//! When the policy is disabled, recording returns `true` (below the limit) and
//! does **not** mutate any counter, matching upstream. Advancing the clock may
//! still decay the EMA, mirroring upstream's always-running ticker (which keeps
//! folding zero deltas while disabled).
//!
//! # Real-time ("now") variants and clock-domain mixing
//!
//! [`RateEngine`] and the caller-timestamp [`SharedRateCounter`] methods
//! (`advance`, `try_record_tx`, `try_record_rx`, `snapshot`) are a *manual*
//! clock API and stay exactly as-is for deterministic tests.
//!
//! The `*_now` methods ([`SharedRateCounter::try_record_tx_now`],
//! [`SharedRateCounter::try_record_rx_now`], [`SharedRateCounter::snapshot_now`]
//! and [`SharedRateCounter::advance_now`]) are the production real-time API:
//! they sample [`Instant::now`] **inside** the already-acquired mutex guard and
//! then call the same engine. The lock is held only for the short synchronous
//! engine call (no I/O, `await`, ticker or thread creation).
//!
//! Future workers must use **only** the now-variants. The process supervisor
//! owns exactly one counter and clones it across workers and reconnects.
//!
//! **Do not mix** a manually-timestamped counter with real-time (`*_now`) calls
//! on the same shared state: the two clock domains are unrelated, so the mix
//! yields a typed [`RateError::BackwardClock`]. There is deliberately no clock
//! clamping or error hiding — a real timeline violation stays visible. This
//! batch does **not** enable or wire the configuration/runtime paths; the
//! daemon is unchanged.

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Tick period in whole seconds (upstream's 5 s EMA tick).
const TICK_SECONDS_U32: u32 = 5;

/// Tick period in nanoseconds (5 s) expressed as `u128` for checked math.
const TICK_NANOS: u128 = 5_000_000_000;

/// `2^32` as `f64`, used for the exact high-word reconstruction.
const TWO_POW_32: f64 = 4_294_967_296.0;

/// Configured rate limits for one engine.
///
/// A `max_*_per_minute` value of `0` means *unlimited* (matching upstream).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RateLimits {
    /// Whether the limits are enforced at all.
    pub enabled: bool,
    /// Maximum transmitted bytes per minute; `0` means unlimited.
    pub max_bytes_tx_per_minute: u64,
    /// Maximum received bytes per minute; `0` means unlimited.
    pub max_bytes_rx_per_minute: u64,
}

/// Typed errors from the rate engine. All variants are fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateError {
    /// The supplied clock went backwards relative to the last advance.
    BackwardClock,
    /// A tick count or duration computation overflowed its checked type.
    TimeOverflow,
    /// The computed EMA was not finite.
    NonFiniteAverage,
    /// The shared state lock was poisoned (a previous holder panicked).
    Poisoned,
}

impl fmt::Display for RateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::BackwardClock => "the supplied clock went backwards",
            Self::TimeOverflow => "time arithmetic overflowed",
            Self::NonFiniteAverage => "the computed rate average was not finite",
            Self::Poisoned => "the shared rate-counter state was poisoned",
        };
        f.write_str(message)
    }
}

impl std::error::Error for RateError {}

/// Read-only snapshot of the raw totals and the soft EMA values.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RateSnapshot {
    /// Total transmitted bytes recorded so far.
    pub bytes_sent: u64,
    /// Total received bytes recorded so far.
    pub bytes_received: u64,
    /// Soft EMA of transmitted bytes per 5 s tick.
    pub bytes_sent_avg: f64,
    /// Soft EMA of received bytes per 5 s tick.
    pub bytes_received_avg: f64,
}

/// Pure, manual-clock rate counter.
///
/// See the module documentation for the ownership and wiring contract. This
/// type holds no lock and performs no I/O; all time comes from the caller.
#[derive(Debug)]
pub struct RateEngine {
    limits: RateLimits,
    bytes_sent: u64,
    bytes_received: u64,
    avg_sent: f64,
    avg_received: f64,
    last_tick_sent: u64,
    last_tick_received: u64,
    last_advance: Instant,
}

impl RateEngine {
    /// Create a fresh engine with zero totals, anchored at `now`.
    pub fn new(limits: RateLimits, now: Instant) -> Self {
        Self {
            limits,
            bytes_sent: 0,
            bytes_received: 0,
            avg_sent: 0.0,
            avg_received: 0.0,
            last_tick_sent: 0,
            last_tick_received: 0,
            last_advance: now,
        }
    }

    /// The configured limits.
    pub fn limits(&self) -> RateLimits {
        self.limits
    }

    /// Whether the limits are enforced.
    pub fn is_enabled(&self) -> bool {
        self.limits.enabled
    }

    /// Advance the clock to `now`, folding any elapsed 5 s ticks into the EMA
    /// in O(1). Returns an error (leaving all state untouched) on a backward
    /// clock or checked-arithmetic overflow.
    pub fn advance(&mut self, now: Instant) -> Result<(), RateError> {
        let elapsed = now
            .checked_duration_since(self.last_advance)
            .ok_or(RateError::BackwardClock)?;

        let ticks_u128 = elapsed.as_nanos() / TICK_NANOS;
        if ticks_u128 == 0 {
            return Ok(());
        }
        let ticks = u64::try_from(ticks_u128).map_err(|_| RateError::TimeOverflow)?;

        let consumed_nanos = ticks_u128
            .checked_mul(TICK_NANOS)
            .ok_or(RateError::TimeOverflow)?;
        let consumed_nanos_u64 =
            u64::try_from(consumed_nanos).map_err(|_| RateError::TimeOverflow)?;
        let consumed = Duration::from_nanos(consumed_nanos_u64);

        let new_last_advance = self
            .last_advance
            .checked_add(consumed)
            .ok_or(RateError::TimeOverflow)?;

        let delta_sent = self.bytes_sent.saturating_sub(self.last_tick_sent);
        let delta_received = self.bytes_received.saturating_sub(self.last_tick_received);

        let (weight, decay) = ema_weights();

        let mut avg_sent = weight * u64_to_f64(delta_sent) + decay * self.avg_sent;
        let mut avg_received = weight * u64_to_f64(delta_received) + decay * self.avg_received;

        if ticks > 1 {
            let rest_decay = decay.powf(u64_to_f64(ticks - 1));
            avg_sent *= rest_decay;
            avg_received *= rest_decay;
        }

        if !avg_sent.is_finite() || !avg_received.is_finite() {
            return Err(RateError::NonFiniteAverage);
        }

        // Commit atomically once every value has been validated.
        self.avg_sent = avg_sent;
        self.avg_received = avg_received;
        self.last_tick_sent = self.bytes_sent;
        self.last_tick_received = self.bytes_received;
        self.last_advance = new_last_advance;
        Ok(())
    }

    /// Record transmitted bytes and return `true` when still below the limit.
    ///
    /// When disabled, returns `true` without touching any counter. The raw
    /// total is incremented (with the upstream overflow guard) *before* the
    /// decision is taken, so a denial does not suppress the accounting.
    pub fn try_record_tx(&mut self, now: Instant, bytes: u64) -> Result<bool, RateError> {
        if !self.limits.enabled {
            return Ok(true);
        }
        self.advance(now)?;

        if bytes != 0 && self.bytes_sent < u64::MAX - bytes {
            self.bytes_sent += bytes;
        }

        let limit = self.limits.max_bytes_tx_per_minute;
        let below = !(limit > 0 && self.avg_sent >= u64_to_f64(limit));
        Ok(below)
    }

    /// Record received bytes and return `true` when still below the limit.
    ///
    /// Symmetric to [`Self::try_record_tx`].
    pub fn try_record_rx(&mut self, now: Instant, bytes: u64) -> Result<bool, RateError> {
        if !self.limits.enabled {
            return Ok(true);
        }
        self.advance(now)?;

        if bytes != 0 && self.bytes_received < u64::MAX - bytes {
            self.bytes_received += bytes;
        }

        let limit = self.limits.max_bytes_rx_per_minute;
        let below = !(limit > 0 && self.avg_received >= u64_to_f64(limit));
        Ok(below)
    }

    /// The current raw totals and soft EMA values.
    pub fn snapshot(&self) -> RateSnapshot {
        RateSnapshot {
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
            bytes_sent_avg: self.avg_sent,
            bytes_received_avg: self.avg_received,
        }
    }
}

/// A shared, poison-safe handle to a single [`RateEngine`].
///
/// Cloning shares the *same* engine state via `Arc<Mutex<..>>`, so every clone
/// observes one counter. The mutex is only held for the short, synchronous
/// engine call and never across an `await` or I/O; a poisoned lock yields
/// [`RateError::Poisoned`] (fail-closed).
#[derive(Clone)]
pub struct SharedRateCounter {
    inner: Arc<Mutex<RateEngine>>,
}

impl SharedRateCounter {
    /// Wrap an engine in a shared handle.
    pub fn new(engine: RateEngine) -> Self {
        Self {
            inner: Arc::new(Mutex::new(engine)),
        }
    }

    /// Return the immutable configured limits of the wrapped engine.
    ///
    /// The mutex is held only for this short synchronous read; the returned
    /// value is a `Copy` snapshot and never borrows the shared state. This lets
    /// a caller verify that an injected counter matches the intended policy
    /// without resetting or re-anchoring the clock.
    pub fn configured_limits(&self) -> Result<RateLimits, RateError> {
        self.inner
            .lock()
            .map_err(|_| RateError::Poisoned)
            .map(|guard| guard.limits())
    }

    /// See [`RateEngine::advance`].
    pub fn advance(&self, now: Instant) -> Result<(), RateError> {
        self.inner
            .lock()
            .map_err(|_| RateError::Poisoned)?
            .advance(now)
    }

    /// See [`RateEngine::try_record_tx`].
    pub fn try_record_tx(&self, now: Instant, bytes: u64) -> Result<bool, RateError> {
        self.inner
            .lock()
            .map_err(|_| RateError::Poisoned)?
            .try_record_tx(now, bytes)
    }

    /// See [`RateEngine::try_record_rx`].
    pub fn try_record_rx(&self, now: Instant, bytes: u64) -> Result<bool, RateError> {
        self.inner
            .lock()
            .map_err(|_| RateError::Poisoned)?
            .try_record_rx(now, bytes)
    }

    /// See [`RateEngine::snapshot`].
    pub fn snapshot(&self) -> Result<RateSnapshot, RateError> {
        self.inner
            .lock()
            .map_err(|_| RateError::Poisoned)
            .map(|guard| guard.snapshot())
    }

    /// Real-time [`RateEngine::advance`] that samples [`Instant::now`] inside
    /// the acquired guard. The clock is only sampled once the lock is held, so
    /// the timestamp ordering matches the mutation ordering.
    pub fn advance_now(&self) -> Result<(), RateError> {
        let mut guard = self.inner.lock().map_err(|_| RateError::Poisoned)?;
        guard.advance(Instant::now())
    }

    /// Real-time [`RateEngine::try_record_tx`] that samples [`Instant::now`]
    /// inside the acquired guard.
    pub fn try_record_tx_now(&self, bytes: u64) -> Result<bool, RateError> {
        let mut guard = self.inner.lock().map_err(|_| RateError::Poisoned)?;
        guard.try_record_tx(Instant::now(), bytes)
    }

    /// Real-time [`RateEngine::try_record_rx`] that samples [`Instant::now`]
    /// inside the acquired guard.
    pub fn try_record_rx_now(&self, bytes: u64) -> Result<bool, RateError> {
        let mut guard = self.inner.lock().map_err(|_| RateError::Poisoned)?;
        guard.try_record_rx(Instant::now(), bytes)
    }

    /// Real-time snapshot: advances the EMA to [`Instant::now`] (sampled inside
    /// the acquired guard) *before* reading, then returns the snapshot.
    pub fn snapshot_now(&self) -> Result<RateSnapshot, RateError> {
        let mut guard = self.inner.lock().map_err(|_| RateError::Poisoned)?;
        guard.advance(Instant::now())?;
        Ok(guard.snapshot())
    }
}

/// The fixed upstream 5 s EMA weights: `(weight, decay)`.
fn ema_weights() -> (f64, f64) {
    let decay = (-(f64::from(TICK_SECONDS_U32) * (1.0 / 60.0))).exp();
    let weight = 1.0 - decay;
    (weight, decay)
}

/// Convert a `u64` to `f64` via exact 32-bit words and `f64::from(u32)`.
///
/// Values above `2^53` are not exactly representable, which is inherent to
/// `f64`; the decomposition avoids any lossy or unchecked integer cast.
fn u64_to_f64(value: u64) -> f64 {
    let high = u32::try_from(value >> 32).unwrap_or(0);
    let low = u32::try_from(value & 0xFFFF_FFFF).unwrap_or(0);
    f64::from(high) * TWO_POW_32 + f64::from(low)
}

#[cfg(test)]
mod poison_tests {
    use super::{RateEngine, RateError, RateLimits, SharedRateCounter};
    use std::time::Instant;

    /// A poisoned lock must fail closed for every real-time entry point and
    /// must neither recover nor mutate the historical state.
    #[test]
    fn poisoned_counter_fails_closed_for_now_variants() {
        let limits = RateLimits {
            enabled: true,
            max_bytes_tx_per_minute: 0,
            max_bytes_rx_per_minute: 0,
        };
        let counter = SharedRateCounter::new(RateEngine::new(limits, Instant::now()));
        assert!(counter.try_record_tx_now(7).unwrap_or(false));

        // Intentionally poison the mutex from a test-only worker panic.
        let poisoner = counter.clone();
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = poisoner.inner.lock();
            panic!("intentional test-only lock poison");
        }));
        assert!(poisoned.is_err());

        assert_eq!(counter.try_record_tx_now(1), Err(RateError::Poisoned));
        assert_eq!(counter.try_record_rx_now(1), Err(RateError::Poisoned));
        assert_eq!(counter.advance_now(), Err(RateError::Poisoned));
        assert_eq!(counter.snapshot_now(), Err(RateError::Poisoned));

        // The historical totals are unchanged (no recovery attempt mutated them).
        match counter.inner.lock() {
            Ok(_) => panic!("lock unexpectedly healthy after poisoning"),
            Err(err) => {
                let snap = err.into_inner().snapshot();
                assert_eq!(snap.bytes_sent, 7);
                assert_eq!(snap.bytes_received, 0);
            }
        }
    }
}
