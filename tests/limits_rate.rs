//! Deterministic manual-clock tests for the rate-counter foundation.
//!
//! No sleeps, threads or background runtimes: every timestamp is
//! caller-supplied and every expectation is derived from the upstream 5 s EMA
//! formula.

use std::time::{Duration, Instant};

use mender_connect_rust::limits_rate::{RateEngine, RateError, RateLimits, SharedRateCounter};

/// Upstream decay/weight pair, mirrored exactly from the module.
fn weights() -> (f64, f64) {
    let decay = (-(f64::from(5u32) * (1.0 / 60.0))).exp();
    (1.0 - decay, decay)
}

fn approx(a: f64, b: f64) -> bool {
    (a - b).abs() <= 1e-9 * b.abs().max(1.0)
}

fn enabled(tx: u64, rx: u64) -> RateLimits {
    RateLimits {
        enabled: true,
        max_bytes_tx_per_minute: tx,
        max_bytes_rx_per_minute: rx,
    }
}

#[test]
fn source_formula_five_second_tick() {
    let t0 = Instant::now();
    let mut engine = RateEngine::new(enabled(0, 0), t0);

    // Recording at the same instant does not tick.
    assert!(engine.try_record_tx(t0, 1251).unwrap());
    assert!(approx(engine.snapshot().bytes_sent_avg, 0.0));

    // One 5 s tick folds the whole window delta into the EMA.
    engine.advance(t0 + Duration::from_secs(5)).unwrap();

    let (weight, decay) = weights();
    let expected = weight * 1251.0 + decay * 0.0;
    let snap = engine.snapshot();
    assert!(approx(snap.bytes_sent_avg, expected));
    assert_eq!(snap.bytes_sent, 1251);
}

#[test]
fn tx_and_rx_are_isolated() {
    let t0 = Instant::now();
    let mut engine = RateEngine::new(enabled(0, 0), t0);

    assert!(engine.try_record_tx(t0, 800).unwrap());
    engine.advance(t0 + Duration::from_secs(5)).unwrap();

    let snap = engine.snapshot();
    let (weight, _) = weights();
    assert!(approx(snap.bytes_sent_avg, weight * 800.0));
    assert_eq!(snap.bytes_received, 0);
    assert!(approx(snap.bytes_received_avg, 0.0));
}

#[test]
fn threshold_below_equal_and_over() {
    let t0 = Instant::now();
    // Build the same EMA value (~100.02 bytes/tick) for each case.
    let build = |limit: u64| {
        let mut engine = RateEngine::new(enabled(limit, 0), t0);
        engine.try_record_tx(t0, 1251).unwrap();
        engine.advance(t0 + Duration::from_secs(5)).unwrap();
        engine
    };

    // uint64(avg) == 100, so limit 100 is "equal" and denies.
    let mut equal = build(100);
    assert!(!equal.try_record_tx(t0 + Duration::from_secs(5), 0).unwrap());

    // One below the truncated average is allowed.
    let mut below = build(101);
    assert!(below.try_record_tx(t0 + Duration::from_secs(5), 0).unwrap());

    // One over denies.
    let mut over = build(99);
    assert!(!over.try_record_tx(t0 + Duration::from_secs(5), 0).unwrap());
}

#[test]
fn zero_limit_is_unlimited() {
    let t0 = Instant::now();
    let mut engine = RateEngine::new(enabled(0, 0), t0);
    engine.try_record_tx(t0, u64::MAX / 2).unwrap();
    engine.advance(t0 + Duration::from_secs(5)).unwrap();
    assert!(
        engine
            .try_record_tx(t0 + Duration::from_secs(5), 0)
            .unwrap()
    );
}

#[test]
fn disabled_calls_do_not_mutate() {
    let t0 = Instant::now();
    let mut engine = RateEngine::new(RateLimits::default(), t0);

    assert!(engine.try_record_tx(t0, 4096).unwrap());
    assert!(engine.try_record_rx(t0, 4096).unwrap());

    let snap = engine.snapshot();
    assert_eq!(snap.bytes_sent, 0);
    assert_eq!(snap.bytes_received, 0);
    assert!(approx(snap.bytes_sent_avg, 0.0));
    assert!(approx(snap.bytes_received_avg, 0.0));
}

#[test]
fn overflow_does_not_wrap() {
    let t0 = Instant::now();
    let mut engine = RateEngine::new(enabled(0, 0), t0);

    engine.try_record_tx(t0, 10).unwrap();
    assert_eq!(engine.snapshot().bytes_sent, 10);

    // Guard drops this add entirely (10 < MAX - MAX is false): no wrap.
    engine.try_record_tx(t0, u64::MAX).unwrap();
    assert_eq!(engine.snapshot().bytes_sent, 10);

    // Further small adds still work and stay monotonic.
    engine.try_record_tx(t0, 5).unwrap();
    assert_eq!(engine.snapshot().bytes_sent, 15);
}

#[test]
fn denial_still_mutates_totals() {
    let t0 = Instant::now();
    let mut engine = RateEngine::new(enabled(100, 0), t0);
    engine.try_record_tx(t0, 1251).unwrap();
    engine.advance(t0 + Duration::from_secs(5)).unwrap();

    // avg ~100.02 => 100 limit denies, but the total still grows by 50.
    let below = engine
        .try_record_tx(t0 + Duration::from_secs(5), 50)
        .unwrap();
    assert!(!below);
    assert_eq!(engine.snapshot().bytes_sent, 1301);
}

#[test]
fn shared_clones_observe_one_state() {
    let t0 = Instant::now();
    let counter = SharedRateCounter::new(RateEngine::new(enabled(0, 0), t0));
    let first = counter.clone();
    let second = counter.clone();

    first.try_record_tx(t0, 100).unwrap();
    second.try_record_tx(t0, 50).unwrap();
    counter.try_record_rx(t0, 25).unwrap();

    let snap = counter.snapshot().unwrap();
    assert_eq!(snap.bytes_sent, 150);
    assert_eq!(snap.bytes_received, 25);
}

#[test]
fn totals_are_not_reset_across_advances() {
    let t0 = Instant::now();
    let mut engine = RateEngine::new(enabled(0, 0), t0);

    engine.try_record_tx(t0, 100).unwrap();
    engine.advance(t0 + Duration::from_secs(5)).unwrap();
    engine
        .try_record_tx(t0 + Duration::from_secs(10), 200)
        .unwrap();

    assert_eq!(engine.snapshot().bytes_sent, 300);
}

#[test]
fn large_elapsed_is_o1_and_decays_finitely() {
    let t0 = Instant::now();
    let mut engine = RateEngine::new(enabled(0, 0), t0);

    engine.try_record_tx(t0, 1000).unwrap();
    engine.advance(t0 + Duration::from_secs(5)).unwrap();
    let after_one_tick = engine.snapshot().bytes_sent_avg;
    assert!(after_one_tick > 0.0);

    // A long idle window folds in closed form, never looping per tick.
    engine
        .advance(t0 + Duration::from_secs(60 * 60 * 24 * 30))
        .unwrap();

    let snap = engine.snapshot();
    assert!(snap.bytes_sent_avg.is_finite());
    assert!(snap.bytes_sent_avg >= 0.0);
    assert!(snap.bytes_sent_avg < after_one_tick);
    assert_eq!(snap.bytes_sent, 1000);
}

#[test]
fn backward_clock_errors_without_partial_state() {
    let t0 = Instant::now();
    let mut engine = RateEngine::new(enabled(0, 0), t0);

    engine.try_record_tx(t0, 10).unwrap();
    let past = t0.checked_sub(Duration::from_secs(1)).unwrap();

    assert_eq!(engine.advance(past), Err(RateError::BackwardClock));
    assert_eq!(engine.try_record_tx(past, 5), Err(RateError::BackwardClock));

    let snap = engine.snapshot();
    assert_eq!(snap.bytes_sent, 10);
    assert!(approx(snap.bytes_sent_avg, 0.0));
}

#[test]
fn now_variants_record_and_advance() {
    let counter = SharedRateCounter::new(RateEngine::new(enabled(0, 0), Instant::now()));

    assert!(counter.try_record_tx_now(10).unwrap());
    assert!(counter.try_record_rx_now(20).unwrap());
    assert!(counter.advance_now().is_ok());

    let snap = counter.snapshot_now().unwrap();
    assert_eq!(snap.bytes_sent, 10);
    assert_eq!(snap.bytes_received, 20);
    assert!(snap.bytes_sent_avg.is_finite());
}

#[test]
fn disabled_now_variants_do_not_mutate() {
    let counter = SharedRateCounter::new(RateEngine::new(RateLimits::default(), Instant::now()));

    assert!(counter.try_record_tx_now(4096).unwrap());
    assert!(counter.try_record_rx_now(4096).unwrap());

    let snap = counter.snapshot_now().unwrap();
    assert_eq!(snap.bytes_sent, 0);
    assert_eq!(snap.bytes_received, 0);
}

#[test]
fn snapshot_now_advances_boundary_without_sleep() {
    // Anchor the engine 5 s in the past so a single real ``now`` sample crosses
    // the tick boundary without any sleep.
    let anchor = Instant::now().checked_sub(Duration::from_secs(5)).unwrap();
    let mut engine = RateEngine::new(enabled(0, 0), anchor);
    engine.try_record_tx(anchor, 1000).unwrap();
    let counter = SharedRateCounter::new(engine);

    let snap = counter.snapshot_now().unwrap();
    assert_eq!(snap.bytes_sent, 1000);
    assert!(snap.bytes_sent_avg > 0.0);
    assert!(snap.bytes_sent_avg.is_finite());
}

#[test]
fn backward_mix_is_typed_and_not_clamped() {
    let anchor = Instant::now();
    let counter = SharedRateCounter::new(RateEngine::new(enabled(0, 0), anchor));
    let past = anchor.checked_sub(Duration::from_secs(1)).unwrap();

    assert_eq!(
        counter.try_record_tx(past, 1),
        Err(RateError::BackwardClock)
    );
    assert_eq!(
        counter.try_record_rx(past, 1),
        Err(RateError::BackwardClock)
    );
    assert_eq!(counter.advance(past), Err(RateError::BackwardClock));

    let snap = counter.snapshot().unwrap();
    assert_eq!(snap.bytes_sent, 0);
    assert_eq!(snap.bytes_received, 0);
}

#[test]
fn concurrent_real_now_callers_share_state() {
    let counter = SharedRateCounter::new(RateEngine::new(enabled(0, 0), Instant::now()));

    let mut handles = Vec::new();
    for _ in 0..4 {
        let worker = counter.clone();
        handles.push(std::thread::spawn(move || {
            let mut saw_backward = false;
            for _ in 0..1000 {
                if worker.try_record_tx_now(1) == Err(RateError::BackwardClock) {
                    saw_backward = true;
                }
                if worker.try_record_rx_now(1) == Err(RateError::BackwardClock) {
                    saw_backward = true;
                }
            }
            saw_backward
        }));
    }

    let mut any_backward = false;
    for handle in handles {
        match handle.join() {
            Ok(flag) => any_backward |= flag,
            Err(_) => panic!("worker thread panicked"),
        }
    }

    assert!(
        !any_backward,
        "real-time callers must not see BackwardClock"
    );
    let snap = counter.snapshot_now().unwrap();
    assert_eq!(snap.bytes_sent, 4 * 1000);
    assert_eq!(snap.bytes_received, 4 * 1000);
}
