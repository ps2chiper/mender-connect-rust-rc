use std::time::Duration;

use tokio::time::Instant;

use mender_connect_rust::config::SessionsConfig;
use mender_connect_rust::session_policy::SessionPolicy;

fn cfg(stop_expired: bool, expire_after: u32, expire_after_idle: u32) -> SessionsConfig {
    SessionsConfig {
        stop_expired,
        expire_after,
        expire_after_idle,
        max_per_user: 0,
    }
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

#[test]
fn absolute_only_deadline() {
    let now = Instant::now();
    let policy = SessionPolicy::new(&cfg(true, 10, 0), now);
    assert_eq!(policy.deadline(), Some(now + secs(10)));
    assert!(!policy.is_expired(now + secs(9)));
    assert!(policy.is_expired(now + secs(10)));
}

#[test]
fn idle_only_deadline() {
    let now = Instant::now();
    let policy = SessionPolicy::new(&cfg(true, 0, 5), now);
    assert_eq!(policy.deadline(), Some(now + secs(5)));
    assert!(!policy.is_expired(now + secs(4)));
    assert!(policy.is_expired(now + secs(5)));
}

#[test]
fn idle_takes_precedence_over_absolute() {
    let now = Instant::now();
    // Absolute (5s) would be earlier than idle (10s), but upstream precedence
    // uses idle exclusively when it is configured.
    let policy = SessionPolicy::new(&cfg(true, 5, 10), now);
    assert_eq!(policy.deadline(), Some(now + secs(10)));
    assert!(!policy.is_expired(now + secs(5)));
    assert!(!policy.is_expired(now + secs(9)));
    assert!(policy.is_expired(now + secs(10)));
}

#[test]
fn idle_precedence_ignores_later_absolute() {
    let now = Instant::now();
    // Absolute (20s) is later than idle (5s); idle still wins.
    let policy = SessionPolicy::new(&cfg(true, 20, 5), now);
    assert_eq!(policy.deadline(), Some(now + secs(5)));
    assert!(!policy.is_expired(now + secs(4)));
    assert!(policy.is_expired(now + secs(5)));
}

#[test]
fn input_extends_idle() {
    let now = Instant::now();
    let mut policy = SessionPolicy::new(&cfg(true, 0, 5), now);
    policy.note_input(now + secs(3));
    assert_eq!(policy.deadline(), Some(now + secs(8)));
    assert!(!policy.is_expired(now + secs(7)));
    assert!(policy.is_expired(now + secs(8)));
}

#[test]
fn input_extends_idle_when_both_configured() {
    let now = Instant::now();
    // Idle (5s) takes precedence; absolute (100s) is ignored. Input resets
    // the idle deadline.
    let mut policy = SessionPolicy::new(&cfg(true, 100, 5), now);
    policy.note_input(now + secs(3));
    assert_eq!(policy.deadline(), Some(now + secs(8)));
    assert!(!policy.is_expired(now + secs(7)));
    assert!(policy.is_expired(now + secs(8)));
}

#[test]
fn input_cannot_extend_absolute() {
    let now = Instant::now();
    // Absolute-only configuration: input must never extend the deadline.
    let mut policy = SessionPolicy::new(&cfg(true, 10, 0), now);
    policy.note_input(now + secs(3));
    assert_eq!(policy.deadline(), Some(now + secs(10)));
    assert!(!policy.is_expired(now + secs(9)));
    assert!(policy.is_expired(now + secs(10)));
}

#[test]
fn expiration_at_exact_boundary() {
    let now = Instant::now();
    let policy = SessionPolicy::new(&cfg(true, 10, 0), now);
    assert!(!policy.is_expired(now + secs(10) - Duration::from_nanos(1)));
    assert!(policy.is_expired(now + secs(10)));
}

#[test]
fn stop_expired_false_disables_all() {
    let now = Instant::now();
    let mut policy = SessionPolicy::new(&cfg(false, 10, 5), now);
    assert_eq!(policy.deadline(), None);
    policy.note_input(now + secs(1));
    assert_eq!(policy.deadline(), None);
    assert!(!policy.is_expired(now + secs(1_000_000)));
}

#[test]
fn both_limits_zero_disables_all() {
    let now = Instant::now();
    let policy = SessionPolicy::new(&cfg(true, 0, 0), now);
    assert_eq!(policy.deadline(), None);
    assert!(!policy.is_expired(now + secs(1_000_000)));
}

#[test]
fn zero_idle_keeps_absolute() {
    let now = Instant::now();
    let policy = SessionPolicy::new(&cfg(true, 10, 0), now);
    assert_eq!(policy.deadline(), Some(now + secs(10)));
}

#[test]
fn zero_absolute_keeps_idle() {
    let now = Instant::now();
    let policy = SessionPolicy::new(&cfg(true, 0, 5), now);
    assert_eq!(policy.deadline(), Some(now + secs(5)));
}
