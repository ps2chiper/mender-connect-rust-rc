//! External, deterministic tests for the pure session-router foundation.
//!
//! All time advances are expressed as caller-supplied [`Instant`] values derived
//! from a base instant, so no sleeps or fake clocks are involved. Boundaries and
//! failures are exercised only through the public API.

use std::time::{Duration, Instant};

use mender_connect_rust::session_router::MAX_USER_SESSIONS;
use mender_connect_rust::session_router::{
    IdError, MAX_ID_LEN, MAX_ROUTER_SESSIONS, MAX_SHELLS_SPAWNED, RouterAction, RouterError,
    SessionDisposition, SessionId, SessionRouter, ShellRegistry, ShellRegistryError, UserId,
};

fn sid(value: &str) -> SessionId {
    SessionId::new(value).expect("valid session id")
}

fn uid(value: &str) -> UserId {
    UserId::new(value).expect("valid user id")
}

#[test]
fn ping_and_timeout_boundaries() {
    let base = Instant::now();
    let mut router = SessionRouter::new(Duration::from_secs(60)).expect("router");
    assert_eq!(router.ping_wait(), Duration::from_secs(48));
    assert_eq!(router.pong_wait(), Duration::from_secs(12));

    let s = sid("sid-1");
    assert_eq!(
        router.open_or_touch(&s, base).expect("open"),
        SessionDisposition::Created
    );
    assert_eq!(
        router.nearest_deadline(),
        Some(base + Duration::from_secs(48))
    );

    assert!(router.poll_due(base + Duration::from_secs(47)).is_none());
    assert!(matches!(
        router.poll_due(base + Duration::from_secs(48)),
        Some(RouterAction::Ping { session }) if session == s
    ));
    assert_eq!(
        router.nearest_deadline(),
        Some(base + Duration::from_secs(60))
    );
    assert!(router.poll_due(base + Duration::from_secs(59)).is_none());
    assert!(matches!(
        router.poll_due(base + Duration::from_secs(60)),
        Some(RouterAction::Timeout { session }) if session == s
    ));
    assert!(router.is_retiring(&s));
}

#[test]
fn any_inbound_resets_idle() {
    let base = Instant::now();
    let mut router = SessionRouter::new(Duration::from_secs(60)).expect("router");
    let s = sid("a");
    router.open_or_touch(&s, base).expect("open");
    assert_eq!(
        router
            .open_or_touch(&s, base + Duration::from_secs(47))
            .expect("touch"),
        SessionDisposition::Touched
    );
    assert_eq!(
        router.nearest_deadline(),
        Some(base + Duration::from_secs(95))
    );
    assert!(router.poll_due(base + Duration::from_secs(48)).is_none());
}

#[test]
fn pong_after_ping_resets_grace() {
    let base = Instant::now();
    let mut router = SessionRouter::new(Duration::from_secs(60)).expect("router");
    let s = sid("a");
    router.open_or_touch(&s, base).expect("open");
    assert!(matches!(
        router.poll_due(base + Duration::from_secs(48)),
        Some(RouterAction::Ping { .. })
    ));
    // Late pong at 55s resets to 55 + 48 = 103s and clears the ping flag.
    router
        .open_or_touch(&s, base + Duration::from_secs(55))
        .expect("touch");
    assert_eq!(
        router.nearest_deadline(),
        Some(base + Duration::from_secs(103))
    );
    assert!(router.poll_due(base + Duration::from_secs(60)).is_none());
    assert!(matches!(
        router.poll_due(base + Duration::from_secs(103)),
        Some(RouterAction::Ping { .. })
    ));
}

#[test]
fn sid_isolation() {
    let base = Instant::now();
    let mut router = SessionRouter::new(Duration::from_secs(60)).expect("router");
    let a = sid("a");
    let b = sid("b");
    router.open_or_touch(&a, base).expect("a");
    router
        .open_or_touch(&b, base + Duration::from_secs(10))
        .expect("b");
    assert!(matches!(
        router.poll_due(base + Duration::from_secs(48)),
        Some(RouterAction::Ping { session }) if session == a
    ));
    assert!(matches!(
        router.poll_due(base + Duration::from_secs(58)),
        Some(RouterAction::Ping { session }) if session == b
    ));
    assert!(matches!(
        router.poll_due(base + Duration::from_secs(60)),
        Some(RouterAction::Timeout { session }) if session == a
    ));
    assert!(router.is_retiring(&a));
    assert!(!router.is_retiring(&b));
}

#[test]
fn empty_sid_supported() {
    let base = Instant::now();
    let mut router = SessionRouter::new(Duration::from_secs(60)).expect("router");
    let empty = SessionId::new("").expect("empty ok");
    assert!(empty.is_empty());
    assert_eq!(
        router.open_or_touch(&empty, base).expect("open"),
        SessionDisposition::Created
    );
    assert_eq!(router.len(), 1);
}

#[test]
fn capacity_reject_and_reclaim() {
    let base = Instant::now();
    let mut router = SessionRouter::new(Duration::from_secs(60)).expect("router");
    for i in 0..MAX_ROUTER_SESSIONS {
        let s = sid(&format!("s{i}"));
        assert_eq!(
            router.open_or_touch(&s, base).expect("open"),
            SessionDisposition::Created
        );
    }
    let over = sid("overflow");
    assert_eq!(
        router.open_or_touch(&over, base),
        Err(RouterError::CapacityExceeded)
    );

    let first = sid("s0");
    router.complete_close(&first).expect("close");
    assert_eq!(
        router.open_or_touch(&over, base).expect("open"),
        SessionDisposition::Created
    );
    assert_eq!(router.len(), MAX_ROUTER_SESSIONS);
}

#[test]
fn closing_no_resurrection_until_ack() {
    let base = Instant::now();
    let mut router = SessionRouter::new(Duration::from_secs(60)).expect("router");
    let s = sid("x");
    router.open_or_touch(&s, base).expect("open");
    assert!(matches!(
        router.poll_due(base + Duration::from_secs(48)),
        Some(RouterAction::Ping { .. })
    ));
    assert!(matches!(
        router.poll_due(base + Duration::from_secs(60)),
        Some(RouterAction::Timeout { .. })
    ));
    assert!(router.is_retiring(&s));

    assert_eq!(
        router
            .open_or_touch(&s, base + Duration::from_secs(61))
            .expect("still there"),
        SessionDisposition::Retiring
    );
    assert!(router.is_retiring(&s));
    assert_eq!(router.nearest_deadline(), None);

    router.complete_close(&s).expect("ack");
    assert!(!router.contains(&s));
    assert_eq!(
        router
            .open_or_touch(&s, base + Duration::from_secs(62))
            .expect("recreate"),
        SessionDisposition::Created
    );
}

#[test]
fn id_length_boundary() {
    let ok = "a".repeat(MAX_ID_LEN);
    assert!(SessionId::new(ok).is_ok());

    let bad = "a".repeat(MAX_ID_LEN + 1);
    assert_eq!(SessionId::new(bad), Err(IdError::TooLong));

    // Multi-byte: 64 two-byte chars = 128 bytes (ok); 65 = 130 bytes (too long).
    let two_ok = "\u{e9}".repeat(64);
    assert!(UserId::new(two_ok).is_ok());
    let two_bad = "\u{e9}".repeat(65);
    assert_eq!(UserId::new(two_bad), Err(IdError::TooLong));
}

#[test]
fn duration_validation() {
    assert!(matches!(
        SessionRouter::new(Duration::ZERO),
        Err(RouterError::ZeroIdleDuration)
    ));
    assert!(matches!(
        SessionRouter::new(Duration::from_nanos(1)),
        Err(RouterError::ZeroIdleDuration)
    ));
    assert!(matches!(
        SessionRouter::new(Duration::new(u64::MAX, 0)),
        Err(RouterError::DurationOverflow)
    ));
}

#[test]
fn close_missing_entry_errors() {
    let mut router = SessionRouter::new(Duration::from_secs(60)).expect("router");
    let ghost = sid("ghost");
    assert_eq!(router.begin_close(&ghost), Err(RouterError::MissingEntry));
    assert_eq!(
        router.complete_close(&ghost),
        Err(RouterError::MissingEntry)
    );
}

#[test]
fn shell_quota_same_user_rejected_different_allowed() {
    let mut reg = ShellRegistry::new();
    let s1 = sid("s1");
    let s2 = sid("s2");
    let alice = uid("alice");
    let bob = uid("bob");

    assert!(reg.try_reserve(&s1, &alice).is_ok());
    assert_eq!(
        reg.try_reserve(&s2, &alice),
        Err(ShellRegistryError::QuotaExceeded)
    );
    assert!(reg.try_reserve(&s2, &bob).is_ok());
    assert_eq!(reg.count(), 2);
}

#[test]
fn shell_global_capacity_sixteen() {
    let mut reg = ShellRegistry::new();
    for i in 0..MAX_SHELLS_SPAWNED {
        let s = sid(&format!("s{i}"));
        let u = uid(&format!("u{i}"));
        assert!(reg.try_reserve(&s, &u).is_ok());
    }
    let over_s = sid("over");
    let over_u = uid("over-u");
    assert_eq!(
        reg.try_reserve(&over_s, &over_u),
        Err(ShellRegistryError::CapacityExceeded)
    );
}

#[test]
fn empty_user_is_shared_quota_bucket() {
    let mut reg = ShellRegistry::new();
    let empty = UserId::new("").expect("empty user ok");
    let s1 = sid("s1");
    let s2 = sid("s2");
    assert!(reg.try_reserve(&s1, &empty).is_ok());
    assert_eq!(
        reg.try_reserve(&s2, &empty),
        Err(ShellRegistryError::QuotaExceeded)
    );
}

#[test]
fn release_reuse_and_user_lookup() {
    let mut reg = ShellRegistry::new();
    let s1 = sid("s1");
    let alice = uid("alice");
    assert!(reg.try_reserve(&s1, &alice).is_ok());
    assert_eq!(reg.sessions_for_user(&alice), vec![s1.clone()]);
    assert_eq!(reg.user_of(&s1), Some(&alice));

    assert_eq!(reg.release(&s1), Some(alice.clone()));
    assert!(reg.is_empty());
    assert!(reg.sessions_for_user(&alice).is_empty());

    let s2 = sid("s2");
    assert!(reg.try_reserve(&s2, &alice).is_ok());
    assert_eq!(reg.user_of(&s2), Some(&alice));
}

#[test]
fn stop_user_lookup_exact_match() {
    let mut reg = ShellRegistry::new();
    let s1 = sid("s1");
    let alice = uid("alice");
    reg.try_reserve(&s1, &alice).expect("reserve");

    assert_eq!(reg.sessions_for_user(&alice), vec![s1.clone()]);

    let different_case = uid("Alice");
    assert!(reg.sessions_for_user(&different_case).is_empty());
    let nobody = uid("nobody");
    assert!(reg.sessions_for_user(&nobody).is_empty());

    let unknown = sid("unknown");
    assert_eq!(reg.release(&unknown), None);
}

#[test]
fn late_ping_uses_actual_poll_time_for_grace() {
    let base = Instant::now();
    let mut router = SessionRouter::new(Duration::from_secs(60)).expect("router");
    let s = sid("late");
    router.open_or_touch(&s, base).expect("open");
    // Poll after the original 48s ping deadline: still emits a Ping.
    assert!(matches!(
        router.poll_due(base + Duration::from_secs(50)),
        Some(RouterAction::Ping { session }) if session == s
    ));
    // The full 12s grace runs from the actual poll time (50 + 12 = 62),
    // matching the Go reset, rather than an immediate timeout at 60.
    assert_eq!(
        router.nearest_deadline(),
        Some(base + Duration::from_secs(62))
    );
    assert!(router.poll_due(base + Duration::from_secs(61)).is_none());
    assert!(matches!(
        router.poll_due(base + Duration::from_secs(62)),
        Some(RouterAction::Timeout { session }) if session == s
    ));
    assert!(router.is_retiring(&s));
}

#[test]
fn with_limits_rejects_invalid_values() {
    assert_eq!(
        ShellRegistry::with_limits(0, MAX_SHELLS_SPAWNED).err(),
        Some(ShellRegistryError::InvalidLimits)
    );
    assert_eq!(
        ShellRegistry::with_limits(MAX_USER_SESSIONS, 0).err(),
        Some(ShellRegistryError::InvalidLimits)
    );
    assert_eq!(
        ShellRegistry::with_limits(MAX_USER_SESSIONS + 1, MAX_SHELLS_SPAWNED).err(),
        Some(ShellRegistryError::InvalidLimits)
    );
    assert_eq!(
        ShellRegistry::with_limits(MAX_USER_SESSIONS, MAX_SHELLS_SPAWNED + 1).err(),
        Some(ShellRegistryError::InvalidLimits)
    );
    assert_eq!(
        ShellRegistry::with_limits(usize::MAX, usize::MAX).err(),
        Some(ShellRegistryError::InvalidLimits)
    );
}

#[test]
fn with_limits_lower_global_cap_and_release() {
    let cap = 2;
    let mut reg =
        ShellRegistry::with_limits(MAX_USER_SESSIONS, cap).expect("valid lower global cap");
    for i in 0..cap {
        let s = sid(&format!("s{i}"));
        let u = uid(&format!("u{i}"));
        assert!(reg.try_reserve(&s, &u).is_ok());
    }
    assert_eq!(reg.count(), cap);
    assert_eq!(
        reg.try_reserve(&sid("over"), &uid("over-u")),
        Err(ShellRegistryError::CapacityExceeded)
    );

    let first = sid("s0");
    assert!(reg.release(&first).is_some());
    assert_eq!(reg.count(), cap - 1);
    assert!(!reg.is_empty());
    assert!(reg.try_reserve(&sid("over"), &uid("over-u")).is_ok());
    assert_eq!(reg.count(), cap);
}
