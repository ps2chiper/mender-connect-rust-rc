//! Deterministic shell-expiry policy.
//!
//! Computes the active deadline from a [`SessionsConfig`] and a
//! caller-supplied [`Instant`]. No wall-clock reads, sleeps or global state
//! are used; the caller drives time and reports successful shell input via
//! [`SessionPolicy::note_input`].
//!
//! Precedence matches upstream `session/shell.go:IsExpired`: when
//! `expire_after_idle > 0` the idle deadline is used exclusively and
//! `expire_after` is ignored for this session. The two settings are
//! mutually exclusive upstream (`config/config.go:283-285`); this module
//! does not normalize or log that condition, it simply honors the
//! precedence. Only when idle is disabled does `expire_after > 0` apply as
//! an absolute deadline.

use std::time::Duration;

use tokio::time::Instant;

use crate::config::SessionsConfig;

/// Tracks the active deadline for a single shell session.
///
/// At most one of `absolute` / `idle` is `Some` at a time, reflecting the
/// upstream mutual-exclusion of `ExpireAfter` and `ExpireAfterIdle`.
#[derive(Debug, Clone)]
pub struct SessionPolicy {
    absolute: Option<Instant>,
    idle: Option<Instant>,
    idle_duration: Option<Duration>,
}

impl SessionPolicy {
    /// Build a policy from configuration at session creation time `now`.
    ///
    /// `StopExpired == false` disables both limits. Otherwise, if
    /// `expire_after_idle > 0` the idle deadline is used exclusively and
    /// `expire_after` is ignored (the settings are mutually exclusive
    /// upstream). Only when idle is disabled does `expire_after > 0` apply
    /// as an absolute deadline. If neither is enabled, no deadline is set.
    /// No defaults are applied here.
    pub fn new(config: &SessionsConfig, now: Instant) -> Self {
        if !config.stop_expired {
            return Self {
                absolute: None,
                idle: None,
                idle_duration: None,
            };
        }
        // Idle takes precedence; absolute is ignored when idle is enabled.
        if config.expire_after_idle > 0 {
            let idle_duration = Duration::from_secs(u64::from(config.expire_after_idle));
            return Self {
                absolute: None,
                idle: Some(now + idle_duration),
                idle_duration: Some(idle_duration),
            };
        }
        let absolute = (config.expire_after > 0)
            .then(|| now + Duration::from_secs(u64::from(config.expire_after)));
        Self {
            absolute,
            idle: None,
            idle_duration: None,
        }
    }

    /// Record successful remote shell input at `now`, extending only the idle
    /// deadline. When the policy is absolute-only (idle disabled), this is a
    /// no-op and the absolute deadline is never extended.
    pub fn note_input(&mut self, now: Instant) {
        if let Some(duration) = self.idle_duration {
            self.idle = Some(now + duration);
        }
    }

    /// Active deadline, or `None` when both limits are disabled.
    pub fn deadline(&self) -> Option<Instant> {
        match (self.absolute, self.idle) {
            (Some(a), Some(i)) => Some(a.min(i)),
            (a, i) => a.or(i),
        }
    }

    /// True when `now` is at or past the active deadline.
    pub fn is_expired(&self, now: Instant) -> bool {
        self.deadline().is_some_and(|deadline| now >= deadline)
    }
}
