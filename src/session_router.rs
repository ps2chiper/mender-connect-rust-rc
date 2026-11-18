//! Pure, deterministic, bounded session-routing foundation.
//!
//! This module provides the generic, *non-shell* session scaffolding that will
//! later back the daemon's `session.Router` integration. It is intentionally
//! **not wired into the daemon in this batch**: existing daemon/PTY behavior is
//! unchanged.
//!
//! The upstream Go daemon routes `SHELL` protocol messages directly through the
//! legacy handlers (`app/daemon_shell.go`); only non-shell protocols (including
//! `CONTROL`, file transfer, port-forward and mender-client commands) ever reach
//! `session.Router` (`app/daemon.go`). This module mirrors that split:
//!
//! * [`SessionRouter`] models the *generic* per-`SessionID` lifecycle and the
//!   upstream CONTROL idle heartbeat (ping / pong / timeout) from
//!   `session/session.go`.
//! * [`ShellRegistry`] is a **separate** helper for shell quota bookkeeping: one
//!   live shell per exact logical user-ID string (`MaxUserSessions = 1`) and a
//!   global cap of 16 shells (`MaxShellsSpawned`).
//!
//! Nothing here performs asynchronous work, spawns tasks, owns PTYs, or keeps
//! hidden clocks. Time is entirely caller-supplied via [`Instant`], and all
//! durations are validated and combined with checked arithmetic. The caller
//! retains ownership of any real PTY / worker resources; a timed-out session is
//! only marked *retiring* until the caller confirms cleanup, so a live resource
//! is never silently freed or resurrected by a stray inbound message.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

/// Maximum length, in bytes, of a [`SessionId`] or [`UserId`].
///
/// This is *our* defensive bound, not a limit enforced by the upstream Go
/// source: upstream treats the session ID and the shell-header user ID as
/// opaque strings, so this foundation caps them at 128 bytes to keep router
/// state bounded.
pub const MAX_ID_LEN: usize = 128;

/// Defensive cap on the number of concurrently tracked generic session IDs.
///
/// Upstream keeps an unbounded `sync.Map` keyed by SID; this foundation keeps a
/// small, documented upper bound so a misbehaving peer cannot grow router state
/// without limit.
pub const MAX_ROUTER_SESSIONS: usize = 64;

/// Hard cap on live shells per exact logical user-ID string (`MaxUserSessions`).
pub const MAX_USER_SESSIONS: usize = 1;

/// Hard cap on the total number of live shells (`MaxShellsSpawned`).
pub const MAX_SHELLS_SPAWNED: usize = 16;

/// Error returned when an identifier fails validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdError {
    /// The raw byte length exceeds [`MAX_ID_LEN`].
    TooLong,
}

impl std::fmt::Display for IdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdError::TooLong => {
                write!(f, "identifier exceeds the {MAX_ID_LEN}-byte limit")
            }
        }
    }
}

impl std::error::Error for IdError {}

fn validate_id(value: &str) -> Result<(), IdError> {
    if value.len() > MAX_ID_LEN {
        Err(IdError::TooLong)
    } else {
        Ok(())
    }
}

/// A bounded, validated session identifier.
///
/// The empty string is a valid identifier: upstream creates a session for
/// Mender-client commands that carry no `SessionID` ("emptySID"). Shell / file
/// transfer SID validation is handled separately by their own layers.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(String);

impl SessionId {
    /// Construct a validated session identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        validate_id(&value)?;
        Ok(SessionId(value))
    }

    /// Borrow the identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this is the empty SID ("emptySID").
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Byte length of the identifier.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// A bounded, validated logical user identifier.
///
/// This is the *remote* user-ID string taken from the message header, used for
/// shell quota and internal stop-by-user-ID lookup. It is deliberately not tied
/// to any local OS identity or configured user. The empty string is a valid,
/// shared quota bucket that matches upstream behaviour when the header carries
/// no user ID.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UserId(String);

impl UserId {
    /// Construct a validated user identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        validate_id(&value)?;
        Ok(UserId(value))
    }

    /// Borrow the identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this is the empty (missing) user ID.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Errors produced by [`SessionRouter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouterError {
    /// The bounded session table is full.
    CapacityExceeded,
    /// The referenced session ID is not tracked.
    MissingEntry,
    /// The idle duration is zero (or its ping/pong split rounds to zero).
    ZeroIdleDuration,
    /// Duration or `Instant` arithmetic overflowed.
    DurationOverflow,
}

impl std::fmt::Display for RouterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouterError::CapacityExceeded => write!(f, "session router capacity exceeded"),
            RouterError::MissingEntry => write!(f, "session ID is not tracked"),
            RouterError::ZeroIdleDuration => write!(f, "idle duration must be non-zero"),
            RouterError::DurationOverflow => write!(f, "duration arithmetic overflowed"),
        }
    }
}

impl std::error::Error for RouterError {}

/// Outcome of feeding an inbound message for a session ID to the router.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionDisposition {
    /// A fresh session entry was created.
    Created,
    /// An existing active session's idle timer was reset.
    Touched,
    /// The session is retiring; the message is acknowledged but ignored so it
    /// cannot resurrect or reuse the state before explicit cleanup.
    Retiring,
}

/// A single action the daemon should perform for a session.
///
/// The variant only carries the correlated session ID so the daemon can build
/// the existing correlated CONTROL messages itself; this module never imports
/// daemon control helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouterAction {
    /// Send a `CONTROL` ping for this session and await a response within the
    /// pong grace window.
    Ping { session: SessionId },
    /// The session exhausted its idle grace and is now retiring. The caller must
    /// free its resources and then call [`SessionRouter::complete_close`].
    Timeout { session: SessionId },
}

struct IdleState {
    deadline: Instant,
    ping_sent: bool,
}

enum SessionState {
    Active(IdleState),
    Retiring,
}

struct Entry {
    state: SessionState,
}

/// Pure, deterministic generic session router.
///
/// Tracks per-`SessionID` CONTROL idle state using caller-supplied [`Instant`]
/// values. Callers drive it by:
///
/// 1. feeding inbound messages through [`open_or_touch`](Self::open_or_touch),
/// 2. polling [`poll_due`](Self::poll_due) for the single next due action,
/// 3. scheduling their own timer on [`nearest_deadline`](Self::nearest_deadline),
/// 4. retiring timed-out sessions and, once resources are freed, calling
///    [`complete_close`](Self::complete_close).
pub struct SessionRouter {
    sessions: BTreeMap<SessionId, Entry>,
    idle_duration: Duration,
    ping_wait: Duration,
    pong_wait: Duration,
}

impl SessionRouter {
    /// Create a router with the given idle duration.
    ///
    /// Upstream splits the idle timeout into `pingWait = idle * 4 / 5` and
    /// `pongWait = idle - pingWait`. For the default 60-second idle timeout
    /// this yields a 48-second ping wait and a 12-second pong grace.
    ///
    /// # Errors
    /// Returns [`RouterError::ZeroIdleDuration`] if the duration is zero or the
    /// split rounds to zero, and [`RouterError::DurationOverflow`] if the split
    /// arithmetic overflows.
    pub fn new(idle_duration: Duration) -> Result<Self, RouterError> {
        if idle_duration.is_zero() {
            return Err(RouterError::ZeroIdleDuration);
        }
        let ping_wait = idle_duration
            .checked_mul(4)
            .ok_or(RouterError::DurationOverflow)?
            / 5;
        let pong_wait = idle_duration
            .checked_sub(ping_wait)
            .ok_or(RouterError::DurationOverflow)?;
        if ping_wait.is_zero() || pong_wait.is_zero() {
            return Err(RouterError::ZeroIdleDuration);
        }
        Ok(SessionRouter {
            sessions: BTreeMap::new(),
            idle_duration,
            ping_wait,
            pong_wait,
        })
    }

    /// The configured idle duration.
    pub fn idle_duration(&self) -> Duration {
        self.idle_duration
    }

    /// The computed ping wait (`idle * 4 / 5`).
    pub fn ping_wait(&self) -> Duration {
        self.ping_wait
    }

    /// The computed pong grace (`idle - ping_wait`).
    pub fn pong_wait(&self) -> Duration {
        self.pong_wait
    }

    /// Register or refresh the session for an inbound message.
    ///
    /// Any inbound message for an active session resets its idle timer. A new
    /// session ID creates an entry, subject to [`MAX_ROUTER_SESSIONS`]. A session
    /// that is already retiring reports [`SessionDisposition::Retiring`] and is
    /// **not** resurrected.
    ///
    /// # Errors
    /// [`RouterError::CapacityExceeded`] when the table is full, or
    /// [`RouterError::DurationOverflow`] if the deadline cannot be represented.
    pub fn open_or_touch(
        &mut self,
        id: &SessionId,
        now: Instant,
    ) -> Result<SessionDisposition, RouterError> {
        let ping_wait = self.ping_wait;
        if let Some(entry) = self.sessions.get_mut(id) {
            match &mut entry.state {
                SessionState::Active(idle) => {
                    idle.deadline = now
                        .checked_add(ping_wait)
                        .ok_or(RouterError::DurationOverflow)?;
                    idle.ping_sent = false;
                    return Ok(SessionDisposition::Touched);
                }
                SessionState::Retiring => return Ok(SessionDisposition::Retiring),
            }
        }
        if self.sessions.len() >= MAX_ROUTER_SESSIONS {
            return Err(RouterError::CapacityExceeded);
        }
        let deadline = now
            .checked_add(ping_wait)
            .ok_or(RouterError::DurationOverflow)?;
        self.sessions.insert(
            id.clone(),
            Entry {
                state: SessionState::Active(IdleState {
                    deadline,
                    ping_sent: false,
                }),
            },
        );
        Ok(SessionDisposition::Created)
    }

    /// Begin retiring a session (e.g. on a caller-initiated CONTROL close).
    ///
    /// # Errors
    /// [`RouterError::MissingEntry`] if the session is unknown.
    pub fn begin_close(&mut self, id: &SessionId) -> Result<(), RouterError> {
        match self.sessions.get_mut(id) {
            Some(entry) => {
                entry.state = SessionState::Retiring;
                Ok(())
            }
            None => Err(RouterError::MissingEntry),
        }
    }

    /// Remove a session after the caller has finished cleaning up its resources.
    ///
    /// # Errors
    /// [`RouterError::MissingEntry`] if the session is unknown.
    pub fn complete_close(&mut self, id: &SessionId) -> Result<(), RouterError> {
        if self.sessions.remove(id).is_some() {
            Ok(())
        } else {
            Err(RouterError::MissingEntry)
        }
    }

    /// The earliest idle deadline across all active sessions, if any.
    pub fn nearest_deadline(&self) -> Option<Instant> {
        self.sessions
            .values()
            .filter_map(|entry| match &entry.state {
                SessionState::Active(idle) => Some(idle.deadline),
                SessionState::Retiring => None,
            })
            .min()
    }

    /// Return and apply the single next due action, if one is due at `now`.
    ///
    /// Ties are broken deterministically: earliest deadline first, then smallest
    /// session ID. A ping action arms the pong grace; a timeout action marks the
    /// session retiring.
    pub fn poll_due(&mut self, now: Instant) -> Option<RouterAction> {
        let mut target: Option<SessionId> = None;
        let mut target_deadline: Option<Instant> = None;
        for (id, entry) in &self.sessions {
            let SessionState::Active(idle) = &entry.state else {
                continue;
            };
            if idle.deadline <= now {
                let replace = match target_deadline {
                    None => true,
                    Some(current) => idle.deadline < current,
                };
                if replace {
                    target = Some(id.clone());
                    target_deadline = Some(idle.deadline);
                }
            }
        }
        let id = target?;
        let pong_wait = self.pong_wait;

        let entry = self.sessions.get_mut(&id)?;

        let ping_sent = match &entry.state {
            SessionState::Active(idle) => idle.ping_sent,
            SessionState::Retiring => return None,
        };

        if ping_sent {
            entry.state = SessionState::Retiring;
            return Some(RouterAction::Timeout { session: id });
        }

        let next_deadline = now.checked_add(pong_wait);
        let mut overflow = false;
        if let SessionState::Active(idle) = &mut entry.state {
            idle.ping_sent = true;
            match next_deadline {
                Some(deadline) => idle.deadline = deadline,
                None => overflow = true,
            }
        }

        if overflow {
            entry.state = SessionState::Retiring;
            Some(RouterAction::Timeout { session: id })
        } else {
            Some(RouterAction::Ping { session: id })
        }
    }

    /// Whether a session is currently retiring.
    pub fn is_retiring(&self, id: &SessionId) -> bool {
        matches!(
            self.sessions.get(id),
            Some(Entry {
                state: SessionState::Retiring
            })
        )
    }

    /// Whether a session is currently tracked (active or retiring).
    pub fn contains(&self, id: &SessionId) -> bool {
        self.sessions.contains_key(id)
    }

    /// Number of tracked sessions.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Whether no sessions are tracked.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Drop all tracked sessions.
    pub fn clear(&mut self) {
        self.sessions.clear();
    }
}

/// Errors produced by [`ShellRegistry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellRegistryError {
    /// A shell slot is already reserved for this session ID.
    AlreadyActive,
    /// The exact user already holds the maximum number of shells.
    QuotaExceeded,
    /// The global shell cap has been reached.
    CapacityExceeded,
    /// The requested limits are zero or exceed the hard caps.
    InvalidLimits,
}

impl std::fmt::Display for ShellRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShellRegistryError::AlreadyActive => {
                write!(f, "session already holds a shell slot")
            }
            ShellRegistryError::QuotaExceeded => write!(f, "per-user shell quota exceeded"),
            ShellRegistryError::CapacityExceeded => write!(f, "global shell capacity exceeded"),
            ShellRegistryError::InvalidLimits => write!(f, "invalid shell registry limits"),
        }
    }
}

impl std::error::Error for ShellRegistryError {}

/// Shell quota helper: maps session IDs to exact logical user IDs and enforces
/// the per-user and global shell caps.
///
/// The caller retains ownership of the actual PTY / worker resources. A slot is
/// reserved before a shell is spawned and released only after cleanup is
/// confirmed. This exposes internal, quota-aware lookups; it invents no wire
/// action for stop-by-user-ID.
pub struct ShellRegistry {
    by_session: BTreeMap<SessionId, UserId>,
    by_user: BTreeMap<UserId, BTreeSet<SessionId>>,
    max_per_user: usize,
    global_max: usize,
}

impl ShellRegistry {
    /// Create a registry with the upstream limits: one shell per user and a
    /// global cap of 16.
    pub fn new() -> Self {
        ShellRegistry {
            by_session: BTreeMap::new(),
            by_user: BTreeMap::new(),
            max_per_user: MAX_USER_SESSIONS,
            global_max: MAX_SHELLS_SPAWNED,
        }
    }

    /// Create a registry with explicit, validated limits.
    ///
    /// The limits must be non-zero and may not exceed the hard caps
    /// ([`MAX_USER_SESSIONS`] per user, [`MAX_SHELLS_SPAWNED`] globally). The
    /// hard caps are enforced here so the constructor cannot produce a registry
    /// that silently allows more shells than the advertised defensive maximum.
    ///
    /// # Errors
    /// [`ShellRegistryError::InvalidLimits`] if either limit is zero or exceeds
    /// its hard cap.
    pub fn with_limits(max_per_user: usize, global_max: usize) -> Result<Self, ShellRegistryError> {
        if max_per_user == 0 || max_per_user > MAX_USER_SESSIONS {
            return Err(ShellRegistryError::InvalidLimits);
        }
        if global_max == 0 || global_max > MAX_SHELLS_SPAWNED {
            return Err(ShellRegistryError::InvalidLimits);
        }
        Ok(ShellRegistry {
            by_session: BTreeMap::new(),
            by_user: BTreeMap::new(),
            max_per_user,
            global_max,
        })
    }

    /// Reserve a shell slot for `session` owned by `user`.
    ///
    /// The empty user ID is a normal, shared quota bucket, matching upstream.
    ///
    /// # Errors
    /// [`ShellRegistryError::AlreadyActive`] if the session already holds a slot,
    /// [`ShellRegistryError::QuotaExceeded`] if the user is at their limit, or
    /// [`ShellRegistryError::CapacityExceeded`] if the global cap is reached.
    pub fn try_reserve(
        &mut self,
        session: &SessionId,
        user: &UserId,
    ) -> Result<(), ShellRegistryError> {
        if self.by_session.contains_key(session) {
            return Err(ShellRegistryError::AlreadyActive);
        }
        if self.by_session.len() >= self.global_max {
            return Err(ShellRegistryError::CapacityExceeded);
        }
        let existing = self.by_user.get(user).map_or(0, |set| set.len());
        if existing >= self.max_per_user {
            return Err(ShellRegistryError::QuotaExceeded);
        }
        self.by_session.insert(session.clone(), user.clone());
        self.by_user
            .entry(user.clone())
            .or_default()
            .insert(session.clone());
        Ok(())
    }

    /// Release the slot for `session`, returning the owning user ID if present.
    ///
    /// Callers must invoke this only after the underlying resources have been
    /// cleaned up.
    pub fn release(&mut self, session: &SessionId) -> Option<UserId> {
        let user = self.by_session.remove(session)?;
        let now_empty = if let Some(set) = self.by_user.get_mut(&user) {
            set.remove(session);
            set.is_empty()
        } else {
            false
        };
        if now_empty {
            self.by_user.remove(&user);
        }
        Some(user)
    }

    /// The exact user ID owning `session`, if reserved.
    pub fn user_of(&self, session: &SessionId) -> Option<&UserId> {
        self.by_session.get(session)
    }

    /// The session IDs owned by the exact `user`, for internal stop-by-user-ID.
    pub fn sessions_for_user(&self, user: &UserId) -> Vec<SessionId> {
        self.by_user
            .get(user)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Whether `session` currently holds a slot.
    pub fn contains(&self, session: &SessionId) -> bool {
        self.by_session.contains_key(session)
    }

    /// Number of reserved slots.
    pub fn count(&self) -> usize {
        self.by_session.len()
    }

    /// Whether no slots are reserved.
    pub fn is_empty(&self) -> bool {
        self.by_session.is_empty()
    }
}

impl Default for ShellRegistry {
    fn default() -> Self {
        Self::new()
    }
}
