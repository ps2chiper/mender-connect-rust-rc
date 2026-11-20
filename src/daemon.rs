//! Single-session remote terminal daemon with reconnect supervision.
//!
//! This is an experimental prototype: one websocket connection at a time, one
//! active PTY shell, reconnect with exponential backoff, per-shell session
//! expiry, a websocket-level heartbeat (periodic pings with a bounded
//! read/liveness timeout), and a separate shell-session healthcheck. It does
//! not implement privilege switching. See `README.md` for the full list of
//! deferred features.
//!
//! # Supervision model
//!
//! A single continuous `JwtTokenStateChange` subscription is established once
//! and reused across reconnects. The supervisor loop:
//!
//! 1. Obtains credentials via `GetJwtToken` (retrying with backoff on error).
//! 2. If the token or server URL is empty, enters the unauthorized state:
//!    requests `FetchJwtToken` (one attempt per auth backoff slot), then waits
//!    with a bounded deadline for a real state-change signal.
//! 3. Connects the websocket, resetting backoff on success.
//! 4. Runs one connected session until shutdown, a credentials change, or a
//!    retryable failure (network error, EOF, websocket liveness timeout).
//! 5. On a retryable failure, waits with backoff before reconnecting.
//!
//! Shutdown is honoured in every wait. Credentials changes reset backoff and
//! reconnect with the newest tuple. A PTY cleanup failure is fatal and is
//! never followed by a reconnect.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rand::RngExt;
use rmpv::Value;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::auth::{AuthClient, JwtTokenStateChangeSubscription};
use crate::backoff::Backoff;
use crate::config::Config;
use crate::file_transfer_manager::FileTransferManager;
use crate::file_transfer_schema::TransferError;
use crate::limits_config::LiveNss;
use crate::logging::{RuntimeEvent, RuntimeEvents};
use crate::mender_command::MenderCommandManager;
use crate::port_forward::error_reply as port_forward_error_reply;
use crate::port_forward_manager::PortForwardManager;
use crate::protocol::{
    Accept, Error as ControlError, Open, ProtoHdr, ProtoMsg, ProtoType, decode, encode,
};
use crate::pty::{CleanupFailure, PtyShell};
use crate::session_policy::SessionPolicy;
use crate::session_router::{
    RouterAction, RouterError, SessionDisposition, SessionId, SessionRouter, ShellRegistry,
    ShellRegistryError, UserId,
};
use crate::transfer_limits::TransferLimits;
use crate::transport::{Transport, TransportEvent, is_unauthorized_error};

/// Bounded wait for the D-Bus signal subscription to become ready.
pub const SUBSCRIPTION_READY_TIMEOUT: Duration = Duration::from_secs(5);

/// Bound for a single post-`FetchJwtToken` wait for a real state-change signal.
///
/// Official `mender-auth` issues only one HTTP attempt per fetch and will not
/// retry autonomously, so a successful fetch that never yields a valid signal
/// must not wait forever: the attempt times out and retries through backoff.
pub const AUTH_RESULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Websocket read/liveness timeout.
///
/// If no inbound websocket frame (including Ping/Pong) arrives within this
/// window, the connection is considered dead and the supervisor reconnects.
/// Application messages do not extend this deadline.
pub const WEBSOCKET_READ_TIMEOUT: Duration = Duration::from_secs(60);

/// Interval between outbound websocket pings (90% of the read timeout),
/// matching upstream Go `connection/connection.go`.
pub const WEBSOCKET_PING_INTERVAL: Duration = Duration::from_secs(54);

/// Interval between outbound shell-session healthcheck pings.
pub const SHELL_PING_INTERVAL: Duration = Duration::from_secs(60);

/// Shell-session liveness timeout, refreshed only by a matching shell pong.
pub const SHELL_LIVENESS_TIMEOUT: Duration = Duration::from_secs(65);

/// Property value used for shell healthcheck pings.
pub const STATUS_PONG: i64 = 3;

/// Property key for the shell healthcheck timeout.
pub const PROP_TIMEOUT: &str = "timeout";

const SHELL_LIVENESS_TIMEOUT_PROP: i64 = 65;

/// Interval between nonblocking checks for a natural PTY child exit.
///
/// A shell can exit while a background job keeps the PTY slave open, so reader
/// EOF never arrives. Polling the child status lets the daemon clean up and
/// emit a normal `SHELL/stop` notification in that case.
pub const PTY_EXIT_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Maximum consecutive duplicate (ignored) auth signals before the auth branch
/// is temporarily suppressed so timers and data can make progress.
pub const MAX_IGNORED_DUPLICATE_AUTH: u8 = 8;

/// Maximum time to keep draining PTY output after a natural shell exit before
/// giving up and reporting that the final output could not be fully delivered.
pub const NATURAL_DRAIN_DEADLINE: Duration = Duration::from_secs(2);

/// Deprecated alias for [`WEBSOCKET_READ_TIMEOUT`].
///
/// This now refers to websocket liveness, not application-message idleness.
pub const IDLE_RECEIVE_TIMEOUT: Duration = WEBSOCKET_READ_TIMEOUT;

/// Maximum random jitter added to each backoff delay.
pub const MAX_JITTER_MILLIS: u64 = 5000;

/// Idle timeout applied to the generic (non-SHELL) session router.
///
/// Mirrors upstream `connectionmanager.DefaultPingWait` (60s), split by
/// [`SessionRouter`] into a 48s ping wait and a 12s pong grace window.
pub const GENERIC_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Status property value used for successful shell responses.
pub const STATUS_OK: i64 = 1;

/// Status property value used for rejected shell responses.
pub const STATUS_ERROR: i64 = 2;

/// Property key for the shell response status.
pub const PROP_STATUS: &str = "status";

/// Property key for the requested terminal height.
pub const PROP_TERMINAL_HEIGHT: &str = "terminal_height";

/// Property key for the requested terminal width.
pub const PROP_TERMINAL_WIDTH: &str = "terminal_width";

/// Property key for the requesting user id.
pub const PROP_USER_ID: &str = "user_id";

/// Return `true` when both the token and server URL are non-empty.
///
/// This is the authorization predicate used by the supervisor: an empty token
/// or server URL means the device is not authorized and no websocket may be
/// opened.
pub fn is_authorized(token: &str, server_url: &str) -> bool {
    !token.trim().is_empty() && !server_url.trim().is_empty()
}

/// Deterministic shell-session healthcheck policy.
///
/// The daemon sends a shell ping every [`SHELL_PING_INTERVAL`] and expects a
/// matching shell pong within [`SHELL_LIVENESS_TIMEOUT`]. Only a matching pong
/// refreshes the liveness deadline.
#[derive(Debug, Clone)]
pub struct ShellHealthcheck {
    ping_deadline: Instant,
    liveness_deadline: Instant,
}

impl ShellHealthcheck {
    /// Create a fresh policy with deadlines relative to `now`.
    pub fn new(now: Instant) -> Self {
        Self {
            ping_deadline: now + SHELL_PING_INTERVAL,
            liveness_deadline: now + SHELL_LIVENESS_TIMEOUT,
        }
    }

    /// Deadline for the next outbound shell ping.
    pub fn ping_deadline(&self) -> Instant {
        self.ping_deadline
    }

    /// Deadline after which the shell is considered unhealthy.
    pub fn liveness_deadline(&self) -> Instant {
        self.liveness_deadline
    }

    /// Return `true` when a shell ping is due at `now`.
    pub fn is_ping_due(&self, now: Instant) -> bool {
        now >= self.ping_deadline
    }

    /// Return `true` when the shell liveness deadline has elapsed at `now`.
    pub fn is_liveness_expired(&self, now: Instant) -> bool {
        now >= self.liveness_deadline
    }

    /// Refresh the liveness deadline after a matching shell pong.
    pub fn note_pong(&mut self, now: Instant) {
        self.liveness_deadline = now + SHELL_LIVENESS_TIMEOUT;
    }

    /// Schedule the next shell ping after one has been sent.
    pub fn advance_ping(&mut self, now: Instant) {
        self.ping_deadline = now + SHELL_PING_INTERVAL;
    }
}

/// Draw a uniform random jitter in `0..=MAX_JITTER_MILLIS`.
fn random_jitter() -> Duration {
    let mut rng = rand::rng();
    Duration::from_millis(rng.random_range(0..=MAX_JITTER_MILLIS))
}

/// Outcome of one connected session.
enum SessionOutcome {
    /// Shutdown was requested; the daemon should exit.
    Shutdown,
    /// A retryable failure occurred; reconnect after backoff.
    Retry,
    /// The auth subscription delivered new credentials.
    CredentialsChanged(String, String),
}

/// Outcome of waiting for a backoff delay.
enum BackoffOutcome {
    /// The delay elapsed; proceed.
    Elapsed,
    /// Shutdown was requested.
    Shutdown,
    /// New credentials arrived during the wait.
    CredentialsChanged(String, String),
}

/// Outcome of a fixed, cancellable delay in the unauthorized state.
enum AuthWaitOutcome {
    /// The delay elapsed.
    Elapsed,
    /// Shutdown was requested.
    Shutdown,
    /// A valid authorization signal arrived during the delay.
    Authorized(String, String),
}

/// Outcome of waiting for a valid state-change signal after a fetch.
enum AuthResultOutcome {
    /// Shutdown was requested.
    Shutdown,
    /// A valid authorization signal arrived.
    Authorized(String, String),
    /// A non-authorized state-change signal arrived; retry through backoff.
    Unavailable,
    /// The bounded deadline elapsed without a valid signal.
    Timeout,
}

/// Outcome of obtaining initial credentials.
enum GetOutcome {
    Shutdown,
    Got(String, String),
    Empty,
}

/// Immutable per-connection context shared by the supervisor and one session.
///
/// The transfer-limits context is the single supervisor-wide instance shared
/// across reconnects, and the runtime event sink is a cheaply cloned bounded
/// handle. Bundling them keeps the connected-session helper focused while
/// preserving their lifetimes and behaviour.
#[derive(Clone)]
struct ConnectionContext {
    transfer_limits: Option<Arc<TransferLimits>>,
    events: RuntimeEvents,
}

/// Marker error indicating a PTY cleanup failure, which is fatal.
///
/// The supervisor never reconnects after this error: an unreported cleanup
/// failure must surface to the caller instead of being retried.
#[derive(Debug)]
struct PtyCleanupError(anyhow::Error);

impl std::fmt::Display for PtyCleanupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PTY cleanup failed: {}", self.0)
    }
}

impl std::error::Error for PtyCleanupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

/// Return `true` when `err` wraps a classified fatal cleanup marker.
///
/// Such failures indicate that a resource (shell, Mender command worker, or a
/// blocking `stat` job) could not be verified cleaned up, so the supervisor
/// must not reconnect. Ordinary manager errors (for example a missing command
/// binary or a non-zero command exit) are reported as status-`2` wire replies
/// instead and are never fatal here.
fn is_fatal_cleanup_error(err: &anyhow::Error) -> bool {
    err.downcast_ref::<PtyCleanupError>().is_some()
        || err
            .downcast_ref::<crate::mender_command::CommandCleanupFailure>()
            .is_some()
        || err
            .downcast_ref::<crate::file_transfer_manager::StatCleanupTimeout>()
            .is_some()
}

/// Run a supervised single-session terminal daemon until shutdown or a fatal
/// error.
///
/// The function:
/// 1. Subscribes to `JwtTokenStateChange` once and waits (bounded) for
///    readiness.
/// 2. Repeatedly obtains credentials, connects, and runs one session.
/// 3. Reconnects with exponential backoff on retryable failures.
/// 4. Enters the unauthorized state when the token or server URL is empty or a
///    handshake was rejected with HTTP 401, requesting `FetchJwtToken` and
///    waiting (bounded) for a real state-change signal.
///
/// Shutdown is honoured in every wait. Any active PTY is stopped and reaped
/// before returning, regardless of how the session loop exits.
pub async fn run<F>(config: Config, auth: AuthClient, shutdown: F) -> Result<()>
where
    F: Future<Output = ()> + Send,
{
    run_with_events(config, auth, shutdown, RuntimeEvents::disabled()).await
}

/// Run the supervised daemon with a caller-provided bounded runtime event sink.
///
/// This is the shared runtime path used by `main`; the public [`run`] wrapper
/// passes a disabled sink so existing callers and behaviour are unchanged.
/// Only fixed, payload-free [`RuntimeEvent`] values are emitted at true
/// lifecycle transitions, and emission never awaits or blocks the daemon.
pub async fn run_with_events<F>(
    config: Config,
    auth: AuthClient,
    shutdown: F,
    events: RuntimeEvents,
) -> Result<()>
where
    F: Future<Output = ()> + Send,
{
    config.validate().context("invalid configuration")?;

    // Create exactly one shared file-transfer limit context for the whole
    // supervisor lifetime. Clones share the same rate counters across every
    // reconnect, authentication refresh and per-connection manager. When
    // limits or file transfer are disabled no context is allocated.
    let transfer_limits: Option<Arc<TransferLimits>> =
        if config.limits_enabled && !config.file_transfer.disable {
            Some(Arc::new(
                TransferLimits::new(&config.limits, &LiveNss)
                    .context("failed to initialize file-transfer limits")?,
            ))
        } else {
            None
        };

    let mut subscription = auth.subscribe_jwt_token_state_change();
    tokio::pin!(shutdown);
    let ready = tokio::time::timeout(SUBSCRIPTION_READY_TIMEOUT, subscription.wait_ready());
    tokio::select! {
        biased;
        _ = shutdown.as_mut() => return Ok(()),
        result = ready => {
            result
                .context("timed out waiting for JwtTokenStateChange subscription")?
                .context("JwtTokenStateChange subscription failed")?;
        }
    }

    let mut backoff = Backoff::default();
    let mut rpc_backoff = Backoff::default();
    // Credentials supplied out-of-band by a valid unsolicited state change.
    let mut current: Option<(String, String)> = None;
    // Device is in the unauthorized state; `FetchJwtToken` is required.
    let mut unauthorized = false;
    // A handshake 401 forces a fetch even if a cached token still exists.
    let mut force_fetch = false;

    loop {
        // Phase 1: ensure we have credentials.
        let (token, server_url) = if let Some(pair) = current.take() {
            pair
        } else if force_fetch || unauthorized {
            // A forced refresh requires a real `FetchJwtToken` result; a cached
            // tuple from `GetJwtToken` must not be trusted here.
            force_fetch = false;
            match wait_for_authorization(
                &auth,
                &mut subscription,
                &mut shutdown,
                &mut rpc_backoff,
                &events,
            )
            .await?
            {
                Some(pair) => {
                    // A valid auth result resets its own retry counter; the
                    // connection backoff is intentionally preserved.
                    rpc_backoff.reset();
                    pair
                }
                None => return Ok(()),
            }
        } else {
            match get_credentials(
                &auth,
                &mut subscription,
                &mut shutdown,
                &mut rpc_backoff,
                &events,
            )
            .await?
            {
                GetOutcome::Shutdown => return Ok(()),
                GetOutcome::Got(token, server_url) => {
                    // Valid credentials at the normal run phase reset rpc backoff.
                    rpc_backoff.reset();
                    (token, server_url)
                }
                GetOutcome::Empty => {
                    // A successful Get with empty credentials is not an RPC
                    // failure; reset so the first FetchJwtToken is immediate.
                    rpc_backoff.reset();
                    events.emit(RuntimeEvent::AuthRetry);
                    unauthorized = true;
                    continue;
                }
            }
        };
        unauthorized = false;

        // Consume one connection backoff slot before the actual connect
        // attempt, so the first failure is followed by a real delay. This is
        // preserved across forced refreshes to avoid a tight 401 loop.
        let delay = backoff.next_delay(random_jitter());
        match wait_backoff(&mut subscription, &mut shutdown, delay, &token, &server_url).await? {
            BackoffOutcome::Elapsed => {}
            BackoffOutcome::Shutdown => return Ok(()),
            BackoffOutcome::CredentialsChanged(new_token, new_server) => {
                events.emit(RuntimeEvent::AuthChanged);
                backoff.reset();
                if is_authorized(&new_token, &new_server) {
                    current = Some((new_token, new_server));
                } else {
                    unauthorized = true;
                }
                continue;
            }
        }

        // Phase 2: connect, cancellable by shutdown and auth changes.
        let connect_result = {
            events.emit(RuntimeEvent::Connecting);
            let connect_fut = Transport::connect(&server_url, &token);
            tokio::pin!(connect_fut);
            loop {
                // A completed connect wins over a simultaneously ready auth
                // signal. On success the session loop gives auth bounded
                // priority: after eight duplicate signals it services ready
                // data or yields before polling auth again. A queued change
                // behind duplicates can therefore follow one data event.
                // On failure the next auth phase polls signals normally.
                tokio::select! {
                    biased;
                    _ = shutdown.as_mut() => return Ok(()),
                    result = &mut connect_fut => break Some(result),
                    event = subscription.next() => {
                        match event.context("JwtTokenStateChange subscription failed")? {
                            Some((new_token, new_server)) => {
                                if new_token != token || new_server != server_url {
                                    events.emit(RuntimeEvent::AuthChanged);
                                    backoff.reset();
                                    if is_authorized(&new_token, &new_server) {
                                        current = Some((new_token, new_server));
                                    } else {
                                        unauthorized = true;
                                    }
                                    break None;
                                }
                            }
                            None => bail!("JwtTokenStateChange subscription ended"),
                        }
                    }
                }
            }
        };

        let transport = match connect_result {
            None => continue,
            Some(Ok(transport)) => {
                events.emit(RuntimeEvent::Connected);
                transport
            }
            Some(Err(err)) => {
                // A handshake 401 means the cached token was rejected: force a
                // fresh fetch and a real result on the next iteration. Other
                // failures simply re-query `GetJwtToken` (discovering a
                // restarted auth daemon or changed proxy URL). The connection
                // backoff is preserved either way.
                if is_unauthorized_error(&err) {
                    force_fetch = true;
                }
                continue;
            }
        };

        // Phase 3: run the connected session.
        backoff.reset();
        rpc_backoff.reset();
        let session_result = run_connected_session(
            &config,
            transport,
            ConnectionContext {
                transfer_limits: transfer_limits.clone(),
                events: events.clone(),
            },
            &mut subscription,
            &mut shutdown,
            &token,
            &server_url,
        )
        .await;
        events.emit(RuntimeEvent::Disconnected);
        let outcome = session_result?;

        match outcome {
            SessionOutcome::Shutdown => return Ok(()),
            SessionOutcome::Retry => {
                // Re-query `GetJwtToken` on the next iteration; the next loop
                // consumes the next backoff slot before reconnecting.
            }
            SessionOutcome::CredentialsChanged(new_token, new_server) => {
                events.emit(RuntimeEvent::AuthChanged);
                backoff.reset();
                if is_authorized(&new_token, &new_server) {
                    current = Some((new_token, new_server));
                } else {
                    unauthorized = true;
                }
            }
        }
    }
}

/// Obtain initial credentials via `GetJwtToken`, retrying with backoff on
/// error. Returns `Empty` when the token or server URL is empty.
///
/// Valid auth signals and shutdown are honoured both during the RPC and during
/// the backoff wait; the RPC is a single pinned future so a signal flood cannot
/// starve its deadline.
async fn get_credentials<F>(
    auth: &AuthClient,
    subscription: &mut JwtTokenStateChangeSubscription,
    shutdown: &mut Pin<&mut F>,
    backoff: &mut Backoff,
    events: &RuntimeEvents,
) -> Result<GetOutcome>
where
    F: Future<Output = ()> + Send,
{
    loop {
        // Consume one RPC backoff slot before each Get attempt (first is
        // zero). Invalid-but-nonempty tuples must not skip retry delays.
        let delay = backoff.next_delay(random_jitter());
        match auth_delay(subscription, shutdown, delay).await? {
            AuthWaitOutcome::Shutdown => return Ok(GetOutcome::Shutdown),
            AuthWaitOutcome::Authorized(token, server_url) => {
                return Ok(GetOutcome::Got(token, server_url));
            }
            AuthWaitOutcome::Elapsed => {}
        }

        let get_fut = auth.get_jwt_token();
        tokio::pin!(get_fut);
        let result = tokio::select! {
            biased;
            _ = shutdown.as_mut() => return Ok(GetOutcome::Shutdown),
            event = subscription.next() => {
                match event.context("JwtTokenStateChange subscription failed")? {
                    Some((token, server_url)) => {
                        if is_authorized(&token, &server_url) {
                            return Ok(GetOutcome::Got(token, server_url));
                        }
                        // A revocation/invalid signal: fail closed rather
                        // than trust a stale GetJwtToken reply.
                        return Ok(GetOutcome::Empty);
                    }
                    None => bail!("JwtTokenStateChange subscription ended"),
                }
            }
            result = &mut get_fut => result,
        };
        match result {
            Ok((token, server_url)) => {
                if is_authorized(&token, &server_url) {
                    return Ok(GetOutcome::Got(token, server_url));
                }
                return Ok(GetOutcome::Empty);
            }
            Err(_) => {
                // Retry through the same backoff; the next loop consumes the
                // next slot before the next Get attempt.
                events.emit(RuntimeEvent::AuthRetry);
                continue;
            }
        }
    }
}

/// Enter the unauthorized state: request `FetchJwtToken` once per auth backoff
/// slot, then wait (bounded) for a real state-change signal carrying non-empty
/// credentials.
///
/// Each attempt consumes one `Backoff::next_delay` slot *before* the fetch
/// (first attempt has no delay). A successful `FetchJwtToken` does not by
/// itself grant authorization; only a state-change signal with a non-empty
/// token and server URL does. Empty/invalid signals are ignored only during
/// the pre-fetch auth delay; an observed empty fetch result ends that attempt,
/// including results arriving before the RPC completes. The due timer always
/// wins over a signal flood.
async fn wait_for_authorization<F>(
    auth: &AuthClient,
    subscription: &mut JwtTokenStateChangeSubscription,
    shutdown: &mut Pin<&mut F>,
    backoff: &mut Backoff,
    events: &RuntimeEvents,
) -> Result<Option<(String, String)>>
where
    F: Future<Output = ()> + Send,
{
    loop {
        // Consume one auth backoff slot before fetching.
        let delay = backoff.next_delay(random_jitter());
        match auth_delay(subscription, shutdown, delay).await? {
            AuthWaitOutcome::Shutdown => return Ok(None),
            AuthWaitOutcome::Authorized(token, server_url) => {
                return Ok(Some((token, server_url)));
            }
            AuthWaitOutcome::Elapsed => {}
        }

        // Single pinned HTTP fetch attempt; empty signals never restart it.
        let fetch_fut = auth.fetch_jwt_token();
        tokio::pin!(fetch_fut);
        let mut observed_unavailable = false;
        let fetched = loop {
            tokio::select! {
                biased;
                _ = shutdown.as_mut() => return Ok(None),
                result = &mut fetch_fut => break result,
                event = subscription.next() => {
                    match event.context("JwtTokenStateChange subscription failed")? {
                        Some((token, server_url)) => {
                            if is_authorized(&token, &server_url) {
                                return Ok(Some((token, server_url)));
                            }
                            // Record the failed result; the pinned RPC
                            // continues towards its own completion.
                            observed_unavailable = true;
                        }
                        None => bail!("JwtTokenStateChange subscription ended"),
                    }
                }
            }
        };

        match fetched {
            Ok(true) => {
                if observed_unavailable {
                    // A failed auth result already arrived during the RPC;
                    // retry through backoff instead of a fresh wait.
                    events.emit(RuntimeEvent::AuthRetry);
                    continue;
                }
                // Fetch scheduled an attempt; wait up to the bound for a real
                // result. Empty/invalid signals end that attempt.
                match wait_for_auth_result(subscription, shutdown).await? {
                    AuthResultOutcome::Shutdown => return Ok(None),
                    AuthResultOutcome::Authorized(token, server_url) => {
                        return Ok(Some((token, server_url)));
                    }
                    AuthResultOutcome::Unavailable | AuthResultOutcome::Timeout => {
                        events.emit(RuntimeEvent::AuthRetry);
                        continue;
                    }
                }
            }
            // Fetch=false or RPC error: retry through the same backoff.
            Ok(false) | Err(_) => {
                events.emit(RuntimeEvent::AuthRetry);
                continue;
            }
        }
    }
}

/// Fixed, cancellable delay used before an auth fetch.
///
/// Valid auth signals return immediately; invalid/empty tuples are ignored
/// without restarting or shortening the sleep. Shutdown is honoured, and the
/// due timer wins over an empty-signal flood thanks to biased polling.
async fn auth_delay<F>(
    subscription: &mut JwtTokenStateChangeSubscription,
    shutdown: &mut Pin<&mut F>,
    delay: Duration,
) -> Result<AuthWaitOutcome>
where
    F: Future<Output = ()> + Send,
{
    let sleep = tokio::time::sleep(delay);
    tokio::pin!(sleep);
    loop {
        tokio::select! {
            biased;
            _ = shutdown.as_mut() => return Ok(AuthWaitOutcome::Shutdown),
            _ = &mut sleep => return Ok(AuthWaitOutcome::Elapsed),
            event = subscription.next() => {
                match event.context("JwtTokenStateChange subscription failed")? {
                    Some((token, server_url)) => {
                        if is_authorized(&token, &server_url) {
                            return Ok(AuthWaitOutcome::Authorized(token, server_url));
                        }
                        // Invalid/empty signal: keep the same sleep.
                    }
                    None => bail!("JwtTokenStateChange subscription ended"),
                }
            }
        }
    }
}

/// Wait up to [`AUTH_RESULT_TIMEOUT`] for a valid state-change signal.
///
/// The deadline is fixed: repeated empty/duplicate signals neither reset it nor
/// accelerate the next attempt. The due timer wins over a signal flood.
async fn wait_for_auth_result<F>(
    subscription: &mut JwtTokenStateChangeSubscription,
    shutdown: &mut Pin<&mut F>,
) -> Result<AuthResultOutcome>
where
    F: Future<Output = ()> + Send,
{
    let deadline = tokio::time::sleep(AUTH_RESULT_TIMEOUT);
    tokio::pin!(deadline);
    tokio::select! {
        biased;
        _ = shutdown.as_mut() => Ok(AuthResultOutcome::Shutdown),
        _ = &mut deadline => Ok(AuthResultOutcome::Timeout),
        event = subscription.next() => {
            match event.context("JwtTokenStateChange subscription failed")? {
                Some((token, server_url)) => {
                    if is_authorized(&token, &server_url) {
                        Ok(AuthResultOutcome::Authorized(token, server_url))
                    } else {
                        // A non-authorized signal ends this attempt; the caller
                        // retries through the existing pre-attempt backoff.
                        Ok(AuthResultOutcome::Unavailable)
                    }
                }
                None => bail!("JwtTokenStateChange subscription ended"),
            }
        }
    }
}

/// Wait for `delay`, cancellable by shutdown and auth state changes.
async fn wait_backoff<F>(
    subscription: &mut JwtTokenStateChangeSubscription,
    shutdown: &mut Pin<&mut F>,
    delay: Duration,
    token: &str,
    server_url: &str,
) -> Result<BackoffOutcome>
where
    F: Future<Output = ()> + Send,
{
    let sleep = tokio::time::sleep(delay);
    tokio::pin!(sleep);
    loop {
        // The due backoff sleep wins over a ready duplicate auth signal so a
        // duplicate signal flood cannot starve the delay.
        tokio::select! {
            biased;
            _ = shutdown.as_mut() => return Ok(BackoffOutcome::Shutdown),
            _ = &mut sleep => return Ok(BackoffOutcome::Elapsed),
            event = subscription.next() => {
                match event.context("JwtTokenStateChange subscription failed")? {
                    Some((new_token, new_server)) => {
                        if new_token != token || new_server != server_url {
                            return Ok(BackoffOutcome::CredentialsChanged(new_token, new_server));
                        }
                    }
                    None => bail!("JwtTokenStateChange subscription ended"),
                }
            }
        }
    }
}

/// Run one connected session until shutdown, a credentials change, or a
/// retryable failure.
///
/// The helper unconditionally stops and reaps its PTY before returning any
/// outcome. Transport, read and handler failures become `Retry` only after
/// that cleanup succeeds; a cleanup failure is fatal and is returned as `Err`.
async fn run_connected_session<F>(
    config: &Config,
    transport: Transport,
    connection: ConnectionContext,
    subscription: &mut JwtTokenStateChangeSubscription,
    shutdown: &mut Pin<&mut F>,
    token: &str,
    server_url: &str,
) -> Result<SessionOutcome>
where
    F: Future<Output = ()> + Send,
{
    let mut session = Session::new(
        config.clone(),
        transport,
        connection.transfer_limits.clone(),
    )?;
    // Preserve `Session::new`'s existing signature (and test callers) while
    // activating the production event sink here.
    session.set_events(connection.events.clone());
    let mut read_deadline = Instant::now() + WEBSOCKET_READ_TIMEOUT;
    let mut next_ping_deadline = Instant::now() + WEBSOCKET_PING_INTERVAL;
    let mut next_exit_poll = Instant::now() + PTY_EXIT_POLL_INTERVAL;
    // Rotate transport/output/port-forward/file-transfer priority so no ready
    // source can starve the others.
    let mut preferred_source = DataSource::Transport;
    // Rotating start index within the per-SID shell output set, so no single
    // ready shell can starve the others.
    let mut output_offset = 0usize;
    // Consecutive ignored duplicate auth signals; reset by any data event.
    let mut ignored_duplicate_auth: u8 = 0;
    let mut auth_suppressed = false;

    let loop_result: Result<SessionOutcome> = async {
        loop {
            let shell_deadline = session.nearest_shell_deadline();
            let router_deadline = session.router_nearest_deadline();
            // Only arm the exit poll while at least one shell exists; otherwise
            // the branch stays disabled and cannot busy-loop.
            let exit_poll_deadline = if session.shells.is_empty() {
                None
            } else {
                Some(next_exit_poll)
            };
            // Re-drive any cleanup task whose owning stop/drain future was
            // cancelled before the handle was joined. The branch is disabled
            // (never resolves) when nothing is pending, so it cannot busy-loop.
            let cleanup_deadline = if session.has_pending_cleanup() {
                Some(Instant::now())
            } else {
                None
            };
            tokio::select! {
                biased;
                _ = shutdown.as_mut() => {
                    return Ok(SessionOutcome::Shutdown);
                }
                _ = wait_until(cleanup_deadline) => {
                    // Finish a retained stop/drain cleanup exactly once.
                    session.service_pending_cleanup().await?;
                }
                _ = wait_until(shell_deadline) => {
                    // Service per-SID shell expiry, healthcheck and drain timers.
                    match session.service_shell_timers().await {
                        Ok(TimerSignal::Continue) => {}
                        Ok(TimerSignal::Retry) => return Ok(SessionOutcome::Retry),
                        Err(err) => return Err(err),
                    }
                }
                _ = wait_until(router_deadline) => {
                    // Service the generic (non-SHELL) idle router timers.
                    match session.service_router_timers().await {
                        Ok(None) => {}
                        Ok(Some(outcome)) => return Ok(outcome),
                        Err(err) => return Err(err),
                    }
                }
                _ = wait_until(exit_poll_deadline) => {
                    next_exit_poll = Instant::now() + PTY_EXIT_POLL_INTERVAL;
                    session.poll_shell_exits().await?;
                }
                _ = tokio::time::sleep_until(read_deadline) => {
                    return Ok(SessionOutcome::Retry);
                }
                _ = tokio::time::sleep_until(next_ping_deadline) => {
                    if session.transport.send_ping(b"60").await.is_err() {
                        return Ok(SessionOutcome::Retry);
                    }
                    next_ping_deadline = Instant::now() + WEBSOCKET_PING_INTERVAL;
                }
                event = subscription.next(), if !auth_suppressed => {
                    match event.context("JwtTokenStateChange subscription failed")? {
                        Some((new_token, new_server)) => {
                            if new_token != token || new_server != server_url {
                                return Ok(SessionOutcome::CredentialsChanged(new_token, new_server));
                            }
                            // Duplicate signal: count it, but never reset timers
                            // or an existing backoff/deadline.
                            ignored_duplicate_auth = ignored_duplicate_auth.saturating_add(1);
                            if ignored_duplicate_auth >= MAX_IGNORED_DUPLICATE_AUTH {
                                auth_suppressed = true;
                            }
                        }
                        None => {
                            bail!("JwtTokenStateChange subscription ended");
                        }
                    }
                }
                event = next_data_event(
                    &mut session.transport,
                    &mut session.shells,
                    output_offset,
                    &mut session.port_forward,
                    &mut session.file_transfer,
                    &mut session.mender,
                    preferred_source,
                ) => {
                    // Any serviced data source clears the auth-flood budget and
                    // rotates priority so every ready source is served within
                    // four data events.
                    ignored_duplicate_auth = 0;
                    auth_suppressed = false;
                    match event {
                        DataEvent::Transport(message) => {
                            preferred_source = DataSource::Output;
                            match message {
                                Ok(TransportEvent::Message(message)) => {
                                    if let Err(err) = session.handle(message).await {
                                        if is_fatal_cleanup_error(&err) {
                                            return Err(err);
                                        }
                                        return Ok(SessionOutcome::Retry);
                                    }
                                }
                                Ok(TransportEvent::Ping) | Ok(TransportEvent::Pong) => {
                                    read_deadline = Instant::now() + WEBSOCKET_READ_TIMEOUT;
                                }
                                Ok(TransportEvent::Closed) => return Ok(SessionOutcome::Retry),
                                Err(_) => return Ok(SessionOutcome::Retry),
                            }
                        }
                        DataEvent::Output { sid, data, next_offset } => {
                            preferred_source = DataSource::PortForward;
                            output_offset = next_offset;
                            match data {
                                Some(bytes) => {
                                    if session.forward_output(&sid, bytes).await.is_err() {
                                        return Ok(SessionOutcome::Retry);
                                    }
                                }
                                None => {
                                    // Per-SID PTY output reached EOF: the drain
                                    // for this shell is complete.
                                    session.stop_shell(&sid).await?;
                                    let notification = shell_stop_notification(&sid);
                                    if session.transport.send(&notification).await.is_err() {
                                        return Ok(SessionOutcome::Retry);
                                    }
                                }
                            }
                        }
                        DataEvent::PortForward(message) => {
                            preferred_source = DataSource::FileTransfer;
                            match message {
                                Ok(Some(message)) => {
                                    if session.transport.send(&message).await.is_err() {
                                        return Ok(SessionOutcome::Retry);
                                    }
                                }
                                Ok(None) => {}
                                // Manager error: a fatal cleanup marker is
                                // surfaced immediately; otherwise retry only
                                // after the unconditional cleanup below.
                                Err(err) => {
                                    if is_fatal_cleanup_error(&err) {
                                        return Err(err);
                                    }
                                    return Ok(SessionOutcome::Retry);
                                }
                            }
                        }
                        DataEvent::FileTransfer(message) => {
                            preferred_source = DataSource::MenderCommand;
                            match message {
                                Ok(message) => {
                                    if session.transport.send(&message).await.is_err() {
                                        return Ok(SessionOutcome::Retry);
                                    }
                                }
                                // Manager error: a fatal cleanup marker is
                                // surfaced immediately; otherwise retry only
                                // after the unconditional cleanup below.
                                Err(err) => {
                                    if is_fatal_cleanup_error(&err) {
                                        return Err(err);
                                    }
                                    return Ok(SessionOutcome::Retry);
                                }
                            }
                        }
                        DataEvent::MenderCommand(message) => {
                            preferred_source = DataSource::Transport;
                            match message {
                                Ok(Some(message)) => {
                                    if session.transport.send(&message).await.is_err() {
                                        return Ok(SessionOutcome::Retry);
                                    }
                                }
                                // No pending command: nothing to send.
                                Ok(None) => {}
                                // Manager error: a fatal cleanup marker is
                                // surfaced immediately; otherwise retry only
                                // after the unconditional cleanup below.
                                Err(err) => {
                                    if is_fatal_cleanup_error(&err) {
                                        return Err(err);
                                    }
                                    return Ok(SessionOutcome::Retry);
                                }
                            }
                        }
                    }
                }
                _ = tokio::task::yield_now(), if auth_suppressed => {
                    // No data was ready while auth was suppressed: cooperatively
                    // yield, then re-enable auth with a fresh budget.
                    auth_suppressed = false;
                    ignored_duplicate_auth = 0;
                }
            }
        }
    }
    .await;

    // Unconditional cleanup: attempt PTY, port-forward, file-transfer and
    // Mender command teardown even if one fails, and await every owned worker
    // before returning.
    session.begin_connection_teardown();
    let pty_cleanup_result = session.stop_all_shells().await;
    let port_forward_cleanup_result = session.port_forward.close_all().await;
    let file_transfer_cleanup_result = session.file_transfer.close_all().await;
    let mender_cleanup_result = session.mender.close_all().await;
    match (
        loop_result,
        pty_cleanup_result,
        port_forward_cleanup_result,
        file_transfer_cleanup_result,
        mender_cleanup_result,
    ) {
        (Err(err), _, _, _, _) => Err(err),
        (_, Err(err), _, _, _) => Err(err),
        (_, _, Err(err), _, _) => Err(err),
        (_, _, _, Err(err), _) => Err(err),
        (_, _, _, _, Err(err)) => Err(err),
        (Ok(outcome), Ok(()), Ok(()), Ok(()), Ok(())) => Ok(outcome),
    }
}

/// Cancellation-safe multiplexer over every active per-SID PTY output channel.
///
/// Polls each shell's bounded receiver in a rotating order so that a single
/// continuously-ready shell cannot starve the others. It owns no detached
/// forwarder task: it is a single future driven by the session loop and drops
/// cleanly when the loop repolls. `offset` seeds the rotation so successive
/// calls advance through the shells.
struct ShellOutputs<'a> {
    shells: &'a mut BTreeMap<String, ActiveShell>,
    offset: usize,
}

impl Future for ShellOutputs<'_> {
    type Output = (String, Option<Vec<u8>>, usize);

    fn poll(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let len = this.shells.len();
        if len == 0 {
            return Poll::Pending;
        }
        let start = this.offset % len;
        let keys: Vec<String> = this.shells.keys().cloned().collect();
        for step in 0..len {
            let index = (start + step) % len;
            let Some(key) = keys.get(index) else {
                continue;
            };
            let Some(shell) = this.shells.get_mut(key) else {
                continue;
            };
            let Some(receiver) = shell.output.as_mut() else {
                continue;
            };
            match receiver.poll_recv(cx) {
                Poll::Ready(Some(bytes)) => {
                    let next_offset = (index + 1) % len;
                    return Poll::Ready((key.clone(), Some(bytes), next_offset));
                }
                Poll::Ready(None) => {
                    let next_offset = (index + 1) % len;
                    return Poll::Ready((key.clone(), None, next_offset));
                }
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }
}

async fn next_shell_output(
    shells: &mut BTreeMap<String, ActiveShell>,
    offset: usize,
) -> (String, Option<Vec<u8>>, usize) {
    ShellOutputs { shells, offset }.await
}

/// Await the next Mender command manager message.
///
/// When no command worker is pending the future awaits `pending()` so the
/// `select!` branch is disabled instead of returning `None` in a tight loop.
/// The manager yields at most one outbound reply per worker, and `None` is
/// handled as a harmless no-op by the caller.
async fn next_mender_command(manager: &mut MenderCommandManager) -> Result<Option<ProtoMsg>> {
    if manager.has_pending() {
        manager.next_message().await
    } else {
        std::future::pending::<()>().await;
        Ok(None)
    }
}

/// Coordinate unrelated output while a scoped file-transfer close waits.
///
/// Polls the pinned `close` future together with unrelated file-transfer
/// replies forwarded through the bounded `forwarded` channel and unrelated v2
/// port-forward replies from `port_forward`, writing every outbound message
/// through the single `sink`. The `close` future's own sink only enqueues into
/// the bounded channel (it never touches the transport), so no transport lock
/// is held across an `await` inside the selected close future. When the close
/// future completes, any reply already accepted into the single-slot channel is
/// drained before returning so the final forwarded message is not dropped.
async fn service_close_output<C, S>(
    mut close: Pin<&mut C>,
    forwarded: &mut mpsc::Receiver<ProtoMsg>,
    port_forward: &mut PortForwardManager,
    sink: &mut S,
) -> Result<()>
where
    C: Future<Output = Result<()>>,
    S: AsyncFnMut(ProtoMsg) -> Result<()>,
{
    // Keep the close future highest priority, but rotate the preferred
    // unrelated source after every send. With two biased variants, each ready
    // source is serviced within two outputs even when one channel is
    // continuously ready.
    let mut prefer_file_transfer = true;
    let mut forwarded_open = true;
    let result = loop {
        if !forwarded_open {
            tokio::select! {
                biased;
                result = &mut close => break result,
                message = port_forward.next_message() => {
                    let message =
                        message.context("port-forward manager failed during file close")?;
                    sink(message)
                        .await
                        .context("failed to send unrelated port-forward reply during close")?;
                    prefer_file_transfer = !prefer_file_transfer;
                }
            }
        } else if prefer_file_transfer {
            tokio::select! {
                biased;
                result = &mut close => break result,
                maybe = forwarded.recv() => {
                    match maybe {
                        Some(message) => {
                            sink(message)
                                .await
                                .context("failed to send forwarded file reply during close")?;
                            prefer_file_transfer = !prefer_file_transfer;
                        }
                        None => forwarded_open = false,
                    }
                }
                message = port_forward.next_message() => {
                    let message =
                        message.context("port-forward manager failed during file close")?;
                    sink(message)
                        .await
                        .context("failed to send unrelated port-forward reply during close")?;
                    prefer_file_transfer = !prefer_file_transfer;
                }
            }
        } else {
            tokio::select! {
                biased;
                result = &mut close => break result,
                message = port_forward.next_message() => {
                    let message =
                        message.context("port-forward manager failed during file close")?;
                    sink(message)
                        .await
                        .context("failed to send unrelated port-forward reply during close")?;
                    prefer_file_transfer = !prefer_file_transfer;
                }
                maybe = forwarded.recv() => {
                    match maybe {
                        Some(message) => {
                            sink(message)
                                .await
                                .context("failed to send forwarded file reply during close")?;
                            prefer_file_transfer = !prefer_file_transfer;
                        }
                        None => forwarded_open = false,
                    }
                }
            }
        }
    };

    // Drain any single reply already accepted into the bounded forwarding
    // channel before the close future completed.
    while let Ok(message) = forwarded.try_recv() {
        sink(message)
            .await
            .context("failed to drain forwarded file reply")?;
    }

    result
}

/// Outcome of servicing per-SID shell timers.
enum TimerSignal {
    /// Continue the session loop.
    Continue,
    /// The transport is no longer usable; reconnect after cleanup.
    Retry,
}

/// A scheduled data event: inbound transport, per-SID PTY output, a
/// port-forward manager message, a file-transfer manager message, or a Mender
/// command manager message.
enum DataEvent {
    Transport(Result<TransportEvent>),
    Output {
        sid: String,
        data: Option<Vec<u8>>,
        next_offset: usize,
    },
    PortForward(Result<Option<ProtoMsg>>),
    FileTransfer(Result<ProtoMsg>),
    MenderCommand(Result<Option<ProtoMsg>>),
}

/// Cyclic priority for the five data sources.
#[derive(Clone, Copy)]
enum DataSource {
    Transport,
    Output,
    PortForward,
    FileTransfer,
    MenderCommand,
}

/// Await the next data event with cyclic biased priority.
///
/// The branches borrow disjoint session fields (`transport`, `shells`,
/// `port_forward`, `file_transfer`, and `mender`). Rotating the biased order
/// ensures that a continuously ready source cannot starve the others: all
/// ready sources are serviced within five data events.
async fn next_data_event(
    transport: &mut Transport,
    shells: &mut BTreeMap<String, ActiveShell>,
    offset: usize,
    port_forward: &mut PortForwardManager,
    file_transfer: &mut FileTransferManager,
    mender: &mut MenderCommandManager,
    preferred: DataSource,
) -> DataEvent {
    // Hold at most one parsed overflow command in the manager. Pausing this
    // shared WebSocket inevitably delays subsequent inbound sessions, while
    // all output sources and the outer auth/shutdown/timers remain serviced.
    // A None admission event returns to the driver so this gate is recomputed
    // even when the worker produces no wire reply (notably v2 writes).
    let receive_enabled = port_forward.accepts_input();
    match preferred {
        DataSource::Transport => tokio::select! {
            biased;
            message = transport.receive_event(), if receive_enabled => DataEvent::Transport(message),
            (sid, data, next_offset) = next_shell_output(shells, offset) => DataEvent::Output { sid, data, next_offset },
            message = port_forward.next_event() => DataEvent::PortForward(message),
            message = file_transfer.next_message() => DataEvent::FileTransfer(message),
            message = next_mender_command(mender) => DataEvent::MenderCommand(message),
        },
        DataSource::Output => tokio::select! {
            biased;
            (sid, data, next_offset) = next_shell_output(shells, offset) => DataEvent::Output { sid, data, next_offset },
            message = port_forward.next_event() => DataEvent::PortForward(message),
            message = file_transfer.next_message() => DataEvent::FileTransfer(message),
            message = next_mender_command(mender) => DataEvent::MenderCommand(message),
            message = transport.receive_event(), if receive_enabled => DataEvent::Transport(message),
        },
        DataSource::PortForward => tokio::select! {
            biased;
            message = port_forward.next_event() => DataEvent::PortForward(message),
            message = file_transfer.next_message() => DataEvent::FileTransfer(message),
            message = next_mender_command(mender) => DataEvent::MenderCommand(message),
            message = transport.receive_event(), if receive_enabled => DataEvent::Transport(message),
            (sid, data, next_offset) = next_shell_output(shells, offset) => DataEvent::Output { sid, data, next_offset },
        },
        DataSource::FileTransfer => tokio::select! {
            biased;
            message = file_transfer.next_message() => DataEvent::FileTransfer(message),
            message = next_mender_command(mender) => DataEvent::MenderCommand(message),
            message = transport.receive_event(), if receive_enabled => DataEvent::Transport(message),
            (sid, data, next_offset) = next_shell_output(shells, offset) => DataEvent::Output { sid, data, next_offset },
            message = port_forward.next_event() => DataEvent::PortForward(message),
        },
        DataSource::MenderCommand => tokio::select! {
            biased;
            message = next_mender_command(mender) => DataEvent::MenderCommand(message),
            message = transport.receive_event(), if receive_enabled => DataEvent::Transport(message),
            (sid, data, next_offset) = next_shell_output(shells, offset) => DataEvent::Output { sid, data, next_offset },
            message = port_forward.next_event() => DataEvent::PortForward(message),
            message = file_transfer.next_message() => DataEvent::FileTransfer(message),
        },
    }
}

/// Await a copied session deadline, or never resolve when no deadline is set.
///
/// Takes an owned `Option<Instant>` so the `select!` branch does not borrow the
/// whole `Session` alongside the transport and output branches.
async fn wait_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending::<()>().await,
    }
}

/// Per-connection session state.
struct Session {
    config: Config,
    transport: Transport,
    /// Runtime event sink for lifecycle transitions; disabled by default and
    /// assigned by the production connection path.
    events: RuntimeEvents,
    /// Bounded set of active per-SID shells (global cap `MAX_SHELLS_SPAWNED`).
    shells: BTreeMap<String, ActiveShell>,
    /// Per exact logical user quota bookkeeping for shells.
    registry: ShellRegistry,
    /// Generic non-SHELL session router (idle heartbeat/timeout).
    router: SessionRouter,
    /// Owns and supervises every port-forward worker for this session.
    port_forward: PortForwardManager,
    /// Owns and supervises every in-flight file transfer for this session.
    file_transfer: FileTransferManager,
    /// Owns and supervises the active Mender command worker.
    mender: MenderCommandManager,
}

/// Lifecycle phase of an active shell.
///
/// The in-flight cleanup phases own their blocking `JoinHandle` so that a
/// cancelled stop/drain future cannot detach the cleanup task: the map entry
/// (and its registry reservation) is only released after the owned handle is
/// joined and reports success. A handle whose result has already been observed
/// is dropped immediately, so it is never polled after completion.
enum ActiveShellPhase {
    /// The shell is running normally and accepting input/resize.
    Running,
    /// The child leader exited; PTY output is being drained until `deadline`.
    Draining { deadline: Instant },
    /// A blocking stop is in flight; the entry stays reserved until it joins.
    Stopping { handle: JoinHandle<Result<()>> },
    /// A blocking natural-drain terminate is in flight; the shell is restored
    /// on success and the fixed `deadline` is preserved.
    DrainingCleanup {
        handle: JoinHandle<(PtyShell, Result<()>)>,
        deadline: Instant,
    },
    /// Cleanup completed with an error/panic; the entry and reservation are
    /// retained (fatal) and the completed handle is dropped so it is never
    /// polled again.
    Failed,
}

struct ActiveShell {
    /// The live shell. `None` only transiently while a blocking operation
    /// owns it; it is always restored before the operation's result is
    /// handled.
    shell: Option<PtyShell>,
    /// Bounded PTY output receiver owned alongside the shell (keyed by SID).
    output: Option<mpsc::Receiver<Vec<u8>>>,
    /// Expiry policy for this shell, created when the PTY starts.
    policy: SessionPolicy,
    /// Shell-session healthcheck policy, created when the PTY starts.
    health: ShellHealthcheck,
    /// Current lifecycle phase.
    phase: ActiveShellPhase,
}

impl Session {
    fn new(
        config: Config,
        transport: Transport,
        transfer_limits: Option<Arc<TransferLimits>>,
    ) -> Result<Self> {
        let router = SessionRouter::new(GENERIC_IDLE_TIMEOUT)
            .map_err(|err| anyhow::anyhow!("failed to initialize generic session router: {err}"))?;
        let file_transfer = if config.limits_enabled && !config.file_transfer.disable {
            // An enabled active transfer path must never silently fall back to
            // an unrestricted manager when its shared context is missing.
            let limits = transfer_limits.ok_or_else(|| {
                anyhow::anyhow!("file-transfer limits context missing for enabled file transfer")
            })?;
            FileTransferManager::with_limits(limits)
        } else {
            FileTransferManager::new()
        };
        let port_forward = PortForwardManager::with_allowed_destinations(
            config.port_forward.allowed_destinations.clone(),
        );
        Ok(Self {
            config,
            transport,
            events: RuntimeEvents::disabled(),
            shells: BTreeMap::new(),
            registry: ShellRegistry::new(),
            router,
            port_forward,
            file_transfer,
            mender: MenderCommandManager::new(),
        })
    }

    /// Install the production runtime event sink for this session.
    fn set_events(&mut self, events: RuntimeEvents) {
        self.events = events;
    }

    /// Nearest deadline across every active shell's per-SID timers.
    fn nearest_shell_deadline(&self) -> Option<Instant> {
        let mut nearest: Option<Instant> = None;
        for shell in self.shells.values() {
            match &shell.phase {
                ActiveShellPhase::Draining { deadline } => {
                    nearest = Some(nearest.map_or(*deadline, |current| current.min(*deadline)));
                }
                ActiveShellPhase::Running => {
                    for deadline in [
                        shell.health.ping_deadline(),
                        shell.health.liveness_deadline(),
                    ] {
                        nearest = Some(nearest.map_or(deadline, |current| current.min(deadline)));
                    }
                    if let Some(deadline) = shell.policy.deadline() {
                        nearest = Some(nearest.map_or(deadline, |current| current.min(deadline)));
                    }
                }
                // In-flight cleanup and failed entries schedule no live
                // timers; they are driven by `service_pending_cleanup` and
                // teardown instead.
                ActiveShellPhase::Stopping { .. }
                | ActiveShellPhase::DrainingCleanup { .. }
                | ActiveShellPhase::Failed => {}
            }
        }
        nearest
    }

    /// Nearest generic-router idle deadline across the tracked non-SHELL SIDs.
    fn router_nearest_deadline(&self) -> Option<Instant> {
        self.router.nearest_deadline().map(Instant::from_std)
    }

    /// Forward a per-SID PTY output chunk as a `SHELL/shell` message.
    async fn forward_output(&mut self, sid: &str, bytes: Vec<u8>) -> Result<()> {
        let message = shell_output_message(sid, bytes);
        self.transport.send(&message).await
    }

    /// Service per-SID shell expiration, healthcheck ping/liveness and drain
    /// timers. Returns whether the transport is still usable.
    async fn service_shell_timers(&mut self) -> Result<TimerSignal> {
        let now = Instant::now();
        let sids: Vec<String> = self.shells.keys().cloned().collect();
        let mut pings: Vec<String> = Vec::new();
        let mut stops: Vec<(String, bool)> = Vec::new();
        for sid in &sids {
            let Some(shell) = self.shells.get(sid) else {
                continue;
            };
            match &shell.phase {
                ActiveShellPhase::Draining { deadline } => {
                    if now >= *deadline {
                        stops.push((sid.clone(), true));
                    }
                }
                ActiveShellPhase::Running => {
                    if shell.health.is_liveness_expired(now) || shell.policy.is_expired(now) {
                        stops.push((sid.clone(), false));
                    } else if shell.health.is_ping_due(now) {
                        pings.push(sid.clone());
                    }
                }
                // Stopping/failed entries accept no input, resize or pings.
                ActiveShellPhase::Stopping { .. }
                | ActiveShellPhase::DrainingCleanup { .. }
                | ActiveShellPhase::Failed => {}
            }
        }
        for sid in pings {
            let ping = shell_ping_message(&sid);
            if self.transport.send(&ping).await.is_err() {
                return Ok(TimerSignal::Retry);
            }
            if let Some(shell) = self.shells.get_mut(&sid) {
                shell.health.advance_ping(Instant::now());
            }
        }
        for (sid, abort_drain) in stops {
            self.stop_shell(&sid).await?;
            let notification = if abort_drain {
                shell_stop_abort_notification(&sid)
            } else {
                shell_stop_notification(&sid)
            };
            if self.transport.send(&notification).await.is_err() {
                return Ok(TimerSignal::Retry);
            }
        }
        Ok(TimerSignal::Continue)
    }

    /// Service the generic (non-SHELL) session router's idle ping/timeout
    /// timers. On timeout the same-SID `CONTROL/error` (`close = true`) is sent,
    /// scoped resources are cleaned, then the retiring entry is completed.
    async fn service_router_timers(&mut self) -> Result<Option<SessionOutcome>> {
        service_router_timers_at(self, Instant::now().into_std()).await
    }

    /// Poll every running shell for a natural leader exit and begin draining.
    async fn poll_shell_exits(&mut self) -> Result<()> {
        let sids: Vec<String> = self.shells.keys().cloned().collect();
        for sid in sids {
            let exited = match self.shells.get(&sid) {
                Some(shell) => match (&shell.phase, shell.shell.as_ref()) {
                    (ActiveShellPhase::Running, Some(pty)) => pty.has_exited()?,
                    _ => false,
                },
                None => false,
            };
            if exited {
                self.begin_natural_drain(&sid).await?;
            }
        }
        Ok(())
    }

    /// Drop a generic router entry after its scoped resources were cleaned.
    fn forget_router_session(&mut self, sid: &str) {
        if let Ok(id) = SessionId::new(sid.to_owned()) {
            let _ = self.router.complete_close(&id);
        }
    }

    async fn handle(&mut self, message: ProtoMsg) -> Result<()> {
        // The generic SessionRouter applies only to non-SHELL protocols:
        // upstream `app/daemon.go` bypasses SHELL and routes everything else
        // (including CONTROL, file transfer, port-forward and mender) through
        // the router.
        //
        // Admission is explicit and exhaustive: only a successfully admitted
        // (or already tracked) SID may reach a protocol worker. A failed
        // admission (capacity, arithmetic overflow or an invalid SID) is
        // rejected here, before dispatch, so a new SID can never start work
        // without generic idle/heartbeat tracking.
        // Cleanup-only control messages do not create generic sessions. This
        // also permits CONTROL teardown of legacy SHELL SIDs (which bypass
        // this router), and never reflects an error back to an unknown error.
        // Existing tracked/retiring SIDs retain the ordinary router path.
        if message.header.proto == ProtoType::CONTROL
            && matches!(message.header.msg_type.as_str(), "close" | "error")
        {
            let tracked = match SessionId::new(message.header.session_id.clone()) {
                Ok(id) => self.router.contains(&id),
                Err(_) => false,
            };
            if !tracked {
                return self.handle_control(message).await;
            }
        }
        if message.header.proto != ProtoType::SHELL {
            match SessionId::new(message.header.session_id.clone()) {
                Ok(id) => match self.router.open_or_touch(&id, Instant::now().into_std()) {
                    // Created or touched: dispatch to the protocol worker and
                    // preserve existing tracked-SID behaviour, including when
                    // the router is full.
                    Ok(SessionDisposition::Created | SessionDisposition::Touched) => {}
                    // Retiring entries keep their existing cleanup/retiring
                    // behaviour: the message is ignored until teardown.
                    Ok(SessionDisposition::Retiring) => return Ok(()),
                    // Failed admission: reject with a fixed, bounded reason
                    // before any protocol worker is dispatched.
                    Err(RouterError::CapacityExceeded) => {
                        return self
                            .reject_router_admission(
                                &message.header,
                                "session router capacity exceeded",
                            )
                            .await;
                    }
                    Err(_) => {
                        return self
                            .reject_router_admission(
                                &message.header,
                                "session router admission failed",
                            )
                            .await;
                    }
                },
                // An invalid (e.g. over-long) SID can never be tracked by the
                // router; reject it before dispatch as well.
                Err(_) => {
                    return self
                        .reject_router_admission(&message.header, "invalid session id")
                        .await;
                }
            }
        }
        match message.header.proto {
            ProtoType::CONTROL => self.handle_control(message).await,
            ProtoType::SHELL => self.handle_shell(message).await,
            ProtoType::PORT_FORWARD | ProtoType::PORT_FORWARD_V2 | ProtoType::PORT_FORWARD_V3 => {
                self.handle_port_forward(message).await
            }
            ProtoType::FILE_TRANSFER | ProtoType::FILE_TRANSFER_V2 => {
                self.handle_file_transfer(message).await
            }
            ProtoType::MENDER_CLIENT => self.handle_mender(message).await,
            other => {
                self.events.emit(RuntimeEvent::ProtocolRejected);
                let error = ControlError {
                    error: format!("unsupported protocol {other}"),
                    close: false,
                    ..ControlError::default()
                };
                self.send_error(&message.header, error).await
            }
        }
    }

    /// Reject a non-SHELL message whose SID could not be admitted to the
    /// generic router, before any protocol worker is dispatched.
    ///
    /// Emits the fixed, payload-free [`RuntimeEvent::ProtocolRejected`] and
    /// replies through the existing [`Session::send_error`] path, which
    /// centrally correlates and bounds the reflected header fields
    /// (`MAX_HEADER_FIELD_BYTES`) while the reason stays a caller-supplied
    /// constant literal that is never reflected from untrusted input.
    async fn reject_router_admission(
        &mut self,
        header: &ProtoHdr,
        reason: &'static str,
    ) -> Result<()> {
        self.events.emit(RuntimeEvent::ProtocolRejected);
        let error = ControlError {
            error: reason.to_owned(),
            close: false,
            ..ControlError::default()
        };
        self.send_error(header, error).await
    }

    async fn handle_control(&mut self, message: ProtoMsg) -> Result<()> {
        match message.header.msg_type.as_str() {
            "open" => {
                let response = runtime_control_open(
                    &message,
                    self.config.terminal.disable,
                    self.config.port_forward.disable,
                    self.config.file_transfer.disable,
                    self.config.mender_client.disable,
                );
                // If the open response is a control error with `close = true`,
                // close every matching resource (shell and all port-forward
                // connections) while keeping the websocket alive. Unrelated
                // sessions are unaffected.
                let close = response.header.proto == ProtoType::CONTROL
                    && response.header.msg_type == "error"
                    && decode::<ControlError>(&response.body)
                        .map(|error| error.close)
                        .unwrap_or(false);
                if close {
                    self.close_session_resources(&response.header.session_id)
                        .await?;
                }
                self.transport.send(&response).await
            }
            "ping" => {
                let response = control_pong(&message);
                self.transport.send(&response).await
            }
            // Upstream CONTROL/pong is a pure no-op: it emits no reply and
            // touches no health or deadline state.
            "pong" => Ok(()),
            // Validate the peer handshake response exactly like upstream. A
            // malformed or unsupported-version `accept` is fatal for every
            // resource bound to this session id: close them first, then reply
            // with a correlated `close = true` control error. A valid version
            // 1 `accept` is a no-op and sends nothing.
            "accept" => {
                let Some(error) = control_accept_error(&message) else {
                    return Ok(());
                };
                self.close_session_resources(&message.header.session_id)
                    .await?;
                self.send_error(&message.header, error).await
            }
            "close" => {
                self.close_session_resources(&message.header.session_id)
                    .await?;
                Ok(())
            }
            "error" => {
                let close = decode::<ControlError>(&message.body)
                    .map(|error| error.close)
                    .unwrap_or(false);
                if close {
                    self.close_session_resources(&message.header.session_id)
                        .await?;
                }
                Ok(())
            }
            other => {
                self.events.emit(RuntimeEvent::ProtocolRejected);
                let error = ControlError {
                    error: format!("unsupported control message type: {other}"),
                    close: false,
                    ..ControlError::default()
                };
                self.send_error(&message.header, error).await
            }
        }
    }

    async fn handle_port_forward(&mut self, message: ProtoMsg) -> Result<()> {
        if self.config.port_forward.disable {
            let reply = port_forward_error_reply(&message.header, "port forwarding disabled")?;
            return self.transport.send(&reply).await;
        }

        let replies = self.port_forward.handle(message).await?;
        for reply in replies {
            self.transport.send(&reply).await?;
        }
        Ok(())
    }

    async fn handle_file_transfer(&mut self, message: ProtoMsg) -> Result<()> {
        if self.config.file_transfer.disable {
            let error = TransferError {
                err: Some("file transfer disabled".to_owned()),
                msgtype: Some(message.header.msg_type.clone()),
                msgid: message
                    .header
                    .properties
                    .get("msgid")
                    .and_then(Value::as_str)
                    .filter(|id| id.len() <= 128)
                    .map(str::to_owned),
            };
            let body = encode(&error).context("failed to encode file transfer error")?;
            let reply = ProtoMsg {
                header: ProtoHdr {
                    proto: message.header.proto,
                    msg_type: "error".to_owned(),
                    session_id: message.header.session_id,
                    properties: Default::default(),
                },
                body,
            };
            return self.transport.send(&reply).await;
        }

        let replies = self.file_transfer.handle(message).await?;
        for reply in replies {
            self.transport.send(&reply).await?;
        }
        Ok(())
    }

    async fn handle_mender(&mut self, message: ProtoMsg) -> Result<()> {
        if self.config.mender_client.disable {
            let mut properties = std::collections::BTreeMap::new();
            properties.insert(PROP_STATUS.to_owned(), Value::from(STATUS_ERROR));
            let reply = ProtoMsg {
                header: ProtoHdr {
                    proto: message.header.proto,
                    msg_type: message.header.msg_type,
                    session_id: message.header.session_id,
                    properties,
                },
                body: b"Mender commands disabled".to_vec(),
            };
            return self.transport.send(&reply).await;
        }

        let replies = self.mender.handle(message).await?;
        for reply in replies {
            self.transport.send(&reply).await?;
        }
        Ok(())
    }

    /// Close every resource tagged with `sid` (the shell, all port-forward
    /// connections, all file transfers and the Mender command worker),
    /// attempting each even if one cleanup fails.
    async fn close_session_resources(&mut self, sid: &str) -> Result<()> {
        let shell_result = self.stop_shell(sid).await;
        let port_forward_result = self.port_forward.close_session(sid).await;
        // Service unrelated output while the scoped close waits for any
        // completing upload within its bounded window: unrelated file-transfer
        // replies are forwarded through a bounded single-slot channel and
        // unrelated v2 port-forward replies are drained inline, all written by
        // the sole transport owner. Without this, an unrelated download or a
        // sustained port-forward stream could fill its own bounded queue and
        // hit its send timeout while the close waits up to
        // `UPLOAD_COMPLETION_WINDOW`. The sink never touches the transport, so
        // no transport lock is held inside the selected close future.
        // Scope every borrow of the file-transfer close future, its forwarded
        // channel, the port-forward manager and the transport sink inside a
        // lexical block that returns only the `Result`. The pinned close future
        // holds a mutable borrow of `self.file_transfer` until it is dropped, so
        // letting it live to the end of the function would conflict with the
        // later whole-`Self` methods (`mender.close_session`, `forget_router_session`).
        // Dropping the pinned binding at block end (rather than only dropping the
        // `Pin` reference) ensures the underlying future itself is released once
        // the scoped close has genuinely completed.
        let file_transfer_result = {
            let (forward_sender, mut forwarded) = mpsc::channel::<ProtoMsg>(1);
            let close_future =
                self.file_transfer
                    .close_session_servicing(sid, async move |message: ProtoMsg| {
                        forward_sender
                            .send(message)
                            .await
                            .map_err(|_| anyhow::anyhow!("file transfer forwarding channel closed"))
                    });
            tokio::pin!(close_future);
            let mut sink = async |message: ProtoMsg| self.transport.send(&message).await;
            service_close_output(
                close_future.as_mut(),
                &mut forwarded,
                &mut self.port_forward,
                &mut sink,
            )
            .await
        };
        let mender_result = self.mender.close_session(sid).await;
        self.forget_router_session(sid);
        match (
            shell_result,
            port_forward_result,
            file_transfer_result,
            mender_result,
        ) {
            (Err(err), _, _, _) => Err(err),
            (_, Err(err), _, _) => Err(err),
            (_, _, Err(err), _) => Err(err),
            (_, _, _, Err(err)) => Err(err),
            (Ok(()), Ok(()), Ok(()), Ok(())) => Ok(()),
        }
    }

    async fn handle_shell(&mut self, message: ProtoMsg) -> Result<()> {
        match message.header.msg_type.as_str() {
            "new" => self.handle_shell_new(message).await,
            "shell" => self.handle_shell_input(message).await,
            "resize" => self.handle_shell_resize(message).await,
            "stop" => self.handle_shell_stop(message).await,
            "pong" => self.handle_shell_pong(message).await,
            other => {
                self.events.emit(RuntimeEvent::ProtocolRejected);
                let error = ControlError {
                    error: format!("unsupported shell message type: {other}"),
                    close: false,
                    ..ControlError::default()
                };
                self.send_error(&message.header, error).await
            }
        }
    }

    async fn handle_shell_new(&mut self, message: ProtoMsg) -> Result<()> {
        let sid = message.header.session_id.clone();
        if sid.is_empty() {
            return self
                .send_shell_status(&message.header, STATUS_ERROR, b"empty session id")
                .await;
        }
        if self.config.terminal.disable {
            return self
                .send_shell_status(&message.header, STATUS_ERROR, b"terminal disabled")
                .await;
        }
        let Ok(session_id) = SessionId::new(sid.clone()) else {
            return self
                .send_shell_status(&message.header, STATUS_ERROR, b"invalid session id")
                .await;
        };
        if self.shells.contains_key(&sid) {
            return self
                .send_shell_status(&message.header, STATUS_ERROR, b"shell already active")
                .await;
        }
        // The remote `user_id` is a logical quota bucket taken from the header;
        // it is NOT the configured OS user. Missing/non-string becomes the
        // shared empty bucket.
        let user_raw = message
            .header
            .properties
            .get(PROP_USER_ID)
            .and_then(Value::as_str)
            .unwrap_or("");
        let Ok(user) = UserId::new(user_raw.to_owned()) else {
            return self
                .send_shell_status(&message.header, STATUS_ERROR, b"invalid user id")
                .await;
        };
        match self.registry.try_reserve(&session_id, &user) {
            Ok(()) => {}
            Err(ShellRegistryError::QuotaExceeded) => {
                return self
                    .send_shell_status(
                        &message.header,
                        STATUS_ERROR,
                        b"user has too many open sessions",
                    )
                    .await;
            }
            Err(ShellRegistryError::CapacityExceeded) => {
                return self
                    .send_shell_status(&message.header, STATUS_ERROR, b"too many shells spawned")
                    .await;
            }
            Err(ShellRegistryError::AlreadyActive) => {
                return self
                    .send_shell_status(&message.header, STATUS_ERROR, b"shell already active")
                    .await;
            }
            Err(ShellRegistryError::InvalidLimits) => {
                return self
                    .send_shell_status(&message.header, STATUS_ERROR, b"shell registry error")
                    .await;
            }
        }

        let (rows, cols) = terminal_dimensions(&message.header, &self.config);
        let config = self.config.clone();
        let spawned = tokio::task::spawn_blocking(move || PtyShell::spawn(&config, rows, cols))
            .await
            .context("PTY spawn task panicked")?;

        let mut shell = match spawned {
            Ok(shell) => shell,
            Err(err) => {
                // A spawn failure that could not fully clean up is fatal and
                // must keep the reserved slot (cleanup is unverified).
                if err.downcast_ref::<CleanupFailure>().is_some() {
                    self.events.emit(RuntimeEvent::CleanupFailed);
                    return Err(anyhow::Error::new(PtyCleanupError(err)));
                }
                // Ordinary failure: release the reservation and report a shell
                // error rather than aborting the whole websocket.
                self.registry.release(&session_id);
                let body = format!("failed to spawn PTY shell: {err:#}");
                return self
                    .send_shell_status(&message.header, STATUS_ERROR, body.as_bytes())
                    .await;
            }
        };

        let output = match shell.take_output() {
            Some(output) => output,
            None => {
                // Drop the shell on a blocking context.
                let _ = tokio::task::spawn_blocking(move || drop(shell)).await;
                self.registry.release(&session_id);
                return self
                    .send_shell_status(
                        &message.header,
                        STATUS_ERROR,
                        b"PTY shell did not provide an output channel",
                    )
                    .await;
            }
        };

        let policy = SessionPolicy::new(&self.config.sessions, Instant::now());
        self.shells.insert(
            sid,
            ActiveShell {
                shell: Some(shell),
                output: Some(output),
                policy,
                health: ShellHealthcheck::new(Instant::now()),
                phase: ActiveShellPhase::Running,
            },
        );
        self.events.emit(RuntimeEvent::ShellStarted);

        self.send_shell_status(&message.header, STATUS_OK, b"Shell started")
            .await
    }

    async fn handle_shell_input(&mut self, message: ProtoMsg) -> Result<()> {
        let sid = message.header.session_id.clone();
        match self.shells.get(&sid) {
            None => {
                return self
                    .send_shell_status(&message.header, STATUS_ERROR, b"no active shell")
                    .await;
            }
            Some(active) => {
                if !matches!(active.phase, ActiveShellPhase::Running) {
                    return self
                        .send_shell_status(&message.header, STATUS_ERROR, b"shell terminating")
                        .await;
                }
            }
        }

        let Some(shell) = self
            .shells
            .get_mut(&sid)
            .and_then(|active| active.shell.take())
        else {
            return self
                .send_shell_status(&message.header, STATUS_ERROR, b"shell busy")
                .await;
        };

        let data = message.body;
        let write_result = tokio::task::spawn_blocking(move || {
            let mut shell = shell;
            let result = shell.write_input(&data);
            (shell, result)
        })
        .await;

        // Restore the shell before handling the result so state is consistent
        // even on error.
        let (shell, result) = match write_result {
            Ok(pair) => pair,
            Err(join_err) => {
                // The blocking task panicked; the shell was dropped inside it.
                self.shells.remove(&sid);
                return Err(anyhow::Error::new(join_err).context("PTY write task panicked"));
            }
        };
        if let Some(active) = self.shells.get_mut(&sid) {
            active.shell = Some(shell);
        }

        result.context("failed to write to PTY")?;
        if let Some(active) = self.shells.get_mut(&sid) {
            active.policy.note_input(Instant::now());
        }
        Ok(())
    }

    async fn handle_shell_resize(&mut self, message: ProtoMsg) -> Result<()> {
        let sid = message.header.session_id.clone();
        match self.shells.get(&sid) {
            None => {
                return self
                    .send_shell_status(&message.header, STATUS_ERROR, b"no active shell")
                    .await;
            }
            Some(active) => {
                if !matches!(active.phase, ActiveShellPhase::Running) {
                    return self
                        .send_shell_status(&message.header, STATUS_ERROR, b"shell terminating")
                        .await;
                }
            }
        }

        let Some(shell) = self
            .shells
            .get_mut(&sid)
            .and_then(|active| active.shell.take())
        else {
            return self
                .send_shell_status(&message.header, STATUS_ERROR, b"shell busy")
                .await;
        };

        let (rows, cols) = terminal_dimensions(&message.header, &self.config);
        let resize_result = tokio::task::spawn_blocking(move || {
            let result = shell.resize(rows, cols);
            (shell, result)
        })
        .await;

        let (shell, result) = match resize_result {
            Ok(pair) => pair,
            Err(join_err) => {
                self.shells.remove(&sid);
                return Err(anyhow::Error::new(join_err).context("PTY resize task panicked"));
            }
        };
        if let Some(active) = self.shells.get_mut(&sid) {
            active.shell = Some(shell);
        }

        result.context("failed to resize PTY")?;
        Ok(())
    }

    async fn handle_shell_stop(&mut self, message: ProtoMsg) -> Result<()> {
        let sid = message.header.session_id.clone();

        // Upstream `routeMessageStopShell`: an empty SID plus a non-empty
        // string `user_id` stops every shell for that exact logical user.
        // Empty SID and empty (or non-string) user id is an error.
        if sid.is_empty() {
            let user_raw = message
                .header
                .properties
                .get(PROP_USER_ID)
                .and_then(Value::as_str)
                .unwrap_or("");
            if user_raw.is_empty() {
                return self
                    .send_shell_status(
                        &message.header,
                        STATUS_ERROR,
                        b"StopShellMessage: sessionId not given and userId empty",
                    )
                    .await;
            }
            let Ok(user) = UserId::new(user_raw.to_owned()) else {
                return self
                    .send_shell_status(&message.header, STATUS_ERROR, b"session not found")
                    .await;
            };
            let sids = self.registry.sessions_for_user(&user);
            let mut stopped = 0usize;
            for session in &sids {
                self.stop_shell(session.as_str()).await?;
                stopped += 1;
            }
            if stopped == 0 {
                return self
                    .send_shell_status(&message.header, STATUS_ERROR, b"session not found")
                    .await;
            }
            return self
                .send_shell_status(&message.header, STATUS_OK, b"")
                .await;
        }

        // SID-specific stop affects only that SID; an absent SID is an
        // ordinary (non-fatal) error.
        if !self.shells.contains_key(&sid) {
            return self
                .send_shell_status(&message.header, STATUS_ERROR, b"no matching shell")
                .await;
        }
        self.stop_shell(&sid).await?;
        self.send_shell_status(&message.header, STATUS_OK, b"")
            .await
    }

    async fn handle_shell_pong(&mut self, message: ProtoMsg) -> Result<()> {
        let sid = message.header.session_id.clone();
        match self.shells.get(&sid) {
            None => {
                return self
                    .send_shell_status(&message.header, STATUS_ERROR, b"no active shell")
                    .await;
            }
            Some(active) if !matches!(active.phase, ActiveShellPhase::Running) => {
                return self
                    .send_shell_status(&message.header, STATUS_ERROR, b"shell terminating")
                    .await;
            }
            Some(_) => {}
        }
        if let Some(active) = self.shells.get_mut(&sid) {
            active.health.note_pong(Instant::now());
        }
        Ok(())
    }

    /// Stop and reap the shell bound to `sid`, if any.
    ///
    /// The per-SID map entry and its registry reservation are kept until the
    /// blocking `stop`/drop task is joined and verified successful. The join
    /// handle is owned by the entry (across cancellable awaits) so a cancelled
    /// stop future never detaches the cleanup task and a retry resumes the
    /// same handle instead of spawning a duplicate. Failures are wrapped in
    /// [`PtyCleanupError`] so the supervisor treats them as fatal, and a live
    /// PTY slot is never released as if cleanup had succeeded.
    async fn stop_shell(&mut self, sid: &str) -> Result<()> {
        // Settle any in-flight natural-drain terminate task first so the shell
        // handle is restored before stopping it.
        self.join_drain_cleanup(sid).await?;

        // A previously observed cleanup failure keeps the reservation retained
        // and stays fatal: never treat it as stopped or try to free the slot.
        if let Some(active) = self.shells.get(sid)
            && matches!(active.phase, ActiveShellPhase::Failed)
        {
            return Err(anyhow::Error::new(PtyCleanupError(anyhow::anyhow!(
                "PTY cleanup previously failed for session {sid}; reservation retained"
            ))));
        }

        if self.start_stop_cleanup(sid) {
            self.join_stop_cleanup(sid).await?;
        } else {
            self.finalize_stopped_shell(sid);
        }
        Ok(())
    }

    /// Move a live shell into a blocking stop task owned by the entry.
    ///
    /// Returns `true` when the entry now owns a stop join handle (including
    /// when one was already in flight), `false` when there is no live shell to
    /// stop.
    fn start_stop_cleanup(&mut self, sid: &str) -> bool {
        let Some(active) = self.shells.get_mut(sid) else {
            return false;
        };
        if matches!(active.phase, ActiveShellPhase::Stopping { .. }) {
            return true;
        }
        let Some(shell) = active.shell.take() else {
            return false;
        };
        // Disable this session's output while the PTY is being stopped so
        // stale bytes cannot reach a future session.
        active.output = None;
        let handle = tokio::task::spawn_blocking(move || {
            let mut shell = shell;
            let stop_result = shell.stop();
            drop(shell);
            stop_result
        });
        active.phase = ActiveShellPhase::Stopping { handle };
        true
    }

    /// Await and finalize an owned stop cleanup handle.
    ///
    /// The handle is polled through a mutable reference so cancellation does
    /// not consume it. Once a result is observed the handle is dropped by the
    /// transition (finalize or [`ActiveShellPhase::Failed`]) so it is never
    /// polled after completion.
    async fn join_stop_cleanup(&mut self, sid: &str) -> Result<()> {
        let joined = {
            let Some(active) = self.shells.get_mut(sid) else {
                return Ok(());
            };
            match &mut active.phase {
                ActiveShellPhase::Stopping { handle } => Some((&mut *handle).await),
                _ => None,
            }
        };
        match joined {
            None => Ok(()),
            Some(Ok(Ok(()))) => {
                self.finalize_stopped_shell(sid);
                self.events.emit(RuntimeEvent::ShellStopped);
                Ok(())
            }
            Some(Ok(Err(err))) => {
                self.mark_cleanup_failed(sid);
                self.events.emit(RuntimeEvent::CleanupFailed);
                Err(anyhow::Error::new(PtyCleanupError(
                    err.context("failed to stop PTY shell"),
                )))
            }
            Some(Err(join_err)) => {
                self.mark_cleanup_failed(sid);
                self.events.emit(RuntimeEvent::CleanupFailed);
                Err(anyhow::Error::new(PtyCleanupError(
                    anyhow::Error::new(join_err).context("PTY stop task panicked"),
                )))
            }
        }
    }

    /// Remove a shell entry and release its reservation only after verified
    /// cleanup.
    fn finalize_stopped_shell(&mut self, sid: &str) {
        if self.shells.remove(sid).is_some()
            && let Ok(session_id) = SessionId::new(sid.to_owned())
        {
            self.registry.release(&session_id);
        }
    }

    /// Mark an entry whose cleanup failed as fatal while retaining its entry
    /// and registry reservation. The completed handle is dropped.
    fn mark_cleanup_failed(&mut self, sid: &str) {
        if let Some(active) = self.shells.get_mut(sid) {
            active.output = None;
            active.phase = ActiveShellPhase::Failed;
        }
    }

    /// Whether any per-SID cleanup task is in flight and must be re-driven.
    fn has_pending_cleanup(&self) -> bool {
        self.shells.values().any(|active| {
            matches!(
                active.phase,
                ActiveShellPhase::Stopping { .. } | ActiveShellPhase::DrainingCleanup { .. }
            )
        })
    }

    /// Re-drive a retained in-flight cleanup task for the smallest SID.
    ///
    /// Used when a prior stop/drain future was cancelled before the owned
    /// handle was joined, so the entry and reservation are eventually settled
    /// without spawning a duplicate task.
    async fn service_pending_cleanup(&mut self) -> Result<()> {
        let Some(sid) = self.shells.iter().find_map(|(sid, active)| {
            matches!(
                active.phase,
                ActiveShellPhase::Stopping { .. } | ActiveShellPhase::DrainingCleanup { .. }
            )
            .then(|| sid.clone())
        }) else {
            return Ok(());
        };
        let is_drain = matches!(
            self.shells.get(&sid).map(|active| &active.phase),
            Some(ActiveShellPhase::DrainingCleanup { .. })
        );
        if is_drain {
            self.join_drain_cleanup(&sid).await
        } else {
            self.join_stop_cleanup(&sid).await
        }
    }

    fn begin_connection_teardown(&mut self) {
        self.start_stop_all_shells();
        self.port_forward.begin_close_all();
        self.file_transfer.begin_close_all();
        self.mender.request_cancel_all();
    }

    fn start_stop_all_shells(&mut self) {
        let sids: Vec<String> = self.shells.keys().cloned().collect();
        for sid in sids {
            if let Some(active) = self.shells.get_mut(&sid) {
                active.output = None;
            }
            self.start_stop_cleanup(&sid);
        }
    }

    /// Stop and reap every owned shell, attempting each even if one fails.
    async fn stop_all_shells(&mut self) -> Result<()> {
        let sids: Vec<String> = self.shells.keys().cloned().collect();
        let mut first_err: Option<anyhow::Error> = None;
        for sid in sids {
            if let Err(err) = self.stop_shell(&sid).await
                && first_err.is_none()
            {
                first_err = Some(err);
            }
        }
        match first_err {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    /// Begin draining PTY output for `sid` after the shell leader exited.
    ///
    /// Terminates and reaps the child processes (via
    /// [`PtyShell::terminate_processes`]) while leaving the reader/output
    /// channel alive, then records a fixed drain deadline. The per-SID output
    /// receiver stays active so queued/readable bytes can still be delivered.
    ///
    /// The terminate join handle is owned by the entry
    /// ([`ActiveShellPhase::DrainingCleanup`]) so a cancelled drain future does
    /// not detach the blocking task; a retry (or
    /// [`Session::service_pending_cleanup`]) resumes the same handle and only
    /// restores the shell/phase once the result is observed. Any cleanup
    /// failure is wrapped in [`PtyCleanupError`] (fatal) and never frees the
    /// reservation as if cleanup had succeeded.
    async fn begin_natural_drain(&mut self, sid: &str) -> Result<()> {
        let Some(active) = self.shells.get_mut(sid) else {
            return Ok(());
        };
        if !matches!(active.phase, ActiveShellPhase::Running)
            && !matches!(active.phase, ActiveShellPhase::DrainingCleanup { .. })
        {
            return Ok(());
        }
        if matches!(active.phase, ActiveShellPhase::Running) {
            let Some(shell) = active.shell.take() else {
                return Ok(());
            };
            // Preserve the bounded output receiver; only the process cleanup is
            // moved to the blocking task.
            let handle = tokio::task::spawn_blocking(move || {
                let mut shell = shell;
                let result = shell.terminate_processes();
                (shell, result)
            });
            active.phase = ActiveShellPhase::DrainingCleanup {
                handle,
                deadline: Instant::now() + NATURAL_DRAIN_DEADLINE,
            };
        }

        self.join_drain_cleanup(sid).await
    }

    /// Await and settle an owned natural-drain terminate handle.
    ///
    /// On success the shell is restored and the phase becomes
    /// [`ActiveShellPhase::Draining`] with the preserved fixed deadline. On a
    /// reported cleanup error the shell is restored (a later stop can replay
    /// the idempotent failure) while the reservation is retained; a panic
    /// marks the entry [`ActiveShellPhase::Failed`]. Both are fatal.
    async fn join_drain_cleanup(&mut self, sid: &str) -> Result<()> {
        let joined = {
            let Some(active) = self.shells.get_mut(sid) else {
                return Ok(());
            };
            match &mut active.phase {
                ActiveShellPhase::DrainingCleanup { handle, .. } => Some((&mut *handle).await),
                _ => None,
            }
        };
        let Some(joined) = joined else {
            return Ok(());
        };
        let deadline = self
            .shells
            .get(sid)
            .and_then(|active| match &active.phase {
                ActiveShellPhase::DrainingCleanup { deadline, .. } => Some(*deadline),
                _ => None,
            })
            .unwrap_or_else(|| Instant::now() + NATURAL_DRAIN_DEADLINE);
        match joined {
            Ok((shell, Ok(()))) => {
                if let Some(active) = self.shells.get_mut(sid) {
                    active.shell = Some(shell);
                    active.phase = ActiveShellPhase::Draining { deadline };
                }
                Ok(())
            }
            Ok((shell, Err(err))) => {
                if let Some(active) = self.shells.get_mut(sid) {
                    active.shell = Some(shell);
                    active.phase = ActiveShellPhase::Draining { deadline };
                }
                self.events.emit(RuntimeEvent::CleanupFailed);
                Err(anyhow::Error::new(PtyCleanupError(
                    err.context("failed to terminate PTY processes"),
                )))
            }
            Err(join_err) => {
                self.mark_cleanup_failed(sid);
                self.events.emit(RuntimeEvent::CleanupFailed);
                Err(anyhow::Error::new(PtyCleanupError(
                    anyhow::Error::new(join_err).context("PTY terminate task panicked"),
                )))
            }
        }
    }

    async fn send_error(&mut self, header: &ProtoHdr, error: ControlError) -> Result<()> {
        // Normalize header correlation centrally so every protocol, control
        // and shell error reflects the offending header consistently before
        // it is encoded. The helper preserves `error`, `close` and `code`.
        let error = correlate_control_error(header, error);
        let body = encode(&error).context("failed to encode control error")?;
        let message = ProtoMsg {
            header: ProtoHdr {
                proto: ProtoType::CONTROL,
                msg_type: "error".to_owned(),
                session_id: header.session_id.clone(),
                properties: Default::default(),
            },
            body,
        };
        self.transport.send(&message).await
    }

    async fn send_shell_status(
        &mut self,
        header: &ProtoHdr,
        status: i64,
        body: &[u8],
    ) -> Result<()> {
        let mut properties = std::collections::BTreeMap::new();
        properties.insert(PROP_STATUS.to_owned(), Value::from(status));
        let message = ProtoMsg {
            header: ProtoHdr {
                proto: ProtoType::SHELL,
                msg_type: header.msg_type.clone(),
                session_id: header.session_id.clone(),
                properties,
            },
            body: body.to_vec(),
        };
        self.transport.send(&message).await
    }
}

/// Drive the generic (non-SHELL) router with a caller-supplied `now`.
///
/// This is the shared runtime path used by both the session loop and the
/// timer-route tests. The helper performs exactly one due-action per poll and
/// keeps the transport as the sole writer.
async fn service_router_timers_at(
    session: &mut Session,
    now: std::time::Instant,
) -> Result<Option<SessionOutcome>> {
    loop {
        match session.router.poll_due(now) {
            None => return Ok(None),
            Some(RouterAction::Ping {
                session: router_session,
            }) => {
                let ping = control_ping_message(router_session.as_str());
                if session.transport.send(&ping).await.is_err() {
                    return Ok(Some(SessionOutcome::Retry));
                }
            }
            Some(RouterAction::Timeout {
                session: router_session,
            }) => {
                let sid = router_session.as_str().to_owned();
                session.close_session_resources(&sid).await?;
                let message = control_session_timeout_message(&sid)?;
                let send_failed = session.transport.send(&message).await.is_err();
                session.forget_router_session(&sid);
                if send_failed {
                    return Ok(Some(SessionOutcome::Retry));
                }
            }
        }
    }
}

/// Build a correlated control error from an offending header.
///
/// Always overwrites the message metadata (protocol, type and id) with the
/// values from `header` while preserving the caller-provided `error`, `close`
/// and `code`. Reflected fields are bounded to
/// [`crate::transport::MAX_HEADER_FIELD_BYTES`]; oversized or non-string
/// values are omitted (set to empty) rather than truncated, so no unsafe UTF-8
/// slicing is ever performed. This is a pure helper so it can be unit tested
/// without a live transport, and `send_error` reapplies it idempotently.
fn correlate_control_error(header: &ProtoHdr, mut error: ControlError) -> ControlError {
    error.message_proto = header.proto;
    error.message_type = if header.msg_type.len() <= crate::transport::MAX_HEADER_FIELD_BYTES {
        header.msg_type.clone()
    } else {
        String::new()
    };
    error.message_id = match header.properties.get("msgid").and_then(Value::as_str) {
        Some(msgid) if msgid.len() <= crate::transport::MAX_HEADER_FIELD_BYTES => msgid.to_owned(),
        _ => String::new(),
    };
    error
}

/// Validate an inbound CONTROL/accept handshake response.
///
/// Returns `None` when the body decodes into the private wire schema that
/// mirrors upstream Go `ws.Accept` (a `u16` version defaulting to 0 when the
/// field is absent, plus an optional `protocols` list) advertising protocol
/// version 1 (a valid no-op). Otherwise returns an already-correlated
/// `close = true` control error: malformed, empty or trailing-garbage bodies
/// use a static reason, and unsupported in-range numeric versions only reflect
/// the numeric version. The protocol list is validated solely by Serde; no
/// extra capability registry is consulted.
fn control_accept_error(message: &ProtoMsg) -> Option<ControlError> {
    // Private wire type mirroring Go `ws.Accept` (`Version uint16`,
    // `Protocols []ProtoType`) so a canonical Go body with `version: 1` and
    // `protocols: nil`/omitted/`[]` decodes, while non-numeric/out-of-range
    // versions and malformed protocol lists are still rejected. The public
    // `protocol::Accept` schema is intentionally left unchanged.
    #[derive(serde::Deserialize)]
    struct AcceptWire {
        #[serde(default)]
        version: u16,
        #[serde(rename = "protocols", default)]
        _protocols: Option<Vec<ProtoType>>,
    }

    let accept = match decode::<AcceptWire>(&message.body) {
        Ok(accept) => accept,
        Err(_) => {
            let error = ControlError {
                error: "malformed handshake response".to_owned(),
                close: true,
                ..ControlError::default()
            };
            return Some(correlate_control_error(&message.header, error));
        }
    };
    if accept.version != 1 {
        let error = ControlError {
            error: format!(
                "unsupported protocol version {}: require version 1",
                accept.version
            ),
            close: true,
            ..ControlError::default()
        };
        return Some(correlate_control_error(&message.header, error));
    }
    None
}

/// Build the control `open` response for a received `open` message.
///
/// This is a pure helper so tests can exercise handshake behavior without a
/// live transport.
pub fn control_open(message: &ProtoMsg, terminal_disabled: bool) -> ProtoMsg {
    let sid = message.header.session_id.clone();
    let open = decode::<Open>(&message.body).unwrap_or_default();
    if !open.versions.contains(&1) {
        let error = ControlError {
            error: "unsupported protocol version".to_owned(),
            close: true,
            ..ControlError::default()
        };
        // This pure helper bypasses `send_error`, so correlate the offending
        // header here too, mirroring the live error path.
        let error = correlate_control_error(&message.header, error);
        let body = encode(&error).unwrap_or_default();
        return ProtoMsg {
            header: ProtoHdr {
                proto: ProtoType::CONTROL,
                msg_type: "error".to_owned(),
                session_id: sid,
                properties: Default::default(),
            },
            body,
        };
    }

    let protocols = if terminal_disabled {
        Vec::new()
    } else {
        vec![ProtoType::SHELL]
    };
    let accept = Accept {
        version: 1,
        protocols,
    };
    let body = encode(&accept).unwrap_or_default();
    ProtoMsg {
        header: ProtoHdr {
            proto: ProtoType::CONTROL,
            msg_type: "accept".to_owned(),
            session_id: sid,
            properties: Default::default(),
        },
        body,
    }
}

/// Build the live runtime `open` response, advertising port-forward support
/// when enabled without changing the pure public [`control_open`] helper.
fn runtime_control_open(
    message: &ProtoMsg,
    terminal_disabled: bool,
    port_forward_disabled: bool,
    file_transfer_disabled: bool,
    mender_client_disabled: bool,
) -> ProtoMsg {
    let mut response = control_open(message, terminal_disabled);
    if response.header.msg_type != "accept" {
        return response;
    }
    if port_forward_disabled && file_transfer_disabled && mender_client_disabled {
        return response;
    }
    let Ok(mut accept) = decode::<Accept>(&response.body) else {
        return response;
    };
    if !port_forward_disabled {
        if !accept.protocols.contains(&ProtoType::PORT_FORWARD) {
            accept.protocols.push(ProtoType::PORT_FORWARD);
        }
        if !accept.protocols.contains(&ProtoType::PORT_FORWARD_V2) {
            accept.protocols.push(ProtoType::PORT_FORWARD_V2);
        }
        if !accept.protocols.contains(&ProtoType::PORT_FORWARD_V3) {
            accept.protocols.push(ProtoType::PORT_FORWARD_V3);
        }
    }
    if !file_transfer_disabled {
        if !accept.protocols.contains(&ProtoType::FILE_TRANSFER) {
            accept.protocols.push(ProtoType::FILE_TRANSFER);
        }
        if !accept.protocols.contains(&ProtoType::FILE_TRANSFER_V2) {
            accept.protocols.push(ProtoType::FILE_TRANSFER_V2);
        }
    }
    if !mender_client_disabled && !accept.protocols.contains(&ProtoType::MENDER_CLIENT) {
        accept.protocols.push(ProtoType::MENDER_CLIENT);
    }
    match encode(&accept) {
        Ok(body) => response.body = body,
        Err(_) => return response,
    }
    response
}

/// Build the control `pong` response for a received `ping` message.
pub fn control_pong(message: &ProtoMsg) -> ProtoMsg {
    ProtoMsg {
        header: ProtoHdr {
            proto: ProtoType::CONTROL,
            msg_type: "pong".to_owned(),
            session_id: message.header.session_id.clone(),
            properties: Default::default(),
        },
        body: Vec::new(),
    }
}

/// Build a `CONTROL/ping` for the generic router's idle heartbeat.
fn control_ping_message(sid: &str) -> ProtoMsg {
    ProtoMsg {
        header: ProtoHdr {
            proto: ProtoType::CONTROL,
            msg_type: "ping".to_owned(),
            session_id: sid.to_owned(),
            properties: Default::default(),
        },
        body: Vec::new(),
    }
}

/// Build the correlated `CONTROL/error` (`close = true`) sent when a generic
/// session idles past its timeout, mirroring upstream `"session timeout"`.
fn control_session_timeout_message(sid: &str) -> Result<ProtoMsg> {
    let error = ControlError {
        error: "session timeout".to_owned(),
        close: true,
        ..ControlError::default()
    };
    let body = encode(&error).context("failed to encode session timeout error")?;
    Ok(ProtoMsg {
        header: ProtoHdr {
            proto: ProtoType::CONTROL,
            msg_type: "error".to_owned(),
            session_id: sid.to_owned(),
            properties: Default::default(),
        },
        body,
    })
}

fn shell_ping_message(sid: &str) -> ProtoMsg {
    let mut properties = std::collections::BTreeMap::new();
    properties.insert(PROP_STATUS.to_owned(), Value::from(STATUS_PONG));
    properties.insert(
        PROP_TIMEOUT.to_owned(),
        Value::from(SHELL_LIVENESS_TIMEOUT_PROP),
    );
    ProtoMsg {
        header: ProtoHdr {
            proto: ProtoType::SHELL,
            msg_type: "ping".to_owned(),
            session_id: sid.to_owned(),
            properties,
        },
        body: Vec::new(),
    }
}

fn shell_output_message(sid: &str, body: Vec<u8>) -> ProtoMsg {
    let mut properties = std::collections::BTreeMap::new();
    properties.insert(PROP_STATUS.to_owned(), Value::from(STATUS_OK));
    ProtoMsg {
        header: ProtoHdr {
            proto: ProtoType::SHELL,
            msg_type: "shell".to_owned(),
            session_id: sid.to_owned(),
            properties,
        },
        body,
    }
}

fn shell_stop_notification(sid: &str) -> ProtoMsg {
    let mut properties = std::collections::BTreeMap::new();
    properties.insert(PROP_STATUS.to_owned(), Value::from(STATUS_OK));
    ProtoMsg {
        header: ProtoHdr {
            proto: ProtoType::SHELL,
            msg_type: "stop".to_owned(),
            session_id: sid.to_owned(),
            properties,
        },
        body: Vec::new(),
    }
}

/// Build a `SHELL/stop` notification reporting that the final PTY output could
/// not be fully delivered before the drain deadline.
fn shell_stop_abort_notification(sid: &str) -> ProtoMsg {
    let mut properties = std::collections::BTreeMap::new();
    properties.insert(PROP_STATUS.to_owned(), Value::from(STATUS_ERROR));
    ProtoMsg {
        header: ProtoHdr {
            proto: ProtoType::SHELL,
            msg_type: "stop".to_owned(),
            session_id: sid.to_owned(),
            properties,
        },
        body: b"final PTY output could not be fully delivered before drain deadline".to_vec(),
    }
}

fn terminal_dimensions(header: &ProtoHdr, config: &Config) -> (u16, u16) {
    let height = header
        .properties
        .get(PROP_TERMINAL_HEIGHT)
        .and_then(positive_u16)
        .unwrap_or(config.terminal.height);
    let width = header
        .properties
        .get(PROP_TERMINAL_WIDTH)
        .and_then(positive_u16)
        .unwrap_or(config.terminal.width);
    (height, width)
}

fn positive_u16(value: &Value) -> Option<u16> {
    let raw = match value {
        Value::Integer(integer) => integer.as_u64()?,
        _ => return None,
    };
    if raw == 0 {
        return None;
    }
    u16::try_from(raw).ok()
}

#[cfg(test)]
mod control_parity_tests {
    use super::*;
    use anyhow::Result;

    fn request(kind: &str, body: Vec<u8>) -> ProtoMsg {
        let mut properties = std::collections::BTreeMap::new();
        properties.insert("msgid".into(), Value::from("request-42"));
        ProtoMsg {
            header: ProtoHdr {
                proto: ProtoType::CONTROL,
                msg_type: kind.into(),
                session_id: "control-session".into(),
                properties,
            },
            body,
        }
    }
    fn assert_correlation(error: &ControlError, kind: &str) {
        assert_eq!(error.message_proto, ProtoType::CONTROL);
        assert_eq!(error.message_type, kind);
        assert_eq!(error.message_id, "request-42");
    }

    #[test]
    fn valid_accept_is_noop_without_protocol_registry_constraints() -> Result<()> {
        for protocols in [Vec::new(), vec![ProtoType::SHELL, ProtoType(0x4242)]] {
            let body = encode(&Accept {
                version: 1,
                protocols,
            })?;
            assert!(control_accept_error(&request("accept", body)).is_none());
        }
        // Upstream allows an omitted protocols list on version1 responses.
        let body = encode(&serde_json::json!({"version": 1}))?;
        assert!(control_accept_error(&request("accept", body)).is_none());
        // Canonical Go Accept{Version:1}: the untagged nil slice is encoded
        // explicitly as MessagePack nil, rather than omitted.
        let body = encode(&serde_json::json!({"version": 1, "protocols": null}))?;
        assert!(control_accept_error(&request("accept", body)).is_none());
        Ok(())
    }

    #[test]
    fn unsupported_accept_versions_close_with_correlation() -> Result<()> {
        for version in [0, 2, i64::from(u16::MAX)] {
            let body = encode(&Accept {
                version,
                protocols: Vec::new(),
            })?;
            let error = control_accept_error(&request("accept", body))
                .ok_or_else(|| anyhow::anyhow!("unsupported accept was not rejected"))?;
            assert!(error.close);
            assert!(error.error.contains("version"));
            assert!(error.error.len() < 256);
            assert_correlation(&error, "accept");
        }
        Ok(())
    }

    #[test]
    fn malformed_accept_version_and_protocol_types_are_rejected() -> Result<()> {
        for value in [
            serde_json::json!({"version": -1}),
            serde_json::json!({"version": 65536}),
            serde_json::json!({"version": "1"}),
            serde_json::json!({"version": 1.0}),
            serde_json::json!({"version": null}),
            serde_json::json!({"version": {}, "protocols": []}),
            serde_json::json!({"version": 1, "protocols": {}}),
            serde_json::json!({"version": 1, "protocols": "shell"}),
            serde_json::json!({"version": 1, "protocols": ["shell"]}),
            serde_json::json!({"version": 1, "protocols": [-1]}),
            serde_json::json!({"version": 1, "protocols": [65536]}),
            serde_json::json!({"version": 1, "protocols": [null]}),
        ] {
            let body = encode(&value)?;
            let error = control_accept_error(&request("accept", body))
                .ok_or_else(|| anyhow::anyhow!("malformed typed accept was not rejected"))?;
            assert!(error.close);
            assert_eq!(error.error, "malformed handshake response");
            assert_correlation(&error, "accept");
        }
        Ok(())
    }

    #[test]
    fn malformed_accept_including_trailing_data_closes() -> Result<()> {
        let mut trailing = encode(&Accept {
            version: 1,
            protocols: Vec::new(),
        })?;
        trailing.push(0xc0);
        for body in [
            Vec::new(),
            vec![0x81],
            vec![0xc0],
            vec![0xc1],
            vec![1],
            trailing,
        ] {
            let error = control_accept_error(&request("accept", body))
                .ok_or_else(|| anyhow::anyhow!("malformed accept was not rejected"))?;
            assert!(error.close);
            assert_eq!(error.error, "malformed handshake response");
            assert_correlation(&error, "accept");
        }
        Ok(())
    }

    #[test]
    fn malformed_accept_does_not_reflect_untrusted_body() -> Result<()> {
        let secret = format!("UNTRUSTED-BODY-{}", "x".repeat(7800));
        let body = encode(&serde_json::json!({"version": secret}))?;
        let error = control_accept_error(&request("accept", body))
            .ok_or_else(|| anyhow::anyhow!("bad typed version accepted"))?;
        assert_eq!(error.error, "malformed handshake response");
        assert!(!error.error.contains("UNTRUSTED-BODY"));
        assert!(encode(&error)?.len() < 512);
        Ok(())
    }

    #[test]
    fn central_error_correlation_overwrites_stale_fields_preserving_error_policy() {
        let mut message = request("unknown", Vec::new());
        message.header.proto = ProtoType(0x4242);
        message
            .header
            .properties
            .insert("private".into(), Value::from("do-not-reflect"));
        let error = correlate_control_error(
            &message.header,
            ControlError {
                error: "original reason".into(),
                close: true,
                code: 19,
                message_proto: ProtoType::SHELL,
                message_type: "stale-type".into(),
                message_id: "stale-id".into(),
            },
        );
        assert_eq!(error.error, "original reason");
        assert!(error.close);
        assert_eq!(error.code, 19);
        assert_eq!(error.message_proto, ProtoType(0x4242));
        assert_eq!(error.message_type, "unknown");
        assert_eq!(error.message_id, "request-42");
    }

    #[test]
    fn missing_or_nonstring_message_ids_are_not_reflected() {
        for value in [
            None,
            Some(Value::Nil),
            Some(Value::from(7)),
            Some(Value::Binary(vec![1, 2, 3])),
        ] {
            let mut message = request("unknown", Vec::new());
            message.header.properties.clear();
            if let Some(value) = value {
                message.header.properties.insert("msgid".into(), value);
            }
            let error = correlate_control_error(
                &message.header,
                ControlError {
                    message_id: "stale".into(),
                    ..ControlError::default()
                },
            );
            assert!(error.message_id.is_empty());
            assert_eq!(error.message_type, "unknown");
        }
    }

    #[test]
    fn correlation_limits_are_bytes_and_do_not_cut_utf8() {
        for (text, expected) in [
            ("x".repeat(128), true),
            ("x".repeat(129), false),
            ("é".repeat(64), true),
            ("é".repeat(65), false),
        ] {
            let mut message = request(&text, Vec::new());
            message
                .header
                .properties
                .insert("msgid".into(), Value::from(text.clone()));
            let error = correlate_control_error(&message.header, ControlError::default());
            if expected {
                assert_eq!(error.message_type, text);
                assert_eq!(error.message_id, text);
            } else {
                assert!(error.message_type.is_empty());
                assert!(error.message_id.is_empty());
            }
        }
    }

    #[test]
    fn pure_open_error_is_correlated_without_changing_success_capabilities() -> Result<()> {
        let message = request("open", encode(&Open { versions: vec![2] })?);
        let response = control_open(&message, false);
        assert_eq!(response.header.proto, ProtoType::CONTROL);
        assert_eq!(response.header.msg_type, "error");
        assert_eq!(response.header.session_id, "control-session");
        let error: ControlError = decode(&response.body)?;
        assert!(error.close);
        assert_correlation(&error, "open");
        let success = request("open", encode(&Open { versions: vec![1] })?);
        let accept: Accept = decode(&control_open(&success, false).body)?;
        assert_eq!(accept.protocols, vec![ProtoType::SHELL]);
        let disabled: Accept = decode(&control_open(&success, true).body)?;
        assert!(disabled.protocols.is_empty());
        Ok(())
    }

    #[test]
    fn runtime_open_advertises_only_configured_enabled_capabilities() -> Result<()> {
        let message = request("open", encode(&Open { versions: vec![1] })?);
        let accept: Accept =
            decode(&runtime_control_open(&message, false, false, false, false).body)?;
        for proto in [
            ProtoType::SHELL,
            ProtoType::FILE_TRANSFER,
            ProtoType::FILE_TRANSFER_V2,
            ProtoType::PORT_FORWARD,
            ProtoType::PORT_FORWARD_V2,
            ProtoType::MENDER_CLIENT,
        ] {
            assert!(accept.protocols.contains(&proto), "missing {proto}");
        }

        // Fully disabled features advertise nothing and cannot claim enabled.
        let all_disabled: Accept =
            decode(&runtime_control_open(&message, true, true, true, true).body)?;
        assert!(all_disabled.protocols.is_empty());

        // Only the shell is enabled: capabilities stay deterministic.
        let shell_only: Accept =
            decode(&runtime_control_open(&message, false, true, true, true).body)?;
        assert_eq!(shell_only.protocols, vec![ProtoType::SHELL]);
        Ok(())
    }

    #[test]
    fn generic_router_idle_split_matches_upstream() -> Result<()> {
        let router = SessionRouter::new(GENERIC_IDLE_TIMEOUT)
            .map_err(|err| anyhow::anyhow!("router init failed: {err}"))?;
        assert_eq!(router.idle_duration(), Duration::from_secs(60));
        assert_eq!(router.ping_wait(), Duration::from_secs(48));
        assert_eq!(router.pong_wait(), Duration::from_secs(12));
        Ok(())
    }
}

#[cfg(test)]
mod close_output_tests {
    use super::*;
    use std::collections::BTreeMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::task::JoinSet;

    #[tokio::test]
    async fn close_output_coordination_services_real_port_forward_under_file_transfer_flood()
    -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let target = listener.local_addr()?;
        let data: Vec<u8> = (0..300_000usize)
            .map(|index| u8::try_from(index % 251).unwrap_or(0))
            .collect();
        let expected = data.clone();

        // JoinSet owns the local TCP feeder; dropping or aborting it on failure
        // cannot leak a background task.
        let mut feeders = JoinSet::new();
        let server_data = data.clone();
        feeders.spawn(async move {
            let (mut stream, _peer) = listener.accept().await?;
            stream.write_all(&server_data).await?;
            stream.shutdown().await?;
            let mut sink = [0u8; 1024];
            loop {
                match stream.read(&mut sink).await {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
            Ok::<(), anyhow::Error>(())
        });

        // Real v2 port-forward manager connected to the local TCP listener.
        let mut port_forward = PortForwardManager::new();
        let mut properties = BTreeMap::new();
        properties.insert("connection_id".to_owned(), Value::from("pf-real"));
        let new = ProtoMsg {
            header: ProtoHdr {
                proto: ProtoType::PORT_FORWARD_V2,
                msg_type: "new".to_owned(),
                session_id: "closing".to_owned(),
                properties,
            },
            body: encode(&serde_json::json!({
                "remote_host": "127.0.0.1",
                "remote_port": target.port(),
                "protocol": "tcp",
            }))?,
        };
        let immediate = port_forward.handle(new).await?;
        assert!(
            immediate
                .iter()
                .all(|message| message.header.msg_type != "error"),
            "real port-forward new must be accepted"
        );

        // The close future continuously feeds file-transfer replies through a
        // bounded single-slot channel and only completes once the sink has seen
        // the real port-forward stop after all forwarded bytes.
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let (tx, mut forwarded) = mpsc::channel::<ProtoMsg>(1);
        let close = async move {
            let mut release_rx = release_rx;
            loop {
                tokio::select! {
                    biased;
                    _ = &mut release_rx => return Ok::<(), anyhow::Error>(()),
                    result = tx.send(ProtoMsg {
                        header: ProtoHdr {
                            proto: ProtoType::FILE_TRANSFER_V2,
                            msg_type: "file_chunk".to_owned(),
                            session_id: "unrelated-ft".to_owned(),
                            properties: BTreeMap::new(),
                        },
                        body: b"ft".to_vec(),
                    }) => {
                        result.map_err(|_| {
                            anyhow::anyhow!("file transfer forwarding channel closed")
                        })?;
                    }
                }
            }
        };
        tokio::pin!(close);

        let mut pf_received: Vec<u8> = Vec::with_capacity(expected.len());
        let mut ft_messages = 0usize;
        let mut pf_stop = false;
        let mut release = Some(release_tx);
        let mut sink = async |message: ProtoMsg| -> Result<()> {
            match message.header.proto {
                ProtoType::PORT_FORWARD | ProtoType::PORT_FORWARD_V2 => {
                    if message.header.msg_type == "forward" {
                        let next = pf_received
                            .len()
                            .checked_add(message.body.len())
                            .ok_or_else(|| anyhow::anyhow!("port-forward byte count overflow"))?;
                        if next > expected.len() {
                            return Err(anyhow::anyhow!(
                                "port-forward bytes exceeded expected fixture length"
                            ));
                        }
                        pf_received.extend_from_slice(&message.body);
                    } else if message.header.msg_type == "stop" {
                        pf_stop = true;
                        if let Some(tx) = release.take() {
                            let _ = tx.send(());
                        }
                    }
                }
                ProtoType::FILE_TRANSFER | ProtoType::FILE_TRANSFER_V2 => {
                    ft_messages = ft_messages.saturating_add(1);
                }
                _ => {}
            }
            Ok(())
        };

        let result = tokio::time::timeout(
            Duration::from_secs(10),
            service_close_output(close.as_mut(), &mut forwarded, &mut port_forward, &mut sink),
        )
        .await;

        port_forward.close_all().await?;
        while let Some(joined) = feeders.join_next().await {
            joined??;
        }

        result??;
        assert!(pf_stop, "real port-forward stop must be delivered");
        assert!(
            ft_messages > 0,
            "continuous file-transfer flood must be serviced"
        );
        assert_eq!(
            pf_received, expected,
            "every port-forward byte delivered exactly once"
        );
        assert_eq!(
            pf_received.len(),
            300_000,
            "fixture must exceed queue capacities"
        );
        Ok(())
    }
}

#[cfg(test)]
mod shell_control_wire_tests {
    //! Native private tests asserting the exact protocol messages the daemon
    //! emits for shell healthchecks, natural/aborted shell stops and generic
    //! CONTROL router heartbeats/timeouts. These build on the pure foundation
    //! coverage already present and intentionally avoid duplicating the
    //! control handshake/accept parity suite.
    use super::*;

    #[test]
    fn shell_ping_carries_healthcheck_properties() {
        let ping = shell_ping_message("sid-ping");
        assert_eq!(ping.header.proto, ProtoType::SHELL);
        assert_eq!(ping.header.msg_type, "ping");
        assert_eq!(ping.header.session_id, "sid-ping");
        assert_eq!(
            ping.header
                .properties
                .get(PROP_STATUS)
                .and_then(Value::as_i64),
            Some(STATUS_PONG)
        );
        assert_eq!(
            ping.header
                .properties
                .get(PROP_TIMEOUT)
                .and_then(Value::as_i64),
            Some(SHELL_LIVENESS_TIMEOUT_PROP)
        );
        assert!(ping.body.is_empty());
    }

    #[test]
    fn shell_output_and_stop_messages_encode_expected_wire() -> Result<()> {
        let output = shell_output_message("sid-out", b"hello".to_vec());
        assert_eq!(output.header.proto, ProtoType::SHELL);
        assert_eq!(output.header.msg_type, "shell");
        assert_eq!(output.header.session_id, "sid-out");
        assert_eq!(output.body, b"hello".to_vec());
        assert_eq!(
            output
                .header
                .properties
                .get(PROP_STATUS)
                .and_then(Value::as_i64),
            Some(STATUS_OK)
        );
        // The emitted message round-trips through the real wire codec.
        let encoded = encode(&output)?;
        let decoded: ProtoMsg = decode(&encoded)?;
        assert_eq!(decoded.header, output.header);
        assert_eq!(decoded.body, output.body);

        let stop = shell_stop_notification("sid-out");
        assert_eq!(stop.header.msg_type, "stop");
        assert_eq!(stop.header.session_id, "sid-out");
        assert!(stop.body.is_empty());
        assert_eq!(
            stop.header
                .properties
                .get(PROP_STATUS)
                .and_then(Value::as_i64),
            Some(STATUS_OK)
        );

        let abort = shell_stop_abort_notification("sid-out");
        assert_eq!(abort.header.msg_type, "stop");
        assert_eq!(abort.header.session_id, "sid-out");
        assert!(!abort.body.is_empty());
        assert_eq!(
            abort
                .header
                .properties
                .get(PROP_STATUS)
                .and_then(Value::as_i64),
            Some(STATUS_ERROR)
        );
        Ok(())
    }

    #[test]
    fn control_ping_and_timeout_messages_are_correlated() -> Result<()> {
        let ping = control_ping_message("sid-ctl");
        assert_eq!(ping.header.proto, ProtoType::CONTROL);
        assert_eq!(ping.header.msg_type, "ping");
        assert_eq!(ping.header.session_id, "sid-ctl");
        assert!(ping.body.is_empty());

        let timeout = control_session_timeout_message("sid-ctl")?;
        assert_eq!(timeout.header.proto, ProtoType::CONTROL);
        assert_eq!(timeout.header.msg_type, "error");
        assert_eq!(timeout.header.session_id, "sid-ctl");
        let error: ControlError = decode(&timeout.body)?;
        assert!(error.close);
        assert_eq!(error.error, "session timeout");
        Ok(())
    }

    #[test]
    fn control_pong_echoes_session_id_without_properties() {
        let mut request = ProtoMsg {
            header: ProtoHdr {
                proto: ProtoType::CONTROL,
                msg_type: "ping".to_owned(),
                session_id: "sid-pong".to_owned(),
                properties: Default::default(),
            },
            body: Vec::new(),
        };
        request
            .header
            .properties
            .insert("status".to_owned(), Value::from(1));
        let pong = control_pong(&request);
        assert_eq!(pong.header.proto, ProtoType::CONTROL);
        assert_eq!(pong.header.msg_type, "pong");
        assert_eq!(pong.header.session_id, "sid-pong");
        assert!(pong.body.is_empty());
        assert!(pong.header.properties.is_empty());
    }
}

#[cfg(test)]
mod runtime_session_tests {
    //! Actual runtime tests over a local websocket pair. These construct
    //! `Session`, spawn real `PtyShell` children, drive the real output
    //! multiplexer and assert the frames the real peer receives. No D-Bus,
    //! server, key material or background task is used.
    use super::*;
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::time::Duration;

    use futures_util::StreamExt;
    use nix::unistd::{Uid, User};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::{WebSocketStream, accept_async};

    const FRAME_TIMEOUT: Duration = Duration::from_secs(10);
    const PUMP_TIMEOUT: Duration = Duration::from_secs(20);

    type TestPeer = WebSocketStream<TcpStream>;

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempConfigDir {
        path: PathBuf,
    }

    impl Drop for TempConfigDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn fixture_config() -> Result<(TempConfigDir, Config)> {
        let user = User::from_uid(Uid::effective())
            .context("failed to resolve current effective OS user")?
            .ok_or_else(|| anyhow::anyhow!("no passwd entry for current effective uid"))?;
        let unique = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "mender-connect-runtime-test-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&path).context("failed to create private test config directory")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .context("failed to make test config directory private")?;

        let primary = path.join("mender-connect.conf");
        let fallback = path.join("missing-fallback.conf");
        let document = serde_json::json!({
            "User": user.name,
            "ShellCommand": "/bin/bash",
            "ShellArguments": ["--noprofile", "--norc"],
            "Terminal": { "Width": 80, "Height": 40 },
            "Sessions": { "StopExpired": false },
            "PortForward": { "Disable": true },
            "FileTransfer": { "Disable": true },
            "MenderClient": { "Disable": true },
        });
        fs::write(&primary, serde_json::to_vec(&document)?)
            .context("failed to write fixture configuration")?;
        let config = crate::config::load_config(&primary, &fallback)
            .context("failed to load fixture config")?;
        Ok((TempConfigDir { path }, config))
    }

    async fn local_pair() -> Result<(Transport, TestPeer)> {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .context("failed to bind local fixture listener")?;
        let address = listener
            .local_addr()
            .context("failed to read local fixture listener address")?;
        let url = format!("http://127.0.0.1:{}", address.port());
        let (transport, peer) =
            tokio::try_join!(Transport::connect(&url, "fixture-token"), async move {
                let (stream, _) = listener
                    .accept()
                    .await
                    .context("fixture listener accept failed")?;
                let peer = accept_async(stream)
                    .await
                    .context("fixture websocket accept failed")?;
                Ok::<_, anyhow::Error>(peer)
            })?;
        Ok((transport, peer))
    }

    async fn read_msg(peer: &mut TestPeer) -> Result<ProtoMsg> {
        let deadline = tokio::time::Instant::now() + FRAME_TIMEOUT;
        loop {
            let frame = tokio::time::timeout_at(deadline, peer.next())
                .await
                .context("timed out waiting for fixture peer frame")?;
            let frame = frame.context("fixture peer stream ended")??;
            match frame {
                Message::Binary(bytes) => return Ok(decode::<ProtoMsg>(&bytes)?),
                Message::Close(_) => anyhow::bail!("fixture peer closed before a message arrived"),
                _ => {}
            }
        }
    }

    fn shell_new_message(sid: &str, user: &str) -> ProtoMsg {
        let mut properties = BTreeMap::new();
        properties.insert(PROP_USER_ID.to_owned(), Value::from(user));
        ProtoMsg {
            header: ProtoHdr {
                proto: ProtoType::SHELL,
                msg_type: "new".to_owned(),
                session_id: sid.to_owned(),
                properties,
            },
            body: Vec::new(),
        }
    }

    fn shell_input_message(sid: &str, body: &[u8]) -> ProtoMsg {
        ProtoMsg {
            header: ProtoHdr {
                proto: ProtoType::SHELL,
                msg_type: "shell".to_owned(),
                session_id: sid.to_owned(),
                properties: BTreeMap::new(),
            },
            body: body.to_vec(),
        }
    }

    fn shell_stop_message(sid: &str, user: Option<&str>) -> ProtoMsg {
        let mut properties = BTreeMap::new();
        if let Some(user) = user {
            properties.insert(PROP_USER_ID.to_owned(), Value::from(user));
        }
        ProtoMsg {
            header: ProtoHdr {
                proto: ProtoType::SHELL,
                msg_type: "stop".to_owned(),
                session_id: sid.to_owned(),
                properties,
            },
            body: Vec::new(),
        }
    }

    fn control_message(kind: &str, sid: &str) -> ProtoMsg {
        ProtoMsg {
            header: ProtoHdr {
                proto: ProtoType::CONTROL,
                msg_type: kind.to_owned(),
                session_id: sid.to_owned(),
                properties: BTreeMap::new(),
            },
            body: Vec::new(),
        }
    }

    fn file_transfer_message(sid: &str) -> ProtoMsg {
        ProtoMsg {
            header: ProtoHdr {
                proto: ProtoType::FILE_TRANSFER,
                msg_type: "stat".to_owned(),
                session_id: sid.to_owned(),
                properties: BTreeMap::new(),
            },
            body: Vec::new(),
        }
    }

    /// Fill the generic (non-SHELL) router to its defensive capacity so the
    /// next unseen SID must be rejected at admission time.
    fn fill_router_to_capacity(session: &mut Session) -> Result<Vec<String>> {
        let now = std::time::Instant::now();
        let mut sids = Vec::new();
        for index in 0..crate::session_router::MAX_ROUTER_SESSIONS {
            let sid = format!("generic-capacity-{index}");
            let id = SessionId::new(sid.clone())?;
            let disposition = session.router.open_or_touch(&id, now)?;
            assert!(matches!(disposition, SessionDisposition::Created));
            sids.push(sid);
        }
        assert_eq!(
            session.router.len(),
            crate::session_router::MAX_ROUTER_SESSIONS
        );
        Ok(sids)
    }

    async fn send_new(
        session: &mut Session,
        peer: &mut TestPeer,
        sid: &str,
        user: &str,
        expected_status: i64,
    ) -> Result<ProtoMsg> {
        session.handle(shell_new_message(sid, user)).await?;
        let reply = read_msg(peer).await?;
        assert_eq!(reply.header.proto, ProtoType::SHELL);
        assert_eq!(reply.header.msg_type, "new");
        assert_eq!(reply.header.session_id, sid);
        assert_eq!(
            reply
                .header
                .properties
                .get(PROP_STATUS)
                .and_then(Value::as_i64),
            Some(expected_status),
            "unexpected SHELL/new status for {sid}"
        );
        Ok(reply)
    }

    async fn stop_and_read_ack(
        session: &mut Session,
        peer: &mut TestPeer,
        message: ProtoMsg,
        expected_status: i64,
    ) -> Result<ProtoMsg> {
        let expected_sid = message.header.session_id.clone();
        session.handle(message).await?;
        // Output frames already forwarded before the stop may still be queued
        // ahead of the correlated acknowledgement; skip only those.
        for _ in 0..64 {
            let reply = read_msg(peer).await?;
            if reply.header.proto != ProtoType::SHELL
                || reply.header.msg_type != "stop"
                || reply.header.session_id != expected_sid
            {
                continue;
            }
            assert_eq!(
                reply
                    .header
                    .properties
                    .get(PROP_STATUS)
                    .and_then(Value::as_i64),
                Some(expected_status),
                "unexpected SHELL/stop status for {expected_sid}"
            );
            return Ok(reply);
        }
        anyhow::bail!("did not receive a correlated SHELL/stop acknowledgement for {expected_sid}")
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() {
            return true;
        }
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    async fn pump_until_marker(
        session: &mut Session,
        peer: &mut TestPeer,
        expected_sid: &str,
        marker: &str,
    ) -> Result<Vec<ProtoMsg>> {
        let deadline = tokio::time::Instant::now() + PUMP_TIMEOUT;
        let marker_bytes = marker.as_bytes();
        let mut offset = 0usize;
        let mut buffers: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut frames = Vec::new();

        loop {
            let selected = tokio::time::timeout_at(deadline, async {
                tokio::select! {
                    output = next_shell_output(&mut session.shells, offset) => (Some(output), None),
                    frame = peer.next() => (None, Some(frame)),
                }
            })
            .await
            .context("timed out waiting for a real PTY output marker")?;

            let (output, frame) = selected;
            if let Some((sid, data, next_offset)) = output {
                offset = next_offset;
                match data {
                    Some(bytes) => session.forward_output(&sid, bytes).await?,
                    None => session.stop_shell(&sid).await?,
                }
            }

            if let Some(frame) = frame {
                let frame = frame.context("fixture peer stream ended while pumping")??;
                let Message::Binary(bytes) = frame else {
                    continue;
                };
                let message = decode::<ProtoMsg>(&bytes)?;
                if message.header.proto != ProtoType::SHELL || message.header.msg_type != "shell" {
                    continue;
                }
                let sid = message.header.session_id.clone();
                if sid != expected_sid && contains_bytes(&message.body, marker_bytes) {
                    anyhow::bail!("marker {marker} leaked into output for unexpected SID {sid}");
                }
                let buffer = buffers.entry(sid.clone()).or_default();
                buffer.extend_from_slice(&message.body);
                frames.push(message);
                if sid == expected_sid
                    && buffers
                        .get(expected_sid)
                        .is_some_and(|received| contains_bytes(received, marker_bytes))
                {
                    return Ok(frames);
                }
            }
        }
    }

    async fn run_shell_runtime_case(session: &mut Session, peer: &mut TestPeer) -> Result<()> {
        let sid_a = "runtime-shell-a";
        let sid_b = "runtime-shell-b";
        let sid_c = "runtime-shell-c";

        send_new(session, peer, sid_a, "logical-a", STATUS_OK).await?;
        send_new(session, peer, sid_b, "logical-b", STATUS_OK).await?;
        send_new(session, peer, sid_c, "logical-a", STATUS_ERROR).await?;
        assert_eq!(
            session.shells.len(),
            2,
            "quota rejection must not spawn a shell"
        );
        assert_eq!(session.registry.count(), 2);
        // Legacy SHELL handling must not feed the generic router.
        assert!(session.router.is_empty());

        session
            .handle(shell_input_message(
                sid_a,
                b"stty -echo; printf '%s%s\\n' '__SID_' 'A__'\n",
            ))
            .await?;
        let frames_a = pump_until_marker(session, peer, sid_a, "__SID_A__").await?;
        assert!(
            frames_a.iter().any(|frame| {
                frame.header.session_id == sid_a && contains_bytes(&frame.body, b"__SID_A__")
            }),
            "real SID A marker was not received from the peer"
        );
        assert!(session.router.is_empty());

        session
            .handle(shell_input_message(
                sid_b,
                b"stty -echo; printf '%s%s\\n' '__SID_' 'B__'\n",
            ))
            .await?;
        let frames_b = pump_until_marker(session, peer, sid_b, "__SID_B__").await?;
        assert!(
            frames_b.iter().any(|frame| {
                frame.header.session_id == sid_b && contains_bytes(&frame.body, b"__SID_B__")
            }),
            "real SID B marker was not received from the peer"
        );

        stop_and_read_ack(session, peer, shell_stop_message(sid_a, None), STATUS_OK).await?;

        session
            .handle(shell_input_message(
                sid_b,
                b"stty -echo; printf '%s%s\\n' '__SID_' 'B2__'\n",
            ))
            .await?;
        let frames_b2 = pump_until_marker(session, peer, sid_b, "__SID_B2__").await?;
        assert!(
            frames_b2.iter().any(|frame| {
                frame.header.session_id == sid_b && contains_bytes(&frame.body, b"__SID_B2__")
            }),
            "SID B did not produce fresh output after SID A was stopped"
        );

        let empty_sid_stop = stop_and_read_ack(
            session,
            peer,
            shell_stop_message("", Some("logical-b")),
            STATUS_OK,
        )
        .await?;
        assert_eq!(empty_sid_stop.header.session_id, "");
        assert!(session.shells.is_empty());
        assert_eq!(session.registry.count(), 0);

        stop_and_read_ack(session, peer, shell_stop_message("", None), STATUS_ERROR).await?;

        let mut non_string_properties = BTreeMap::new();
        non_string_properties.insert(PROP_USER_ID.to_owned(), Value::from(7));
        let non_string_stop = ProtoMsg {
            header: ProtoHdr {
                proto: ProtoType::SHELL,
                msg_type: "stop".to_owned(),
                session_id: String::new(),
                properties: non_string_properties,
            },
            body: Vec::new(),
        };
        stop_and_read_ack(session, peer, non_string_stop, STATUS_ERROR).await?;
        assert!(session.shells.is_empty());
        assert_eq!(session.registry.count(), 0);
        Ok(())
    }

    async fn run_generic_timer_case(session: &mut Session, peer: &mut TestPeer) -> Result<()> {
        let sid = "runtime-generic-sid";
        session.handle(control_message("pong", sid)).await?;

        let base = std::time::Instant::now();
        let first_ping_now = base + Duration::from_secs(48);
        let outcome = service_router_timers_at(session, first_ping_now).await?;
        assert!(outcome.is_none());
        let ping = read_msg(peer).await?;
        assert_eq!(ping.header.proto, ProtoType::CONTROL);
        assert_eq!(ping.header.msg_type, "ping");
        assert_eq!(ping.header.session_id, sid);
        assert!(ping.body.is_empty());

        // An inbound CONTROL/pong refreshes the same router entry.
        session.handle(control_message("pong", sid)).await?;
        let second_ping_now = first_ping_now + Duration::from_millis(700);
        let outcome = service_router_timers_at(session, second_ping_now).await?;
        assert!(outcome.is_none());
        let ping = read_msg(peer).await?;
        assert_eq!(ping.header.proto, ProtoType::CONTROL);
        assert_eq!(ping.header.msg_type, "ping");
        assert_eq!(ping.header.session_id, sid);

        // Before the 12s pong grace elapses the entry is still alive.
        let outcome =
            service_router_timers_at(session, second_ping_now + Duration::from_secs(11)).await?;
        assert!(outcome.is_none());

        // At the grace deadline the same SID receives a correlated close error.
        let outcome =
            service_router_timers_at(session, second_ping_now + Duration::from_secs(12)).await?;
        assert!(outcome.is_none());
        let timeout = read_msg(peer).await?;
        assert_eq!(timeout.header.proto, ProtoType::CONTROL);
        assert_eq!(timeout.header.msg_type, "error");
        assert_eq!(timeout.header.session_id, sid);
        let error: ControlError = decode(&timeout.body)?;
        assert!(error.close);
        assert_eq!(error.error, "session timeout");
        assert!(session.shells.is_empty());
        assert!(session.router.is_empty());
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn actual_session_runtime_multiplexes_pty_output_and_user_stop() -> Result<()> {
        let (_temp, config) = fixture_config()?;
        let (transport, mut peer) = local_pair().await?;
        let mut session = Session::new(config, transport, None)?;
        let run_result = run_shell_runtime_case(&mut session, &mut peer).await;
        let cleanup_result = session.stop_all_shells().await;
        run_result?;
        cleanup_result?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn actual_generic_control_timer_emits_ping_pong_and_timeout() -> Result<()> {
        let (_temp, config) = fixture_config()?;
        let (transport, mut peer) = local_pair().await?;
        let mut session = Session::new(config, transport, None)?;
        let run_result = run_generic_timer_case(&mut session, &mut peer).await;
        let cleanup_result = session.stop_all_shells().await;
        run_result?;
        cleanup_result?;
        Ok(())
    }

    /// Install a per-SID entry whose owned stop cleanup task is fully
    /// controlled by the caller, so cancellation and result handling can be
    /// observed deterministically without a real PTY.
    fn install_controlled_stop(
        session: &mut Session,
        sid: &str,
        config: &Config,
        handle: tokio::task::JoinHandle<Result<()>>,
    ) -> Result<SessionId> {
        let session_id = SessionId::new(sid.to_owned())?;
        let user = UserId::new("cleanup-user".to_owned())?;
        session.registry.try_reserve(&session_id, &user)?;
        session.shells.insert(
            sid.to_owned(),
            ActiveShell {
                shell: None,
                output: None,
                policy: SessionPolicy::new(&config.sessions, Instant::now()),
                health: ShellHealthcheck::new(Instant::now()),
                phase: ActiveShellPhase::Stopping { handle },
            },
        );
        Ok(session_id)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn teardown_preserves_inflight_drain_until_join() -> Result<()> {
        let (_temp, config) = fixture_config()?;
        let (transport, mut peer) = local_pair().await?;
        let mut session = Session::new(config, transport, None)?;
        let sid = "teardown-drain";
        send_new(&mut session, &mut peer, sid, "drain-user", STATUS_OK).await?;
        let shell = session
            .shells
            .get_mut(sid)
            .and_then(|active| active.shell.take())
            .ok_or_else(|| anyhow::anyhow!("missing test shell"))?;
        let (release, gate) = tokio::sync::oneshot::channel::<()>();
        let (ready, started) = tokio::sync::oneshot::channel::<()>();
        let runs = Arc::new(AtomicUsize::new(0));
        let task_runs = runs.clone();
        let handle = tokio::task::spawn_blocking(move || {
            let mut shell = shell;
            task_runs.fetch_add(1, Ordering::SeqCst);
            let result = shell.terminate_processes();
            let _ = ready.send(());
            let _ = gate.blocking_recv();
            (shell, result)
        });
        let handle_id = handle.id();
        let deadline = Instant::now() + Duration::from_secs(30);
        session
            .shells
            .get_mut(sid)
            .ok_or_else(|| anyhow::anyhow!("missing shell entry"))?
            .phase = ActiveShellPhase::DrainingCleanup { handle, deadline };
        let session_id = SessionId::new(sid.to_owned())?;
        let reserved_before = session.registry.contains(&session_id);
        let ready = tokio::time::timeout(Duration::from_secs(10), started).await;
        if !matches!(ready, Ok(Ok(()))) {
            let _ = release.send(());
            let shells = session.stop_all_shells().await;
            let forward = session.port_forward.close_all().await;
            let transfer = session.file_transfer.close_all().await;
            let command = session.mender.close_all().await;
            shells?;
            forward?;
            transfer?;
            command?;
            anyhow::bail!("drain fixture did not become ready");
        }
        session.begin_connection_teardown();
        session.begin_connection_teardown();
        let retained = session.shells.get(sid).is_some_and(|active| {
            active.shell.is_none() && active.output.is_none() && matches!(&active.phase, ActiveShellPhase::DrainingCleanup { handle, deadline: d } if handle.id() == handle_id && *d == deadline)
        });
        let mut stop = Box::pin(session.stop_all_shells());
        let blocked = tokio::time::timeout(Duration::from_millis(30), &mut stop)
            .await
            .is_err();
        drop(stop);
        let reserved_while_blocked = session.registry.contains(&session_id);
        let _ = release.send(());
        let shells = session.stop_all_shells().await;
        let forward = session.port_forward.close_all().await;
        let transfer = session.file_transfer.close_all().await;
        let command = session.mender.close_all().await;
        shells?;
        forward?;
        transfer?;
        command?;
        assert!(retained && blocked && reserved_before && reserved_while_blocked);
        assert!(!session.registry.contains(&session_id));
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        assert!(!session.shells.contains_key(sid));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn teardown_signals_all_groups_before_gated_shell_join() -> Result<()> {
        let (_temp, config) = fixture_config()?;
        let (transport, _peer) = local_pair().await?;
        let mut session = Session::new(config.clone(), transport, None)?;
        let (shell_release, shell_gate) = tokio::sync::oneshot::channel::<()>();
        let shell_handle = tokio::spawn(async move {
            let _ = shell_gate.await;
            Ok::<(), anyhow::Error>(())
        });
        let sid = install_controlled_stop(&mut session, "teardown-gate", &config, shell_handle)?;
        let forward = session.port_forward.install_teardown_probe().await?;
        let transfer = session.file_transfer.install_teardown_probe().await?;
        let (command, command_release) = session.mender.install_teardown_probe()?;
        session.begin_connection_teardown();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !(forward.load(Ordering::SeqCst) && transfer.load(Ordering::SeqCst))
            && std::time::Instant::now() < deadline
        {
            tokio::task::yield_now().await;
        }
        let before_join = (
            forward.load(Ordering::SeqCst),
            transfer.load(Ordering::SeqCst),
            command.load(Ordering::SeqCst),
            session.registry.contains(&sid),
        );
        let mut stop = Box::pin(session.stop_all_shells());
        let blocked = tokio::time::timeout(Duration::from_millis(30), &mut stop)
            .await
            .is_err();
        drop(stop);
        let _ = shell_release.send(());
        let _ = command_release.send(());
        let shells = session.stop_all_shells().await;
        let forward_cleanup = session.port_forward.close_all().await;
        let transfer_cleanup = session.file_transfer.close_all().await;
        let command_cleanup = session.mender.close_all().await;
        shells?;
        forward_cleanup?;
        transfer_cleanup?;
        command_cleanup?;
        assert_eq!(before_join, (true, true, true, true));
        assert!(blocked);
        assert!(!session.registry.contains(&sid));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stop_cleanup_cancellation_retains_state_then_retry_completes_once() -> Result<()> {
        let (_temp, config) = fixture_config()?;
        let (transport, peer) = local_pair().await?;
        let mut session = Session::new(config.clone(), transport, None)?;

        let sid = "cleanup-cancel-sid";
        let runs = Arc::new(AtomicUsize::new(0));
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let runs_task = Arc::clone(&runs);
        let handle = tokio::task::spawn_blocking(move || {
            runs_task.fetch_add(1, Ordering::SeqCst);
            let _ = release_rx.blocking_recv();
            Ok::<(), anyhow::Error>(())
        });
        let session_id = install_controlled_stop(&mut session, sid, &config, handle)?;

        // Cancel the first attempt while the join is still pending.
        {
            let mut fut = Box::pin(session.stop_shell(sid));
            let timed_out = tokio::time::timeout(Duration::from_millis(50), &mut fut).await;
            assert!(
                timed_out.is_err(),
                "cleanup should remain pending until the controlled task is released"
            );
        }

        assert!(
            session.shells.contains_key(sid),
            "map entry must be retained when the stop future is cancelled"
        );
        assert!(
            session.registry.contains(&session_id),
            "registry quota must be retained when the stop future is cancelled"
        );
        assert!(
            matches!(
                session.shells.get(sid).map(|active| &active.phase),
                Some(ActiveShellPhase::Stopping { .. })
            ),
            "the owned cleanup join handle must be retained when cancelled"
        );
        assert_eq!(
            runs.load(Ordering::SeqCst),
            1,
            "cancelling must not spawn a duplicate cleanup task"
        );

        // Retry: resume the same handle, which now completes exactly once.
        release_tx
            .send(())
            .map_err(|_| anyhow::anyhow!("controlled cleanup receiver dropped"))?;
        session.stop_shell(sid).await?;
        assert!(
            !session.shells.contains_key(sid),
            "entry released only after verified cleanup"
        );
        assert!(
            !session.registry.contains(&session_id),
            "quota released only after verified cleanup"
        );
        assert_eq!(
            runs.load(Ordering::SeqCst),
            1,
            "cleanup must be spawned and completed exactly once across retries"
        );

        drop(peer);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_stop_cleanup_retains_reservation_and_stays_fatal() -> Result<()> {
        let (_temp, config) = fixture_config()?;
        let (transport, peer) = local_pair().await?;
        let mut session = Session::new(config.clone(), transport, None)?;

        let sid = "cleanup-fail-sid";
        let handle = tokio::task::spawn_blocking(move || {
            Err::<(), anyhow::Error>(anyhow::anyhow!("synthetic cleanup failure"))
        });
        let session_id = install_controlled_stop(&mut session, sid, &config, handle)?;

        let err = session
            .stop_shell(sid)
            .await
            .expect_err("failed cleanup must surface a fatal error");
        assert!(
            err.downcast_ref::<PtyCleanupError>().is_some(),
            "cleanup failure must retain PtyCleanupError classification: {err:#}"
        );
        assert!(
            session.shells.contains_key(sid),
            "failed cleanup must not remove the entry"
        );
        assert!(
            session.registry.contains(&session_id),
            "failed cleanup must not release the quota reservation"
        );
        assert!(
            matches!(
                session.shells.get(sid).map(|active| &active.phase),
                Some(ActiveShellPhase::Failed)
            ),
            "failed cleanup must mark the entry failed without a completed handle"
        );

        // A second stop stays fatal and neither resurrects nor frees anything.
        let second = session
            .stop_shell(sid)
            .await
            .expect_err("failed cleanup must remain fatal on retry");
        assert!(
            second.downcast_ref::<PtyCleanupError>().is_some(),
            "retained cleanup failure must stay classified as fatal"
        );
        assert!(session.shells.contains_key(sid));
        assert!(session.registry.contains(&session_id));
        assert!(matches!(
            session.shells.get(sid).map(|active| &active.phase),
            Some(ActiveShellPhase::Failed)
        ));

        drop(peer);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn runtime_events_report_shell_lifecycle_from_real_session() -> Result<()> {
        let (_temp, config) = fixture_config()?;
        let (transport, mut peer) = local_pair().await?;
        let (events, mut event_rx) = RuntimeEvents::channel();
        let mut session = Session::new(config, transport, None)?;
        session.set_events(events);

        // A freshly connected session must not fabricate success.
        assert!(
            event_rx.try_recv().is_err(),
            "fresh session must emit no events before any transition"
        );

        send_new(
            &mut session,
            &mut peer,
            "event-started-sid",
            "event-logical-user",
            STATUS_OK,
        )
        .await?;
        assert_eq!(
            event_rx.try_recv().ok(),
            Some(RuntimeEvent::ShellStarted),
            "successful owned PTY admission must emit ShellStarted"
        );

        stop_and_read_ack(
            &mut session,
            &mut peer,
            shell_stop_message("event-started-sid", None),
            STATUS_OK,
        )
        .await?;
        assert_eq!(
            event_rx.try_recv().ok(),
            Some(RuntimeEvent::ShellStopped),
            "verified cleanup must emit ShellStopped"
        );

        let cleanup_result = session.stop_all_shells().await;
        cleanup_result?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn runtime_events_do_not_claim_shell_started_on_failed_admission() -> Result<()> {
        let (_temp, config) = fixture_config()?;
        let (transport, mut peer) = local_pair().await?;
        let (events, mut event_rx) = RuntimeEvents::channel();
        let mut session = Session::new(config, transport, None)?;
        session.set_events(events);

        // An empty session id is rejected before any PTY admission.
        send_new(
            &mut session,
            &mut peer,
            "",
            "event-logical-user",
            STATUS_ERROR,
        )
        .await?;
        assert!(
            event_rx.try_recv().is_err(),
            "rejected admission must never emit ShellStarted"
        );

        let cleanup_result = session.stop_all_shells().await;
        cleanup_result?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn runtime_events_report_cleanup_failure_without_shell_stopped() -> Result<()> {
        let (_temp, config) = fixture_config()?;
        let (transport, peer) = local_pair().await?;
        let (events, mut event_rx) = RuntimeEvents::channel();
        let mut session = Session::new(config.clone(), transport, None)?;
        session.set_events(events);

        let sid = "event-cleanup-fail-sid";
        let handle = tokio::task::spawn_blocking(move || {
            Err::<(), anyhow::Error>(anyhow::anyhow!("synthetic cleanup failure"))
        });
        let _session_id = install_controlled_stop(&mut session, sid, &config, handle)?;

        assert!(
            session.stop_shell(sid).await.is_err(),
            "failed cleanup must surface a fatal error"
        );
        let mut seen_cleanup_failed = false;
        let mut seen_shell_stopped = false;
        while let Ok(event) = event_rx.try_recv() {
            match event {
                RuntimeEvent::CleanupFailed => seen_cleanup_failed = true,
                RuntimeEvent::ShellStopped => seen_shell_stopped = true,
                _ => {}
            }
        }
        assert!(
            seen_cleanup_failed,
            "actual cleanup failure must emit CleanupFailed"
        );
        assert!(
            !seen_shell_stopped,
            "failed cleanup must never emit ShellStopped"
        );
        drop(peer);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn runtime_events_report_rejected_unsupported_protocol() -> Result<()> {
        let (_temp, config) = fixture_config()?;
        let (transport, mut peer) = local_pair().await?;
        let (events, mut event_rx) = RuntimeEvents::channel();
        let mut session = Session::new(config, transport, None)?;
        session.set_events(events);

        let message = ProtoMsg {
            header: ProtoHdr {
                proto: ProtoType(0x4242),
                msg_type: "open".to_owned(),
                session_id: "event-rejected-sid".to_owned(),
                properties: BTreeMap::new(),
            },
            body: Vec::new(),
        };
        session.handle(message).await?;
        let reply = read_msg(&mut peer).await?;
        assert_eq!(reply.header.proto, ProtoType::CONTROL);
        assert_eq!(reply.header.msg_type, "error");
        assert_eq!(
            event_rx.try_recv().ok(),
            Some(RuntimeEvent::ProtocolRejected),
            "rejected inbound protocol must emit ProtocolRejected"
        );

        let cleanup_result = session.stop_all_shells().await;
        cleanup_result?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn capacity_rejection_precedes_protocol_worker_dispatch() -> Result<()> {
        let (_temp, config) = fixture_config()?;
        let (transport, mut peer) = local_pair().await?;
        let mut session = Session::new(config, transport, None)?;
        let (events, mut event_rx) = RuntimeEvents::channel();
        session.set_events(events);

        let tracked = fill_router_to_capacity(&mut session)?;

        // A brand-new SID cannot be admitted: it must be rejected at admission
        // with a fixed capacity reason before any file-transfer worker runs
        // (which would otherwise emit the disabled-feature reply).
        // Unknown cleanup messages produce no reply or new admission, even
        // with a full router. The first frame below must belong to new_sid,
        // so an error reflected from either cleanup message fails the test.
        session
            .handle(control_message("close", "untracked-close"))
            .await?;
        let mut peer_error = control_message("error", "untracked-error");
        peer_error.body = encode(&ControlError {
            close: true,
            ..ControlError::default()
        })?;
        session.handle(peer_error).await?;
        assert_eq!(
            session.router.len(),
            crate::session_router::MAX_ROUTER_SESSIONS
        );

        let new_sid = "generic-capacity-overflow-new";
        session.handle(file_transfer_message(new_sid)).await?;
        let reply = read_msg(&mut peer).await?;
        assert_eq!(reply.header.proto, ProtoType::CONTROL);
        assert_eq!(reply.header.msg_type, "error");
        assert_eq!(reply.header.session_id, new_sid);
        let error: ControlError = decode(&reply.body)?;
        assert_eq!(
            error.error, "session router capacity exceeded",
            "failed admission must report the fixed capacity reason"
        );
        assert!(!error.close);
        assert_eq!(
            event_rx.try_recv().ok(),
            Some(RuntimeEvent::ProtocolRejected),
            "failed admission must emit the fixed redacted event"
        );
        assert!(
            !session
                .router
                .contains(&SessionId::new(new_sid.to_owned())?),
            "a rejected SID must never be admitted to the router"
        );

        // An already tracked SID keeps working while the router is full: it is
        // touched and dispatched as before (a CONTROL/pong is a pure no-op).
        let existing = tracked[0].clone();
        session.handle(control_message("pong", &existing)).await?;
        assert!(
            session.router.contains(&SessionId::new(existing.clone())?),
            "tracked SIDs stay usable when the router is full"
        );
        assert!(
            event_rx.try_recv().is_err(),
            "a tracked-SID touch must not emit ProtocolRejected"
        );
        session.handle(control_message("close", &existing)).await?;
        assert!(!session.router.contains(&SessionId::new(existing)?));
        assert_eq!(
            session.router.len(),
            crate::session_router::MAX_ROUTER_SESSIONS - 1
        );

        let cleanup_result = session.stop_all_shells().await;
        cleanup_result?;
        Ok(())
    }
}
