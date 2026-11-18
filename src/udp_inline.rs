//! Experimental inline UDP forwarding path.
//!
//! This module provides a small, self-contained building block used by the
//! parent port-forwarding managers/workers. It owns a single shared UDP socket
//! plus a small amount of forwarding state (TTL deadline, closed flag) and is
//! designed to be shared across tasks via [`SharedUdp`].
//!
//! Design invariants:
//!
//! * All state mutations are serialized behind a single `std::sync::Mutex`.
//!   No guard is ever held across an `.await`.
//! * [`Attempt`] describes the outcome of an opportunistic (inline) attempt.
//!   A successful send is *only* reported when the entire datagram was accepted
//!   by the OS; partial writes are treated as a hard error and never retried.
//! * The fallback [`SharedUdp::send`] path is the only place that awaits; it
//!   still performs the actual send under the state lock via
//!   [`SharedUdp::try_forward`].
//! * Expiry, close and the TTL refresh are atomic with respect to each other
//!   because they share the same lock.
//!
//! The module intentionally contains no `unsafe` code, performs no unbounded
//! allocation and never panics on runtime input.

use std::fmt;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::Instant;

/// Maximum number of payload bytes accepted for a single datagram (inclusive).
pub(crate) const MAX_DATAGRAM: usize = 4096;

/// Default TTL applied on creation and on every successful forward.
pub(crate) const DEFAULT_TTL: Duration = Duration::from_secs(600);

/// Absolute upper bound for the fallback [`SharedUdp::send`] operation.
pub(crate) const FALLBACK_TIMEOUT: Duration = Duration::from_secs(4);

/// Internal state guarded by the shared mutex.
#[derive(Debug)]
pub(crate) struct State {
    /// Installed socket, if any. Taken on close/expiry so that the shared
    /// state no longer owns an `Arc` to the socket; existing clones owned by
    /// callers drain naturally while new sends fail.
    pub(crate) socket: Option<Arc<UdpSocket>>,
    /// Time after which the state is considered expired.
    pub(crate) deadline: Instant,
    /// Set once the state is closed or expired; terminal for this instance.
    pub(crate) closed: bool,
    /// Test-only hook: when set, the next inline attempt is reported as
    /// [`Attempt::Busy`] without touching the OS. Never compiled into
    /// non-test builds.
    #[cfg(test)]
    pub(crate) force_busy_once: bool,
}

/// Outcome of an inline forwarding attempt.
#[derive(Debug)]
pub(crate) enum Attempt {
    /// The whole datagram was accepted.
    Sent,
    /// The socket would block or the state lock was contended; retrying later
    /// (while within the deadline) is expected to be productive.
    Busy,
    /// A terminal failure happened; the caller should surface the error.
    Failed(io::Error),
}

impl fmt::Display for Attempt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Attempt::Sent => f.write_str("sent"),
            Attempt::Busy => f.write_str("busy"),
            Attempt::Failed(_) => f.write_str("failed"),
        }
    }
}

/// Shared handle to a UDP forwarding state.
///
/// Cloning is cheap; every clone refers to the same underlying [`State`].
#[derive(Clone)]
pub(crate) struct SharedUdp {
    inner: Arc<Mutex<State>>,
}

impl fmt::Debug for SharedUdp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.inner.lock() {
            Ok(state) => f
                .debug_struct("SharedUdp")
                .field("installed", &state.socket.is_some())
                .field("closed", &state.closed)
                .field("deadline", &state.deadline)
                .finish(),
            Err(_) => f
                .debug_struct("SharedUdp")
                .field("poisoned", &true)
                .finish(),
        }
    }
}

fn poisoned_err() -> io::Error {
    io::Error::other("udp_inline state mutex poisoned")
}

fn closed_err() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "udp_inline state is closed")
}

/// Map a non-blocking send result to an [`Attempt`], consuming any pending
/// test hook flag.
///
/// This helper is deliberately pure: it does not touch the socket, which makes
/// the classification (full/partial/error) unit-testable without depending on
/// the Tokio implementation details of `try_send`.
fn classify_send_result(result: io::Result<usize>, len: usize) -> Attempt {
    match result {
        Ok(sent) if sent == len => Attempt::Sent,
        Ok(sent) if sent < len => Attempt::Failed(io::Error::new(
            io::ErrorKind::WriteZero,
            format!("partial udp datagram write: {sent} of {len} bytes"),
        )),
        // Larger-than-requested results are impossible for UDP; treat any
        // mismatch as terminal rather than retrying.
        Ok(_) => Attempt::Failed(io::Error::new(
            io::ErrorKind::InvalidData,
            "udp send reported more bytes than requested",
        )),
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => Attempt::Busy,
        Err(err) => Attempt::Failed(err),
    }
}

impl SharedUdp {
    /// Create a fresh handle without an installed socket.
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(State {
                socket: None,
                deadline: Instant::now() + DEFAULT_TTL,
                closed: false,
                #[cfg(test)]
                force_busy_once: false,
            })),
        }
    }

    /// Install the socket owned by this forwarding state.
    ///
    /// Fails if the state is closed or a socket is already installed, so a
    /// second install can never silently replace a live socket.
    pub(crate) fn install(&self, socket: Arc<UdpSocket>) -> io::Result<()> {
        let mut guard = self.inner.lock().map_err(|_| poisoned_err())?;
        if guard.closed {
            return Err(closed_err());
        }
        if guard.socket.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "udp_inline socket already installed",
            ));
        }
        let candidate = Instant::now() + DEFAULT_TTL;
        guard.deadline = guard.deadline.max(candidate);
        guard.socket = Some(socket);
        Ok(())
    }

    /// Synchronously close the state and release the socket.
    ///
    /// Idempotent. Recovers from poisoning on purpose: closing is a cleanup
    /// operation and must not fail. Other operations surface poison errors.
    pub(crate) fn close(&self) {
        let mut guard = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poison) => poison.into_inner(),
        };
        guard.closed = true;
        let _taken = guard.socket.take();
    }

    /// Return the current validated deadline without mutating state.
    pub(crate) fn deadline(&self) -> io::Result<Instant> {
        let guard = self.inner.lock().map_err(|_| poisoned_err())?;
        if guard.closed {
            return Err(closed_err());
        }
        Ok(guard.deadline)
    }

    /// Extend the deadline to `now + DEFAULT_TTL` if it is still live and a
    /// socket is installed. Never resurrects a closed state.
    pub(crate) fn refresh(&self) -> io::Result<()> {
        let mut guard = self.inner.lock().map_err(|_| poisoned_err())?;
        if guard.closed || guard.socket.is_none() {
            return Err(closed_err());
        }
        let candidate = Instant::now() + DEFAULT_TTL;
        guard.deadline = guard.deadline.max(candidate);
        Ok(())
    }

    /// Atomically expire the state when the deadline has passed.
    ///
    /// Returns `true` when the state is now closed. An already-closed state
    /// also reports `true` so the caller can stop cleanly.
    pub(crate) fn expire(&self) -> io::Result<bool> {
        let mut guard = self.inner.lock().map_err(|_| poisoned_err())?;
        if guard.closed {
            return Ok(true);
        }
        if Instant::now() >= guard.deadline {
            guard.closed = true;
            let _taken = guard.socket.take();
            return Ok(true);
        }
        Ok(false)
    }

    /// Opportunistic, fully synchronous forwarding attempt.
    ///
    /// The state lock is held for the entire operation, serializing inline
    /// sends, expiry decisions and close. The lock is never held across an
    /// `.await` because this function does not await.
    pub(crate) fn try_forward(&self, data: &[u8]) -> Attempt {
        if data.len() > MAX_DATAGRAM {
            return Attempt::Failed(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "udp datagram of {} bytes exceeds limit of {MAX_DATAGRAM}",
                    data.len()
                ),
            ));
        }

        let mut guard = match self.inner.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::WouldBlock) => return Attempt::Busy,
            Err(std::sync::TryLockError::Poisoned(_)) => return Attempt::Failed(poisoned_err()),
        };

        #[cfg(test)]
        if guard.force_busy_once {
            guard.force_busy_once = false;
            return Attempt::Busy;
        }

        if guard.closed {
            return Attempt::Failed(closed_err());
        }

        if Instant::now() >= guard.deadline {
            guard.closed = true;
            let _taken = guard.socket.take();
            return Attempt::Failed(io::Error::new(
                io::ErrorKind::TimedOut,
                "udp_inline deadline expired",
            ));
        }

        let socket = match guard.socket.as_ref() {
            Some(socket) => Arc::clone(socket),
            None => {
                return Attempt::Failed(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "udp_inline socket not installed",
                ));
            }
        };

        let result = socket.try_send(data);
        let outcome = classify_send_result(result, data.len());

        if let Attempt::Sent = outcome {
            let candidate = Instant::now() + DEFAULT_TTL;
            guard.deadline = guard.deadline.max(candidate);
        }

        outcome
    }

    /// Fallback path used *only* by the worker when the manager reports
    /// in-flight work. Owns an absolute 4 second budget for the whole
    /// operation.
    ///
    /// The socket clone is obtained under a brief guard and awaited outside of
    /// it; the actual datagram is then sent through [`SharedUdp::try_forward`]
    /// so TTL/expiry semantics stay identical to the inline path.
    pub(crate) async fn send(&self, data: &[u8]) -> io::Result<()> {
        if data.len() > MAX_DATAGRAM {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "udp datagram of {} bytes exceeds limit of {MAX_DATAGRAM}",
                    data.len()
                ),
            ));
        }

        let started = Instant::now();
        let op_deadline = started + FALLBACK_TIMEOUT;

        loop {
            if Instant::now() >= op_deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "udp_inline fallback send timed out",
                ));
            }

            // Obtain a socket clone under a brief, validated guard. The guard
            // is dropped before any await.
            let socket = {
                let guard = self.inner.lock().map_err(|_| poisoned_err())?;
                if guard.closed {
                    return Err(closed_err());
                }
                match guard.socket.as_ref() {
                    Some(socket) => Arc::clone(socket),
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "udp_inline socket not installed",
                        ));
                    }
                }
            };

            match self.try_forward(data) {
                Attempt::Sent => return Ok(()),
                Attempt::Failed(err) => return Err(err),
                Attempt::Busy => {
                    let remaining = op_deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "udp_inline fallback send timed out",
                        ));
                    }
                    // Wait for writability, bounded by the absolute budget.
                    // Both I/O errors and the timeout are terminal so the
                    // loop can never spin without making progress.
                    match tokio::time::timeout_at(op_deadline, socket.writable()).await {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => return Err(err),
                        Err(_) => {
                            return Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "udp_inline fallback send timed out",
                            ));
                        }
                    }
                    let _ = remaining;
                    tokio::task::yield_now().await;
                }
            }
        }
    }

    /// Test-only helper installing the single-shot busy hook.
    #[cfg(test)]
    pub(crate) fn force_busy_once(&self) -> io::Result<()> {
        let mut guard = self.inner.lock().map_err(|_| poisoned_err())?;
        guard.force_busy_once = true;
        Ok(())
    }
}

/// RAII guard that closes the shared state on drop.
///
/// Used by the worker inside its main loop so that terminal events and local
/// reads observe a closed socket before the owned socket handle is released.
pub(crate) struct CloseOnDrop {
    shared: SharedUdp,
}

impl CloseOnDrop {
    /// Create a closing guard from a cheap clone of the shared handle.
    pub(crate) fn new(shared: SharedUdp) -> Self {
        Self { shared }
    }
}

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        self.shared.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    // Native IPv6 loopback keeps these datagrams on Linux `lo`; WSL's
    // 127.0.0.1 bridge drops payloads near/above the 1500-byte MTU.
    async fn loopback_pair() -> (Arc<UdpSocket>, UdpSocket, SocketAddr) {
        let receiver = UdpSocket::bind("[::1]:0").await.expect("bind receiver");
        let addr = receiver.local_addr().expect("receiver addr");
        let sender = UdpSocket::bind("[::1]:0").await.expect("bind sender");
        (Arc::new(sender), receiver, addr)
    }

    async fn connected_socket() -> (Arc<UdpSocket>, UdpSocket) {
        let (sender, receiver, addr) = loopback_pair().await;
        sender.connect(addr).await.expect("connect sender");
        sender.writable().await.expect("sender writable");
        (sender, receiver)
    }

    #[tokio::test]
    async fn new_state_has_no_socket_and_is_open() {
        let shared = SharedUdp::new();
        let guard = shared.inner.lock().expect("lock");
        assert!(guard.socket.is_none());
        assert!(!guard.closed);
        drop(guard);
        assert!(shared.deadline().is_ok());
    }

    #[tokio::test]
    async fn zero_and_max_datagrams_are_sent_exactly_once() {
        let (socket, receiver) = connected_socket().await;
        let shared = SharedUdp::new();
        shared.install(Arc::clone(&socket)).expect("install");

        assert!(matches!(shared.try_forward(&[]), Attempt::Sent));

        let payload = vec![0xABu8; MAX_DATAGRAM];
        assert!(matches!(shared.try_forward(&payload), Attempt::Sent));

        let mut buf = vec![0u8; MAX_DATAGRAM + 16];

        let n = tokio::time::timeout(Duration::from_secs(1), receiver.recv(&mut buf))
            .await
            .expect("recv empty timed out")
            .expect("recv empty");
        assert_eq!(n, 0);

        let n = tokio::time::timeout(Duration::from_secs(1), receiver.recv(&mut buf))
            .await
            .expect("recv max timed out")
            .expect("recv max");
        assert_eq!(n, MAX_DATAGRAM);
        assert_eq!(&buf[..n], payload.as_slice());

        // No third datagram was produced by a retry.
        let extra = tokio::time::timeout(Duration::from_millis(50), receiver.recv(&mut buf)).await;
        assert!(extra.is_err(), "unexpected extra datagram");
    }

    #[tokio::test]
    async fn oversized_datagram_is_rejected_without_send() {
        let (socket, receiver) = connected_socket().await;
        let shared = SharedUdp::new();
        shared.install(socket).expect("install");

        let payload = vec![0u8; MAX_DATAGRAM + 1];
        match shared.try_forward(&payload) {
            Attempt::Failed(err) => assert_eq!(err.kind(), io::ErrorKind::InvalidInput),
            other => panic!("unexpected outcome: {other}"),
        }

        let mut buf = vec![0u8; 64];
        let extra = tokio::time::timeout(Duration::from_millis(50), receiver.recv(&mut buf)).await;
        assert!(extra.is_err(), "oversized datagram must not be sent");
    }

    #[tokio::test]
    async fn install_twice_is_rejected() {
        let (socket, _receiver) = connected_socket().await;
        let shared = SharedUdp::new();
        shared.install(Arc::clone(&socket)).expect("first install");
        let err = shared
            .install(Arc::clone(&socket))
            .expect_err("second install must fail");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[tokio::test]
    async fn close_is_idempotent_and_blocks_further_sends() {
        let (socket, _receiver) = connected_socket().await;
        let shared = SharedUdp::new();
        shared.install(socket).expect("install");

        shared.close();
        shared.close();

        assert!(shared.inner.lock().expect("lock").socket.is_none());
        assert_eq!(
            shared.deadline().expect_err("closed").kind(),
            io::ErrorKind::BrokenPipe
        );
        assert!(matches!(shared.try_forward(b"x"), Attempt::Failed(_)));
        assert!(shared.refresh().is_err());
        assert!(shared.expire().expect("expire"));
        let err = shared.install(Arc::new(
            UdpSocket::bind("127.0.0.1:0").await.expect("bind"),
        ));
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn expire_respects_updated_deadline_after_inline_success() {
        let (socket, _receiver) = connected_socket().await;
        let shared = SharedUdp::new();
        shared.install(socket).expect("install");
        tokio::time::pause();

        let old_deadline = shared.deadline().expect("deadline");

        // Advance most of the way to the original deadline only.
        tokio::time::advance(DEFAULT_TTL - Duration::from_secs(60)).await;
        assert!(!shared.expire().expect("expire before inline"));

        // Inline success pushes the deadline forward.
        assert!(matches!(shared.try_forward(b"keepalive"), Attempt::Sent));
        let new_deadline = shared.deadline().expect("deadline");
        assert!(new_deadline >= old_deadline);

        // Crossing the *old* deadline must no longer expire the state.
        tokio::time::advance(Duration::from_secs(120)).await;
        assert!(Instant::now() >= old_deadline);
        assert!(!shared.expire().expect("expire after inline"));

        // But the refreshed deadline still expires eventually.
        tokio::time::advance(DEFAULT_TTL).await;
        assert!(shared.expire().expect("expire after refresh"));
        assert!(matches!(shared.try_forward(b"late"), Attempt::Failed(_)));
    }

    #[tokio::test]
    async fn expired_try_forward_closes_atomically() {
        let (socket, _receiver) = connected_socket().await;
        let shared = SharedUdp::new();
        shared.install(socket).expect("install");
        tokio::time::pause();

        tokio::time::advance(DEFAULT_TTL + Duration::from_secs(1)).await;

        match shared.try_forward(b"late") {
            Attempt::Failed(err) => assert_eq!(err.kind(), io::ErrorKind::TimedOut),
            other => panic!("unexpected outcome: {other}"),
        }

        let guard = shared.inner.lock().expect("lock");
        assert!(guard.closed);
        assert!(guard.socket.is_none());
    }

    #[tokio::test]
    async fn close_on_drop_fences_state() {
        let (socket, _receiver) = connected_socket().await;
        let shared = SharedUdp::new();
        shared.install(socket).expect("install");

        {
            let _guard = CloseOnDrop::new(shared.clone());
        }

        let guard = shared.inner.lock().expect("lock");
        assert!(guard.closed);
        assert!(guard.socket.is_none());
        drop(guard);

        assert!(matches!(shared.try_forward(b"x"), Attempt::Failed(_)));
    }

    #[test]
    fn classify_full_partial_and_error() {
        assert!(matches!(classify_send_result(Ok(4), 4), Attempt::Sent));
        assert!(matches!(classify_send_result(Ok(0), 0), Attempt::Sent));

        match classify_send_result(Ok(2), 4) {
            Attempt::Failed(err) => assert_eq!(err.kind(), io::ErrorKind::WriteZero),
            other => panic!("unexpected outcome: {other}"),
        }

        assert!(matches!(
            classify_send_result(Err(io::Error::from(io::ErrorKind::WouldBlock)), 4),
            Attempt::Busy
        ));

        match classify_send_result(Err(io::Error::from(io::ErrorKind::ConnectionRefused)), 4) {
            Attempt::Failed(err) => assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused),
            other => panic!("unexpected outcome: {other}"),
        }
    }

    #[tokio::test]
    async fn forced_busy_hook_returns_busy_once() {
        let (socket, receiver) = connected_socket().await;
        let shared = SharedUdp::new();
        shared.install(socket).expect("install");

        shared.force_busy_once().expect("hook");
        assert!(matches!(shared.try_forward(b"hello"), Attempt::Busy));

        // Hook is single-shot; the next attempt really sends.
        assert!(matches!(shared.try_forward(b"hello"), Attempt::Sent));

        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(1), receiver.recv(&mut buf))
            .await
            .expect("recv timed out")
            .expect("recv");
        assert_eq!(&buf[..n], b"hello");
    }

    #[tokio::test]
    async fn fallback_send_succeeds_through_busy_hook() {
        let (socket, receiver) = connected_socket().await;
        let shared = SharedUdp::new();
        shared.install(socket).expect("install");
        shared.force_busy_once().expect("hook");

        shared.send(b"fallback").await.expect("fallback send");

        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(1), receiver.recv(&mut buf))
            .await
            .expect("recv timed out")
            .expect("recv");
        assert_eq!(&buf[..n], b"fallback");
    }

    #[tokio::test]
    async fn fallback_send_fails_when_closed() {
        let (socket, _receiver) = connected_socket().await;
        let shared = SharedUdp::new();
        shared.install(socket).expect("install");
        shared.close();

        let err = shared.send(b"x").await.expect_err("closed");
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn fallback_send_times_out_without_socket() {
        let shared = SharedUdp::new();
        let err = shared.send(b"x").await.expect_err("no socket");
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);
    }

    #[tokio::test]
    async fn refresh_never_resurrects_closed_state() {
        let (socket, _receiver) = connected_socket().await;
        let shared = SharedUdp::new();
        shared.install(socket).expect("install");
        shared.close();
        assert!(shared.refresh().is_err());
        assert!(shared.inner.lock().expect("lock").closed);
    }
}
