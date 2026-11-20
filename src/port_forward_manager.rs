//! Bounded manager that owns port-forward socket workers.
//!
//! The manager keeps a small, capacity-limited map of active connections. Each
//! connection is driven by exactly one worker task (see
//! [`crate::port_forward_worker`]) whose `JoinHandle` is owned here, so the
//! manager can deterministically abort and await every worker on close or drop.
//!
//! All inter-task traffic is bounded: worker commands use a small channel and
//! worker output funnels through one shared manager event channel. The
//! dispatcher never blocks on a full command queue (`try_send`); instead it
//! retains at most one command while that worker's bounded queue is full.
//!
//! Backpressure limits are explicit: while one command is retained, the driver
//! pauses *all* port-forward inbound handling until admission succeeds, so the
//! shared WS inbound stream is head-of-line blocked across sessions. Sockets
//! into workers, worker output for already-produced frames, authentication,
//! shutdown and timers keep running because the manager never holds an async
//! lock across an unrelated receive. Unrelated *inbound* port-forward traffic is
//! therefore delayed, not serviced concurrently.
//!
//! Each worker also bounds socket reads per write budget, so a fast peer cannot
//! make a worker queue unboundedly many frames.
//!
//! Event hand-off is cancellation-safe: an event dequeued from the shared
//! channel is stored in a manager-owned field before any `await`, so canceling
//! `next_message`/`next_event` never loses a frame even when a `tokio::select!`
//! reserve branch wins. At most one dequeued event plus one pending command are
//! retained; neither buffer grows.
//!
//! The public driver methods ([`PortForwardManager::handle`],
//! [`PortForwardManager::next_message`], [`PortForwardManager::close_session`]
//! and [`PortForwardManager::close_all`]) take `&mut self`, so safe Rust cannot
//! drive a single manager from concurrent consumers while the reaper also runs.
//! This makes the serialized-driver invariant an API guarantee rather than a
//! documentation-only convention.
//!
//! Worker retirement is cancellation-safe: a worker handle stays inside its map
//! entry until it has actually been awaited to completion. A canceled
//! `next_message` or close future therefore never detaches an aborted worker or
//! loses a terminal frame that was already produced by the worker.

use std::collections::HashMap;
use std::time::Duration;

use std::io;

use anyhow::{Result, anyhow};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

use crate::port_forward::{ConnectionKey, ForwardRequest, Network, error_reply, parse};
use crate::port_forward_worker::{self, Command, Event};
use crate::protocol::{ProtoHdr, ProtoMsg, ProtoType};
use crate::udp_inline::{Attempt, SharedUdp};

/// Maximum number of simultaneously tracked connections.
const MAX_ENTRIES: usize = 16;
/// Per-connection command queue depth.
const COMMAND_CAPACITY: usize = 8;
/// Shared manager event queue depth.
const EVENT_CAPACITY: usize = 64;
/// Bounded maintenance interval used while waiting for a worker event so that a
/// completion that races past `is_finished` observation can still be reaped.
const MAINTENANCE_TICK: Duration = Duration::from_millis(100);

/// Connection lifecycle phase, tracked explicitly instead of by inspecting the
/// textual body of worker messages.
#[derive(Clone, Copy)]
enum Phase {
    /// Worker spawned; the socket has not yet acknowledged a successful connect.
    Connecting,
    /// Worker delivered the new acknowledgement and the socket is established.
    Established,
    /// Worker is being retired; its handle remains owned by the entry until an
    /// await completes, making retirement cancellation-safe.
    Retiring,
}

/// One tracked connection: its generation, lifecycle phase, command sender and
/// owned task.
struct Entry {
    tcp_frame_size: Option<usize>,
    generation: u64,
    phase: Phase,
    commands: mpsc::Sender<Command>,
    handle: JoinHandle<()>,
    /// Terminal frame saved before awaiting an aborted worker.
    pending_message: Option<ProtoMsg>,
    /// Managed shared UDP state for v1 UDP connections. Closed before the
    /// worker is aborted so inline attempts fail rather than race a dead socket.
    udp_inline: Option<SharedUdp>,
    /// Number of legacy `forward`/`FailForward` commands accepted for this
    /// managed UDP worker that the worker has not yet observed via a consumed
    /// `ack`. Bounds outstanding outbound forwards conservatively.
    legacy_forwards: usize,
}

/// Mutable manager state guarded by an async mutex.
struct Inner {
    entries: HashMap<ConnectionKey, Entry>,
    generation: u64,
}

/// A single parsed command retained because its target worker's bounded queue
/// was momentarily full. The manager owns at most one such command; while it
/// exists the driver must stop feeding new input and call
/// [`PortForwardManager::next_event`] until admission no longer applies.
///
/// The stored `key` and `generation` pin the exact worker the command was
/// destined for, so a retained command can never be routed to a replacement
/// worker that reused the same key.
struct PendingCommand {
    key: ConnectionKey,
    generation: u64,
    command: Command,
}

/// Owns and supervises all port-forward workers.
pub struct PortForwardManager {
    allowed_destinations: Option<Vec<crate::config::ForwardDestination>>,
    inner: Mutex<Inner>,
    /// Manager-side sender kept alive so the event channel never closes merely
    /// because no workers currently exist.
    event_tx: mpsc::Sender<Event>,
    events: Mutex<mpsc::Receiver<Event>>,
    /// At most one command retained across a full command queue. Held outside
    /// the async `inner` lock so `next_event` can wait on admission without
    /// blocking unrelated manager state.
    pending: Option<PendingCommand>,
    /// At most one worker event dequeued from the shared channel but not yet
    /// processed. Stored here (manager-owned, not future-local) so that the
    /// cancellation window between `recv()` and the `inner` lock cannot drop an
    /// event: `next_message` always processes a retained event before polling
    /// the channel again, and it is only cleared in the same poll that either
    /// returns it or installs its outcome in an owned entry.
    dequeued_event: Option<Event>,
}

impl PortForwardManager {
    pub fn new() -> Self {
        Self::with_allowed_destinations(None)
    }

    pub fn with_allowed_destinations(
        allowed_destinations: Option<Vec<crate::config::ForwardDestination>>,
    ) -> Self {
        let (event_tx, event_rx) = mpsc::channel(EVENT_CAPACITY);
        Self {
            allowed_destinations,
            inner: Mutex::new(Inner {
                entries: HashMap::new(),
                generation: 0,
            }),
            event_tx,
            events: Mutex::new(event_rx),
            pending: None,
            dequeued_event: None,
        }
    }

    /// Handle one inbound protocol message, returning any immediate replies.
    ///
    /// Takes `&mut self` so callers hold exclusive manager access; concurrent
    /// drivers cannot race the maintenance reaper.
    pub async fn handle(&mut self, message: ProtoMsg) -> Result<Vec<ProtoMsg>> {
        // A retained command means a previous dispatch hit a full queue. The
        // driver must drain admission through `next_event` before feeding more
        // input; overwriting the pending command would silently drop it.
        if self.pending.is_some() {
            return Err(anyhow!(
                "port forward handle called while a command is pending; driver must call next_event first"
            ));
        }

        let header = message.header.clone();
        let request = match parse(message) {
            Ok(request) => request,
            Err(err) => return Ok(vec![error_reply(&header, &err.to_string())?]),
        };

        let mut inner = self.inner.lock().await;

        // Reap finished workers before duplicate/capacity decisions so stale
        // entries cannot block new connections. `reap_locked` only removes
        // tasks when the shared queue is already drained, so queued terminal
        // messages are never discarded.
        if let Some(err) = self.reap_locked(&mut inner).await {
            return Err(err);
        }
        if let Some(err) = finish_quiet_retirements(&mut inner).await {
            return Err(err);
        }

        let out = match request {
            ForwardRequest::New {
                key,
                network,
                host,
                port,
                tcp_frame_size,
            } => {
                if let Some(allowed) = &self.allowed_destinations {
                    let ip = host.parse::<std::net::IpAddr>().ok();
                    if !allowed.iter().any(|rule| {
                        Some(rule.address) == ip
                            && rule.protocol == network
                            && rule.port.get() == port
                    }) {
                        return Ok(vec![error_reply(
                            &header,
                            "destination denied by device policy",
                        )?]);
                    }
                }
                let retiring = inner
                    .entries
                    .get(&key)
                    .map(|entry| matches!(entry.phase, Phase::Retiring))
                    .unwrap_or(false);
                if retiring {
                    // A same-key retry invalidates any saved terminal frame and
                    // joins the aborted worker before the key may be reused.
                    begin_retirement(&mut inner, &key, None);
                    finish_retirement(&mut inner, &key).await?;
                }

                if inner.entries.contains_key(&key) {
                    vec![error_reply(&header, "connection already exists")?]
                } else if inner.entries.len() >= MAX_ENTRIES {
                    vec![error_reply(&header, "connection capacity reached")?]
                } else {
                    let generation = match inner.generation.checked_add(1) {
                        Some(next) => next,
                        None => return Err(anyhow!("port forward generation exhausted")),
                    };
                    inner.generation = generation;
                    let (commands, command_rx) = mpsc::channel(COMMAND_CAPACITY);
                    // Only v1 UDP connections get an inline-capable shared
                    // socket; every other proto/network keeps `None`.
                    let shared = if matches!(network, Network::Udp)
                        && matches!(key.proto(), ProtoType::PORT_FORWARD)
                    {
                        Some(SharedUdp::new())
                    } else {
                        None
                    };
                    let mode = match (shared.clone(), tcp_frame_size) {
                        (Some(udp), _) => port_forward_worker::WorkerMode::ManagedUdp(udp),
                        (None, Some(size)) => port_forward_worker::WorkerMode::LargeTcp(size),
                        (None, None) => port_forward_worker::WorkerMode::Standard,
                    };
                    let handle = tokio::spawn(port_forward_worker::run_inner(
                        key.clone(),
                        generation,
                        network,
                        host,
                        port,
                        command_rx,
                        self.event_tx.clone(),
                        mode,
                    ));
                    inner.entries.insert(
                        key,
                        Entry {
                            tcp_frame_size,
                            generation,
                            phase: Phase::Connecting,
                            commands,
                            handle,
                            pending_message: None,
                            udp_inline: shared,
                            legacy_forwards: 0,
                        },
                    );
                    // The real "new" acknowledgement is emitted by the worker
                    // once the socket has actually connected.
                    Vec::new()
                }
            }
            ForwardRequest::Forward { key, body } => {
                if body.len() > crate::port_forward::V2_MAX_FORWARD_BODY
                    && !inner
                        .entries
                        .get(&key)
                        .and_then(|entry| entry.tcp_frame_size)
                        .is_some_and(|size| body.len() <= size)
                {
                    return Ok(vec![error_reply(&header, "forward body too large")?]);
                }
                // Fast inline path: an established managed UDP worker with no
                // outstanding legacy forward can accept the datagram directly.
                let inline = match inner.entries.get(&key) {
                    Some(entry)
                        if matches!(entry.phase, Phase::Established)
                            && entry.legacy_forwards == 0 =>
                    {
                        entry.udp_inline.clone()
                    }
                    _ => None,
                };
                match inline {
                    Some(shared) => match shared.try_forward(&body) {
                        // The datagram was fully written; return the ack with no
                        // further await so no future-local ack can be lost.
                        Attempt::Sent => {
                            return Ok(vec![key.message("ack", Vec::new())]);
                        }
                        // Busy: fall back to the legacy queued command path.
                        Attempt::Busy => {
                            dispatch_legacy_forward(
                                &mut inner,
                                &mut self.pending,
                                &header,
                                &key,
                                Command::Forward(body),
                            )
                            .await?
                        }
                        // Hard/partial failure: never retry the datagram; report
                        // a typed `forward` error through the worker instead.
                        Attempt::Failed(err) => {
                            let reason = if err.kind() == io::ErrorKind::WriteZero {
                                "partial udp datagram write"
                            } else {
                                "inline udp socket write failed"
                            };
                            dispatch_legacy_forward(
                                &mut inner,
                                &mut self.pending,
                                &header,
                                &key,
                                Command::FailForward(reason),
                            )
                            .await?
                        }
                    },
                    None => {
                        dispatch_legacy_forward(
                            &mut inner,
                            &mut self.pending,
                            &header,
                            &key,
                            Command::Forward(body),
                        )
                        .await?
                    }
                }
            }
            ForwardRequest::Ack { key, count } => {
                dispatch(
                    &mut inner,
                    &mut self.pending,
                    &header,
                    &key,
                    Command::Ack(count),
                )
                .await?
            }
            ForwardRequest::HalfClose { key } => {
                dispatch(
                    &mut inner,
                    &mut self.pending,
                    &header,
                    &key,
                    Command::HalfClose,
                )
                .await?
            }
            ForwardRequest::Stop { key } => stop_connection(&mut inner, &header, &key).await?,
        };

        if let Some(err) = self.reap_locked(&mut inner).await {
            return Err(err);
        }
        Ok(out)
    }

    /// Produce the next outbound protocol message from any worker.
    ///
    /// Takes `&mut self` so the event receiver is only polled through exclusive
    /// manager access, preventing a concurrent `next_message`/`handle` caller
    /// from racing the reaper over an already-popped event.
    ///
    /// Cancellation-safe: any worker whose handle is being awaited stays owned
    /// by its entry, and a saved terminal frame is only removed in the same poll
    /// that returns it, so a dropped future cannot lose a frame.
    ///
    /// Output-only: this method never services a retained command. A driver that
    /// may hit command backpressure must call [`Self::next_event`] so a pending
    /// command is admitted; calling only `next_message` would leave it stranded.
    ///
    /// Event retention: an event dequeued from the shared channel is stored in
    /// [`Self::dequeued_event`] before any `await`, so a canceled call can never
    /// lose it. A retained event is processed before new events are polled.
    pub async fn next_message(&mut self) -> Result<ProtoMsg> {
        loop {
            // Resume an in-progress retirement first. Awaiting the borrow in the
            // map keeps the handle owned here, so if this future is canceled the
            // aborted worker and any saved terminal frame remain for a later call.
            {
                let mut inner = self.inner.lock().await;
                let retiring = inner
                    .entries
                    .iter()
                    .find(|(_, entry)| matches!(entry.phase, Phase::Retiring))
                    .map(|(key, _)| key.clone());
                if let Some(key) = retiring {
                    match finish_retirement(&mut inner, &key).await {
                        Ok(Some(message)) => return Ok(message),
                        Ok(None) => continue,
                        Err(err) => return Err(err),
                    }
                }

                // Reap finished workers only while the queue is drained, so a
                // terminal event that was dropped because the queue was full never
                // discards queued messages. Finished workers cannot enqueue more
                // events, so checking emptiness after observing completion is safe.
                if let Some(err) = self.reap_locked(&mut inner).await {
                    return Err(err);
                }
            }

            // Retain dequeued work across every await, including cooperative
            // yields on an otherwise uncontended mutex.
            if self.dequeued_event.is_none() {
                let mut events = self.events.lock().await;
                let wake = tokio::select! {
                    biased;
                    maybe = events.recv() => Wake::Event(maybe),
                    _ = tokio::time::sleep(MAINTENANCE_TICK) => Wake::Tick,
                };
                match wake {
                    Wake::Tick => continue,
                    Wake::Event(None) => {
                        return Err(anyhow!("port forward event channel closed"));
                    }
                    Wake::Event(Some(event)) => {
                        self.dequeued_event = Some(event);
                        continue;
                    }
                }
            }

            let mut inner = self.inner.lock().await;
            // No await may occur between taking an ordinary data event and
            // returning it. Terminal paths first save ownership in the entry.
            let Some(event) = self.dequeued_event.take() else {
                continue;
            };

            match event {
                Event::Message {
                    key,
                    generation,
                    message,
                } => {
                    let current = inner.entries.get(&key).map(|entry| entry.generation);
                    if current != Some(generation) {
                        // Stale (stopped or reused key): discard and continue.
                        self.dequeued_event = None;
                        continue;
                    }
                    if inner
                        .entries
                        .get(&key)
                        .map(|entry| matches!(entry.phase, Phase::Retiring))
                        .unwrap_or(false)
                    {
                        // Retirement owns the terminal outcome; ignore events
                        // that were already queued before the worker was aborted.
                        self.dequeued_event = None;
                        continue;
                    }

                    let is_stop = message.header.msg_type == "stop";
                    let is_error = message.header.msg_type == "error";

                    if is_stop {
                        // Remote socket EOF: the worker drops the socket before
                        // enqueuing the stop. Retire the current generation now
                        // so a same-key `new` can succeed even if the trailing
                        // `Finished` has not yet been consumed. A later `Finished`
                        // is then stale and cannot delete a replacement generation.
                        // The terminal frame is stored in the entry before the
                        // first await inside `begin_retirement`.
                        begin_retirement(&mut inner, &key, Some(message.clone()));
                        self.dequeued_event = None;
                        finish_retirement(&mut inner, &key).await?;
                        return Ok(message);
                    }

                    let connecting = inner
                        .entries
                        .get(&key)
                        .map(|entry| matches!(entry.phase, Phase::Connecting))
                        .unwrap_or(false);
                    if connecting {
                        if is_error {
                            // Connect failure before the new acknowledgement is
                            // terminal: save the frame before awaiting so the
                            // client may retry with the same key immediately.
                            begin_retirement(&mut inner, &key, Some(message.clone()));
                            self.dequeued_event = None;
                            finish_retirement(&mut inner, &key).await?;
                            return Ok(message);
                        }
                        // First non-error message is the worker's new ack.
                        if let Some(entry) = inner.entries.get_mut(&key) {
                            entry.phase = Phase::Established;
                        }
                    }

                    // A v1 ack from a managed UDP worker means the worker has
                    // consumed one legacy outbound forward: release one credit.
                    // Only validated (generation + non-retiring + managed) acks
                    // count; nothing else may decrement the counter. A decrement
                    // without a matching queued forward violates the invariant
                    // and is surfaced as an error instead of being hidden.
                    if message.header.msg_type == "ack"
                        && matches!(message.header.proto, ProtoType::PORT_FORWARD)
                        && let Some(entry) = inner.entries.get_mut(&key)
                        && entry.udp_inline.is_some()
                    {
                        entry.legacy_forwards = entry
                            .legacy_forwards
                            .checked_sub(1)
                            .ok_or_else(|| anyhow!("managed UDP ACK without queued forward"))?;
                    }

                    // Established messages are forwarded as-is. An established
                    // error does not retire the entry so that a following stop
                    // notification still reaches the peer. No await occurs
                    // after taking the retained event.
                    self.dequeued_event = None;
                    return Ok(message);
                }
                Event::Finished { key, generation } => {
                    let matches =
                        inner.entries.get(&key).map(|entry| entry.generation) == Some(generation);
                    self.dequeued_event = None;
                    if matches {
                        // Never overwrite a saved terminal frame with an
                        // unrelated trailing `Finished`; keep the handle in the
                        // map until it has actually been awaited.
                        let already_pending = inner
                            .entries
                            .get(&key)
                            .map(|entry| {
                                matches!(entry.phase, Phase::Retiring)
                                    && entry.pending_message.is_some()
                            })
                            .unwrap_or(false);
                        if !already_pending {
                            begin_retirement(&mut inner, &key, None);
                        }
                        match finish_retirement(&mut inner, &key).await {
                            Ok(Some(message)) => return Ok(message),
                            Ok(None) => {}
                            Err(err) => return Err(err),
                        }
                    }
                }
            }
        }
    }

    /// Whether new inbound protocol messages may be handed to [`Self::handle`].
    ///
    /// Returns `false` while a command is retained because a worker queue was
    /// momentarily full. The driver must service admission with
    /// [`Self::next_event`] before feeding more input; calling [`Self::handle`]
    /// while this is `false` returns a usage error rather than dropping data.
    pub fn accepts_input(&self) -> bool {
        self.pending.is_none()
    }

    /// Drive either a pending admission or the next outbound worker message.
    ///
    /// Returns `Some(message)` when a wire frame is available (exactly like
    /// [`Self::next_message`]). Returns `None` when a retained command was
    /// admitted or discarded (stale/closed entry), signalling that the driver
    /// should re-evaluate input gating via [`Self::accepts_input`] even though
    /// no worker produced output.
    ///
    /// Cancellation-safe: neither the pending command nor its target entry is
    /// removed before the command is actually sent, so dropping this future
    /// (e.g. `select!` cancellation) never loses a retained command.
    pub async fn next_event(&mut self) -> Result<Option<ProtoMsg>> {
        // No retained command: behave exactly like the output-only API.
        if self.pending.is_none() {
            return self.next_message().await.map(Some);
        }

        // Snapshot a clone of the exact worker's sender under a brief lock. The
        // pending command itself is left untouched so cancellation loses nothing.
        let sender = {
            let inner = self.inner.lock().await;
            match self.pending.as_ref() {
                Some(pending) => match inner.entries.get(&pending.key) {
                    Some(entry)
                        if !matches!(entry.phase, Phase::Retiring)
                            && entry.generation == pending.generation =>
                    {
                        Some(entry.commands.clone())
                    }
                    _ => None,
                },
                None => None,
            }
        };

        // No matching live worker (entry removed, retired, or generation
        // replaced): drop the now-unroutable command and rearm driver reads.
        let sender = match sender {
            Some(sender) => sender,
            None => {
                self.pending = None;
                return Ok(None);
            }
        };

        // Wait for either an admission slot on the pinned worker or unrelated
        // worker output. Neither future removes the pending command, so a
        // canceled `select!` (drained elsewhere) loses no command. The outcome
        // is collected first so the losing future is dropped before we touch
        // manager state again.
        enum Outcome {
            Permit(std::result::Result<mpsc::OwnedPermit<Command>, mpsc::error::SendError<()>>),
            Message(Result<ProtoMsg>),
        }
        let reserve = sender.reserve_owned();
        let outcome = tokio::select! {
            biased;
            permit = reserve => Outcome::Permit(permit),
            message = self.next_message() => Outcome::Message(message),
        };

        match outcome {
            Outcome::Message(message) => message.map(Some),
            Outcome::Permit(permit) => {
                let permit = match permit {
                    Ok(permit) => permit,
                    Err(_) => {
                        // Receiver closed: the command can never be admitted.
                        self.pending = None;
                        return Ok(None);
                    }
                };
                // Revalidate synchronously against the pinned generation before
                // removing the command; the send below stays synchronous.
                let valid = {
                    let inner = self.inner.lock().await;
                    match self.pending.as_ref() {
                        Some(pending) => inner
                            .entries
                            .get(&pending.key)
                            .map(|entry| {
                                !matches!(entry.phase, Phase::Retiring)
                                    && entry.generation == pending.generation
                            })
                            .unwrap_or(false),
                        None => false,
                    }
                };
                if valid {
                    if let Some(pending) = self.pending.take() {
                        // No await after removal; hand the command over now.
                        permit.send(pending.command);
                    }
                } else {
                    // Target changed while waiting; discard and rearm reads.
                    self.pending = None;
                }
                Ok(None)
            }
        }
    }

    /// Close every connection belonging to `session` across all protocols.
    ///
    /// Takes `&mut self` so teardown also requires exclusive manager access.
    pub async fn close_session(&mut self, session: &str) -> Result<()> {
        // A retained command for this session can no longer be admitted once its
        // worker is closed, so drop it to rearm the driver's input gating.
        let clear_pending = self
            .pending
            .as_ref()
            .map(|pending| pending.key.session() == session)
            .unwrap_or(false);
        if clear_pending {
            self.pending = None;
        }
        // Drop a retained event belonging to this session; it would be stale
        // once the session's entries are retired anyway. Events for other
        // sessions stay retained.
        if self
            .dequeued_event
            .as_ref()
            .map(|event| {
                let key = match event {
                    Event::Message { key, .. } | Event::Finished { key, .. } => key,
                };
                key.session() == session
            })
            .unwrap_or(false)
        {
            self.dequeued_event = None;
        }
        let mut inner = self.inner.lock().await;
        let keys: Vec<ConnectionKey> = inner
            .entries
            .keys()
            .filter(|key| key.session() == session)
            .cloned()
            .collect();
        let first_err = drain_and_abort(&mut inner, keys).await;
        drop(inner);
        match first_err {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    /// Close every tracked connection, aborting all workers before awaiting.
    ///
    /// Takes `&mut self` so teardown also requires exclusive manager access.
    pub(crate) fn begin_close_all(&mut self) {
        self.pending = None;
        self.dequeued_event = None;
        for entry in self.inner.get_mut().entries.values_mut() {
            if let Some(shared) = entry.udp_inline.as_ref() {
                shared.close();
            }
            entry.phase = Phase::Retiring;
            entry.pending_message = None;
            entry.handle.abort();
        }
    }

    pub async fn close_all(&mut self) -> Result<()> {
        self.begin_close_all();
        let mut inner = self.inner.lock().await;
        let keys: Vec<ConnectionKey> = inner.entries.keys().cloned().collect();
        let first_err = drain_and_abort(&mut inner, keys).await;
        drop(inner);
        match first_err {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    /// Remove and await normally finished workers when the shared queue is
    /// empty. Retiring entries are never reaped here, because they may still own
    /// a saved terminal frame that must be delivered by `next_message`.
    ///
    /// Uses `try_lock` on the receiver so it degrades gracefully if the
    /// receiver is momentarily busy. If the queue still holds events or the
    /// receiver is locked, reaping is deferred so that no queued terminal
    /// message is ever discarded. Public driver methods take `&mut self`, so a
    /// concurrent `next_message` cannot actually hold that lock simultaneously.
    async fn reap_locked(&self, inner: &mut Inner) -> Option<anyhow::Error> {
        // A retained event is equivalent to a non-empty event queue: reaping
        // now could discard the last pending terminal message.
        if self.dequeued_event.is_some() {
            return None;
        }
        let finished: Vec<ConnectionKey> = inner
            .entries
            .iter()
            .filter(|(_, entry)| {
                !matches!(entry.phase, Phase::Retiring) && entry.handle.is_finished()
            })
            .map(|(key, _)| key.clone())
            .collect();
        if finished.is_empty() {
            return None;
        }
        match self.events.try_lock() {
            Ok(events) => {
                if !events.is_empty() {
                    return None;
                }
            }
            Err(_) => return None,
        }

        let mut first_err = None;
        for key in finished {
            // Await through the borrowed handle still in the map so canceled
            // callers leave the aborted worker owned by its entry.
            let result = match inner.entries.get_mut(&key) {
                Some(entry) => (&mut entry.handle).await,
                None => continue,
            };
            inner.entries.remove(&key);
            match result {
                Ok(()) => {}
                Err(err) if err.is_cancelled() => {}
                Err(err) => {
                    if first_err.is_none() {
                        first_err = Some(anyhow!("port forward worker failed: {err}"));
                    }
                }
            }
        }
        first_err
    }
}

/// Kind of wakeup observed while waiting for the next worker event.
enum Wake {
    /// The event channel produced a value (or closed).
    Event(Option<Event>),
    /// Bounded maintenance timer elapsed; the caller should reap and retry.
    Tick,
}

impl Default for PortForwardManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PortForwardManager {
    fn drop(&mut self) {
        // `&mut self` guarantees exclusive access, so we can reach the entries
        // directly without locking. Explicitly abort every worker so none keeps
        // running: a `JoinHandle` dropped on its own only detaches the task,
        // whereas `abort` requests cancellation first. Because `Drop` is
        // synchronous we cannot await, so after signalling abort the detached
        // tasks are already cancelled and will terminate promptly. No concurrent
        // manager can claim these entries because `&mut self` is exclusive.
        let inner = self.inner.get_mut();
        for (_, entry) in inner.entries.drain() {
            // Close the shared UDP state before aborting so inline attempts from
            // a concurrently dropped manager fail fast rather than write.
            if let Some(shared) = entry.udp_inline.as_ref() {
                shared.close();
            }
            entry.handle.abort();
        }
    }
}

/// Forward an `ack`/`forward` command without ever blocking the dispatcher.
///
/// A transiently full command queue is not treated as failure: the parsed
/// command is retained in `pending` (tagged with the exact worker key and
/// generation) so it can be admitted later via [`PortForwardManager::next_event`]
/// instead of aborting a healthy worker during a burst.
async fn dispatch(
    inner: &mut Inner,
    pending: &mut Option<PendingCommand>,
    header: &ProtoHdr,
    key: &ConnectionKey,
    command: Command,
) -> Result<Vec<ProtoMsg>> {
    let generation = match inner.entries.get(key) {
        Some(entry) if !matches!(entry.phase, Phase::Retiring) => {
            (entry.generation, entry.commands.clone())
        }
        _ => return Ok(vec![error_reply(header, "unknown connection")?]),
    };
    let (generation, sender) = generation;
    let send_result = sender.try_send(command);

    match send_result {
        Ok(()) => Ok(Vec::new()),
        Err(mpsc::error::TrySendError::Full(command)) => {
            // Retain the single bounded command keyed to this exact worker;
            // generation validation prevents later routing to a replacement.
            *pending = Some(PendingCommand {
                key: key.clone(),
                generation,
                command,
            });
            Ok(Vec::new())
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            // Mark and abort first, then join through the owned map entry so a
            // canceled dispatch leaves the aborted handle safely in place.
            begin_retirement(inner, key, None);
            finish_retirement(inner, key).await?;
            let mut out = vec![error_reply(header, "connection closed unexpectedly")?];
            out.push(key.message("stop", Vec::new()));
            Ok(out)
        }
    }
}

/// Dispatch a legacy outbound UDP command (`forward` or `FailForward`) while
/// reserving one inline-forward credit *before* the command can become visible
/// to the worker. Credits are checked and incremented synchronously so the
/// manager can never overtake an earlier queued forward.
async fn dispatch_legacy_forward(
    inner: &mut Inner,
    pending: &mut Option<PendingCommand>,
    header: &ProtoHdr,
    key: &ConnectionKey,
    command: Command,
) -> Result<Vec<ProtoMsg>> {
    // Reserve a credit for managed UDP workers only; other protos/transports
    // are unmodified.
    let managed = inner
        .entries
        .get(key)
        .map(|entry| !matches!(entry.phase, Phase::Retiring) && entry.udp_inline.is_some())
        .unwrap_or(false);
    if managed {
        // Conservative bound: completed-but-unconsumed acks also count, so the
        // bound must exceed the queues by a small margin. Both capacities are
        // small compile-time constants, so plain arithmetic cannot overflow.
        let bound = EVENT_CAPACITY + COMMAND_CAPACITY + 4;
        let entry = match inner.entries.get_mut(key) {
            Some(entry) => entry,
            None => return Ok(vec![error_reply(header, "unknown connection")?]),
        };
        let next = match entry.legacy_forwards.checked_add(1) {
            Some(next) => next,
            None => return Err(anyhow!("port forward legacy counter overflow")),
        };
        if next > bound {
            return Err(anyhow!("port forward legacy forwards exceed bounded limit"));
        }
        entry.legacy_forwards = next;
    }

    dispatch(inner, pending, header, key, command).await
}

/// Remove a single tracked connection and confirm it has stopped.
async fn stop_connection(
    inner: &mut Inner,
    header: &ProtoHdr,
    key: &ConnectionKey,
) -> Result<Vec<ProtoMsg>> {
    if !inner.entries.contains_key(key) {
        return Ok(vec![error_reply(header, "unknown connection")?]);
    }
    begin_retirement(inner, key, None);
    finish_retirement(inner, key).await?;
    Ok(vec![key.message("stop", Vec::new())])
}

/// Mark a worker for cancellation-safe retirement and abort it before any
/// await. The handle and optional terminal frame stay owned by the map entry.
fn begin_retirement(inner: &mut Inner, key: &ConnectionKey, pending: Option<ProtoMsg>) {
    if let Some(entry) = inner.entries.get_mut(key) {
        entry.phase = Phase::Retiring;
        entry.pending_message = pending;
        // Close inline forwarding *before* aborting the worker so a racing
        // inline attempt observes a closed state instead of a dead socket.
        if let Some(shared) = entry.udp_inline.as_ref() {
            shared.close();
        }
        entry.handle.abort();
    }
}

/// Await a retiring worker through its borrowed map handle, removing the entry
/// only after the await completes. A canceled caller leaves the aborted handle
/// (and any saved frame) in the map for a later resume.
async fn finish_retirement(inner: &mut Inner, key: &ConnectionKey) -> Result<Option<ProtoMsg>> {
    let join_result = match inner.entries.get_mut(key) {
        Some(entry) => (&mut entry.handle).await,
        None => return Ok(None),
    };
    let entry = match inner.entries.remove(key) {
        Some(entry) => entry,
        None => return Ok(None),
    };
    match join_result {
        Ok(()) => Ok(entry.pending_message),
        Err(err) if err.is_cancelled() => Ok(entry.pending_message),
        Err(err) => Err(anyhow!("port forward worker failed: {err}")),
    }
}

/// Join quiet retirements only. Entries with a saved terminal frame are skipped
/// so unrelated maintenance can never discard an undelivered protocol message.
async fn finish_quiet_retirements(inner: &mut Inner) -> Option<anyhow::Error> {
    let keys: Vec<ConnectionKey> = inner
        .entries
        .iter()
        .filter(|(_, entry)| {
            matches!(entry.phase, Phase::Retiring) && entry.pending_message.is_none()
        })
        .map(|(key, _)| key.clone())
        .collect();

    let mut first_err = None;
    for key in keys {
        let quiet = inner
            .entries
            .get(&key)
            .map(|entry| matches!(entry.phase, Phase::Retiring) && entry.pending_message.is_none())
            .unwrap_or(false);
        if !quiet {
            continue;
        }
        if let Err(err) = finish_retirement(inner, &key).await
            && first_err.is_none()
        {
            first_err = Some(err);
        }
    }
    first_err
}

/// Invalidate saved frames for all selected keys and abort every worker first,
/// then join each through its borrowed handle. The first unexpected failure is
/// returned only after every selected worker has been cleaned up.
async fn drain_and_abort(inner: &mut Inner, keys: Vec<ConnectionKey>) -> Option<anyhow::Error> {
    for key in &keys {
        begin_retirement(inner, key, None);
    }

    let mut first_err = None;
    for key in keys {
        if let Err(err) = finish_retirement(inner, &key).await
            && first_err.is_none()
        {
            first_err = Some(err);
        }
    }
    first_err
}

#[cfg(test)]
struct TeardownProbeGuard(std::sync::Arc<std::sync::atomic::AtomicBool>);
#[cfg(test)]
impl Drop for TeardownProbeGuard {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
impl PortForwardManager {
    pub(crate) async fn install_teardown_probe(
        &mut self,
    ) -> anyhow::Result<std::sync::Arc<std::sync::atomic::AtomicBool>> {
        let inner = self.inner.get_mut();
        if !inner.entries.is_empty() {
            anyhow::bail!("probe manager is not empty");
        }
        let mut properties = std::collections::BTreeMap::new();
        properties.insert("connection_id".to_owned(), rmpv::Value::from("probe"));
        let header = ProtoHdr {
            proto: ProtoType::PORT_FORWARD_V2,
            msg_type: "new".into(),
            session_id: "probe-forward".into(),
            properties,
        };
        let key = ConnectionKey::from_header(&header)?;
        let (commands, receiver) = mpsc::channel(1);
        let (ready, started) = tokio::sync::oneshot::channel();
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let copy = flag.clone();
        let handle = tokio::spawn(async move {
            let _guard = TeardownProbeGuard(copy);
            let _receiver = receiver;
            let _ = ready.send(());
            std::future::pending::<()>().await;
        });
        inner.entries.insert(
            key,
            Entry {
                tcp_frame_size: None,
                generation: 1,
                phase: Phase::Established,
                commands,
                handle,
                pending_message: None,
                udp_inline: None,
                legacy_forwards: 0,
            },
        );
        started.await?;
        Ok(flag)
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    use crate::protocol::ProtoType;
    use std::future::{Future, pending};
    use std::pin::Pin;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::task::{Context, Poll, Waker};
    use tokio::sync::oneshot;
    use tokio::time::timeout;

    const WAIT: Duration = Duration::from_secs(2);

    struct ObservedDrop(Arc<AtomicUsize>);
    impl Drop for ObservedDrop {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    // The fake owns a real bounded receiver and reports readiness only after
    // its terminal event is queued. It then stays pending so abort must be
    // scheduled before JoinHandle can complete on this current-thread runtime.
    async fn install(
        manager: &mut PortForwardManager,
        id: &str,
        phase: Phase,
        terminal: Option<&str>,
        drops: Arc<AtomicUsize>,
    ) -> Result<(ConnectionKey, Option<ProtoMsg>)> {
        let mut properties = std::collections::BTreeMap::new();
        properties.insert("connection_id".to_owned(), rmpv::Value::from(id));
        let header = ProtoHdr {
            proto: ProtoType::PORT_FORWARD_V2,
            msg_type: "new".into(),
            session_id: "cancel-session".into(),
            properties,
        };
        let key = ConnectionKey::from_header(&header)?;
        let message = match terminal {
            Some("stop") => Some(key.message("stop", Vec::new())),
            Some("error") => Some(error_reply(&header, "fixture connect refused")?),
            Some(_) => return Err(anyhow!("unknown fixture terminal")),
            None => None,
        };
        let expected = message.clone();
        let (commands, command_rx) = mpsc::channel(1);
        let events = manager.event_tx.clone();
        let event_key = key.clone();
        let (ready_tx, ready_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            let _drop = ObservedDrop(drops);
            if let Some(message) = message
                && events
                    .send(Event::Message {
                        key: event_key,
                        generation: 1,
                        message,
                    })
                    .await
                    .is_err()
            {
                return;
            }
            let _ = ready_tx.send(());
            pending::<()>().await;
            drop(command_rx);
        });
        let inner = manager.inner.get_mut();
        inner.generation = 1;
        inner.entries.insert(
            key.clone(),
            Entry {
                tcp_frame_size: None,
                generation: 1,
                phase,
                commands,
                handle,
                pending_message: None,
                udp_inline: None,
                legacy_forwards: 0,
            },
        );
        timeout(WAIT, ready_rx).await??;
        Ok((key, expected))
    }

    fn poll_pending<F: Future>(future: Pin<&mut F>) {
        let mut context = Context::from_waker(Waker::noop());
        assert!(
            matches!(future.poll(&mut context), Poll::Pending),
            "fixture must force a pending abort join"
        );
    }

    // A fake worker whose bounded command queue only drains after the returned
    // gate is fired.
    async fn install_consuming(
        manager: &mut PortForwardManager,
        id: &str,
        drops: Arc<AtomicUsize>,
    ) -> Result<(ConnectionKey, oneshot::Sender<()>)> {
        let mut properties = std::collections::BTreeMap::new();
        properties.insert("connection_id".to_owned(), rmpv::Value::from(id));
        let header = ProtoHdr {
            proto: ProtoType::PORT_FORWARD_V2,
            msg_type: "new".into(),
            session_id: "cancel-session".into(),
            properties,
        };
        let key = ConnectionKey::from_header(&header)?;
        let (commands, mut command_rx) = mpsc::channel(1);
        let (gate_tx, gate_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            let _drop = ObservedDrop(drops);
            if gate_rx.await.is_err() {
                return;
            }
            // Consume queued commands without emitting any events.
            while command_rx.recv().await.is_some() {}
        });
        let inner = manager.inner.get_mut();
        inner.generation = 1;
        inner.entries.insert(
            key.clone(),
            Entry {
                tcp_frame_size: None,
                generation: 1,
                phase: Phase::Established,
                commands,
                handle,
                pending_message: None,
                udp_inline: None,
                legacy_forwards: 0,
            },
        );
        Ok((key, gate_tx))
    }

    #[tokio::test(flavor = "current_thread")]
    async fn begin_close_signals_all_and_retains_handles() -> Result<()> {
        let mut manager = PortForwardManager::new();
        let drops = Arc::new(AtomicUsize::new(0));
        let (first, _) =
            install(&mut manager, "one", Phase::Established, None, drops.clone()).await?;
        let (second, _) =
            install(&mut manager, "two", Phase::Established, None, drops.clone()).await?;
        let inner = manager.inner.get_mut();
        inner
            .entries
            .get_mut(&first)
            .ok_or_else(|| anyhow!("first missing"))?
            .pending_message = Some(first.message("stop", Vec::new()));
        manager.begin_close_all();
        manager.begin_close_all();
        let inner = manager.inner.get_mut();
        for key in [&first, &second] {
            let entry = inner
                .entries
                .get(key)
                .ok_or_else(|| anyhow!("entry removed early"))?;
            assert!(matches!(entry.phase, Phase::Retiring));
            assert!(entry.pending_message.is_none());
        }
        timeout(WAIT, manager.close_all()).await??;
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        assert!(manager.inner.get_mut().entries.is_empty());
        Ok(())
    }

    async fn terminal_survives(terminal: &str, phase: Phase) -> Result<()> {
        let mut manager = PortForwardManager::new();
        let drops = Arc::new(AtomicUsize::new(0));
        let (key, expected) = install(
            &mut manager,
            "terminal",
            phase,
            Some(terminal),
            drops.clone(),
        )
        .await?;
        let expected = expected.ok_or_else(|| anyhow!("terminal fixture missing message"))?;
        let mut future = Box::pin(manager.next_message());
        poll_pending(future.as_mut());
        drop(future);
        // No yield between cancel and retry: the manager must still own the
        // join and already-dequeued message, not rely on detached cleanup.
        let actual = timeout(WAIT, manager.next_message()).await??;
        assert_eq!(actual.header.msg_type, expected.header.msg_type);
        assert_eq!(actual.header.proto, key.proto());
        assert_eq!(actual.header.session_id, key.session());
        assert_eq!(actual.header.properties, expected.header.properties);
        assert_eq!(actual.body, expected.body);
        assert_eq!(
            drops.load(Ordering::SeqCst),
            1,
            "worker must be joined before frame delivery"
        );
        assert!(
            timeout(Duration::from_millis(100), manager.next_message())
                .await
                .is_err(),
            "terminal must be delivered exactly once"
        );
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn canceled_stop_delivery_is_resumed_exactly_once() -> Result<()> {
        terminal_survives("stop", Phase::Established).await
    }

    #[tokio::test(flavor = "current_thread")]
    async fn canceled_connect_error_delivery_is_resumed_exactly_once() -> Result<()> {
        terminal_survives("error", Phase::Connecting).await
    }

    #[tokio::test(flavor = "current_thread")]
    async fn canceled_close_all_keeps_every_join_owned() -> Result<()> {
        let mut manager = PortForwardManager::new();
        let drops = Arc::new(AtomicUsize::new(0));
        install(
            &mut manager,
            "first",
            Phase::Established,
            None,
            drops.clone(),
        )
        .await?;
        install(
            &mut manager,
            "second",
            Phase::Established,
            None,
            drops.clone(),
        )
        .await?;
        let mut future = Box::pin(manager.close_all());
        poll_pending(future.as_mut());
        drop(future);
        timeout(WAIT, manager.close_all()).await??;
        assert_eq!(
            drops.load(Ordering::SeqCst),
            2,
            "retry must await both worker destructors before returning"
        );
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn canceled_explicit_stop_keeps_join_owned() -> Result<()> {
        let mut manager = PortForwardManager::new();
        let drops = Arc::new(AtomicUsize::new(0));
        let (key, _) = install(
            &mut manager,
            "stop",
            Phase::Established,
            None,
            drops.clone(),
        )
        .await?;
        let mut future = Box::pin(manager.handle(key.message("stop", Vec::new())));
        poll_pending(future.as_mut());
        drop(future);
        timeout(WAIT, manager.close_all()).await??;
        assert_eq!(
            drops.load(Ordering::SeqCst),
            1,
            "stop cancellation must not detach the aborted worker"
        );
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn full_queue_retains_command_without_aborting() -> Result<()> {
        let mut manager = PortForwardManager::new();
        let drops = Arc::new(AtomicUsize::new(0));
        let (key, _) = install(
            &mut manager,
            "bounded",
            Phase::Established,
            None,
            drops.clone(),
        )
        .await?;
        // First command fills the capacity-1 queue; the second is retained.
        assert!(manager.accepts_input());
        assert!(
            manager
                .handle(key.message("forward", vec![1]))
                .await?
                .is_empty()
        );
        assert!(manager.accepts_input());
        assert!(
            manager
                .handle(key.message("forward", vec![2]))
                .await?
                .is_empty()
        );
        assert!(
            !manager.accepts_input(),
            "a bounded command must be retained, not dropped"
        );
        assert_eq!(
            drops.load(Ordering::SeqCst),
            0,
            "healthy worker must not be aborted on a full queue"
        );
        // `handle` while pending is a documented API misuse.
        assert!(
            manager
                .handle(key.message("forward", vec![3]))
                .await
                .is_err()
        );
        timeout(WAIT, manager.close_all()).await??;
        assert!(manager.accepts_input(), "close_all must clear pending");
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn next_event_admits_without_outbound_event() -> Result<()> {
        let mut manager = PortForwardManager::new();
        let drops = Arc::new(AtomicUsize::new(0));
        let (key, gate) = install_consuming(&mut manager, "admit", drops.clone()).await?;
        assert!(
            manager
                .handle(key.message("forward", vec![1]))
                .await?
                .is_empty()
        );
        assert!(
            manager
                .handle(key.message("forward", vec![2]))
                .await?
                .is_empty()
        );
        assert!(!manager.accepts_input());
        // Release the worker so it drains a slot, letting the retained command
        // be admitted with no worker output.
        let _ = gate.send(());
        let event = timeout(WAIT, manager.next_event()).await??;
        assert!(event.is_none(), "admission must surface as None");
        assert!(manager.accepts_input(), "admission rearms input gating");
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        timeout(WAIT, manager.close_all()).await??;
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn canceled_next_event_retains_pending_command() -> Result<()> {
        let mut manager = PortForwardManager::new();
        let drops = Arc::new(AtomicUsize::new(0));
        let (key, gate) = install_consuming(&mut manager, "cancel-admit", drops.clone()).await?;
        assert!(
            manager
                .handle(key.message("forward", vec![1]))
                .await?
                .is_empty()
        );
        assert!(
            manager
                .handle(key.message("forward", vec![2]))
                .await?
                .is_empty()
        );
        assert!(!manager.accepts_input());
        let mut future = Box::pin(manager.next_event());
        poll_pending(future.as_mut());
        drop(future);
        assert!(
            !manager.accepts_input(),
            "canceled next_event must keep the retained command"
        );
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        // A fresh next_event still admits the retained command.
        let _ = gate.send(());
        let event = timeout(WAIT, manager.next_event()).await??;
        assert!(event.is_none());
        assert!(manager.accepts_input());
        timeout(WAIT, manager.close_all()).await??;
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn close_session_clears_matching_pending_command() -> Result<()> {
        let mut manager = PortForwardManager::new();
        let drops = Arc::new(AtomicUsize::new(0));
        let (key, _gate) = install_consuming(&mut manager, "close-pending", drops.clone()).await?;
        assert!(
            manager
                .handle(key.message("forward", vec![1]))
                .await?
                .is_empty()
        );
        assert!(
            manager
                .handle(key.message("forward", vec![2]))
                .await?
                .is_empty()
        );
        assert!(!manager.accepts_input());
        timeout(WAIT, manager.close_session("cancel-session")).await??;
        assert!(
            manager.accepts_input(),
            "closing the owning session must clear pending"
        );
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stale_generation_pending_is_not_delivered() -> Result<()> {
        let mut manager = PortForwardManager::new();
        let drops = Arc::new(AtomicUsize::new(0));
        let (key, _) = install(
            &mut manager,
            "stale",
            Phase::Established,
            None,
            drops.clone(),
        )
        .await?;
        assert!(
            manager
                .handle(key.message("forward", vec![1]))
                .await?
                .is_empty()
        );
        assert!(
            manager
                .handle(key.message("forward", vec![2]))
                .await?
                .is_empty()
        );
        assert!(!manager.accepts_input());
        // Simulate the key being reused by a replacement worker (new generation)
        // while the retained command still pins the old generation.
        {
            let inner = manager.inner.get_mut();
            if let Some(entry) = inner.entries.get_mut(&key) {
                entry.generation = 2;
            }
        }
        let event = timeout(WAIT, manager.next_event()).await??;
        assert!(event.is_none(), "stale command must not be delivered");
        assert!(
            manager.accepts_input(),
            "stale pending must be discarded to rearm reads"
        );
        timeout(WAIT, manager.close_all()).await??;
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unrelated_request_preserves_pending_terminal() -> Result<()> {
        let mut manager = PortForwardManager::new();
        let drops = Arc::new(AtomicUsize::new(0));
        let (key, _) = install(
            &mut manager,
            "saved",
            Phase::Established,
            Some("stop"),
            drops,
        )
        .await?;
        let mut future = Box::pin(manager.next_message());
        poll_pending(future.as_mut());
        drop(future);
        let mut unrelated = key.message("forward", vec![1]);
        unrelated.header.session_id = "unrelated".into();
        let replies = manager.handle(unrelated).await?;
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].header.msg_type, "error");
        let terminal = timeout(WAIT, manager.next_message()).await??;
        assert_eq!(terminal.header.msg_type, "stop");
        assert_eq!(terminal.header.session_id, key.session());
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn close_session_invalidates_saved_terminal() -> Result<()> {
        let mut manager = PortForwardManager::new();
        let drops = Arc::new(AtomicUsize::new(0));
        install(
            &mut manager,
            "saved",
            Phase::Established,
            Some("stop"),
            drops.clone(),
        )
        .await?;
        let mut future = Box::pin(manager.next_message());
        poll_pending(future.as_mut());
        drop(future);
        timeout(WAIT, manager.close_session("cancel-session")).await??;
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(
            timeout(Duration::from_millis(100), manager.next_message())
                .await
                .is_err()
        );
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retained_dequeued_forward_survives_admission_only_none() -> Result<()> {
        let mut manager = PortForwardManager::new();
        let drops = Arc::new(AtomicUsize::new(0));
        let (key, gate) = install_consuming(&mut manager, "retained", drops.clone()).await?;
        assert!(
            manager
                .handle(key.message("forward", vec![1]))
                .await?
                .is_empty()
        );
        assert!(
            manager
                .handle(key.message("forward", vec![2]))
                .await?
                .is_empty()
        );
        assert!(!manager.accepts_input());
        // Simulate the exact old bug window: a worker event was dequeued by a
        // previous call and retained in the manager field, while a command is
        // also pending. `next_event` must not lose the retained event when the
        // admission branch wins.
        let retained = key.message("forward", b"dequeued".to_vec());
        manager.dequeued_event = Some(Event::Message {
            key: key.clone(),
            generation: 1,
            message: retained.clone(),
        });
        let _ = gate.send(());
        // Wait until the fixture has actually drained its queue, so both
        // admission and the retained event are ready in the same select poll.
        timeout(WAIT, async {
            loop {
                let capacity = manager
                    .inner
                    .get_mut()
                    .entries
                    .get(&key)
                    .ok_or_else(|| anyhow!("missing fixture worker"))?
                    .commands
                    .capacity();
                if capacity > 0 {
                    return Ok::<(), anyhow::Error>(());
                }
                tokio::task::yield_now().await;
            }
        })
        .await??;
        let event = timeout(WAIT, manager.next_event()).await??;
        assert!(event.is_none(), "admission must surface as None");
        assert!(manager.accepts_input());
        let message = timeout(WAIT, manager.next_message()).await??;
        assert_eq!(message.header.msg_type, "forward");
        assert_eq!(message.body, retained.body);
        assert!(
            manager.dequeued_event.is_none(),
            "retained event must be consumed exactly once"
        );
        assert!(
            timeout(Duration::from_millis(100), manager.next_message())
                .await
                .is_err(),
            "retained message must not be delivered twice"
        );
        timeout(WAIT, manager.close_all()).await??;
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retained_last_message_blocks_reaping() -> Result<()> {
        let mut manager = PortForwardManager::new();
        let drops = Arc::new(AtomicUsize::new(0));
        // Terminal fixture finishes its task body right after queueing, so the
        // handle is finished while its event is still queued.
        let (key, _) = install(
            &mut manager,
            "last",
            Phase::Established,
            None,
            drops.clone(),
        )
        .await?;
        let handle = &manager
            .inner
            .get_mut()
            .entries
            .get(&key)
            .ok_or_else(|| anyhow!("missing fixture worker"))?
            .handle;
        handle.abort();
        timeout(WAIT, async {
            while !handle.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        let last = key.message("forward", b"last".to_vec());
        manager.dequeued_event = Some(Event::Message {
            key: key.clone(),
            generation: 1,
            message: last.clone(),
        });
        // A handle-less consumer request must not reap the entry while a last
        // message is retained; otherwise the message is dropped.
        let mut unrelated = key.message("forward", vec![9]);
        unrelated.header.session_id = "other-session".into();
        let replies = manager.handle(unrelated).await?;
        assert_eq!(replies.len(), 1);
        let message = timeout(WAIT, manager.next_message()).await??;
        assert_eq!(message.body, last.body);
        timeout(WAIT, manager.close_all()).await??;
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn close_session_drops_only_matching_saved_event() -> Result<()> {
        let mut manager = PortForwardManager::new();
        let drops = Arc::new(AtomicUsize::new(0));
        let (key, _) = install(
            &mut manager,
            "keep",
            Phase::Established,
            None,
            drops.clone(),
        )
        .await?;
        let keep_msg = key.message("forward", b"keep".to_vec());
        manager.dequeued_event = Some(Event::Message {
            key: key.clone(),
            generation: 1,
            message: keep_msg.clone(),
        });
        // Closing an unrelated session must retain the event.
        timeout(WAIT, manager.close_session("missing-session")).await??;
        assert!(
            manager.dequeued_event.is_some(),
            "unrelated close must keep the saved event"
        );
        let message = timeout(WAIT, manager.next_message()).await??;
        assert_eq!(message.body, keep_msg.body);

        // Closing the owning session discards its saved event.
        let owned = key.message("forward", b"owned".to_vec());
        manager.dequeued_event = Some(Event::Message {
            key: key.clone(),
            generation: 1,
            message: owned,
        });
        timeout(WAIT, manager.close_session(key.session())).await??;
        assert!(
            manager.dequeued_event.is_none(),
            "owning close must discard the saved event"
        );
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn saved_old_generation_event_cannot_reach_replacement() -> Result<()> {
        let mut manager = PortForwardManager::new();
        let drops = Arc::new(AtomicUsize::new(0));
        let (key, _) =
            install(&mut manager, "gen", Phase::Established, None, drops.clone()).await?;
        // The key is reused by a replacement worker (generation 2).
        {
            let inner = manager.inner.get_mut();
            if let Some(entry) = inner.entries.get_mut(&key) {
                entry.generation = 2;
            }
        }
        manager.dequeued_event = Some(Event::Message {
            key: key.clone(),
            generation: 1,
            message: key.message("forward", b"stale".to_vec()),
        });
        assert!(
            timeout(Duration::from_millis(100), manager.next_message())
                .await
                .is_err(),
            "stale generation event must be discarded, not delivered"
        );
        assert!(manager.dequeued_event.is_none());
        timeout(WAIT, manager.close_all()).await??;
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cooperative_budget_exhaustion_does_not_lose_dequeued_event() -> Result<()> {
        let mut cancellations = 0usize;
        // Sweep budget offsets using public APIs. This catches yields both
        // before and after the first uncontended manager lock.
        for offset in 0..=128 {
            let mut manager = PortForwardManager::new();
            let drops = Arc::new(AtomicUsize::new(0));
            let (key, _) = install(&mut manager, "budget", Phase::Established, None, drops).await?;
            let msg = key.message("forward", b"budgeted".to_vec());
            manager.dequeued_event = Some(Event::Message {
                key,
                generation: 1,
                message: msg.clone(),
            });
            tokio::task::yield_now().await;
            let mut context = Context::from_waker(Waker::noop());
            for _ in 0..offset {
                let mut consume = Box::pin(tokio::task::consume_budget());
                if consume.as_mut().poll(&mut context).is_pending() {
                    break;
                }
            }
            let polled = {
                let mut future = Box::pin(manager.next_message());
                future.as_mut().poll(&mut context)
            };
            match polled {
                Poll::Ready(Ok(message)) => assert_eq!(message.body, msg.body),
                Poll::Ready(Err(err)) => return Err(err),
                Poll::Pending => {
                    cancellations += 1;
                    assert!(
                        manager.dequeued_event.is_some(),
                        "cancellation at budget offset {offset} lost the event"
                    );
                    tokio::task::yield_now().await;
                    let message = timeout(WAIT, manager.next_message()).await??;
                    assert_eq!(message.body, msg.body);
                }
            }
            timeout(WAIT, manager.close_all()).await??;
        }
        assert!(
            cancellations > 0,
            "must exercise real cooperative cancellation"
        );
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn same_key_reuse_invalidates_saved_terminal() -> Result<()> {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;
        let mut manager = PortForwardManager::new();
        let drops = Arc::new(AtomicUsize::new(0));
        let (key, _) = install(
            &mut manager,
            "reuse",
            Phase::Established,
            Some("stop"),
            drops.clone(),
        )
        .await?;
        let mut future = Box::pin(manager.next_message());
        poll_pending(future.as_mut());
        drop(future);
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let body = crate::protocol::encode(
            &serde_json::json!({"remote_host":"127.0.0.1","remote_port":listener.local_addr()?.port(),"protocol":"tcp"}),
        )?;
        assert!(manager.handle(key.message("new", body)).await?.is_empty());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        let (mut socket, _) = timeout(WAIT, listener.accept()).await??;
        let new = timeout(WAIT, manager.next_message()).await??;
        assert_eq!(
            new.header.msg_type, "new",
            "saved old stop must not leak into replacement"
        );
        timeout(WAIT, socket.write_all(b"fresh")).await??;
        let output = timeout(WAIT, manager.next_message()).await??;
        assert_eq!(output.header.msg_type, "forward");
        assert_eq!(output.body, b"fresh");
        timeout(WAIT, manager.close_all()).await??;
        Ok(())
    }
}

#[cfg(test)]
#[path = "udp_inline_manager_tests.rs"]
mod udp_inline_tests;
