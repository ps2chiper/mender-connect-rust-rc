//! Exclusive driver for in-flight file transfers.
//!
//! The manager owns one `tokio::spawn(file_transfer_task::run)` task per active
//! transfer and multiplexes their [`Event`] streams back to the caller. All
//! state is guarded by `&mut self` (no `Mutex`); the caller must serialize
//! `handle`/`next_message` calls.
//!
//! Cancellation safety: when a terminal event retires an entry, the outgoing
//! message is stashed in [`FileTransferManager::pending`] *before* any await,
//! the worker is aborted, and its retained handle is awaited before the entry is
//! removed from the map. Graceful completion instead keeps the entry and its
//! handle owned across the join. A caller whose `next_message` future is
//! cancelled mid-retirement therefore observes the stashed message on the next
//! call, and never leaks a detached running task.
//!
//! Upload backpressure: a `Kind::UploadV2` command rejected with a full command
//! queue is retained in `pending_command` and resumed under a bounded four-second
//! reserve; it assumes the per-transfer worker keeps draining its command
//! channel responsively so the reserve completes promptly. Together with the
//! bounded four-second `stat` cleanup window, these are the paths where
//! `handle`/`next_message` may stall the websocket driver.
//!
//! Upload completion: once a candidate end-of-file `file_chunk` (an empty body) has
//! been handed to an upload worker, the transfer enters a bounded completion
//! phase with an absolute deadline. A session-scoped [`Self::close_session`] then
//! aborts every other transfer promptly but awaits in-progress uploads within
//! that stored deadline, reaping them on completion and aborting/joining on
//! expiry, so a candidate EOF handoff can still flush, sync and atomically persist. The
//! worker remains authoritative for offset, declared-size and path validation,
//! so a malformed EOF still never commits. This assumes the worker keeps making
//! progress on local regular files, matching the worker's unchanged assumptions;
//! a synchronous filesystem call already in progress is only observed between
//! completed operations.
//!
//! Event servicing during close: [`Self::close_session`] awaits completing
//! uploads inline and can therefore stall the websocket driver, letting an
//! unrelated transfer fill the shared event queue and hit its own send timeout.
//! The daemon instead calls [`Self::close_session_servicing`], which keeps
//! draining and processing shared events while it waits for completing uploads,
//! forwarding unrelated outbound replies to a caller-supplied async sink as they
//! arrive (no unbounded buffering). Replies for the closing session and stale
//! generation events are suppressed, and the upload completion deadline is
//! absolute and always checked even under continuously ready unrelated events.
//! This is not a fully non-blocking session close: inbound socket handling still
//! waits for the bounded completion window (and the closing upload's final ACK
//! is not awaited once its session has closed); only outbound event servicing is
//! non-blocking.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use tokio::sync::mpsc;
use tokio::task::{JoinError, JoinHandle};
use tokio::time::{Duration, Instant, sleep, sleep_until, timeout_at};

use crate::file_transfer_schema::{self, GetFile, StatFile, UploadRequest};
use crate::file_transfer_task::{self, Event, Key, Request};
use crate::protocol::{self, ProtoHdr, ProtoMsg, ProtoType};
use crate::transfer_limits::TransferLimits;

/// Maximum number of simultaneously active transfers.
const MAX_ENTRIES: usize = 4;
/// Bounded period for tolerating a late acknowledgement of an empty download.
const EMPTY_ACK_WINDOW: Duration = Duration::from_secs(30);
/// Per-transfer command channel capacity.
const COMMAND_CAPACITY: usize = 20;
/// Shared event channel capacity.
const EVENT_CAPACITY: usize = 64;
/// Maximum accepted request/stat body size.
const BODY_CAP: usize = 16_384;
/// Maximum accepted file chunk size.
const CHUNK_CAP: usize = 4_096;
/// Idle maintenance tick.
const TICK: Duration = Duration::from_millis(100);
/// Bounded window for a v1 download worker to finish after its final ACK.
const COMPLETION_WINDOW: Duration = Duration::from_secs(5);
/// Absolute window granted for an upload worker to flush, sync and persist an
/// already-accepted EOF before a session close aborts it. Chosen to cover the
/// worker's bounded flush/sync stages plus a bounded event-send wait, while
/// remaining bounded so a stuck worker is still reaped.
const UPLOAD_COMPLETION_WINDOW: Duration = Duration::from_secs(15);
/// Bounded window to reserve command-channel capacity for a backpressured
/// `Kind::UploadV2` chunk before aborting the transfer.
const COMMAND_RESERVE_WINDOW: Duration = Duration::from_secs(4);
/// Absolute deadline for an active blocking `stat` job to produce its reply.
const STAT_ACTIVE_WINDOW: Duration = Duration::from_secs(4);
/// Absolute window granted for a retiring `stat` job to stop; expiry is fatal.
const STAT_CLEANUP_WINDOW: Duration = Duration::from_secs(4);

/// Fatal marker raised when a blocking `stat` job does not stop within its
/// cleanup deadline.
///
/// A running kernel metadata operation cannot be forcibly cancelled, so the
/// process-wide single `stat` permit may still be held. The root supervisor
/// downcasts this marker to stop and reconnect.
#[derive(Debug)]
pub struct StatCleanupTimeout;

impl std::fmt::Display for StatCleanupTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("stat operation did not stop within its cleanup deadline")
    }
}

impl std::error::Error for StatCleanupTimeout {}

/// Lifecycle phase of a v1 download transfer.
enum DownloadPhase {
    /// Streaming chunks; peer input is a chunk or the empty EOF chunk.
    Streaming,
    /// Worker delivered the empty EOF chunk; awaiting the matching final ACK.
    AwaitingAck { offset: i64 },
    /// Matching final ACK dispatched for `offset`; awaiting bounded graceful
    /// completion under the absolute `deadline`.
    AwaitingCompletion { offset: i64, deadline: Instant },
}

/// Lifecycle phase of an upload transfer.
enum UploadPhase {
    /// Streaming chunks; no end-of-file command has been accepted yet.
    Streaming,
    /// A candidate EOF `file_chunk` handoff was recorded; awaiting bounded
    /// completion (commit and final ACK) under the absolute `deadline`.
    Completing { deadline: Instant },
}

/// Transfer kind, tracking protocol version and (for v1) download phase.
enum Kind {
    DownloadV1(DownloadPhase),
    DownloadV2,
    UploadV1(UploadPhase),
    UploadV2(UploadPhase),
}

/// Result of inspecting an inbound ACK against a v1 download entry.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AckMatch {
    /// Matches the pending `AwaitingAck` offset; transitions to completion.
    Matching,
    /// Duplicate final ACK while already awaiting completion; accept as-is.
    DuplicateFinal,
    /// Not a matching final ACK.
    NotMatching,
}

/// One active transfer owned by the manager.
struct Entry {
    generation: u64,
    commands: mpsc::Sender<ProtoMsg>,
    handle: JoinHandle<()>,
    retiring: bool,
    kind: Kind,
}

/// A single backpressured `Kind::UploadV2` command retained across awaits.
///
/// Exactly one exists globally. The unsent `message` stays manager-owned so a
/// cancelled flush cannot lose the inbound chunk; `failure` records why the
/// worker could not accept it so a resumed flush can emit a single error after
/// the worker joins.
struct PendingCommand {
    key: Key,
    generation: u64,
    message: ProtoMsg,
    deadline: Instant,
    failure: Option<&'static str>,
}

/// A single owned blocking `stat` job multiplexed by the manager.
///
/// At most one exists per manager, and the helper enforces one process-wide
/// permit. The handle is retained directly so it cannot be replaced until the
/// job is joined and the entry taken.
struct StatEntry {
    key: Key,
    header: ProtoHdr,
    handle: JoinHandle<Result<ProtoMsg>>,
    deadline: Instant,
    retiring: bool,
    timed_out: bool,
    cleanup_deadline: Option<Instant>,
}

/// Outcome of one `next_message` wait.
enum Wake {
    Event(Option<Event>),
    StatDone(std::result::Result<Result<ProtoMsg>, JoinError>),
    StatDeadline,
    Tick,
}

/// Outcome of one event-servicing upload-completion wait.
enum ServicingWake {
    Deadline,
    Joined(std::result::Result<(), JoinError>),
    Event(Option<Event>),
}

/// Multiplexes in-flight file transfers behind an exclusive `&mut` driver.
pub struct FileTransferManager {
    entries: HashMap<Key, Entry>,
    // Recently completed empty v1 downloads tolerate late ACK0 without
    // retaining a worker. The map is bounded and cleared on session teardown.
    empty_downloads: HashMap<Key, Instant>,
    generation: u64,
    events_sender: mpsc::Sender<Event>,
    events_receiver: mpsc::Receiver<Event>,
    pending: Option<(Key, u64, ProtoMsg)>,
    pending_command: Option<PendingCommand>,
    stat: Option<StatEntry>,
    limits: Option<Arc<TransferLimits>>,
}

impl FileTransferManager {
    /// Create an empty manager backed by a fresh shared event channel.
    pub fn new() -> Self {
        let (events_sender, events_receiver) = mpsc::channel(EVENT_CAPACITY);
        Self {
            entries: HashMap::new(),
            empty_downloads: HashMap::new(),
            generation: 0,
            events_sender,
            events_receiver,
            pending: None,
            pending_command: None,
            stat: None,
            limits: None,
        }
    }

    /// Create an empty manager bound to a limited execution context.
    ///
    /// Clones of the same `Arc<TransferLimits>` share the single rate counter
    /// and immutable policy, so totals accumulate across manager instances and
    /// the default unlimited behavior of [`Self::new`] is unchanged.
    pub fn with_limits(limits: Arc<TransferLimits>) -> Self {
        let mut manager = Self::new();
        manager.limits = Some(limits);
        manager
    }

    /// Handle one inbound protocol message, returning any immediate replies.
    ///
    /// Any structured error from a previously backpressured upload is flushed
    /// first and returned alongside this message's own replies, so unrelated
    /// input is never lost. A peer `error` that targets the stored command's
    /// key bypasses the flush and cancels promptly.
    pub async fn handle(&mut self, message: ProtoMsg) -> Result<Vec<ProtoMsg>> {
        let matches_pending = if message.header.msg_type == "error" {
            match (
                Key::from_header(&message.header).ok(),
                &self.pending_command,
            ) {
                (Some(key), Some(pending)) => key == pending.key,
                _ => false,
            }
        } else {
            false
        };

        let mut replies = Vec::new();
        if !matches_pending && let Some(reply) = self.flush_pending_command().await? {
            replies.push(reply);
        }
        replies.extend(self.handle_inner(message).await?);
        Ok(replies)
    }

    /// Process one inbound message after any pending backpressure flush.
    ///
    /// Finished transfers are reaped first, but a finished worker whose queued
    /// events have not been drained is deliberately left occupying a slot until
    /// the caller drains it via [`Self::next_message`].
    async fn handle_inner(&mut self, message: ProtoMsg) -> Result<Vec<ProtoMsg>> {
        self.reap_finished().await?;

        let key = match Key::from_header(&message.header) {
            Ok(key) => key,
            Err(_) => {
                return Ok(vec![file_transfer_task::error_reply(
                    &message.header,
                    "invalid key",
                )?]);
            }
        };

        let msg_type = message.header.msg_type.clone();
        match msg_type.as_str() {
            "stat" => self.handle_stat(&key, message).await,
            "get_file" => self.handle_get_file(key, message).await,
            "put_file" => self.handle_put_file(key, message).await,
            "ack" => {
                if !message.body.is_empty() {
                    let header = message.header.clone();
                    return self
                        .reject_and_retire(key, &header, "invalid ack body")
                        .await;
                }
                self.empty_downloads
                    .retain(|_, deadline| *deadline > Instant::now());
                let active_download = matches!(
                    self.entries.get(&key).map(|entry| &entry.kind),
                    Some(Kind::DownloadV1(_)) | Some(Kind::DownloadV2)
                );
                if !active_download
                    && self.empty_downloads.contains_key(&key)
                    && matches!(parse_offset(&message.header), Ok(0))
                {
                    return Ok(Vec::new());
                }
                let header = message.header.clone();
                self.dispatch_command(key, header, message).await
            }
            "file_chunk" => {
                if message.body.len() > CHUNK_CAP {
                    let header = message.header.clone();
                    return self
                        .reject_and_retire(key, &header, "chunk too large")
                        .await;
                }
                let header = message.header.clone();
                self.dispatch_command(key, header, message).await
            }
            "error" => self.handle_peer_error(&key).await,
            _ => Ok(vec![file_transfer_task::error_reply(
                &message.header,
                "unsupported message type",
            )?]),
        }
    }

    /// Produce the next outbound protocol message, waiting for worker events.
    pub async fn next_message(&mut self) -> Result<ProtoMsg> {
        if let Some(message) = self.flush_pending_command().await? {
            return Ok(message);
        }
        if let Some(message) = self.drain_pending().await? {
            return Ok(message);
        }
        loop {
            if matches!(&self.stat, Some(entry) if entry.retiring) {
                if let Some(message) = self.finish_stat_retirement().await? {
                    return Ok(message);
                }
                continue;
            }
            self.reap_finished().await?;
            if let Some(message) = self.flush_pending_command().await? {
                return Ok(message);
            }
            if let Some(message) = self.drain_pending().await? {
                return Ok(message);
            }

            let wake = match self.stat.as_mut() {
                Some(entry) => {
                    let events = &mut self.events_receiver;
                    tokio::select! {
                        biased;
                        _ = sleep_until(entry.deadline) => Wake::StatDeadline,
                        result = &mut entry.handle => Wake::StatDone(result),
                        maybe = events.recv() => Wake::Event(maybe),
                        () = sleep(TICK) => Wake::Tick,
                    }
                }
                None => {
                    let events = &mut self.events_receiver;
                    tokio::select! {
                        maybe = events.recv() => Wake::Event(maybe),
                        () = sleep(TICK) => Wake::Tick,
                    }
                }
            };

            match wake {
                Wake::Event(Some(event)) => {
                    if let Some(message) = self.process_event(event).await? {
                        return Ok(message);
                    }
                }
                Wake::Event(None) => return Err(anyhow!("file transfer event channel closed")),
                Wake::Tick => continue,
                Wake::StatDeadline => {
                    self.begin_stat_retirement();
                    if let Some(message) = self.finish_stat_retirement().await? {
                        return Ok(message);
                    }
                    continue;
                }
                Wake::StatDone(result) => {
                    return self.complete_stat(result);
                }
            }
        }
    }

    /// Deliver a stashed terminal message after its worker has fully joined.
    ///
    /// If a prior `next_message`/`process_event` future was cancelled after
    /// stashing `pending` but before completing retirement, the entry is still
    /// owned (with its `retiring` flag). We await that retained handle first and
    /// only then take `pending`, so no await happens between taking the message
    /// and returning it.
    async fn drain_pending(&mut self) -> Result<Option<ProtoMsg>> {
        let key = match &self.pending {
            Some((key, _generation, _message)) => key.clone(),
            None => return Ok(None),
        };
        self.finish_retirement(&key).await?;
        Ok(self
            .pending
            .take()
            .map(|(_key, _generation, message)| message))
    }

    /// Resume a backpressured UploadV2 command whose chunk is held in
    /// `pending_command`, returning an optional structured error once the worker
    /// can no longer accept it.
    ///
    /// The unsent message stays owned by the manager across the reserve await, so
    /// a cancelled future never loses the chunk. Deadlines are absolute and never
    /// reset by a cancelled or retried caller. On failure the stored command is
    /// retained through [`Self::retire`] until the worker joins, then a single
    /// error reply is emitted. The bounded four-second reserve, like the bounded
    /// four-second `stat` cleanup window, is a path where a `handle`/`next_message`
    /// call may stall the websocket driver; the worker is assumed to keep draining
    /// its command channel responsively.
    async fn flush_pending_command(&mut self) -> Result<Option<ProtoMsg>> {
        let key = match &self.pending_command {
            Some(pending) => pending.key.clone(),
            None => return Ok(None),
        };

        let already_failed =
            matches!(&self.pending_command, Some(pending) if pending.failure.is_some());

        if !already_failed {
            let valid = match self.entries.get(&key) {
                Some(entry) => {
                    let generation = entry.generation;
                    let retiring = entry.retiring;
                    matches!(&self.pending_command, Some(pending) if pending.generation == generation)
                        && !retiring
                }
                None => false,
            };
            if !valid {
                // Stale target: drop the stored command without emitting.
                self.pending_command = None;
                return Ok(None);
            }

            let deadline = match &self.pending_command {
                Some(pending) => pending.deadline,
                None => return Ok(None),
            };

            let sender = match self.entries.get(&key) {
                Some(entry) => entry.commands.clone(),
                None => {
                    self.pending_command = None;
                    return Ok(None);
                }
            };
            let permit_result = tokio::select! {
                biased;
                _ = tokio::time::sleep_until(deadline) => Err(()),
                result = sender.reserve_owned() => Ok(result),
            };

            match permit_result {
                Ok(Ok(permit)) => {
                    // Take the stored message and send it with no await in
                    // between; the permit already reserves capacity. A candidate
                    // upload EOF handoff records its completion phase here, since
                    // this is the actual handoff after backpressure.
                    if let Some(pending) = self.pending_command.take() {
                        let upload_eof = is_upload_eof(&pending.message);
                        permit.send(pending.message);
                        if upload_eof {
                            self.mark_upload_completing(&key);
                        }
                    }
                    return Ok(None);
                }
                Ok(Err(_closed)) => {
                    if let Some(pending) = self.pending_command.as_mut() {
                        pending.failure = Some("transfer unavailable");
                    }
                }
                Err(_elapsed) => {
                    if let Some(pending) = self.pending_command.as_mut() {
                        pending.failure = Some("transfer command queue full");
                    }
                }
            }
        }

        self.retire(&key).await?;

        let (header, reason) = match self.pending_command.take() {
            Some(pending) => (
                pending.message.header,
                pending.failure.unwrap_or("transfer command queue full"),
            ),
            None => return Ok(None),
        };
        Ok(Some(file_transfer_task::error_reply(&header, reason)?))
    }

    /// Abort and retire every transfer belonging to `sid` (both protocols).
    ///
    /// Uploads that have already accepted their EOF are awaited within their
    /// stored bounded completion deadline, so a valid but still-flushing upload
    /// commits before the worker is torn down; all other transfers are aborted
    /// and joined promptly. Any stale own pending reply is discarded first.
    ///
    /// This inline variant does *not* service unrelated events and is intended
    /// only for limited standalone/LAN drivers that serialize all manager
    /// access. The daemon uses [`Self::close_session_servicing`] instead, whose
    /// forwarding must be coordinated by a sole transport owner (see below).
    pub async fn close_session(&mut self, sid: &str) -> Result<()> {
        self.empty_downloads.retain(|key, _| key.sid != sid);
        if let Some((pending_key, _, _)) = &self.pending
            && pending_key.sid.as_str() == sid
        {
            self.pending = None;
        }
        if let Some(pending) = &self.pending_command
            && pending.key.sid.as_str() == sid
        {
            self.pending_command = None;
        }

        // Mark any matching stat lane retiring (quietly) and abort it before
        // awaiting anything.
        let stat_matches = matches!(&self.stat, Some(entry) if entry.key.sid.as_str() == sid);
        if stat_matches {
            self.begin_stat_cancel();
        }

        let keys: Vec<Key> = self
            .entries
            .keys()
            .filter(|key| key.sid.as_str() == sid)
            .cloned()
            .collect();

        // Uploads that have already accepted their EOF get a bounded window to
        // flush, sync and persist before being aborted; everything else is
        // aborted and joined promptly so pre-EOF cancellation stays immediate.
        let (completing, immediate): (Vec<Key>, Vec<Key>) = keys
            .into_iter()
            .partition(|key| self.upload_completion_deadline(key).is_some());

        // Abort all non-completing transfer handles before awaiting any (done
        // inside `retire_many`); the matching stat handle was aborted above.
        let mut first_error: Option<anyhow::Error> = None;
        if let Err(err) = self.retire_many(immediate).await {
            first_error = Some(err);
        }
        for key in completing {
            if let Err(err) = self.await_upload_completion(&key).await
                && first_error.is_none()
            {
                first_error = Some(err);
            }
        }
        if stat_matches
            && let Err(err) = self.finish_stat_retirement().await
            && first_error.is_none()
        {
            first_error = Some(err);
        }
        match first_error {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    /// Close every transfer belonging to `sid` while servicing unrelated events.
    ///
    /// This daemon-facing variant of [`Self::close_session`] keeps draining and
    /// processing the shared event queue while it waits for in-progress uploads
    /// to finish, forwarding every unrelated outbound reply to `sink` (typically
    /// the websocket transport) as it arrives. This prevents an unrelated
    /// transfer — for example a v2 download — from filling the bounded shared
    /// event queue and hitting its own send timeout while a scoped close waits.
    ///
    /// Replies belonging to `sid` (the closing session) and stale-generation
    /// events are suppressed and never forwarded, so nothing is buffered without
    /// bound. The upload completion deadline is absolute and is checked even
    /// under continuously ready unrelated events, so a busy unrelated transfer
    /// can never extend the close. A `sink` error aborts the wait immediately;
    /// every remaining handle stays owned by the manager for the normal
    /// supervisor cleanup path.
    ///
    /// This is deliberately *not* a fully non-blocking session close: inbound
    /// socket handling still waits for the bounded [`UPLOAD_COMPLETION_WINDOW`],
    /// and the closing upload's final ACK is not awaited once its session has
    /// closed. Only outbound event servicing is non-blocking here.
    ///
    /// `sink` must be the *sole* writer to the underlying transport and must
    /// never hold a lock (for example a transport mutex guard) across its
    /// `await`. A guard retained during a pending send can deadlock when a
    /// concurrently selected branch needs the same lock while this close future
    /// is suspended. Forward into a small bounded channel drained by the same
    /// owner that writes the transport instead.
    pub async fn close_session_servicing<F>(&mut self, sid: &str, mut sink: F) -> Result<()>
    where
        F: AsyncFnMut(ProtoMsg) -> Result<()>,
    {
        self.empty_downloads.retain(|key, _| key.sid != sid);
        if let Some((pending_key, _, _)) = &self.pending
            && pending_key.sid.as_str() == sid
        {
            self.pending = None;
        }
        if let Some(pending) = &self.pending_command
            && pending.key.sid.as_str() == sid
        {
            self.pending_command = None;
        }

        // Mark any matching stat lane retiring (quietly) and abort it before
        // awaiting anything.
        let stat_matches = matches!(&self.stat, Some(entry) if entry.key.sid.as_str() == sid);
        if stat_matches {
            self.begin_stat_cancel();
        }

        let keys: Vec<Key> = self
            .entries
            .keys()
            .filter(|key| key.sid.as_str() == sid)
            .cloned()
            .collect();

        // Uploads that have already accepted their EOF get a bounded, serviced
        // window to flush, sync and persist before being aborted; everything
        // else is aborted and joined promptly so pre-EOF cancellation stays
        // immediate.
        let (completing, immediate): (Vec<Key>, Vec<Key>) = keys
            .into_iter()
            .partition(|key| self.upload_completion_deadline(key).is_some());

        let mut first_error: Option<anyhow::Error> = None;
        if let Err(err) = self.retire_many(immediate).await {
            first_error = Some(err);
        }
        for key in completing {
            if let Err(err) = self
                .await_upload_completion_servicing(&key, sid, &mut sink)
                .await
            {
                // Propagate the (possibly sink) error promptly; any remaining
                // completing uploads stay owned for supervisor cleanup.
                if first_error.is_none() {
                    first_error = Some(err);
                }
                break;
            }
        }
        if stat_matches
            && let Err(err) = self.finish_stat_retirement().await
            && first_error.is_none()
        {
            first_error = Some(err);
        }

        // Discard any own-session reply stashed while servicing events so it can
        // never be delivered after the session has closed.
        if let Some((pending_key, _, _)) = &self.pending
            && pending_key.sid.as_str() == sid
        {
            self.pending = None;
        }

        match first_error {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    /// Abort and retire every active transfer.
    pub(crate) fn begin_close_all(&mut self) {
        self.empty_downloads.clear();
        self.pending = None;
        self.pending_command = None;
        self.begin_stat_cancel();
        for entry in self.entries.values_mut() {
            entry.retiring = true;
            entry.handle.abort();
        }
    }

    pub async fn close_all(&mut self) -> Result<()> {
        let stat_present = self.stat.is_some();
        self.begin_close_all();

        let keys: Vec<Key> = self.entries.keys().cloned().collect();
        let mut first_error: Option<anyhow::Error> = None;
        if let Err(err) = self.retire_many(keys).await {
            first_error = Some(err);
        }
        if stat_present
            && let Err(err) = self.finish_stat_retirement().await
            && first_error.is_none()
        {
            first_error = Some(err);
        }
        match first_error {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    async fn handle_stat(&mut self, key: &Key, message: ProtoMsg) -> Result<Vec<ProtoMsg>> {
        if message.body.len() > BODY_CAP {
            return Ok(vec![file_transfer_task::error_reply(
                &message.header,
                "request too large",
            )?]);
        }
        let stat: StatFile = match protocol::decode(&message.body) {
            Ok(value) => value,
            Err(_) => {
                return Ok(vec![file_transfer_task::error_reply(
                    &message.header,
                    "invalid stat request",
                )?]);
            }
        };
        let path = match file_transfer_schema::required_path(stat.path.as_deref()) {
            Ok(path) => path,
            Err(err) => {
                return Ok(vec![file_transfer_task::error_reply(
                    &message.header,
                    &err.to_string(),
                )?]);
            }
        };
        // A stat lane already occupied — even one whose finished reply has not
        // yet been delivered — rejects a second request as busy.
        if self.stat.is_some() {
            return Ok(vec![file_transfer_task::error_reply(
                &message.header,
                "stat busy",
            )?]);
        }
        let started = match &self.limits {
            Some(limits) => file_transfer_task::start_stat_limited(
                message.header.clone(),
                path.to_owned(),
                Some(limits.clone()),
            ),
            None => file_transfer_task::start_stat(message.header.clone(), path.to_owned()),
        };
        match started {
            Some(handle) => {
                self.stat = Some(StatEntry {
                    key: key.clone(),
                    header: message.header.clone(),
                    handle,
                    deadline: Instant::now() + STAT_ACTIVE_WINDOW,
                    retiring: false,
                    timed_out: false,
                    cleanup_deadline: None,
                });
                Ok(Vec::new())
            }
            None => Ok(vec![file_transfer_task::error_reply(
                &message.header,
                "stat busy",
            )?]),
        }
    }

    /// Mark the active `stat` lane retiring (quietly, not timed out) and abort
    /// it before any await. Sets the fixed cleanup deadline once and never
    /// resets it across cancel/retry cycles.
    fn begin_stat_cancel(&mut self) {
        if let Some(entry) = self.stat.as_mut() {
            entry.retiring = true;
            entry.timed_out = false;
            entry.handle.abort();
            if entry.cleanup_deadline.is_none() {
                entry.cleanup_deadline = Some(Instant::now() + STAT_CLEANUP_WINDOW);
            }
        }
    }

    /// Mark the active stat lane as timed out and abort it before awaiting.
    ///
    /// `timed_out` is stored before any await so a cancelled cleanup still
    /// yields a structured timeout reply on resume. The cleanup deadline is set
    /// only once and never reset across cancel/retry cycles.
    fn begin_stat_retirement(&mut self) {
        if let Some(entry) = self.stat.as_mut() {
            entry.timed_out = true;
            entry.retiring = true;
            entry.handle.abort();
            if entry.cleanup_deadline.is_none() {
                entry.cleanup_deadline = Some(Instant::now() + STAT_CLEANUP_WINDOW);
            }
        }
    }

    /// Await a retiring stat lane's retained handle under its stored cleanup
    /// deadline, then take the entry.
    ///
    /// Returns the structured timeout reply when the lane had timed out and the
    /// job has finally stopped. A cleanup-deadline expiry is fatal and leaves
    /// the entry (and the running blocking closure) owned. The entry is only
    /// taken after the join is ready, with no await between taking it and
    /// returning.
    async fn finish_stat_retirement(&mut self) -> Result<Option<ProtoMsg>> {
        let cleanup_deadline = match self.stat.as_ref().and_then(|entry| entry.cleanup_deadline) {
            Some(deadline) => deadline,
            None => return Ok(None),
        };
        let join_result = match self.stat.as_mut() {
            Some(entry) => Some(timeout_at(cleanup_deadline, &mut entry.handle).await),
            None => return Ok(None),
        };
        let join_result = match join_result {
            Some(result) => result,
            None => return Ok(None),
        };
        match join_result {
            Err(_elapsed) => Err(StatCleanupTimeout.into()),
            Ok(Ok(_message)) => {
                let entry = match self.stat.take() {
                    Some(entry) => entry,
                    None => return Ok(None),
                };
                if entry.timed_out {
                    Ok(Some(file_transfer_task::error_reply(
                        &entry.header,
                        "stat operation timed out",
                    )?))
                } else {
                    Ok(None)
                }
            }
            Ok(Err(join_error)) if join_error.is_cancelled() => {
                let entry = match self.stat.take() {
                    Some(entry) => entry,
                    None => return Ok(None),
                };
                if entry.timed_out {
                    Ok(Some(file_transfer_task::error_reply(
                        &entry.header,
                        "stat operation timed out",
                    )?))
                } else {
                    Ok(None)
                }
            }
            Ok(Err(join_error)) => {
                self.stat.take();
                Err(anyhow!("stat worker failed: {join_error}"))
            }
        }
    }

    /// Complete a successful stat join, taking the entry only after the join is
    /// ready and returning the job's result directly.
    fn complete_stat(
        &mut self,
        result: std::result::Result<Result<ProtoMsg>, JoinError>,
    ) -> Result<ProtoMsg> {
        let _entry = match self.stat.take() {
            Some(entry) => entry,
            None => return Err(anyhow!("stat entry lost after completion")),
        };
        match result {
            Ok(Ok(message)) => Ok(message),
            Ok(Err(err)) => Err(err),
            Err(join_error) if join_error.is_cancelled() => {
                Err(anyhow!("stat worker unexpectedly cancelled"))
            }
            Err(join_error) => Err(anyhow!("stat worker failed: {join_error}")),
        }
    }

    async fn handle_get_file(&mut self, key: Key, message: ProtoMsg) -> Result<Vec<ProtoMsg>> {
        if message.body.len() > BODY_CAP {
            return Ok(vec![file_transfer_task::error_reply(
                &message.header,
                "request too large",
            )?]);
        }
        let get: GetFile = match protocol::decode(&message.body) {
            Ok(value) => value,
            Err(_) => {
                return Ok(vec![file_transfer_task::error_reply(
                    &message.header,
                    "invalid get request",
                )?]);
            }
        };
        let path = match file_transfer_schema::required_path(get.path.as_deref()) {
            Ok(path) => path.to_string(),
            Err(err) => {
                return Ok(vec![file_transfer_task::error_reply(
                    &message.header,
                    &err.to_string(),
                )?]);
            }
        };
        let ProtoMsg { header, .. } = message;
        self.start_transfer(key, header, Request::Download(PathBuf::from(path)))
            .await
    }

    async fn handle_put_file(&mut self, key: Key, message: ProtoMsg) -> Result<Vec<ProtoMsg>> {
        if message.body.len() > BODY_CAP {
            return Ok(vec![file_transfer_task::error_reply(
                &message.header,
                "request too large",
            )?]);
        }
        let upload: UploadRequest = match protocol::decode(&message.body) {
            Ok(value) => value,
            Err(_) => {
                return Ok(vec![file_transfer_task::error_reply(
                    &message.header,
                    "invalid put request",
                )?]);
            }
        };
        if let Err(err) = file_transfer_schema::required_path(upload.path.as_deref()) {
            return Ok(vec![file_transfer_task::error_reply(
                &message.header,
                &err.to_string(),
            )?]);
        }
        if let Err(err) = file_transfer_schema::validate_requested_size(upload.size) {
            return Ok(vec![file_transfer_task::error_reply(
                &message.header,
                &err.to_string(),
            )?]);
        }
        let ProtoMsg { header, .. } = message;
        self.start_transfer(key, header, Request::Upload(upload))
            .await
    }

    async fn start_transfer(
        &mut self,
        key: Key,
        header: ProtoHdr,
        request: Request,
    ) -> Result<Vec<ProtoMsg>> {
        if matches!(self.entries.get(&key), Some(entry) if entry.retiring) {
            self.finish_retirement(&key).await?;
        }

        // A v1 download whose matching final ACK was dispatched is finishing
        // gracefully. Block same-key reuse until it joins or its stored deadline
        // elapses, keeping the entry and handle owned across the await.
        if self.is_download_v1_awaiting_completion(&key) {
            if self.await_download_completion(&key).await? {
                // Joined gracefully; the entry was removed inside the helper.
            } else {
                self.retire(&key).await?;
                return Ok(vec![file_transfer_task::error_reply(
                    &header,
                    "download completion timeout",
                )?]);
            }
        }

        if self.entries.contains_key(&key) {
            return Ok(vec![file_transfer_task::error_reply(
                &header,
                "transfer already active",
            )?]);
        }
        if self.entries.len() >= MAX_ENTRIES {
            return Ok(vec![file_transfer_task::error_reply(
                &header,
                "transfer capacity reached",
            )?]);
        }
        let generation = match self.generation.checked_add(1) {
            Some(generation) => generation,
            None => {
                return Ok(vec![file_transfer_task::error_reply(
                    &header,
                    "generation overflow",
                )?]);
            }
        };
        self.generation = generation;
        self.invalidate_pending_for(&key);

        // Derive the kind before `request` is moved into the worker task.
        let kind = transfer_kind(&key, &request);

        let (commands, commands_receiver) = mpsc::channel(COMMAND_CAPACITY);
        let events_sender = self.events_sender.clone();
        let worker_key = key.clone();
        let worker_header = header.clone();
        let handle = tokio::spawn(file_transfer_task::run(
            worker_key,
            generation,
            request,
            worker_header,
            commands_receiver,
            events_sender,
            self.limits.clone(),
        ));
        self.entries.insert(
            key,
            Entry {
                generation,
                commands,
                handle,
                retiring: false,
                kind,
            },
        );
        Ok(Vec::new())
    }

    async fn dispatch_command(
        &mut self,
        key: Key,
        header: ProtoHdr,
        message: ProtoMsg,
    ) -> Result<Vec<ProtoMsg>> {
        // Inspect any inbound ACK before the message is moved into the channel.
        let ack_match = self.classify_ack(&key, &header, &message);
        let is_upload_v2 = matches!(
            self.entries.get(&key).map(|entry| &entry.kind),
            Some(Kind::UploadV2(_))
        );
        // An empty `file_chunk` is the upload EOF marker for both protocols and
        // both empty and nonempty payloads. The completion phase is only
        // recorded once the command is actually handed to the worker; the
        // worker stays authoritative for offset/size validation and will refuse
        // a malformed EOF without committing.
        let upload_eof = is_upload_eof(&message)
            && matches!(
                self.entries.get(&key).map(|entry| &entry.kind),
                Some(Kind::UploadV1(_)) | Some(Kind::UploadV2(_))
            );
        let outcome = self
            .entries
            .get(&key)
            .map(|entry| entry.commands.try_send(message));
        match outcome {
            None => Ok(vec![file_transfer_task::error_reply(
                &header,
                "no active transfer",
            )?]),
            Some(Ok(())) => {
                if matches!(ack_match, AckMatch::Matching) {
                    self.set_awaiting_completion(&key);
                }
                if upload_eof {
                    self.mark_upload_completing(&key);
                }
                Ok(Vec::new())
            }
            Some(Err(mpsc::error::TrySendError::Closed(_)))
                if matches!(ack_match, AckMatch::Matching | AckMatch::DuplicateFinal) =>
            {
                // Worker already finished or dropped the command (e.g. the data
                // was already ACKed). Accept the matching final ACK so a later
                // graceful join can proceed instead of rejecting it.
                if matches!(ack_match, AckMatch::Matching) {
                    self.set_awaiting_completion(&key);
                }
                Ok(Vec::new())
            }
            Some(Err(mpsc::error::TrySendError::Full(returned_message))) if is_upload_v2 => {
                // UploadV2 backpressure: keep the unsent chunk manager-owned so a
                // cancelled flush cannot lose it. Only one pending command exists
                // globally; a second concurrent Full must not overwrite it.
                if self.pending_command.is_some() {
                    let reason = "transfer command queue full";
                    self.invalidate_pending_for(&key);
                    self.retire(&key).await?;
                    return Ok(vec![file_transfer_task::error_reply(&header, reason)?]);
                }
                let generation = match self.entries.get(&key) {
                    Some(entry) => entry.generation,
                    None => {
                        return Ok(vec![file_transfer_task::error_reply(
                            &header,
                            "no active transfer",
                        )?]);
                    }
                };
                self.pending_command = Some(PendingCommand {
                    key: key.clone(),
                    generation,
                    message: returned_message,
                    deadline: Instant::now() + COMMAND_RESERVE_WINDOW,
                    failure: None,
                });
                if let Some(reply) = self.flush_pending_command().await? {
                    return Ok(vec![reply]);
                }
                Ok(Vec::new())
            }
            Some(Err(err)) => {
                let reason = match err {
                    mpsc::error::TrySendError::Full(_) => "transfer command queue full",
                    mpsc::error::TrySendError::Closed(_) => "transfer unavailable",
                };
                self.invalidate_pending_for(&key);
                self.retire(&key).await?;
                Ok(vec![file_transfer_task::error_reply(&header, reason)?])
            }
        }
    }

    async fn reject_and_retire(
        &mut self,
        key: Key,
        header: &ProtoHdr,
        reason: &str,
    ) -> Result<Vec<ProtoMsg>> {
        self.invalidate_pending_for(&key);
        self.retire(&key).await?;
        Ok(vec![file_transfer_task::error_reply(header, reason)?])
    }

    async fn handle_peer_error(&mut self, key: &Key) -> Result<Vec<ProtoMsg>> {
        self.invalidate_pending_for(key);

        // A peer error targets exactly this `(proto, sid)` key. Mark and abort
        // the matching transfer and any exactly-matching `stat` lane before any
        // await so a cancelled cleanup still observes the retirement state.
        let stat_matches = matches!(&self.stat, Some(entry) if &entry.key == key);
        if stat_matches {
            self.begin_stat_cancel();
        }
        if let Some(entry) = self.entries.get_mut(key) {
            entry.retiring = true;
            entry.handle.abort();
        }

        // Await both retirements even if the first fails, collecting the first
        // error while never abandoning a retained handle.
        let mut first_error: Option<anyhow::Error> = None;
        if let Err(err) = self.finish_retirement(key).await {
            first_error = Some(err);
        }
        if stat_matches
            && let Err(err) = self.finish_stat_retirement().await
            && first_error.is_none()
        {
            first_error = Some(err);
        }

        // No reply: answering a peer error would risk an error loop.
        match first_error {
            Some(err) => Err(err),
            None => Ok(Vec::new()),
        }
    }

    async fn process_event(&mut self, event: Event) -> Result<Option<ProtoMsg>> {
        match event {
            Event::Message {
                key,
                generation,
                message,
                terminal,
            } => {
                if !self.matches_active(&key, generation) {
                    return Ok(None);
                }
                if !terminal {
                    // An empty v1 download chunk is the EOF marker, not a
                    // terminal event. Record its offset and keep the entry so
                    // the matching final ACK can be matched afterwards.
                    if message.header.msg_type == "file_chunk"
                        && message.body.is_empty()
                        && let Some(entry) = self.entries.get_mut(&key)
                        && matches!(&entry.kind, Kind::DownloadV1(DownloadPhase::Streaming))
                    {
                        let offset = parse_offset(&message.header)?;
                        if let Kind::DownloadV1(phase) = &mut entry.kind {
                            *phase = DownloadPhase::AwaitingAck { offset };
                        }
                    }
                    return Ok(Some(message));
                }
                // Stash before any await so a cancelled wait still yields the
                // message and never orphans the worker.
                let empty_v1_eof = key.proto == ProtoType::FILE_TRANSFER
                    && message.header.msg_type == "file_chunk"
                    && message.body.is_empty()
                    && matches!(parse_offset(&message.header), Ok(0));
                self.pending = Some((key.clone(), generation, message));
                if empty_v1_eof {
                    let deadline = Instant::now()
                        .checked_add(EMPTY_ACK_WINDOW)
                        .ok_or_else(|| anyhow!("empty acknowledgement deadline overflow"))?;
                    self.empty_downloads
                        .retain(|_, deadline| *deadline > Instant::now());
                    if self.empty_downloads.len() >= MAX_ENTRIES
                        && !self.empty_downloads.contains_key(&key)
                        && let Some(oldest) = self
                            .empty_downloads
                            .iter()
                            .min_by_key(|(_, deadline)| *deadline)
                            .map(|(key, _)| key.clone())
                    {
                        self.empty_downloads.remove(&oldest);
                    }
                    self.empty_downloads.insert(key.clone(), deadline);
                }
                self.retire(&key).await?;
                match self.pending.take() {
                    Some((_key, _generation, message)) => Ok(Some(message)),
                    None => Err(anyhow!("retired transfer message lost")),
                }
            }
            Event::Finished { key, generation } => {
                if !self.matches_active(&key, generation) {
                    return Ok(None);
                }
                self.retire(&key).await?;
                Ok(None)
            }
        }
    }

    fn matches_active(&self, key: &Key, generation: u64) -> bool {
        match self.entries.get(key) {
            Some(entry) => entry.generation == generation && !entry.retiring,
            None => false,
        }
    }

    fn invalidate_pending_for(&mut self, key: &Key) {
        let remove = matches!(&self.pending, Some((pending_key, _, _)) if pending_key == key);
        if remove {
            self.pending = None;
        }
        let remove_command = matches!(&self.pending_command, Some(pending) if &pending.key == key);
        if remove_command {
            self.pending_command = None;
        }
    }

    fn is_download_v1_awaiting_completion(&self, key: &Key) -> bool {
        matches!(
            self.entries.get(key).map(|entry| &entry.kind),
            Some(Kind::DownloadV1(DownloadPhase::AwaitingCompletion { .. }))
        )
    }

    fn classify_ack(&self, key: &Key, header: &ProtoHdr, message: &ProtoMsg) -> AckMatch {
        if header.msg_type != "ack" || !message.body.is_empty() {
            return AckMatch::NotMatching;
        }
        match self.entries.get(key).map(|entry| &entry.kind) {
            Some(Kind::DownloadV1(DownloadPhase::AwaitingAck { offset })) => {
                match parse_offset(header) {
                    Ok(ack_offset) if ack_offset == *offset => AckMatch::Matching,
                    _ => AckMatch::NotMatching,
                }
            }
            Some(Kind::DownloadV1(DownloadPhase::AwaitingCompletion { offset, .. })) => {
                match parse_offset(header) {
                    Ok(ack_offset) if ack_offset == *offset => AckMatch::DuplicateFinal,
                    _ => AckMatch::NotMatching,
                }
            }
            _ => AckMatch::NotMatching,
        }
    }

    fn set_awaiting_completion(&mut self, key: &Key) {
        if let Some(entry) = self.entries.get_mut(key)
            && let Kind::DownloadV1(phase) = &mut entry.kind
        {
            let (offset, deadline) = match phase {
                DownloadPhase::AwaitingAck { offset } => {
                    (*offset, Instant::now() + COMPLETION_WINDOW)
                }
                // Already awaiting completion: keep the original absolute
                // deadline so a duplicate final ACK never extends it.
                DownloadPhase::AwaitingCompletion { offset, deadline } => (*offset, *deadline),
                DownloadPhase::Streaming => return,
            };
            *phase = DownloadPhase::AwaitingCompletion { offset, deadline };
        }
    }

    /// Await a gracefully-completing v1 download under its stored absolute
    /// deadline, keeping the entry and handle owned across the await. Returns
    /// `Ok(true)` once joined (entry removed), `Ok(false)` on timeout (entry
    /// retained for the caller to retire), or a fatal join error.
    async fn await_download_completion(&mut self, key: &Key) -> Result<bool> {
        let deadline = match self.entries.get(key).map(|entry| &entry.kind) {
            Some(Kind::DownloadV1(DownloadPhase::AwaitingCompletion { deadline, .. })) => *deadline,
            _ => return Ok(false),
        };
        let join_result = match self.entries.get_mut(key) {
            Some(entry) => Some(timeout_at(deadline, &mut entry.handle).await),
            None => None,
        };
        match join_result {
            None => Ok(false),
            Some(Err(_elapsed)) => Ok(false),
            Some(Ok(Ok(()))) => {
                self.entries.remove(key);
                Ok(true)
            }
            Some(Ok(Err(err))) if err.is_cancelled() => {
                self.entries.remove(key);
                Ok(true)
            }
            Some(Ok(Err(err))) => {
                self.entries.remove(key);
                Err(anyhow!("transfer worker failed: {err}"))
            }
        }
    }

    /// Return the absolute completion deadline for an upload whose EOF has been
    /// accepted, if any.
    fn upload_completion_deadline(&self, key: &Key) -> Option<Instant> {
        match self.entries.get(key).map(|entry| &entry.kind) {
            Some(Kind::UploadV1(UploadPhase::Completing { deadline }))
            | Some(Kind::UploadV2(UploadPhase::Completing { deadline })) => Some(*deadline),
            _ => None,
        }
    }

    /// Record that a candidate upload EOF has been handed to the worker,
    /// starting the absolute completion window. Idempotent: a repeated or
    /// duplicate handoff never extends an existing deadline.
    fn mark_upload_completing(&mut self, key: &Key) {
        if let Some(entry) = self.entries.get_mut(key) {
            let phase = match &mut entry.kind {
                Kind::UploadV1(phase) => phase,
                Kind::UploadV2(phase) => phase,
                _ => return,
            };
            if matches!(phase, UploadPhase::Streaming) {
                *phase = UploadPhase::Completing {
                    deadline: Instant::now() + UPLOAD_COMPLETION_WINDOW,
                };
            }
        }
    }

    /// Await a completing upload within its stored absolute deadline, keeping
    /// the entry and handle owned across the await. Returns `Ok(())` once the
    /// worker joined (entry removed) or on a benign cancellation; on deadline
    /// expiry the worker is aborted and joined before returning.
    async fn await_upload_completion(&mut self, key: &Key) -> Result<()> {
        let deadline = match self.upload_completion_deadline(key) {
            Some(deadline) => deadline,
            None => return self.retire(key).await,
        };
        let join_result = match self.entries.get_mut(key) {
            Some(entry) => Some(timeout_at(deadline, &mut entry.handle).await),
            None => None,
        };
        match join_result {
            None => Ok(()),
            Some(Ok(Ok(()))) => {
                self.entries.remove(key);
                Ok(())
            }
            Some(Ok(Err(err))) if err.is_cancelled() => {
                self.entries.remove(key);
                Ok(())
            }
            Some(Ok(Err(err))) => {
                self.entries.remove(key);
                Err(anyhow!("transfer worker failed: {err}"))
            }
            Some(Err(_elapsed)) => {
                // Bounded window expired: abort and join so the staging file is
                // removed and the entry reclaimed.
                self.retire(key).await
            }
        }
    }

    /// Await a completing upload within its stored absolute deadline while
    /// continuing to drain and process shared events.
    ///
    /// Unrelated outbound replies are forwarded to `sink` as they arrive; replies
    /// for the closing `sid` and stale-generation events are suppressed. The
    /// deadline is checked on every iteration (biased first) so a continuously
    /// ready unrelated transfer can never extend it. On expiry the worker is
    /// aborted and joined before returning, exactly like
    /// [`Self::await_upload_completion`]. A `sink` error is propagated; the entry
    /// and handle stay owned across every await, so a cancelled or failed wait
    /// leaves the worker owned for supervisor cleanup.
    async fn await_upload_completion_servicing<F>(
        &mut self,
        key: &Key,
        sid: &str,
        sink: &mut F,
    ) -> Result<()>
    where
        F: AsyncFnMut(ProtoMsg) -> Result<()>,
    {
        loop {
            // Drain any retained terminal reply at the top of the loop, before
            // selecting or receiving a fresh event. If a previous wait was
            // cancelled while `drain_pending` was joining a retained handle,
            // the fresh event stays queue-owned and is not lost.
            if let Some(message) = self.drain_pending().await?
                && message.header.session_id != sid
            {
                sink(message).await?;
            }
            let deadline = match self.upload_completion_deadline(key) {
                Some(deadline) => deadline,
                None => {
                    // No longer a completing upload (e.g. already retired by its
                    // own terminal event); nothing left to wait for.
                    return self.retire(key).await;
                }
            };
            let wake = {
                // Borrow the event queue and the retained handle as disjoint
                // fields so both can be awaited in one `select!`.
                let events = &mut self.events_receiver;
                match self.entries.get_mut(key) {
                    Some(entry) => {
                        tokio::select! {
                            biased;
                            _ = sleep_until(deadline) => ServicingWake::Deadline,
                            result = &mut entry.handle => ServicingWake::Joined(result),
                            maybe = events.recv() => ServicingWake::Event(maybe),
                        }
                    }
                    None => return Ok(()),
                }
            };
            match wake {
                ServicingWake::Deadline => {
                    // Absolute window elapsed: abort and join so the staging file
                    // is removed and the entry reclaimed.
                    return self.retire(key).await;
                }
                ServicingWake::Joined(result) => {
                    self.entries.remove(key);
                    return match result {
                        Ok(()) => Ok(()),
                        Err(err) if err.is_cancelled() => Ok(()),
                        Err(err) => Err(anyhow!("transfer worker failed: {err}")),
                    };
                }
                ServicingWake::Event(Some(event)) => {
                    if let Some(message) = self.process_event(event).await? {
                        // Forward unrelated replies; suppress the closing
                        // session's own replies (stale generations are already
                        // filtered out by `process_event`).
                        if message.header.session_id != sid {
                            sink(message).await?;
                        }
                    }
                    // Re-check completion and the absolute deadline.
                }
                ServicingWake::Event(None) => {
                    return Err(anyhow!("file transfer event channel closed"));
                }
            }
        }
    }

    /// Mark an entry as retiring, abort its worker, then await the join while
    /// the entry stays owned in the map. If this future is cancelled during the
    /// await, the entry (with its `retiring` flag and still-owned handle) is
    /// retained so [`Self::finish_retirement`] can resume on a later call. Does
    /// not touch `pending`.
    async fn retire(&mut self, key: &Key) -> Result<()> {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.retiring = true;
            entry.handle.abort();
        }
        self.finish_retirement(key).await
    }

    /// Await the (already aborted) worker for `key` while its entry remains
    /// owned, then remove the entry. Cancellation-safe: a dropped future leaves
    /// the retiring entry and its handle in the map so a later call can resume
    /// the join before any terminal message is delivered.
    async fn finish_retirement(&mut self, key: &Key) -> Result<()> {
        let join_result = match self.entries.get_mut(key) {
            Some(entry) => {
                entry.handle.abort();
                Some((&mut entry.handle).await)
            }
            None => None,
        };
        self.entries.remove(key);
        match join_result {
            None => Ok(()),
            Some(Ok(())) => Ok(()),
            Some(Err(err)) if err.is_cancelled() => Ok(()),
            Some(Err(err)) => Err(anyhow!("transfer worker failed: {err}")),
        }
    }

    /// Mark and abort all selected entries first, then await and remove each in
    /// turn, collecting the first unexpected join error while never abandoning a
    /// handle. Handles are never moved out of the map across an await, so a
    /// cancelled caller leaves every unfinished handle owned by the manager.
    async fn retire_many(&mut self, keys: Vec<Key>) -> Result<()> {
        for key in &keys {
            if let Some(entry) = self.entries.get_mut(key) {
                entry.retiring = true;
                entry.handle.abort();
            }
        }
        let mut first_error: Option<anyhow::Error> = None;
        for key in &keys {
            if let Err(err) = self.finish_retirement(key).await
                && first_error.is_none()
            {
                first_error = Some(err);
            }
        }
        match first_error {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    /// Reap finished workers, but only when no events are queued.
    ///
    /// Keys are captured first; if the shared event queue is non-empty we defer
    /// all reaping so a finished worker's queued output is not discarded. It
    /// will be drained (with generation checks) by [`Self::next_message`].
    async fn reap_finished(&mut self) -> Result<()> {
        let finished: Vec<Key> = self
            .entries
            .iter()
            .filter(|(_key, entry)| entry.handle.is_finished())
            .map(|(key, _entry)| key.clone())
            .collect();
        if finished.is_empty() {
            return Ok(());
        }
        if !self.events_receiver.is_empty() {
            return Ok(());
        }
        for key in finished {
            self.retire(&key).await?;
        }
        Ok(())
    }
}

impl Default for FileTransferManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for FileTransferManager {
    fn drop(&mut self) {
        // Synchronous: abort only. We cannot await join handles here, so a task
        // may finish cancellation asynchronously after the manager is dropped.
        for entry in self.entries.values() {
            entry.handle.abort();
        }
        // A running blocking `stat` job cannot be forcibly cancelled; aborting
        // marks the retained handle while the process-wide permit stays held
        // until the kernel operation actually returns.
        if let Some(stat) = &self.stat {
            stat.handle.abort();
        }
    }
}

/// Derive the transfer kind from the protocol key and the request shape.
fn transfer_kind(key: &Key, request: &Request) -> Kind {
    let is_v1 = matches!(key.proto, protocol::ProtoType::FILE_TRANSFER);
    match request {
        Request::Download(_) => {
            if is_v1 {
                Kind::DownloadV1(DownloadPhase::Streaming)
            } else {
                Kind::DownloadV2
            }
        }
        Request::Upload(_) => {
            if is_v1 {
                Kind::UploadV1(UploadPhase::Streaming)
            } else {
                Kind::UploadV2(UploadPhase::Streaming)
            }
        }
    }
}

/// True when `message` is the upload end-of-file marker: an empty `file_chunk`.
fn is_upload_eof(message: &ProtoMsg) -> bool {
    message.header.msg_type == "file_chunk" && message.body.is_empty()
}

/// Parse the v1 download byte offset carried in a message header.
fn parse_offset(header: &ProtoHdr) -> Result<i64> {
    let offset = header
        .properties
        .get("offset")
        .and_then(rmpv::Value::as_i64)
        .ok_or_else(|| anyhow!("download offset missing or not a signed integer"))?;
    if offset < 0 {
        return Err(anyhow!("download offset invalid"));
    }
    Ok(offset)
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
impl FileTransferManager {
    pub(crate) async fn install_teardown_probe(
        &mut self,
    ) -> anyhow::Result<std::sync::Arc<std::sync::atomic::AtomicBool>> {
        if !self.entries.is_empty() {
            anyhow::bail!("probe manager is not empty");
        }
        let header = ProtoHdr {
            proto: crate::protocol::ProtoType::FILE_TRANSFER_V2,
            session_id: "probe-file".into(),
            ..ProtoHdr::default()
        };
        let key = Key::from_header(&header)?;
        let (commands, receiver) = mpsc::channel(COMMAND_CAPACITY);
        let (ready, started) = tokio::sync::oneshot::channel();
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let copy = flag.clone();
        let handle = tokio::spawn(async move {
            let _guard = TeardownProbeGuard(copy);
            let _receiver = receiver;
            let _ = ready.send(());
            std::future::pending::<()>().await;
        });
        self.entries.insert(
            key,
            Entry {
                generation: 1,
                commands,
                handle,
                retiring: false,
                kind: Kind::UploadV2(UploadPhase::Streaming),
            },
        );
        started.await?;
        Ok(flag)
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use crate::protocol::ProtoType;
    use std::collections::BTreeMap;
    use std::future::{Future, pending};
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};

    #[tokio::test]
    async fn late_ack_marker_does_not_intercept_active_download_ack() -> Result<()> {
        let header = ProtoHdr {
            proto: ProtoType::FILE_TRANSFER,
            session_id: "replacement".to_owned(),
            msg_type: "ack".to_owned(),
            properties: BTreeMap::from([("offset".to_owned(), 0.into())]),
        };
        let key = Key::from_header(&header)?;
        let mut manager = FileTransferManager::new();
        manager
            .empty_downloads
            .insert(key.clone(), Instant::now() + Duration::from_secs(30));
        let (commands, mut receiver) = mpsc::channel(COMMAND_CAPACITY);
        manager.entries.insert(
            key,
            Entry {
                generation: 1,
                commands,
                handle: tokio::spawn(pending::<()>()),
                retiring: false,
                kind: Kind::DownloadV1(DownloadPhase::Streaming),
            },
        );
        assert!(
            manager
                .handle(ProtoMsg {
                    header,
                    body: Vec::new()
                })
                .await?
                .is_empty()
        );
        assert_eq!(receiver.try_recv()?.header.msg_type, "ack");
        manager.close_all().await?;
        Ok(())
    }

    fn key(sid: &str) -> Key {
        Key::from_header(&ProtoHdr {
            proto: ProtoType::FILE_TRANSFER_V2,
            session_id: sid.to_owned(),
            ..ProtoHdr::default()
        })
        .expect("valid fixture identity")
    }

    fn frame(key: &Key, body: &[u8]) -> ProtoMsg {
        ProtoMsg {
            header: ProtoHdr {
                proto: key.proto,
                session_id: key.sid.clone(),
                msg_type: "file_chunk".to_owned(),
                properties: BTreeMap::new(),
            },
            body: body.to_vec(),
        }
    }

    fn install(manager: &mut FileTransferManager, key: Key, handle: JoinHandle<()>) {
        let (commands, _receiver) = mpsc::channel(COMMAND_CAPACITY);
        manager.entries.insert(
            key,
            Entry {
                generation: 1,
                commands,
                handle,
                retiring: false,
                kind: Kind::UploadV2(UploadPhase::Streaming),
            },
        );
    }

    fn poll_once<F: Future + ?Sized>(future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(Waker::noop()))
    }

    #[tokio::test]
    async fn begin_close_aborts_all_but_keeps_entries_until_join() -> Result<()> {
        let mut manager = FileTransferManager::new();
        let first = key("close-one");
        let second = key("close-two");
        install(&mut manager, first.clone(), tokio::spawn(pending()));
        install(&mut manager, second.clone(), tokio::spawn(pending()));
        manager.begin_close_all();
        manager.begin_close_all();
        for k in [&first, &second] {
            let entry = manager
                .entries
                .get(k)
                .ok_or_else(|| anyhow!("entry removed early"))?;
            assert!(entry.retiring);
        }
        tokio::time::timeout(Duration::from_secs(2), manager.close_all()).await??;
        assert!(manager.entries.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn pending_terminal_retirement_survives_cancel() -> Result<()> {
        let mut manager = FileTransferManager::new();
        let key = key("terminal");
        install(&mut manager, key.clone(), tokio::spawn(pending()));
        let expected = frame(&key, b"");
        manager
            .events_sender
            .try_send(Event::Message {
                key: key.clone(),
                generation: 1,
                message: expected.clone(),
                terminal: true,
            })
            .map_err(|_| anyhow!("fixture event queue unexpectedly full"))?;
        let mut drive = Box::pin(manager.next_message());
        assert!(poll_once(drive.as_mut()).is_pending());
        drop(drive);
        let entry = manager
            .entries
            .get(&key)
            .expect("retiring task stays owned");
        assert!(entry.retiring);
        assert!(
            manager.pending.is_some(),
            "terminal message stays owned too"
        );
        let actual = tokio::time::timeout(Duration::from_secs(2), manager.next_message()).await??;
        assert_eq!(actual, expected);
        assert!(manager.entries.is_empty());
        assert!(manager.pending.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn empty_eof_retirement_survives_cancel() -> Result<()> {
        let mut manager = FileTransferManager::new();
        let header = ProtoHdr {
            proto: ProtoType::FILE_TRANSFER,
            session_id: "empty-cancel".into(),
            msg_type: "file_chunk".into(),
            properties: BTreeMap::from([("offset".into(), 0.into())]),
        };
        let key = Key::from_header(&header)?;
        install(&mut manager, key.clone(), tokio::spawn(pending()));
        if let Some(entry) = manager.entries.get_mut(&key) {
            entry.kind = Kind::DownloadV1(DownloadPhase::Streaming);
        }
        let expected = ProtoMsg {
            header,
            body: Vec::new(),
        };
        manager.events_sender.try_send(Event::Message {
            key: key.clone(),
            generation: 1,
            message: expected.clone(),
            terminal: true,
        })?;
        let mut drive = Box::pin(manager.next_message());
        assert!(poll_once(drive.as_mut()).is_pending());
        drop(drive);
        assert!(
            manager
                .entries
                .get(&key)
                .is_some_and(|entry| entry.retiring)
        );
        assert!(manager.pending.is_some());
        assert!(manager.empty_downloads.contains_key(&key));
        let actual = tokio::time::timeout(Duration::from_secs(2), manager.next_message()).await??;
        assert_eq!(actual, expected);
        assert!(!manager.entries.contains_key(&key));
        assert!(manager.pending.is_none());
        assert!(
            tokio::time::timeout(Duration::from_millis(50), manager.next_message())
                .await
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn canceled_close_all_retains_all_join_handles() -> Result<()> {
        let mut manager = FileTransferManager::new();
        for sid in ["first", "second"] {
            install(&mut manager, key(sid), tokio::spawn(pending()));
        }
        let mut close = Box::pin(manager.close_all());
        assert!(poll_once(close.as_mut()).is_pending());
        drop(close);
        assert_eq!(manager.entries.len(), 2);
        assert!(manager.entries.values().all(|entry| entry.retiring));
        tokio::time::timeout(Duration::from_secs(2), manager.close_all()).await??;
        assert!(manager.entries.is_empty());
        Ok(())
    }

    fn install_full_upload(
        manager: &mut FileTransferManager,
        key: &Key,
    ) -> mpsc::Receiver<ProtoMsg> {
        let (commands, receiver) = mpsc::channel(COMMAND_CAPACITY);
        for _ in 0..COMMAND_CAPACITY {
            commands
                .try_send(frame(key, b"queued"))
                .expect("fill bounded fixture queue");
        }
        manager.entries.insert(
            key.clone(),
            Entry {
                generation: 1,
                commands,
                handle: tokio::spawn(pending()),
                retiring: false,
                kind: Kind::UploadV2(UploadPhase::Streaming),
            },
        );
        manager.pending_command = Some(PendingCommand {
            key: key.clone(),
            generation: 1,
            message: frame(key, b"owned unsent chunk"),
            deadline: Instant::now() + COMMAND_RESERVE_WINDOW,
            failure: None,
        });
        receiver
    }

    #[tokio::test]
    async fn canceled_command_reserve_preserves_and_sends_chunk_once() -> Result<()> {
        let mut manager = FileTransferManager::new();
        let key = key("reserve-cancel");
        let mut receiver = install_full_upload(&mut manager, &key);
        let mut flush = Box::pin(manager.flush_pending_command());
        assert!(poll_once(flush.as_mut()).is_pending());
        drop(flush);
        assert!(manager.pending_command.is_some());
        receiver.try_recv().expect("make exactly one queue slot");
        assert!(
            tokio::time::timeout(Duration::from_secs(2), manager.flush_pending_command())
                .await??
                .is_none()
        );
        assert!(manager.pending_command.is_none());
        let mut messages = Vec::new();
        while let Ok(message) = receiver.try_recv() {
            messages.push(message);
        }
        assert_eq!(messages.len(), COMMAND_CAPACITY);
        assert_eq!(
            messages.last().expect("last command").body,
            b"owned unsent chunk"
        );
        tokio::time::timeout(Duration::from_secs(2), manager.close_all()).await??;
        Ok(())
    }

    #[tokio::test]
    async fn canceled_command_reserve_keeps_absolute_deadline_and_cleanup_ownership() -> Result<()>
    {
        let mut manager = FileTransferManager::new();
        let key = key("reserve-expired");
        let mut receiver = install_full_upload(&mut manager, &key);
        let original_deadline = manager
            .pending_command
            .as_ref()
            .expect("stored command")
            .deadline;
        let mut flush = Box::pin(manager.flush_pending_command());
        assert!(poll_once(flush.as_mut()).is_pending());
        drop(flush);
        tokio::time::pause();
        tokio::time::advance(COMMAND_RESERVE_WINDOW + Duration::from_secs(1)).await;
        receiver
            .try_recv()
            .expect("queue becomes writable only after expiry");
        let mut flush = Box::pin(manager.flush_pending_command());
        assert!(
            poll_once(flush.as_mut()).is_pending(),
            "expired command must join aborted worker before replying"
        );
        drop(flush);
        let stored = manager
            .pending_command
            .as_ref()
            .expect("failure remains owned through cleanup");
        assert_eq!(stored.deadline, original_deadline);
        assert!(stored.failure.is_some());
        assert!(
            manager
                .entries
                .get(&key)
                .expect("retiring task stays owned")
                .retiring
        );
        tokio::time::resume();
        let reply = tokio::time::timeout(Duration::from_secs(2), manager.flush_pending_command())
            .await??
            .expect("deadline error reply");
        assert_eq!(reply.header.msg_type, "error");
        assert!(manager.entries.is_empty());
        assert!(manager.pending_command.is_none());
        assert_eq!(
            receiver.len(),
            COMMAND_CAPACITY - 1,
            "expired chunk must never enqueue even if capacity is available"
        );
        Ok(())
    }

    #[tokio::test]
    async fn lost_finished_notification_preserves_queued_output() -> Result<()> {
        let mut manager = FileTransferManager::new();
        let key = key("lost-finished");
        let handle = tokio::spawn(async {});
        tokio::time::timeout(Duration::from_secs(2), async {
            while !handle.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        install(&mut manager, key.clone(), handle);
        let expected = frame(&key, b"last queued data");
        manager
            .events_sender
            .try_send(Event::Message {
                key: key.clone(),
                generation: 1,
                message: expected.clone(),
                terminal: false,
            })
            .map_err(|_| anyhow!("fixture event queue unexpectedly full"))?;
        manager.reap_finished().await?;
        assert!(
            manager.entries.contains_key(&key),
            "queued output prevents early reaping"
        );
        let actual = tokio::time::timeout(Duration::from_secs(2), manager.next_message()).await??;
        assert_eq!(actual, expected);
        manager.reap_finished().await?;
        assert!(
            manager.entries.is_empty(),
            "completion reaped without a Finished event"
        );
        Ok(())
    }

    async fn install_blocked_stat(
        manager: &mut FileTransferManager,
    ) -> Result<std::sync::mpsc::Sender<()>> {
        let key = key("blocked-stat");
        let header = ProtoHdr {
            proto: key.proto,
            session_id: key.sid.clone(),
            msg_type: "stat".to_owned(),
            properties: BTreeMap::new(),
        };
        let reply = ProtoMsg {
            header: header.clone(),
            body: Vec::new(),
        };
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let (started, start) = tokio::sync::oneshot::channel();
        let handle = tokio::task::spawn_blocking(move || {
            let _ = started.send(());
            let _ = wait.recv();
            Ok(reply)
        });
        manager.stat = Some(StatEntry {
            key,
            header,
            handle,
            deadline: Instant::now() + STAT_ACTIVE_WINDOW,
            retiring: false,
            timed_out: false,
            cleanup_deadline: None,
        });
        tokio::time::timeout(Duration::from_secs(2), start).await??;
        Ok(release)
    }

    #[tokio::test]
    async fn repeated_begin_close_preserves_stat_cleanup_deadline() -> Result<()> {
        let mut manager = FileTransferManager::new();
        let release = install_blocked_stat(&mut manager).await?;
        manager.begin_close_all();
        let deadline = manager
            .stat
            .as_ref()
            .and_then(|entry| entry.cleanup_deadline)
            .ok_or_else(|| anyhow!("cleanup deadline missing"))?;
        tokio::task::yield_now().await;
        manager.begin_close_all();
        assert_eq!(
            manager
                .stat
                .as_ref()
                .and_then(|entry| entry.cleanup_deadline),
            Some(deadline)
        );
        release.send(())?;
        tokio::time::timeout(Duration::from_secs(2), manager.close_all()).await??;
        assert!(manager.stat.is_none());
        Ok(())
    }

    async fn wait_stat_finished(manager: &FileTransferManager) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(2), async {
            while manager
                .stat
                .as_ref()
                .is_some_and(|entry| !entry.handle.is_finished())
            {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok(())
    }

    #[tokio::test]
    async fn blocked_stat_cleanup_is_bounded_fatal_and_keeps_handle_owned() -> Result<()> {
        let mut manager = FileTransferManager::new();
        // Dropping this sender always releases the fixture's real blocking job,
        // including on assertion unwind, so runtime shutdown cannot hang.
        let release = install_blocked_stat(&mut manager).await?;
        tokio::time::pause();
        tokio::time::advance(STAT_ACTIVE_WINDOW + Duration::from_secs(1)).await;
        let mut drive = Box::pin(manager.next_message());
        assert!(poll_once(drive.as_mut()).is_pending());
        drop(drive);
        let cleanup_deadline = manager
            .stat
            .as_ref()
            .expect("retained stat")
            .cleanup_deadline;
        assert!(manager.stat.as_ref().expect("retained stat").timed_out);
        tokio::time::advance(STAT_CLEANUP_WINDOW + Duration::from_secs(1)).await;
        let error = manager
            .next_message()
            .await
            .expect_err("blocked cleanup is fatal");
        assert!(error.downcast_ref::<StatCleanupTimeout>().is_some());
        let retained = manager
            .stat
            .as_ref()
            .expect("fatal cleanup never detaches running job");
        assert!(retained.retiring);
        assert_eq!(retained.cleanup_deadline, cleanup_deadline);
        let error = manager
            .close_all()
            .await
            .expect_err("retry cannot reset deadline");
        assert!(error.downcast_ref::<StatCleanupTimeout>().is_some());
        assert_eq!(
            manager
                .stat
                .as_ref()
                .expect("retained stat")
                .cleanup_deadline,
            cleanup_deadline
        );
        tokio::time::resume();
        drop(release);
        wait_stat_finished(&manager).await?;
        tokio::time::timeout(Duration::from_secs(2), manager.close_all()).await??;
        assert!(manager.stat.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn canceled_stat_timeout_cleanup_returns_one_correlated_error_after_exit() -> Result<()> {
        let mut manager = FileTransferManager::new();
        let release = install_blocked_stat(&mut manager).await?;
        tokio::time::pause();
        tokio::time::advance(STAT_ACTIVE_WINDOW + Duration::from_secs(1)).await;
        let mut drive = Box::pin(manager.next_message());
        assert!(poll_once(drive.as_mut()).is_pending());
        drop(drive);
        assert!(manager.stat.as_ref().expect("retained stat").timed_out);
        tokio::time::resume();
        drop(release);
        wait_stat_finished(&manager).await?;
        let reply = tokio::time::timeout(Duration::from_secs(2), manager.next_message()).await??;
        assert_eq!(reply.header.msg_type, "error");
        assert_eq!(reply.header.session_id, "blocked-stat");
        let error: file_transfer_schema::TransferError = protocol::decode(&reply.body)?;
        assert_eq!(error.msgtype.as_deref(), Some("stat"));
        assert!(
            error
                .err
                .as_deref()
                .is_some_and(|reason| reason.contains("timed out"))
        );
        assert!(manager.stat.is_none());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), manager.next_message())
                .await
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn peer_error_cancels_only_exact_stat_key_and_retains_cleanup_on_cancel() -> Result<()> {
        let mut manager = FileTransferManager::new();
        let release = install_blocked_stat(&mut manager).await?;
        let mut wrong_protocol = frame(&key("blocked-stat"), b"");
        wrong_protocol.header.proto = ProtoType::FILE_TRANSFER;
        wrong_protocol.header.msg_type = "error".to_owned();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), manager.handle(wrong_protocol))
                .await??
                .is_empty()
        );
        assert!(
            !manager
                .stat
                .as_ref()
                .expect("other protocol stat preserved")
                .retiring
        );
        let mut matching = frame(&key("blocked-stat"), b"");
        matching.header.msg_type = "error".to_owned();
        let mut cancel = Box::pin(manager.handle(matching));
        assert!(poll_once(cancel.as_mut()).is_pending());
        drop(cancel);
        assert!(
            manager
                .stat
                .as_ref()
                .expect("canceled wait retains stat handle")
                .retiring
        );
        assert!(
            !manager
                .stat
                .as_ref()
                .expect("peer cancel is quiet")
                .timed_out
        );
        drop(release);
        wait_stat_finished(&manager).await?;
        tokio::time::timeout(
            Duration::from_secs(2),
            manager.close_session("blocked-stat"),
        )
        .await??;
        assert!(manager.stat.is_none());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), manager.next_message())
                .await
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn four_transfers_allow_same_key_stat_and_scoped_cancel_reclaims_both_protocols()
    -> Result<()> {
        let mut manager = FileTransferManager::new();
        let shared_v2 = key("shared");
        let shared_v1 = Key::from_header(&ProtoHdr {
            proto: ProtoType::FILE_TRANSFER,
            session_id: "shared".to_owned(),
            ..ProtoHdr::default()
        })?;
        for key in [shared_v1, shared_v2.clone(), key("third"), key("fourth")] {
            install(&mut manager, key, tokio::spawn(pending()));
        }
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("sample");
        std::fs::write(&path, b"sample")?;
        let mut stat = frame(&shared_v2, b"");
        stat.header.msg_type = "stat".to_owned();
        stat.body = protocol::encode(&StatFile {
            path: Some(path.to_string_lossy().into_owned()),
        })?;
        assert!(
            tokio::time::timeout(Duration::from_secs(2), manager.handle(stat))
                .await??
                .is_empty()
        );
        let reply = tokio::time::timeout(Duration::from_secs(2), manager.next_message()).await??;
        assert_eq!(reply.header.msg_type, "file_info");
        assert_eq!(
            manager.entries.len(),
            4,
            "stat never replaces the active transfer"
        );
        let mut fifth = frame(&key("fifth"), b"");
        fifth.header.msg_type = "put_file".to_owned();
        fifth.body = protocol::encode(&UploadRequest {
            path: Some(path.to_string_lossy().into_owned()),
            src_path: None,
            size: Some(0),
            uid: None,
            gid: None,
            mode: None,
            modtime: None,
        })?;
        let replies = tokio::time::timeout(Duration::from_secs(2), manager.handle(fifth)).await??;
        assert_eq!(replies.len(), 1);
        assert_eq!(
            replies.first().expect("capacity rejection").header.msg_type,
            "error"
        );
        assert_eq!(manager.entries.len(), 4);
        tokio::time::timeout(Duration::from_secs(2), manager.close_session("shared")).await??;
        assert_eq!(
            manager.entries.len(),
            2,
            "both protocols canceled for shared SID"
        );
        tokio::time::timeout(Duration::from_secs(2), manager.close_all()).await??;
        Ok(())
    }

    #[tokio::test]
    async fn stale_generation_messages_and_finished_never_affect_replacement() -> Result<()> {
        let mut manager = FileTransferManager::new();
        let key = key("reused");
        install(&mut manager, key.clone(), tokio::spawn(pending()));
        manager
            .entries
            .get_mut(&key)
            .expect("fixture entry")
            .generation = 2;
        for event in [
            Event::Message {
                key: key.clone(),
                generation: 1,
                message: frame(&key, b"stale"),
                terminal: true,
            },
            Event::Finished {
                key: key.clone(),
                generation: 1,
            },
            Event::Message {
                key: key.clone(),
                generation: 2,
                message: frame(&key, b"current"),
                terminal: false,
            },
        ] {
            manager
                .events_sender
                .try_send(event)
                .map_err(|_| anyhow!("fixture event capacity"))?;
        }
        let reply = tokio::time::timeout(Duration::from_secs(2), manager.next_message()).await??;
        assert_eq!(reply.body, b"current");
        assert_eq!(
            manager
                .entries
                .get(&key)
                .expect("replacement survives")
                .generation,
            2
        );
        tokio::time::timeout(Duration::from_secs(2), manager.close_all()).await??;
        Ok(())
    }

    fn install_completing(manager: &mut FileTransferManager, key: Key, handle: JoinHandle<()>) {
        let (commands, _receiver) = mpsc::channel(COMMAND_CAPACITY);
        manager.entries.insert(
            key,
            Entry {
                generation: 1,
                commands,
                handle,
                retiring: false,
                kind: Kind::UploadV2(UploadPhase::Completing {
                    deadline: Instant::now() + UPLOAD_COMPLETION_WINDOW,
                }),
            },
        );
    }

    #[tokio::test]
    async fn close_session_reaps_completing_upload_within_deadline() -> Result<()> {
        let mut manager = FileTransferManager::new();
        let key = key("complete-ok");
        install_completing(&mut manager, key.clone(), tokio::spawn(async {}));
        tokio::time::timeout(Duration::from_secs(2), manager.close_session("complete-ok"))
            .await??;
        assert!(manager.entries.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn completing_upload_keeps_absolute_deadline_then_aborts_on_expiry() -> Result<()> {
        let mut manager = FileTransferManager::new();
        let key = key("complete-stuck");
        install_completing(&mut manager, key.clone(), tokio::spawn(pending()));
        let stored = manager
            .upload_completion_deadline(&key)
            .expect("completing deadline stored");
        tokio::time::pause();
        let mut close = Box::pin(manager.close_session("complete-stuck"));
        assert!(poll_once(close.as_mut()).is_pending());
        drop(close);
        assert_eq!(
            manager.upload_completion_deadline(&key),
            Some(stored),
            "cancelled wait preserves the absolute deadline"
        );
        tokio::time::advance(UPLOAD_COMPLETION_WINDOW + Duration::from_secs(1)).await;
        tokio::time::resume();
        tokio::time::timeout(
            Duration::from_secs(2),
            manager.close_session("complete-stuck"),
        )
        .await??;
        assert!(manager.entries.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn backpressured_eof_handoff_records_completion_phase_once() -> Result<()> {
        let mut manager = FileTransferManager::new();
        let key = key("reserve-eof");
        let (commands, mut receiver) = mpsc::channel(COMMAND_CAPACITY);
        for _ in 0..COMMAND_CAPACITY {
            commands
                .try_send(frame(&key, b"queued"))
                .map_err(|_| anyhow!("fill bounded fixture queue"))?;
        }
        manager.entries.insert(
            key.clone(),
            Entry {
                generation: 1,
                commands,
                handle: tokio::spawn(pending()),
                retiring: false,
                kind: Kind::UploadV2(UploadPhase::Streaming),
            },
        );
        manager.pending_command = Some(PendingCommand {
            key: key.clone(),
            generation: 1,
            message: frame(&key, b""),
            deadline: Instant::now() + COMMAND_RESERVE_WINDOW,
            failure: None,
        });
        let _ = receiver
            .try_recv()
            .map_err(|_| anyhow!("fixture queue unexpectedly empty"))?;
        let outcome =
            tokio::time::timeout(Duration::from_secs(2), manager.flush_pending_command()).await??;
        assert!(outcome.is_none());
        assert!(manager.pending_command.is_none());
        let stored = manager
            .upload_completion_deadline(&key)
            .expect("candidate EOF records completion phase");
        assert_eq!(manager.upload_completion_deadline(&key), Some(stored));
        tokio::time::timeout(Duration::from_secs(2), manager.close_all()).await??;
        Ok(())
    }

    #[tokio::test]
    async fn peer_error_aborts_active_upload_and_close_all_reclaims() -> Result<()> {
        let mut manager = FileTransferManager::new();
        let key = key("peer-abort");
        install(&mut manager, key.clone(), tokio::spawn(pending()));
        let mut error = frame(&key, b"");
        error.header.msg_type = "error".to_owned();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), manager.handle(error))
                .await??
                .is_empty()
        );
        assert!(manager.entries.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn close_all_aborts_completing_upload_without_waiting_for_window() -> Result<()> {
        let mut manager = FileTransferManager::new();
        let key = key("close-all-abort");
        install_completing(&mut manager, key.clone(), tokio::spawn(pending()));
        tokio::time::timeout(Duration::from_secs(2), manager.close_all()).await??;
        assert!(manager.entries.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn scoped_close_services_unrelated_download_over_full_event_queue() -> Result<()> {
        let mut manager = FileTransferManager::new();

        // A synthetic completing upload is held open by a oneshot; it only
        // finishes after the unrelated download has streamed every byte while
        // the scoped close is still waiting inside its bounded window.
        let closing = key("closing");
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let held = tokio::spawn(async move {
            let _ = release_rx.await;
        });
        install_completing(&mut manager, closing.clone(), held);

        // A real v2 download large enough to exceed the shared event queue.
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("big.bin");
        let data: Vec<u8> = (0u8..=250).cycle().take(300_000).collect();
        std::fs::write(&path, &data)?;
        let get = ProtoMsg {
            header: ProtoHdr {
                proto: ProtoType::FILE_TRANSFER_V2,
                session_id: "unrelated".to_owned(),
                msg_type: "get_file".to_owned(),
                properties: BTreeMap::new(),
            },
            body: protocol::encode(&crate::file_transfer_schema::GetFile {
                path: Some(path.to_string_lossy().into_owned()),
            })?,
        };
        assert!(manager.handle(get).await?.is_empty());

        let mut collected: Vec<ProtoMsg> = Vec::new();
        let mut release = Some(release_tx);
        let close_result = tokio::time::timeout(
            Duration::from_secs(5),
            manager.close_session_servicing("closing", async |message: ProtoMsg| {
                // The terminal empty EOF of the unrelated download is forwarded
                // only because events are being serviced mid-close; release the
                // held completing upload once it arrives.
                if message.header.msg_type == "file_chunk"
                    && message.body.is_empty()
                    && let Some(tx) = release.take()
                {
                    let _ = tx.send(());
                }
                collected.push(message);
                Ok::<(), anyhow::Error>(())
            }),
        )
        .await;

        assert!(
            matches!(close_result, Ok(Ok(()))),
            "scoped close with event servicing must complete"
        );
        assert!(manager.entries.is_empty(), "all transfers reclaimed");

        // Every downloaded byte must have been forwarded through the sink while
        // the completing upload was still held open; nothing was lost.
        let streamed: Vec<u8> = collected
            .iter()
            .filter(|message| !message.body.is_empty())
            .flat_map(|message| message.body.iter().copied())
            .collect();
        assert_eq!(streamed, data, "unrelated download fully delivered");
        assert!(
            data.len() > EVENT_CAPACITY * 4096,
            "download must exceed the shared event queue"
        );
        Ok(())
    }

    #[tokio::test]
    async fn servicing_close_propagates_sink_error_and_keeps_handles_owned() -> Result<()> {
        let mut manager = FileTransferManager::new();
        let closing = key("closing");
        let (_release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        manager.entries.insert(
            closing.clone(),
            Entry {
                generation: 1,
                commands: mpsc::channel(COMMAND_CAPACITY).0,
                handle: tokio::spawn(async move {
                    let _ = release_rx.await;
                }),
                retiring: false,
                kind: Kind::UploadV2(UploadPhase::Completing {
                    deadline: Instant::now() + UPLOAD_COMPLETION_WINDOW,
                }),
            },
        );

        // A queued unrelated reply forces the sink to be invoked, which errors.
        let unrelated = key("other");
        manager.entries.insert(
            unrelated.clone(),
            Entry {
                generation: 1,
                commands: mpsc::channel(COMMAND_CAPACITY).0,
                handle: tokio::spawn(pending()),
                retiring: false,
                kind: Kind::UploadV2(UploadPhase::Streaming),
            },
        );
        manager
            .events_sender
            .try_send(Event::Message {
                key: unrelated.clone(),
                generation: 1,
                message: frame(&unrelated, b"data"),
                terminal: false,
            })
            .map_err(|_| anyhow!("fixture event queue unexpectedly full"))?;

        let error = tokio::time::timeout(
            Duration::from_secs(2),
            manager.close_session_servicing("closing", async |_message: ProtoMsg| {
                Err(anyhow!("sink failed"))
            }),
        )
        .await?
        .err()
        .ok_or_else(|| anyhow!("expected sink failure"))?;
        // The error must register as a failed close.
        assert_eq!(error.to_string(), "sink failed");
        Ok(())
    }

    #[tokio::test]
    async fn servicing_close_cancellation_preserves_fresh_terminal_and_forwards_both_once()
    -> Result<()> {
        let mut manager = FileTransferManager::new();

        // A completing upload held open until both terminal replies have been
        // forwarded through the retried close's servicing sink.
        let closing = key("closing");
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        install_completing(
            &mut manager,
            closing.clone(),
            tokio::spawn(async move {
                let _ = release_rx.await;
            }),
        );

        // Key "a": its terminal event is stashed in `pending` after a cancelled
        // `next_message`, with the entry (and handle) still owned and retiring.
        let a = key("a");
        install(&mut manager, a.clone(), tokio::spawn(pending()));
        let first = frame(&a, b"");
        manager
            .events_sender
            .try_send(Event::Message {
                key: a.clone(),
                generation: 1,
                message: first.clone(),
                terminal: true,
            })
            .map_err(|_| anyhow!("fixture event queue unexpectedly full"))?;
        let mut drive = Box::pin(manager.next_message());
        assert!(poll_once(drive.as_mut()).is_pending());
        drop(drive);
        assert!(manager.entries.get(&a).expect("a retained").retiring);
        assert!(manager.pending.is_some(), "terminal reply stashed");

        // Key "b": a fresh terminal event must stay queue-owned while the
        // first serviced close is cancelled inside `drain_pending`.
        let b = key("b");
        install(&mut manager, b.clone(), tokio::spawn(async {}));
        let second = frame(&b, b"second");
        manager
            .events_sender
            .try_send(Event::Message {
                key: b.clone(),
                generation: 1,
                message: second.clone(),
                terminal: true,
            })
            .map_err(|_| anyhow!("fixture event queue unexpectedly full"))?;

        let first_sink = async |_message: ProtoMsg| Ok::<(), anyhow::Error>(());
        let mut close = Box::pin(
            manager.close_session_servicing("closing", async |message: ProtoMsg| {
                first_sink(message).await
            }),
        );
        assert!(
            poll_once(close.as_mut()).is_pending(),
            "serviced close must await pending retirement"
        );
        drop(close);
        assert!(manager.pending.is_some(), "pending terminal stays owned");
        assert!(manager.entries.get(&a).expect("a retained").retiring);
        assert!(
            !manager.events_receiver.is_empty(),
            "fresh terminal remains queue-owned during cancellation"
        );

        let mut collected: Vec<ProtoMsg> = Vec::new();
        let mut release = Some(release_tx);
        let close = tokio::time::timeout(
            Duration::from_secs(5),
            manager.close_session_servicing("closing", async |message: ProtoMsg| {
                if message.header.session_id == "closing" {
                    return Err(anyhow!("closing reply must be suppressed"));
                }
                collected.push(message);
                if collected.len() == 2
                    && let Some(tx) = release.take()
                {
                    let _ = tx.send(());
                }
                Ok::<(), anyhow::Error>(())
            }),
        )
        .await;

        assert!(matches!(close, Ok(Ok(()))), "serviced close must complete");
        assert_eq!(collected.len(), 2, "both replies forwarded exactly once");
        assert_eq!(collected[0], first, "stashed pending forwarded first");
        assert_eq!(collected[1], second, "fresh terminal forwarded second");
        assert!(manager.pending.is_none());
        assert!(manager.entries.is_empty(), "no retained handles lost");
        Ok(())
    }
}
