//! Crate-private helper that owns a single file transfer worker.
//!
//! A `FileTransferManager` is expected to spawn *exactly one* owned outer task
//! that calls [`run`]. `run` itself never spawns tasks: it builds one pinned
//! worker future and drives it to completion while relaying worker output to
//! the manager over a bounded channel.
//!
//! [`start_stat`] is different: it creates exactly one caller-owned blocking
//! job for a metadata (`stat`) request. Callers own and await the returned
//! [`tokio::task::JoinHandle`] directly; no detached supervisor task is spawned.
//! A process-wide single permit bounds outstanding `stat` jobs to one across all
//! manager instances and reconnects, and the permit is held inside the actual
//! blocking closure so it is released only when the kernel metadata operation
//! returns. Because a running kernel operation cannot be forcibly cancelled,
//! this bound remains intact even if the manager drops or aborts the handle.
//!
//! Backpressure is intentional: while the manager blocks forwarding an event,
//! the worker future is not polled. Every channel interaction is time-bounded so
//! a stalled peer or a stalled manager cannot wedge the task forever. The worker
//! relies on the kernel promptly completing operations on local regular files;
//! per-operation deadlines are only observed between completed synchronous
//! filesystem calls.
//!
//! Protocol-specific terminal tagging:
//!
//! * **Upload (v1 and v2)** — initial and per-chunk acknowledgements are never
//!   terminal. The worker sends its final acknowledgement and returns in the
//!   same poll (the local channel has capacity for the pending messages), so
//!   after the worker future completes we drain the local channel and tag the
//!   final `ack` as terminal only when the worker reports `Complete` (never for
//!   a successful abort).
//! * **Download v2** — the terminating empty `file_chunk` is held until the
//!   worker reports success, then relayed as terminal.
//! * **Download v1** — an empty-file EOF is terminal after worker success;
//!   nonempty transfers use the trailing [`Event::Finished`].

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::pin::pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Result, bail};
use rmpv::Value;
use tokio::sync::Semaphore;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;

use crate::file_transfer_download::{DownloadOutcome, download_with_limits};
use crate::file_transfer_schema::{TransferError, UploadRequest};
use crate::file_transfer_upload::{UploadOutcome, upload_with_limits};
use crate::protocol::{self, ProtoHdr, ProtoMsg, ProtoType};
use crate::transfer_limits::TransferLimits;

/// Bounded wait for delivering an event to the manager.
const SEND_TIMEOUT: Duration = Duration::from_secs(4);
/// Local worker-to-relay channel capacity.
const LOCAL_CAPACITY: usize = 8;
/// Maximum accepted session identifier length in bytes.
const MAX_SID_LEN: usize = 128;
/// Maximum characters retained from an error reason.
const MAX_REASON_CHARS: usize = 1024;
/// Maximum characters retained from the originating message type.
const MAX_MSGTYPE_CHARS: usize = 64;
/// Maximum accepted length of a forwarded `msgid`.
const MAX_MSGID_LEN: usize = 128;

/// Process-wide single permit bounding concurrent `stat` jobs.
static STAT_PERMIT: OnceLock<Arc<Semaphore>> = OnceLock::new();

/// Return the process-wide semaphore enforcing one outstanding `stat` job.
fn stat_semaphore() -> &'static Arc<Semaphore> {
    STAT_PERMIT.get_or_init(|| Arc::new(Semaphore::new(1)))
}

/// Validated session identity derived from an initiating header.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Key {
    pub(crate) proto: ProtoType,
    pub(crate) sid: String,
}

impl Key {
    /// Validate that the header addresses a supported file transfer session.
    pub(crate) fn from_header(header: &ProtoHdr) -> Result<Self> {
        let proto = header.proto;
        if !matches!(
            proto,
            ProtoType::FILE_TRANSFER | ProtoType::FILE_TRANSFER_V2
        ) {
            bail!("unsupported file transfer protocol {proto}");
        }
        let sid_len = header.session_id.len();
        if sid_len == 0 || sid_len > MAX_SID_LEN {
            bail!("session identifier length {sid_len} outside 1..={MAX_SID_LEN}");
        }
        Ok(Self {
            proto,
            sid: header.session_id.clone(),
        })
    }
}

/// The transfer to perform, chosen once when the task starts.
pub(crate) enum Request {
    Download(PathBuf),
    Upload(UploadRequest),
}

/// Events relayed to the manager by [`run`].
pub(crate) enum Event {
    /// A worker-produced protocol message.
    Message {
        key: Key,
        generation: u64,
        message: ProtoMsg,
        terminal: bool,
    },
    /// The worker has completed (success or error) and no further messages will
    /// follow.
    Finished { key: Key, generation: u64 },
}

/// Extract the single bounded correlation value allowed to survive into a reply.
///
/// Only a *string* `msgid` of at most [`MAX_MSGID_LEN`] bytes is retained; any
/// other type or an oversized value is dropped rather than reflected. No other
/// inbound property (notably `offset`) is ever considered.
fn bounded_msgid(header: &ProtoHdr) -> Option<String> {
    header
        .properties
        .get("msgid")
        .and_then(Value::as_str)
        .filter(|value| value.len() <= MAX_MSGID_LEN)
        .map(str::to_owned)
}

/// Build a sanitized reply header from an initiating header.
///
/// The header is deliberately *not* cloned. The outbound reply keeps only the
/// protocol and the already-admitted session identity, replaces the message
/// type with `msg_type`, and preserves at most one bounded correlation field: a
/// string `msgid` of at most [`MAX_MSGID_LEN`] bytes. Every other inbound
/// property is dropped.
///
/// Copying arbitrary inbound properties would be unsafe here: an ordinary
/// file-transfer frame is encoded by [`crate::protocol::encode_message`], which
/// requires the `offset` property of *every* file-transfer frame to be a
/// non-negative `i64`. Reflecting a peer-supplied `offset` (for example a
/// string, a negative integer, or `u64::MAX`) would make the reply fail to
/// encode, and reflecting unbounded metadata would let a near-frame-limit
/// request inflate the response past the outbound frame budget. Omitting all
/// non-`msgid` properties keeps both the `error` and `file_info` replies
/// encodable and bounded while leaving the outbound encoder and global
/// transport validation untouched.
///
/// The returned tuple is the sanitized header plus the retained `msgid`, so
/// callers that embed the correlation value in a body (such as the error reply)
/// reuse the exact same validated value instead of re-deriving it.
fn reply_header(header: &ProtoHdr, msg_type: &str) -> (ProtoHdr, Option<String>) {
    let msgid = bounded_msgid(header);
    let mut reply_header = ProtoHdr {
        proto: header.proto,
        msg_type: msg_type.to_owned(),
        session_id: header.session_id.clone(),
        properties: BTreeMap::new(),
    };
    if let Some(ref msgid) = msgid {
        reply_header
            .properties
            .insert("msgid".to_owned(), Value::from(msgid.as_str()));
    }
    (reply_header, msgid)
}

/// Build a sanitized `error` reply from an initiating header.
///
/// The body encodes a bounded [`TransferError`]: the `reason` is a
/// human-readable description (no secret material is inserted here) truncated
/// to [`MAX_REASON_CHARS`], the originating `msgtype` is truncated to
/// [`MAX_MSGTYPE_CHARS`], and an oversized or non-string `msgid` is omitted
/// rather than reflected. The header is sanitized by [`reply_header`], so it
/// preserves only the protocol, admitted session identity, and the bounded
/// `msgid`.
pub(crate) fn error_reply(header: &ProtoHdr, reason: &str) -> Result<ProtoMsg> {
    let err: String = reason.chars().take(MAX_REASON_CHARS).collect();
    let msgtype: String = header.msg_type.chars().take(MAX_MSGTYPE_CHARS).collect();
    let (reply_header, msgid) = reply_header(header, "error");

    let body = TransferError {
        err: Some(err),
        msgtype: Some(msgtype),
        msgid,
    };
    let encoded = protocol::encode(&body)?;

    Ok(ProtoMsg {
        header: reply_header,
        body: encoded,
    })
}

/// Build a sanitized `file_info` reply from an initiating header and metadata.
///
/// The body is the ordinary [`crate::file_transfer_schema::FileInfo`] metadata.
/// The header is sanitized by the same [`reply_header`] policy used for error
/// replies, so it preserves only the protocol, admitted session identity, and a
/// bounded string `msgid`. All offsets, unknown properties, and oversized or
/// non-string correlation values are dropped, guaranteeing the response is
/// encodable and within the outbound frame budget.
fn file_info_reply(
    header: &ProtoHdr,
    info: &crate::file_transfer_schema::FileInfo,
) -> Result<ProtoMsg> {
    let (reply_header, _msgid) = reply_header(header, "file_info");
    let encoded = protocol::encode(info)?;
    Ok(ProtoMsg {
        header: reply_header,
        body: encoded,
    })
}

/// Start one caller-owned blocking metadata (`stat`) job.
///
/// The job is accepted only when the process-wide single permit is available;
/// otherwise `None` is returned immediately so the caller never queues an
/// unbounded blocking submission. On success the resulting `file_info` reply
/// preserves the request protocol, session identifier, and a single bounded
/// string `msgid`; all other request properties (including any `offset`) are
/// dropped so the reply is always encodable. On a metadata error the reply is a
/// structured `error` carrying the bounded request `msgtype` and `msgid`;
/// unrelated request properties are likewise never reflected.
///
/// The returned handle is owned and awaited by the manager. The permit lives
/// inside the blocking closure for the whole kernel operation and is therefore
/// released only after that operation finishes, even if the handle is dropped
/// or aborted.
///
pub(crate) fn start_stat(
    header: ProtoHdr,
    path: String,
) -> Option<tokio::task::JoinHandle<anyhow::Result<ProtoMsg>>> {
    start_stat_limited(header, path, None)
}

/// Start one caller-owned blocking metadata (`stat`) job, optionally through the
/// limited execution context.
///
/// When `limits` is `Some`, the peer path is mapped beneath the trusted root and
/// opened/verified by the descriptor layer; the download owner/group/size/symlink
/// policy is enforced before a `file_info` reply is produced. When `limits` is
/// `None` the upstream-compatible stat behavior is preserved exactly.
pub(crate) fn start_stat_limited(
    header: ProtoHdr,
    path: String,
    limits: Option<Arc<TransferLimits>>,
) -> Option<tokio::task::JoinHandle<anyhow::Result<ProtoMsg>>> {
    let permit = stat_semaphore().clone().try_acquire_owned().ok()?;

    Some(tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let result = match limits {
            Some(limits) => limits.stat(&path).map_err(|err| err.to_string()),
            None => crate::file_transfer_schema::stat_file(&path).map_err(|err| err.to_string()),
        };
        match result {
            Ok(info) => file_info_reply(&header, &info),
            Err(reason) => error_reply(&header, &reason),
        }
    }))
}

/// Defer v2 EOF and the v1 empty-file EOF until the worker succeeds.
fn download_terminal(is_v2: bool, message: &ProtoMsg) -> bool {
    message.header.msg_type == "file_chunk"
        && message.body.is_empty()
        && (is_v2
            || message
                .header
                .properties
                .get("offset")
                .and_then(Value::as_i64)
                == Some(0))
}

/// Try to deliver one event within the bounded send timeout.
///
/// Returns `false` when the manager stopped accepting events (timeout or closed
/// channel), signalling that the caller should stop relaying.
async fn send_event(events: &mpsc::Sender<Event>, event: Event) -> bool {
    matches!(
        tokio::time::timeout(SEND_TIMEOUT, events.send(event)).await,
        Ok(Ok(()))
    )
}

/// Drive one file transfer worker and relay its output as [`Event`]s.
///
/// The caller owns the task lifetime; this function performs no spawning. It
/// returns once the worker completes (successfully or not) and the closing
/// [`Event::Finished`] has been attempted, or earlier if event delivery fails.
pub(crate) async fn run(
    key: Key,
    generation: u64,
    request: Request,
    initial: ProtoHdr,
    commands: mpsc::Receiver<ProtoMsg>,
    events: mpsc::Sender<Event>,
    limits: Option<Arc<TransferLimits>>,
) {
    let is_download = matches!(request, Request::Download(_));
    let is_v2 = key.proto == ProtoType::FILE_TRANSFER_V2;

    let (local_tx, local_rx) = mpsc::channel::<ProtoMsg>(LOCAL_CAPACITY);

    // Clone the session identity parts the worker borrows/owns so the task can
    // retain `key` for its own events.
    let worker_proto = key.proto;
    let worker_sid = key.sid.clone();

    let worker = async move {
        match request {
            Request::Download(path) => {
                download_with_limits(worker_proto, worker_sid, path, commands, local_tx, limits)
                    .await
                    .map(|outcome| matches!(outcome, DownloadOutcome::Complete))
            }
            Request::Upload(upload_request) => upload_with_limits(
                worker_proto,
                worker_sid,
                upload_request,
                commands,
                local_tx,
                limits,
            )
            .await
            .map(|outcome| matches!(outcome, UploadOutcome::Complete)),
        }
    };
    relay_worker(
        key,
        generation,
        initial,
        events,
        local_rx,
        worker,
        is_download,
        is_v2,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn relay_worker<F>(
    key: Key,
    generation: u64,
    initial: ProtoHdr,
    events: mpsc::Sender<Event>,
    mut local_rx: mpsc::Receiver<ProtoMsg>,
    worker: F,
    is_download: bool,
    is_v2: bool,
) where
    F: std::future::Future<Output = anyhow::Result<bool>>,
{
    let mut worker = pin!(worker);
    // Trusted download worker emits exactly one EOF, after all data.
    let mut deferred_eof: Option<ProtoMsg> = None;

    // Biased select: poll the worker first, so a completion that queues its final
    // acknowledgement in the same poll is observed before the message is
    // relayed. Queued messages are then drained below with correct tagging.
    let mut rx_open = true;
    let outcome = loop {
        tokio::select! {
            biased;
            result = &mut worker => break result,
            maybe = local_rx.recv(), if rx_open => {
                match maybe {
                    Some(message) => {
                        if is_download && download_terminal(is_v2, &message) {
                            deferred_eof = Some(message);
                            continue;
                        }
                        let terminal = false;
                        let event = Event::Message {
                            key: key.clone(),
                            generation,
                            message,
                            terminal,
                        };
                        if !send_event(&events, event).await {
                            return;
                        }
                    }
                    None => {
                        // Sender dropped; stop polling to avoid a busy loop and
                        // keep driving the worker to completion.
                        rx_open = false;
                    }
                }
            }
        }
    };

    // Drain whatever the worker queued in its final poll (bounded by capacity).
    let mut buffered: Vec<ProtoMsg> = Vec::new();
    while buffered.len() < LOCAL_CAPACITY {
        match local_rx.try_recv() {
            Ok(message) => buffered.push(message),
            Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
        }
    }

    // On an upload that completed successfully (not aborted), the last queued
    // acknowledgement is the terminating one. Initial and per-chunk
    // acknowledgements never carry the terminal flag.
    let upload_success = !is_download && matches!(&outcome, Ok(true));
    let terminal_ack: Option<usize> = if upload_success {
        buffered
            .iter()
            .enumerate()
            .rfind(|(_, message)| message.header.msg_type == "ack")
            .map(|(index, _)| index)
    } else {
        None
    };

    for (index, message) in buffered.into_iter().enumerate() {
        if is_download && download_terminal(is_v2, &message) {
            deferred_eof = Some(message);
            continue;
        }
        let terminal = if is_download {
            false
        } else {
            terminal_ack == Some(index)
        };
        let event = Event::Message {
            key: key.clone(),
            generation,
            message,
            terminal,
        };
        if !send_event(&events, event).await {
            return;
        }
    }

    if matches!(&outcome, Ok(true))
        && let Some(message) = deferred_eof
    {
        let event = Event::Message {
            key: key.clone(),
            generation,
            message,
            terminal: true,
        };
        if !send_event(&events, event).await {
            return;
        }
    }

    // Surface worker failures as a terminal error message after any queued
    // frames. `{:#}` preserves the full source chain and the explicit
    // `CommittedAckError` display text ("already committed").
    if let Err(err) = &outcome {
        let reason = format!("{err:#}");
        if let Ok(reply) = error_reply(&initial, &reason) {
            let event = Event::Message {
                key: key.clone(),
                generation,
                message: reply,
                terminal: true,
            };
            if !send_event(&events, event).await {
                return;
            }
        }
    }

    // A successful abort is not an error: no error message is emitted. Always
    // attempt a single bounded `Finished`; the manager independently reaps the
    // task when its shared queue empties even if this notification is lost.
    let _ = send_event(&events, Event::Finished { key, generation }).await;
}

#[cfg(test)]
mod relay_outcome_tests {
    use super::*;
    use std::future::Future;

    fn fixture(proto: ProtoType) -> Result<(Key, ProtoHdr, ProtoMsg)> {
        let header = ProtoHdr {
            proto,
            msg_type: "get_file".into(),
            session_id: "relay".into(),
            properties: BTreeMap::new(),
        };
        let key = Key::from_header(&header)?;
        let mut eof = ProtoMsg {
            header: ProtoHdr {
                msg_type: "file_chunk".into(),
                ..header.clone()
            },
            body: Vec::new(),
        };
        if proto == ProtoType::FILE_TRANSFER {
            eof.header
                .properties
                .insert("offset".into(), Value::from(0));
        }
        Ok((key, header, eof))
    }

    async fn gate_case(proto: ProtoType, success: Option<bool>) -> Result<()> {
        let (key, header, eof) = fixture(proto)?;
        let (local_tx, local_rx) = mpsc::channel(2);
        let (events, mut rx) = mpsc::channel(4);
        let (release, gate) = tokio::sync::oneshot::channel::<()>();
        let worker = async move {
            local_tx.send(eof).await?;
            gate.await?;
            match success {
                Some(value) => Ok(value),
                None => Err(anyhow::anyhow!("fixture failure")),
            }
        };
        let relay = relay_worker(
            key.clone(),
            7,
            header,
            events,
            local_rx,
            worker,
            true,
            proto == ProtoType::FILE_TRANSFER_V2,
        );
        tokio::pin!(relay);
        let pending =
            std::future::poll_fn(|cx| std::task::Poll::Ready(relay.as_mut().poll(cx).is_pending()))
                .await;
        assert!(pending && rx.try_recv().is_err());
        release
            .send(())
            .map_err(|_| anyhow::anyhow!("fixture gate closed"))?;
        relay.await;
        match success {
            Some(true) => match rx.recv().await {
                Some(Event::Message {
                    key: actual,
                    generation: 7,
                    message,
                    terminal: true,
                }) => {
                    assert_eq!(actual, key);
                    assert!(message.body.is_empty());
                    assert_eq!(message.header.msg_type, "file_chunk");
                }
                _ => anyhow::bail!("missing terminal EOF"),
            },
            None => match rx.recv().await {
                Some(Event::Message {
                    key: actual,
                    generation: 7,
                    message,
                    terminal: true,
                }) => {
                    assert_eq!(actual, key);
                    assert_eq!(message.header.msg_type, "error");
                }
                _ => anyhow::bail!("missing terminal error"),
            },
            Some(false) => {}
        }
        assert!(
            matches!(rx.recv().await, Some(Event::Finished { key: actual, generation: 7 }) if actual == key)
        );
        assert!(rx.try_recv().is_err());
        Ok(())
    }

    #[tokio::test]
    async fn gated_v2_eof_follows_worker_outcome() -> Result<()> {
        for proto in [ProtoType::FILE_TRANSFER, ProtoType::FILE_TRANSFER_V2] {
            gate_case(proto, Some(true)).await?;
            gate_case(proto, None).await?;
            gate_case(proto, Some(false)).await?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn buffered_data_precedes_terminal_eof_or_error() -> Result<()> {
        for success in [true, false] {
            let (key, header, eof) = fixture(ProtoType::FILE_TRANSFER_V2)?;
            let (tx, local_rx) = mpsc::channel(3);
            let (events, mut rx) = mpsc::channel(4);
            let data = ProtoMsg {
                header: eof.header.clone(),
                body: b"data".to_vec(),
            };
            let worker = async move {
                tx.send(data).await?;
                tx.send(eof).await?;
                if success {
                    Ok(true)
                } else {
                    Err(anyhow::anyhow!("fixture error"))
                }
            };
            relay_worker(key.clone(), 7, header, events, local_rx, worker, true, true).await;
            assert!(
                matches!(rx.recv().await, Some(Event::Message { key: actual, generation: 7, message, terminal: false }) if actual == key && message.body == b"data")
            );
            assert!(
                matches!(rx.recv().await, Some(Event::Message { key: actual, generation: 7, message, terminal: true }) if actual == key && message.header.msg_type == if success { "file_chunk" } else { "error" })
            );
            assert!(
                matches!(rx.recv().await, Some(Event::Finished { key: actual, generation: 7 }) if actual == key)
            );
            assert!(rx.try_recv().is_err());
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn blocked_event_channel_abandons_deferred_eof_boundedly() -> Result<()> {
        let (key, header, eof) = fixture(ProtoType::FILE_TRANSFER_V2)?;
        let (tx, local_rx) = mpsc::channel(2);
        let (events, mut rx) = mpsc::channel(1);
        events
            .send(Event::Finished {
                key: key.clone(),
                generation: 9,
            })
            .await?;
        let worker = async move {
            tx.send(eof).await?;
            Ok(true)
        };
        let relay = relay_worker(key.clone(), 7, header, events, local_rx, worker, true, true);
        tokio::pin!(relay);
        let pending =
            std::future::poll_fn(|cx| std::task::Poll::Ready(relay.as_mut().poll(cx).is_pending()))
                .await;
        assert!(pending);
        tokio::time::advance(SEND_TIMEOUT + Duration::from_secs(1)).await;
        relay.await;
        assert!(
            matches!(rx.recv().await, Some(Event::Finished { key: actual, generation: 9 }) if actual == key)
        );
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn cancel_relay_drops_worker_and_deferred_eof() -> Result<()> {
        struct Guard(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let (key, header, eof) = fixture(ProtoType::FILE_TRANSFER_V2)?;
        let (tx, local_rx) = mpsc::channel(2);
        let (events, mut rx) = mpsc::channel(4);
        let (release, gate) = tokio::sync::oneshot::channel::<()>();
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = dropped.clone();
        let worker = async move {
            let _guard = Guard(flag);
            tx.send(eof).await?;
            gate.await?;
            Ok(true)
        };
        let mut relay = Box::pin(relay_worker(
            key, 7, header, events, local_rx, worker, true, true,
        ));
        let pending =
            std::future::poll_fn(|cx| std::task::Poll::Ready(relay.as_mut().poll(cx).is_pending()))
                .await;
        assert!(pending && rx.try_recv().is_err());
        assert!(!dropped.load(std::sync::atomic::Ordering::SeqCst));
        drop(relay);
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        ));
        assert!(release.send(()).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn same_poll_error_discards_v2_eof() -> Result<()> {
        let (key, header, eof) = fixture(ProtoType::FILE_TRANSFER_V2)?;
        let (tx, local_rx) = mpsc::channel(2);
        let (events, mut rx) = mpsc::channel(4);
        let worker = async move {
            tx.send(eof).await?;
            Err(anyhow::anyhow!("fixture failure"))
        };
        relay_worker(key.clone(), 7, header, events, local_rx, worker, true, true).await;
        assert!(
            matches!(rx.recv().await, Some(Event::Message { key: actual, generation: 7, message, terminal: true }) if actual == key && message.header.msg_type == "error")
        );
        assert!(
            matches!(rx.recv().await, Some(Event::Finished { key: actual, generation: 7 }) if actual == key)
        );
        assert!(rx.try_recv().is_err());
        Ok(())
    }

    #[tokio::test]
    async fn v1_eof_is_visible_before_ack_gate() -> Result<()> {
        let (key, header, mut eof) = fixture(ProtoType::FILE_TRANSFER)?;
        eof.header
            .properties
            .insert("offset".into(), Value::from(1));
        let (tx, local_rx) = mpsc::channel(2);
        let (events, mut rx) = mpsc::channel(4);
        let (release, gate) = tokio::sync::oneshot::channel::<()>();
        let worker = async move {
            tx.send(eof).await?;
            gate.await?;
            Ok(true)
        };
        let relay = relay_worker(
            key.clone(),
            7,
            header,
            events,
            local_rx,
            worker,
            true,
            false,
        );
        tokio::pin!(relay);
        let pending =
            std::future::poll_fn(|cx| std::task::Poll::Ready(relay.as_mut().poll(cx).is_pending()))
                .await;
        assert!(pending);
        assert!(
            matches!(rx.try_recv(), Ok(Event::Message { key: actual, generation: 7, message, terminal: false }) if actual == key && message.body.is_empty())
        );
        release
            .send(())
            .map_err(|_| anyhow::anyhow!("fixture gate closed"))?;
        relay.await;
        assert!(
            matches!(rx.recv().await, Some(Event::Finished { key: actual, generation: 7 }) if actual == key)
        );
        Ok(())
    }
}
