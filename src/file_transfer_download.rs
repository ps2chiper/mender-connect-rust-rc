//! Bounded, safe file-download worker for the file transfer protocol.
//!
//! The worker owns a single regular file and streams it to the transport as
//! `file_chunk` frames. It never follows symlinks, never blocks on special
//! files, and bounds both total bytes and buffered window sizes. All channel
//! interactions are time-bounded so a stalled peer cannot wedge the worker.
//!
//! The transferred length is the file size observed from the open descriptor's
//! metadata at the start of the run (a snapshot). Data appended to the file
//! after that metadata read is deliberately not included. If data is removed
//! after the snapshot so the source is truncated below the expected length, the
//! worker reports an early-EOF error instead of emitting a successful end of
//! stream. The filesystem is assumed to be a responsive local regular
//! filesystem; in-progress reads are bounded by the per-`read` chunk size but
//! are not forcibly cancellable.

use std::collections::BTreeMap;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use nix::libc::{O_NOCTTY, O_NOFOLLOW, O_NONBLOCK};
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::time::Instant;

use crate::file_transfer_schema::required_path;
use crate::limits_rate::SharedRateCounter;
use crate::protocol::{ProtoHdr, ProtoMsg, ProtoType};
use crate::transfer_limits::TransferLimits;

const MAX_SID_LEN: usize = 128;

/// Maximum number of bytes read per `file_chunk` frame.
const CHUNK_SIZE: usize = 4096;
/// Same value as [`CHUNK_SIZE`] as a `u64`, used for checked arithmetic.
const CHUNK_SIZE_U64: u64 = 4096;

const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
/// v1 unacknowledged-bytes window (20 chunks of 4 KiB = 81920 bytes).
const V1_WINDOW_BYTES: u64 = 20 * 4096;

/// Upper bound on the number of queued commands drained between chunks before
/// cooperatively yielding, so a fast concurrent producer cannot starve the
/// window/data/deadline work.
const MAX_DRAIN_PER_ITER: usize = 8;

const SEND_TIMEOUT: Duration = Duration::from_secs(4);
const ACK_TIMEOUT: Duration = Duration::from_secs(30);
/// Matches the upload lifetime limit; very slow large downloads may time out.
const TOTAL_TIMEOUT: Duration = Duration::from_secs(600);

/// Result of a completed (or peer-cancelled) download worker run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadOutcome {
    Complete,
    Aborted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Advance {
    Progress,
    Aborted,
}

#[derive(Debug, Clone, Copy)]
enum Incoming {
    Ack(i64),
    Aborted,
}

/// Stream the file at `path` to the peer over the file transfer session.
///
/// Returns [`DownloadOutcome::Complete`] after the terminating empty chunk has
/// been sent (and, for nonempty v1 downloads, acknowledged). Returns
/// [`DownloadOutcome::Aborted`] when the peer sent a matching `error` message.
/// I/O, validation and timeout failures are reported as errors so the caller
/// can build a proper error response.
///
/// The number of bytes streamed is the file length captured from the open
/// descriptor's metadata at the start of the run. Bytes appended afterwards are
/// not included; the worker never grew the bound after that snapshot.
pub async fn download(
    proto: ProtoType,
    sid: String,
    path: PathBuf,
    commands: mpsc::Receiver<ProtoMsg>,
    output: mpsc::Sender<ProtoMsg>,
) -> Result<DownloadOutcome> {
    download_with_limits(proto, sid, path, commands, output, None).await
}

/// Limited-aware download entry point.
///
/// When `limits` is `Some`, the source is mapped beneath the trusted root,
/// opened and verified by the kernel descriptor layer, and adjudicated by the
/// pure policy using the original absolute path. Actual streamed bytes are
/// recorded against the shared rate counter before each chunk is emitted, and
/// both the snapshot and actual byte counts are bounded by the configured
/// `MaxFileSize` plus the hard 256 MiB cap. All downloads have a 600-second
/// total deadline, including when `limits` is `None`.
pub async fn download_with_limits(
    proto: ProtoType,
    sid: String,
    path: PathBuf,
    commands: mpsc::Receiver<ProtoMsg>,
    output: mpsc::Sender<ProtoMsg>,
    limits: Option<Arc<TransferLimits>>,
) -> Result<DownloadOutcome> {
    let deadline = Instant::now() + TOTAL_TIMEOUT;
    match tokio::time::timeout_at(
        deadline,
        download_inner(proto, sid, path, commands, output, limits, deadline),
    )
    .await
    {
        Ok(result) if Instant::now() < deadline => result,
        _ => bail!("download exceeded total deadline"),
    }
}

#[allow(clippy::too_many_arguments)]
async fn download_inner(
    proto: ProtoType,
    sid: String,
    path: PathBuf,
    mut commands: mpsc::Receiver<ProtoMsg>,
    output: mpsc::Sender<ProtoMsg>,
    limits: Option<Arc<TransferLimits>>,
    deadline: Instant,
) -> Result<DownloadOutcome> {
    let is_v1 = match proto {
        ProtoType::FILE_TRANSFER => true,
        ProtoType::FILE_TRANSFER_V2 => false,
        other => bail!("unsupported file transfer protocol {other}"),
    };

    if sid.is_empty() {
        bail!("empty session identifier");
    }
    if sid.len() > MAX_SID_LEN {
        bail!("session identifier exceeds {MAX_SID_LEN} bytes");
    }

    let mut counter: Option<SharedRateCounter> = None;
    let (std_file, file_len) = match limits.as_ref() {
        Some(limits) => {
            let path_str = path
                .to_str()
                .ok_or_else(|| anyhow!("file path is not valid UTF-8"))?;
            required_path(Some(path_str))?;
            let prepared = limits.prepare_download(path_str)?;
            counter = Some(limits.counter().clone());
            prepared.into_parts()
        }
        None => {
            let path_str = path
                .to_str()
                .ok_or_else(|| anyhow!("file path is not valid UTF-8"))?;
            let validated = required_path(Some(path_str))?;
            let path = PathBuf::from(validated);

            // `custom_flags` takes an `i32` bitmask of `open(2)` flags; the libc
            // constants below avoid hand-written numeric bitmasks.
            let std_file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(O_NOFOLLOW | O_NONBLOCK | O_NOCTTY)
                .open(&path)?;

            // Re-validate on the open descriptor so the checks apply to the
            // object we actually read, not a path that may have been swapped.
            let metadata = std_file.metadata()?;
            if !metadata.file_type().is_file() {
                bail!("refusing to download a non-regular file");
            }
            (std_file, metadata.len())
        }
    };
    ensure_time_remaining(deadline)?;
    if file_len > MAX_FILE_BYTES {
        bail!("file size {file_len} exceeds the {MAX_FILE_BYTES} byte limit");
    }

    let mut file = File::from_std(std_file);
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut sent: u64 = 0;
    let mut acked: u64 = 0;

    while sent < file_len {
        ensure_time_remaining(deadline)?;
        // Draining queued commands between chunks: a matching error aborts
        // immediately (even for v2), and every other message is validated. The
        // per-iteration drain budget is bounded so a continuous stream of
        // duplicate acknowledgements cannot starve the window/data/deadline
        // work below; once the budget is exhausted we cooperatively yield and
        // proceed.
        let mut drained: usize = 0;
        loop {
            if drained >= MAX_DRAIN_PER_ITER {
                tokio::task::yield_now().await;
                break;
            }
            match commands.try_recv() {
                Ok(message) => {
                    match inspect(&message, proto, &sid)? {
                        Incoming::Aborted => return Ok(DownloadOutcome::Aborted),
                        Incoming::Ack(offset) => {
                            let _ = apply_ack(offset, sent, &mut acked)?;
                        }
                    }
                    drained = drained
                        .checked_add(1)
                        .ok_or_else(|| anyhow!("drain counter overflow"))?;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    bail!("command channel closed while streaming file")
                }
            }
        }

        if is_v1 {
            let outstanding = sent
                .checked_sub(acked)
                .ok_or_else(|| anyhow!("acknowledged offset exceeds sent bytes"))?;
            if outstanding >= V1_WINDOW_BYTES
                && wait_progress(&mut commands, proto, &sid, sent, &mut acked).await?
                    == Advance::Aborted
            {
                return Ok(DownloadOutcome::Aborted);
            }
        }

        // Bound each read by the file snapshot remaining, the per-frame chunk
        // size, and (for v1) the remaining space in the acknowledgement window.
        let file_remaining = file_len
            .checked_sub(sent)
            .ok_or_else(|| anyhow!("sent offset exceeds file length"))?;
        let mut limit = file_remaining.min(CHUNK_SIZE_U64);
        if is_v1 {
            let outstanding = sent
                .checked_sub(acked)
                .ok_or_else(|| anyhow!("acknowledged offset exceeds sent bytes"))?;
            let window_remaining = V1_WINDOW_BYTES
                .checked_sub(outstanding)
                .ok_or_else(|| anyhow!("acknowledgement window exceeded"))?;
            limit = limit.min(window_remaining);
        }
        if limit == 0 {
            // No room in the current window; loop back to wait for progress.
            continue;
        }
        let want =
            usize::try_from(limit).map_err(|_| anyhow!("chunk length does not fit in memory"))?;

        let dst = buffer
            .get_mut(..want)
            .ok_or_else(|| anyhow!("chunk buffer bounds exceeded"))?;
        ensure_time_remaining(deadline)?;
        let read = file.read(dst).await?;
        if read == 0 {
            // A zero-length read before the snapshot length has been reached
            // means the source was truncated; do not emit a successful EOF.
            return Err(anyhow!(
                "unexpected early EOF: sent {sent} of {file_len} expected bytes before truncation"
            ));
        }
        let read_len = u64::try_from(read).map_err(|_| anyhow!("chunk length overflow"))?;
        let next_total = sent
            .checked_add(read_len)
            .ok_or_else(|| anyhow!("byte offset overflow"))?;
        if next_total > MAX_FILE_BYTES {
            bail!("transfer exceeds the {MAX_FILE_BYTES} byte limit");
        }
        if let Some(limits) = limits.as_ref()
            && !limits.progress_allowed(next_total)
        {
            bail!("file size exceeds the configured limit");
        }
        if let Some(counter) = counter.as_ref()
            && !counter.try_record_tx_now(read_len)?
        {
            bail!("transfer rate limit exceeded");
        }

        let body = buffer
            .get(..read)
            .ok_or_else(|| anyhow!("chunk buffer bounds exceeded"))?;
        let frame = chunk_frame(proto, &sid, sent, body)?;
        ensure_time_remaining(deadline)?;
        send_frame(&output, frame, deadline).await?;
        sent = next_total;
    }

    ensure_time_remaining(deadline)?;
    let eof = chunk_frame(proto, &sid, sent, &[])?;
    send_frame(&output, eof, deadline).await?;

    if is_v1 {
        while acked < sent {
            if wait_progress(&mut commands, proto, &sid, sent, &mut acked).await?
                == Advance::Aborted
            {
                return Ok(DownloadOutcome::Aborted);
            }
        }
    }

    Ok(DownloadOutcome::Complete)
}

fn ensure_time_remaining(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        bail!("download exceeded total deadline");
    }
    Ok(())
}

fn chunk_frame(proto: ProtoType, sid: &str, offset: u64, body: &[u8]) -> Result<ProtoMsg> {
    let offset = i64::try_from(offset).map_err(|_| anyhow!("chunk offset does not fit in i64"))?;
    let mut properties = BTreeMap::new();
    properties.insert("offset".to_owned(), rmpv::Value::from(offset));
    Ok(ProtoMsg {
        header: ProtoHdr {
            proto,
            msg_type: "file_chunk".to_owned(),
            session_id: sid.to_owned(),
            properties,
        },
        body: body.to_vec(),
    })
}

async fn send_frame(
    output: &mpsc::Sender<ProtoMsg>,
    frame: ProtoMsg,
    deadline: Instant,
) -> Result<()> {
    let send_deadline = (Instant::now() + SEND_TIMEOUT).min(deadline);
    let permit = match tokio::time::timeout_at(send_deadline, output.reserve()).await {
        Ok(Ok(permit)) => permit,
        Ok(Err(_)) => bail!("output channel closed while sending file chunk"),
        Err(_) if Instant::now() >= deadline => bail!("download exceeded total deadline"),
        Err(_) => bail!("timed out sending file chunk"),
    };
    ensure_time_remaining(deadline)?;
    permit.send(frame);
    Ok(())
}

/// Wait until the peer acknowledges enough bytes to make forward progress.
///
/// A single fixed [`ACK_TIMEOUT`] deadline bounds the whole wait: duplicate or
/// stale acknowledgements do not restart the timeout, so a stalled peer cannot
/// keep the worker waiting forever by replaying old acknowledgements. Only an
/// acknowledgement that advances `acked` ends the wait, and the next window
/// starts a fresh bounded wait.
///
/// The deadline uses the Tokio clock ([`tokio::time::Instant`]) so it is driven
/// by virtual Tokio time, while the timeout duration itself remains a plain
/// [`std::time::Duration`].
async fn wait_progress(
    commands: &mut mpsc::Receiver<ProtoMsg>,
    proto: ProtoType,
    sid: &str,
    sent: u64,
    acked: &mut u64,
) -> Result<Advance> {
    let deadline = Instant::now() + ACK_TIMEOUT;
    loop {
        let remaining = match deadline.checked_duration_since(Instant::now()) {
            Some(remaining) if !remaining.is_zero() => remaining,
            _ => bail!("timed out awaiting file chunk acknowledgement"),
        };

        let message = match tokio::time::timeout(remaining, commands.recv()).await {
            Ok(Some(message)) => message,
            Ok(None) => bail!("command channel closed while awaiting acknowledgement"),
            Err(_) => bail!("timed out awaiting file chunk acknowledgement"),
        };

        match inspect(&message, proto, sid)? {
            Incoming::Aborted => return Ok(Advance::Aborted),
            Incoming::Ack(offset) => {
                if apply_ack(offset, sent, acked)? {
                    return Ok(Advance::Progress);
                }
                // Duplicate or stale acknowledgement: keep waiting on the same
                // fixed deadline rather than extending it.
            }
        }
    }
}

/// Validate and apply a v1 acknowledgement offset.
///
/// Returns `true` when `acked` advanced (forward progress), or `false` for a
/// duplicate/stale offset that leaves `acked` unchanged. Offsets above the
/// currently sent byte count are rejected.
fn apply_ack(offset: i64, sent: u64, acked: &mut u64) -> Result<bool> {
    if offset < 0 {
        bail!("negative acknowledgement offset {offset}");
    }
    let offset =
        u64::try_from(offset).map_err(|_| anyhow!("acknowledgement offset does not fit in u64"))?;
    if offset > sent {
        bail!("acknowledgement offset {offset} exceeds sent bytes {sent}");
    }
    if offset <= *acked {
        return Ok(false);
    }
    *acked = offset;
    Ok(true)
}

fn inspect(message: &ProtoMsg, proto: ProtoType, sid: &str) -> Result<Incoming> {
    let header = &message.header;
    if header.proto != proto {
        bail!(
            "message protocol {} does not match session protocol {proto}",
            header.proto
        );
    }
    if header.session_id != sid {
        bail!("message session does not match the download session");
    }
    match header.msg_type.as_str() {
        "ack" => {
            if proto != ProtoType::FILE_TRANSFER {
                bail!("unexpected acknowledgement for protocol {proto}");
            }
            Ok(Incoming::Ack(ack_offset(message)?))
        }
        "error" => Ok(Incoming::Aborted),
        other => bail!("unexpected message type {other:?}"),
    }
}

fn ack_offset(message: &ProtoMsg) -> Result<i64> {
    match message.header.properties.get("offset") {
        Some(rmpv::Value::Integer(value)) => value
            .as_i64()
            .ok_or_else(|| anyhow!("acknowledgement offset is not a signed 64-bit integer")),
        Some(_) => bail!("acknowledgement offset is not an integer"),
        None => bail!("acknowledgement is missing the offset property"),
    }
}

// Append inside file_transfer_download.rs for candidate validation.
#[cfg(test)]
mod total_deadline_tests {
    use super::*;
    use std::future::Future;

    #[tokio::test(start_paused = true)]
    async fn blocked_send_never_enqueues_after_total_deadline() -> Result<()> {
        let (sender, mut receiver) = mpsc::channel(1);
        sender
            .send(chunk_frame(ProtoType::FILE_TRANSFER, "s", 0, b"first")?)
            .await?;
        let deadline = Instant::now() + Duration::from_secs(2);
        let frame = chunk_frame(ProtoType::FILE_TRANSFER, "s", 5, &[])?;
        let worker = send_frame(&sender, frame, deadline);
        tokio::pin!(worker);
        let pending = std::future::poll_fn(|cx| {
            std::task::Poll::Ready(worker.as_mut().poll(cx).is_pending())
        })
        .await;
        assert!(pending);
        tokio::time::advance(Duration::from_secs(3)).await;
        let first = receiver
            .recv()
            .await
            .ok_or_else(|| anyhow!("missing first frame"))?;
        assert_eq!(first.body, b"first");
        assert!(
            worker
                .await
                .expect_err("expired deadline")
                .to_string()
                .contains("download exceeded total deadline")
        );
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
        Ok(())
    }
}
