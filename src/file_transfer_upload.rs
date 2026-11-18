//! Safe, atomic file upload worker for the file transfer protocol.
//!
//! The worker stages incoming data in a temporary file located in the target
//! directory and only replaces the destination via an atomic rename once the
//! client signals EOF and the data has been flushed, had its final permissions
//! applied and been synced. The `NamedTempFile` guard drops and removes the
//! staged data on every pre-commit error, cancellation or abort path, leaving
//! the previous destination untouched.
//!
//! Atomic visibility is provided by the rename: after a successful persist the
//! destination atomically reflects the uploaded data, but this worker does not
//! fsync the parent directory, so it cannot guarantee power-loss durability.
//! Callers that require crash durability must sync the containing directory.
//!
//! Once the data has been committed via `persist`, a subsequent failure to send
//! the final acknowledgement is reported as [`CommittedAckError`]. At that point
//! the destination already contains the uploaded data, so a later cancellation
//! or disconnect cannot roll the commit back; pre-commit errors still preserve
//! the old destination and remove the stage.
//!
//! Cancellation responsiveness relies on the kernel promptly completing local
//! regular-file operations on an unchanged, trusted parent directory. The
//! per-operation and total deadlines bound the awaited async stages, but a
//! synchronous filesystem call already in progress cannot be forcibly
//! cancelled; deadlines are only observed between completed operations.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use rmpv::Value;
use tempfile::Builder;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio::time::{Instant, timeout_at};

use crate::file_transfer_schema::{
    UploadRequest, required_path, source_basename, validate_requested_size,
};
use crate::limits_fs_upload::{MetadataPlan, StagedCreate};
use crate::protocol::{ProtoHdr, ProtoMsg, ProtoType};
use crate::transfer_limits::TransferLimits;

/// The staging backend used by a single upload worker.
///
/// Unlimited uploads keep the upstream-compatible `NamedTempFile` staging that
/// is atomically renamed into place. Limited uploads use the descriptor-safe
/// [`StagedCreate`] (`O_TMPFILE`) whose only publication path is the atomic
/// `linkat` performed by [`StagedCreate::commit_with_metadata`].
enum StageBackend {
    /// Upstream-compatible named staging with its committed destination and the
    /// POSIX mode applied before the atomic rename.
    Named {
        stage: tempfile::NamedTempFile,
        target: PathBuf,
        mode: u32,
    },
    /// Descriptor-safe `O_TMPFILE` staging paired with its validated metadata
    /// plan. The plan always comes from the same context that created the stage;
    /// there is no fallback to an empty plan.
    Limited {
        stage: StagedCreate,
        plan: MetadataPlan,
    },
}

const MAX_UPLOAD_SIZE: u64 = 256 * 1024 * 1024;
const MAX_CHUNK_SIZE: usize = 4096;
const MAX_SID_LEN: usize = 128;
const WRITE_TIMEOUT: Duration = Duration::from_secs(4);
const SEND_TIMEOUT: Duration = Duration::from_secs(4);
const INACTIVITY_TIMEOUT: Duration = Duration::from_secs(30);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(600);

/// Result of an upload session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadOutcome {
    Complete,
    Aborted,
}

/// Error marker returned when the upload data was committed to the destination
/// but the final acknowledgement could not be delivered.
///
/// The destination now contains the uploaded data; the previous destination is
/// no longer present and cannot be restored by this worker. The inner `anyhow`
/// source describes the acknowledgement failure that occurred after commit.
#[derive(Debug)]
pub struct CommittedAckError {
    source: anyhow::Error,
}

impl CommittedAckError {
    fn new(source: anyhow::Error) -> Self {
        Self { source }
    }
}

impl std::fmt::Display for CommittedAckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("upload committed but final acknowledgement failed")
    }
}

impl std::error::Error for CommittedAckError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

fn parse_offset(value: &Value) -> Option<i64> {
    match value {
        Value::Integer(integer) => integer
            .as_i64()
            .or_else(|| integer.as_u64().and_then(|u| i64::try_from(u).ok())),
        _ => None,
    }
}

fn make_ack(proto: ProtoType, sid: &str, offset: Option<i64>) -> ProtoMsg {
    let mut properties = BTreeMap::new();
    if let Some(value) = offset {
        properties.insert("offset".to_string(), Value::Integer(value.into()));
    }
    ProtoMsg {
        header: ProtoHdr {
            proto,
            msg_type: "ack".to_string(),
            session_id: sid.to_string(),
            properties,
        },
        body: Vec::new(),
    }
}

/// Remaining time budget before the overall upload deadline. Rejects an
/// already-expired deadline so no operation can start after it.
fn remaining(deadline: Instant) -> Result<Duration> {
    match deadline.checked_duration_since(Instant::now()) {
        Some(remaining) if !remaining.is_zero() => Ok(remaining),
        _ => Err(anyhow!("upload exceeded total deadline")),
    }
}

/// Compute an operation deadline of at most `budget`, capped by the total
/// deadline. Errors immediately when the total deadline has already expired.
fn capped(deadline: Instant, budget: Duration) -> Result<Instant> {
    let remaining = remaining(deadline)?;
    Ok((Instant::now() + remaining.min(budget)).min(deadline))
}

async fn send_ack(
    output: &mpsc::Sender<ProtoMsg>,
    proto: ProtoType,
    sid: &str,
    offset: Option<i64>,
    deadline: Instant,
) -> Result<()> {
    let op_deadline = capped(deadline, SEND_TIMEOUT)?;
    let message = make_ack(proto, sid, offset);
    match timeout_at(op_deadline, output.send(message)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(anyhow!("output channel closed while sending ack")),
        Err(_) => {
            if Instant::now() >= deadline {
                Err(anyhow!("upload exceeded total deadline"))
            } else {
                Err(anyhow!("timed out sending upload ack"))
            }
        }
    }
}

async fn recv_command(
    commands: &mut mpsc::Receiver<ProtoMsg>,
    deadline: Instant,
) -> Result<Option<ProtoMsg>> {
    let op_deadline = capped(deadline, INACTIVITY_TIMEOUT)?;
    match timeout_at(op_deadline, commands.recv()).await {
        Ok(Some(message)) => Ok(Some(message)),
        Ok(None) => Ok(None),
        Err(_) => {
            if Instant::now() >= deadline {
                Err(anyhow!("upload exceeded total deadline"))
            } else {
                Err(anyhow!("upload command inactivity timeout"))
            }
        }
    }
}

async fn write_all_bounded(
    writer: &mut tokio::fs::File,
    body: &[u8],
    deadline: Instant,
) -> Result<()> {
    let op_deadline = capped(deadline, WRITE_TIMEOUT)?;
    match timeout_at(op_deadline, writer.write_all(body)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(anyhow!("failed writing upload chunk: {err}")),
        Err(_) => {
            if Instant::now() >= deadline {
                Err(anyhow!("upload exceeded total deadline"))
            } else {
                Err(anyhow!("timed out writing upload chunk"))
            }
        }
    }
}

async fn flush_with_deadline(writer: &mut tokio::fs::File, deadline: Instant) -> Result<()> {
    let op_deadline = capped(deadline, WRITE_TIMEOUT)?;
    match timeout_at(op_deadline, writer.flush()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(anyhow!("failed to flush upload staging file: {err}")),
        Err(_) => {
            if Instant::now() >= deadline {
                Err(anyhow!("upload exceeded total deadline"))
            } else {
                Err(anyhow!("timed out flushing upload staging file"))
            }
        }
    }
}

async fn sync_with_deadline(writer: &mut tokio::fs::File, deadline: Instant) -> Result<()> {
    let op_deadline = capped(deadline, WRITE_TIMEOUT)?;
    match timeout_at(op_deadline, writer.sync_all()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(anyhow!("failed to sync upload staging file: {err}")),
        Err(_) => {
            if Instant::now() >= deadline {
                Err(anyhow!("upload exceeded total deadline"))
            } else {
                Err(anyhow!("timed out syncing upload staging file"))
            }
        }
    }
}

/// Drive a single upload to completion or abort.
///
/// The caller owns message routing; this worker only reads commands from
/// `commands`, emits protocol acks on `output` and performs local file I/O as
/// the current OS account.
/// Drive a single upload to completion or abort (unlimited wrapper).
///
/// This keeps the upstream-compatible behavior unchanged by delegating to
/// [`upload_with_limits`] with no limited execution context.
pub async fn upload(
    proto: ProtoType,
    sid: String,
    request: UploadRequest,
    commands: mpsc::Receiver<ProtoMsg>,
    output: mpsc::Sender<ProtoMsg>,
) -> Result<UploadOutcome> {
    upload_with_limits(proto, sid, request, commands, output, None).await
}

/// Drive a single upload to completion or abort, optionally under the limited
/// (policy) execution context.
///
/// When `limits` is `None` the unchanged upstream-compatible behavior is used.
/// When `Some`, the request is resolved and adjudicated against the held root
/// and policy **before** any initial ACK or path touch; the staging file is an
/// unnamed `O_TMPFILE` published only via the descriptor-safe commit. Both
/// modes share the single wire loop, offsets, ACK behavior and EOF validation.
pub async fn upload_with_limits(
    proto: ProtoType,
    sid: String,
    request: UploadRequest,
    mut commands: mpsc::Receiver<ProtoMsg>,
    output: mpsc::Sender<ProtoMsg>,
    limits: Option<Arc<TransferLimits>>,
) -> Result<UploadOutcome> {
    let deadline = Instant::now() + TOTAL_TIMEOUT;
    if !matches!(
        proto,
        ProtoType::FILE_TRANSFER | ProtoType::FILE_TRANSFER_V2
    ) {
        return Err(anyhow!("unsupported protocol for upload: {proto}"));
    }
    if sid.is_empty() || sid.len() > MAX_SID_LEN {
        return Err(anyhow!("invalid upload session id length"));
    }

    // Shared declared-size parse and 256 MiB hard cap for both modes.
    validate_requested_size(request.size).map_err(|e| anyhow!(e.to_string()))?;
    let declared: Option<u64> = match request.size {
        Some(size) => {
            let size = u64::try_from(size).map_err(|_| anyhow!("negative upload size"))?;
            if size > MAX_UPLOAD_SIZE {
                return Err(anyhow!("declared upload size exceeds limit"));
            }
            Some(size)
        }
        None => None,
    };

    let mut writer: tokio::fs::File;
    let stage_backend: StageBackend;

    if let Some(ctx) = &limits {
        // Resolve limits BEFORE any path touch; never stat the peer path
        // lexically. The original absolute path is mapped through the held root
        // and adjudicated by the compiled policy with no existing facts.
        let raw = required_path(request.path.as_deref()).map_err(|e| anyhow!(e.to_string()))?;
        // Validation, path mapping, policy adjudication, the no-overwrite
        // preflight and stage allocation all happen inside the single
        // context-bound call before any initial ACK is produced.
        let prepared = ctx
            .begin_limited_upload(
                raw,
                request.src_path.as_deref(),
                declared,
                request.mode,
                request.uid,
                request.gid,
            )
            .map_err(|err| anyhow!(err.to_string()))?;
        let (staged, plan) = prepared.into_parts();
        // Obtain a CLOEXEC duplicate of the held staging descriptor for the
        // Tokio writer; never replace or expose the stage's own `File`.
        let owned = staged
            .stage_fd()
            .try_clone_to_owned()
            .context("duplicating staging file descriptor")?;
        let std_file = fs::File::from(owned);
        writer = tokio::fs::File::from_std(std_file);
        stage_backend = StageBackend::Limited {
            stage: staged,
            plan,
        };
    } else {
        // Resolve the destination path verbatim, appending the source basename
        // when the requested target is an existing directory.
        let raw = required_path(request.path.as_deref()).map_err(|e| anyhow!(e.to_string()))?;
        let mut target = PathBuf::from(raw);
        match fs::symlink_metadata(&target) {
            Ok(meta) => {
                let file_type = meta.file_type();
                if file_type.is_dir() {
                    let src = request
                        .src_path
                        .as_deref()
                        .ok_or_else(|| anyhow!("upload into directory requires src_path"))?;
                    let base = source_basename(src).map_err(|e| anyhow!(e.to_string()))?;
                    target.push(base);
                } else if !file_type.is_file() {
                    return Err(anyhow!("upload destination is not a regular file"));
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err).context("inspecting upload destination"),
        }
        match fs::symlink_metadata(&target) {
            Ok(meta) => {
                if !meta.file_type().is_file() {
                    return Err(anyhow!("upload destination is not a regular file"));
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err).context("inspecting upload destination"),
        }

        let parent = match target.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let parent_meta = fs::metadata(&parent).context("upload destination parent")?;
        if !parent_meta.is_dir() {
            return Err(anyhow!("upload destination parent is not a directory"));
        }

        let mode = match request.mode {
            Some(mode) => {
                if mode & !0o777 != 0 {
                    return Err(anyhow!("upload mode contains bits outside 0o777"));
                }
                mode & 0o777
            }
            None => 0o644,
        };

        // Reject paths that cannot be represented as C strings before staging so
        // we never create a temporary file we could not atomically rename.
        if target.as_os_str().as_encoded_bytes().contains(&0) {
            return Err(anyhow!("upload destination path contains a NUL byte"));
        }

        // Stage in the destination directory so the final rename is a
        // same-filesystem atomic operation. The guard removes uncommitted data.
        let stage = Builder::new()
            .prefix(".mender-upload-")
            .tempfile_in(&parent)
            .context("creating upload staging file")?;
        let stage_meta = stage
            .as_file()
            .metadata()
            .context("staging file metadata")?;
        let effective_uid = stage_meta.uid();
        let effective_gid = stage_meta.gid();
        if let Some(uid) = request.uid
            && uid != effective_uid
        {
            return Err(anyhow!(
                "upload ownership change to uid {uid} not supported"
            ));
        }
        if let Some(gid) = request.gid
            && gid != effective_gid
        {
            return Err(anyhow!(
                "upload ownership change to gid {gid} not supported"
            ));
        }

        writer = tokio::fs::File::from_std(stage.reopen().context("reopening staging file")?);
        stage_backend = StageBackend::Named {
            stage,
            target,
            mode,
        };
    }

    let is_v1 = proto == ProtoType::FILE_TRANSFER;
    if is_v1 {
        send_ack(&output, proto, &sid, Some(0), deadline).await?;
    }

    let mut accumulated: u64 = 0;

    loop {
        let message = match recv_command(&mut commands, deadline).await? {
            Some(message) => message,
            None => return Ok(UploadOutcome::Aborted),
        };

        if message.header.proto != proto || message.header.session_id != sid {
            return Err(anyhow!("upload message protocol or session mismatch"));
        }
        if message.header.msg_type == "error" {
            return Ok(UploadOutcome::Aborted);
        }
        if message.header.msg_type != "file_chunk" {
            return Err(anyhow!(
                "unexpected upload message type: {}",
                message.header.msg_type
            ));
        }

        let offset_value = message
            .header
            .properties
            .get("offset")
            .ok_or_else(|| anyhow!("file chunk missing offset property"))?;
        let offset = parse_offset(offset_value)
            .ok_or_else(|| anyhow!("file chunk offset is not an integer"))?;
        if offset < 0 {
            return Err(anyhow!("file chunk offset is negative"));
        }
        let offset_unsigned =
            u64::try_from(offset).map_err(|_| anyhow!("invalid file chunk offset"))?;
        if offset_unsigned != accumulated {
            return Err(anyhow!(
                "file chunk offset {offset_unsigned} does not match expected {accumulated}"
            ));
        }

        if message.body.is_empty() {
            if let Some(size) = declared
                && accumulated != size
            {
                return Err(anyhow!(
                    "upload ended at {accumulated} bytes, expected {size}"
                ));
            }
            break;
        }

        if message.body.len() > MAX_CHUNK_SIZE {
            return Err(anyhow!("upload chunk exceeds {MAX_CHUNK_SIZE} byte limit"));
        }
        let chunk_len =
            u64::try_from(message.body.len()).map_err(|_| anyhow!("upload chunk too large"))?;
        let new_total = accumulated
            .checked_add(chunk_len)
            .ok_or_else(|| anyhow!("upload size overflow"))?;
        if new_total > MAX_UPLOAD_SIZE {
            return Err(anyhow!("upload exceeds maximum size"));
        }
        if let Some(size) = declared
            && new_total > size
        {
            return Err(anyhow!("upload exceeds declared size"));
        }
        if let Some(ctx) = &limits {
            // Configured progress cap (inclusive) re-checked before writing.
            if !ctx.progress_allowed(new_total) {
                return Err(anyhow!("upload exceeds maximum size"));
            }
            // Charge the shared RX counter for each accepted nonempty chunk
            // before the write; EOF never reaches this branch.
            match ctx.counter().try_record_rx_now(chunk_len) {
                Ok(true) => {}
                Ok(false) => return Err(anyhow!("upload exceeds receive rate limit")),
                Err(err) => return Err(anyhow!("upload rate counter failure: {err}")),
            }
        }

        write_all_bounded(&mut writer, &message.body, deadline).await?;
        accumulated = new_total;

        if is_v1 {
            send_ack(&output, proto, &sid, Some(offset), deadline).await?;
        }
    }

    // Flush buffered data, apply the final mode (legacy named staging only),
    // then sync. Limited staging defers metadata to the descriptor-safe commit
    // (fchown then fchmod inside `commit_with_metadata`).
    flush_with_deadline(&mut writer, deadline).await?;
    if let StageBackend::Named { stage, mode, .. } = &stage_backend {
        stage
            .as_file()
            .set_permissions(fs::Permissions::from_mode(*mode))
            .context("setting upload file permissions")?;
    }
    sync_with_deadline(&mut writer, deadline).await?;
    drop(writer);

    let final_offset: Option<i64> = if is_v1 {
        Some(i64::try_from(accumulated).map_err(|_| anyhow!("final upload size exceeds i64"))?)
    } else {
        None
    };

    // Check the total deadline immediately before starting the atomic commit so
    // a new publication is not begun after it has expired. A synchronous fsync
    // or link already in progress cannot be forcibly cancelled and may still
    // finish after the deadline; this check only prevents a new publication from
    // being started, it does not bound late completion.
    if Instant::now() >= deadline {
        return Err(anyhow!("upload exceeded total deadline"));
    }

    match stage_backend {
        StageBackend::Named { stage, target, .. } => match stage.persist(&target) {
            Ok(_file) => {}
            Err(err) => return Err(anyhow!("failed to persist upload: {}", err.error)),
        },
        StageBackend::Limited { stage, plan } => {
            // Consume the stage inline; never detach a spawn_blocking commit.
            // `PublishedButDurabilityUnknown` surfaces as an error (the file is
            // visible but durability is uncertain): no success ACK is sent.
            stage
                .commit_with_metadata(plan)
                .map_err(|err| anyhow!("failed to publish upload: {err}"))?;
        }
    }

    // After persist the destination is committed. A failure to deliver the final
    // acknowledgement cannot be rolled back, so surface it distinctly.
    send_ack(&output, proto, &sid, final_offset, deadline)
        .await
        .map_err(CommittedAckError::new)?;

    Ok(UploadOutcome::Complete)
}
