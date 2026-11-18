//! Bounded, synchronous command runner for the Mender command handler.
//!
//! Runs one fixed, validated binary under a bounded execution deadline in its own
//! session (via the `POSIX_SPAWN_SETSID` spawn attribute), then performs
//! session-scoped descendant cleanup before reaping the direct leader. Only a
//! failure to *verify cleanup* is escalated as a typed fatal error; ordinary
//! outcomes (missing binary, spawn error, non-zero exit, timeout, cancel or a
//! status-probe error) are reported as a normal wire reply.
//!
//! # Assumptions
//!
//! * No external child reaper reaps our direct child; the leader stays unreaped
//!   until session kill/verification completes so its SID cannot be reused.
//! * A Linux kernel with `pidfd_open(2)`/`pidfd_send_signal(2)` and a visible
//!   `/proc` is available, and this process may signal its own session members.
//! * A fixed-path system binary is assumed responsive and trusted; a blocked
//!   `posix_spawn`/syscall therefore bounds *our* polling, not real time.
//! * File-capabilities on the trusted system binary are outside the metadata
//!   validation performed here (only mode bits are inspected).
//! * This is not cgroup containment: a descendant that escapes the session is
//!   out of scope.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use nix_spawn::errno::Errno;
use nix_spawn::fcntl::OFlag;
use nix_spawn::spawn::{PosixSpawnAttr, PosixSpawnFileActions, PosixSpawnFlags, posix_spawn};
use nix_spawn::sys::stat::Mode;
use nix_spawn::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid, waitpid};
use nix_spawn::unistd::Pid;
use rustix::process::{Pid as RustixPid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};

use super::schema::{self, Request};
use crate::protocol::ProtoMsg;
use crate::session_process::OwnedSession;

/// Largest accepted execution deadline.
const MAX_EXECUTION: Duration = Duration::from_secs(60);
/// Largest accepted cleanup deadline.
const MAX_CLEANUP: Duration = Duration::from_secs(5);
/// Bounded poll/sleep interval used by the deadline loops.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Fixed command-runner configuration.
#[derive(Clone)]
pub(super) struct Config {
    /// Candidate binary paths, tried in order (falling back only on `NotFound`).
    pub candidates: Vec<PathBuf>,
    /// Bounded deadline for the child's execution.
    pub execution: Duration,
    /// Deadline shared by session scan, signal and leader reaping.
    pub cleanup: Duration,
}

impl Config {
    /// Trusted production configuration for the Mender client binaries.
    pub(super) fn production() -> Self {
        Self {
            candidates: vec![
                PathBuf::from("/usr/bin/mender-update"),
                PathBuf::from("/usr/bin/mender"),
            ],
            execution: Duration::from_secs(60),
            cleanup: Duration::from_secs(5),
        }
    }
}

/// Typed, clonable marker for a fatal cleanup failure.
///
/// Returned (as `anyhow::Error`) only when session-scoped cleanup could not be
/// verified or the leader could not be reaped within the cleanup deadline. The
/// manager reexports this type and downcasts it from the root cause.
#[derive(Clone, Debug)]
pub struct CommandCleanupFailure {
    source: Arc<anyhow::Error>,
}

impl CommandCleanupFailure {
    pub(super) fn new(err: anyhow::Error) -> Self {
        Self {
            source: Arc::new(err),
        }
    }
}

impl std::fmt::Display for CommandCleanupFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "command cleanup failed: {}", self.source)
    }
}

impl std::error::Error for CommandCleanupFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let err: &anyhow::Error = self.source.as_ref();
        let dyn_err: &(dyn std::error::Error + Send + Sync + 'static) =
            <anyhow::Error as AsRef<dyn std::error::Error + Send + Sync + 'static>>::as_ref(err);
        Some(dyn_err)
    }
}

/// Terminal observation of the child, decided before cleanup runs.
enum Stop {
    Exited(WaitStatus),
    TimedOut,
    Cancelled,
    ProbeError(anyhow::Error),
}

/// Run one validated command request.
pub(super) fn run(request: Request, config: Config, cancel: Arc<AtomicBool>) -> Result<ProtoMsg> {
    if let Err(err) = validate_config(&config) {
        return Ok(schema::reply(&request.header, Some(&format!("{err:#}"))));
    }
    if cancel.load(Ordering::Relaxed) {
        return Ok(schema::reply(&request.header, Some("command cancelled")));
    }
    let binary = match select_binary(&config.candidates) {
        Ok(binary) => binary,
        Err(err) => return Ok(schema::reply(&request.header, Some(&format!("{err:#}")))),
    };

    let Ok(binary_c) = CString::new(binary.as_os_str().as_bytes()) else {
        return Ok(schema::reply(&request.header, Some("binary path invalid")));
    };
    let Ok(arg_c) = CString::new(request.command.argument()) else {
        return Ok(schema::reply(
            &request.header,
            Some("command argument invalid"),
        ));
    };
    let Ok(env) = CString::new("PATH=/usr/bin:/bin") else {
        return Ok(schema::reply(
            &request.header,
            Some("internal environment error"),
        ));
    };

    let mut actions = match PosixSpawnFileActions::init() {
        Ok(actions) => actions,
        Err(err) => {
            return Ok(schema::reply(
                &request.header,
                Some(&format!("spawn setup failed: {err}")),
            ));
        }
    };
    for fd in 0..3 {
        if let Err(err) = actions.add_open(fd, "/dev/null", OFlag::O_RDWR, Mode::empty()) {
            return Ok(schema::reply(
                &request.header,
                Some(&format!("spawn setup failed: {err}")),
            ));
        }
    }

    // Known libc constant describing a POSIX extension flag; it is not an
    // arbitrary bit value and is only combined with retained defined bits.
    let setsid_bits = match i32::try_from(i64::from(nix_spawn::libc::POSIX_SPAWN_SETSID)) {
        Ok(bits) => bits,
        Err(_) => {
            return Ok(schema::reply(
                &request.header,
                Some("unsupported setsid spawn flag"),
            ));
        }
    };
    let flags = PosixSpawnFlags::from_bits_retain(setsid_bits);

    let mut attr = match PosixSpawnAttr::init() {
        Ok(attr) => attr,
        Err(err) => {
            return Ok(schema::reply(
                &request.header,
                Some(&format!("spawn setup failed: {err}")),
            ));
        }
    };
    if let Err(err) = attr.set_flags(flags) {
        return Ok(schema::reply(
            &request.header,
            Some(&format!("failed to set spawn flags: {err}")),
        ));
    }
    // `set_flags` only reports the attribute setter result and may not surface
    // every libc error for this POSIX extension bit; a read-back via `attr.flags()`
    // cannot confirm SETSID because it is decoded with `from_bits_truncate`,
    // dropping the POSIX-only bit. The setter is therefore a best-effort request
    // of a known flag, and actual session ownership is verified structurally below
    // by `OwnedSession::capture` requiring SID == leader PID before any wait/reap.

    let start = Instant::now();
    let exec_deadline = match start.checked_add(config.execution) {
        Some(deadline) => deadline,
        None => {
            return Ok(schema::reply(
                &request.header,
                Some("execution deadline overflow"),
            ));
        }
    };

    let args = [binary_c.clone(), arg_c];
    let child = match posix_spawn(binary_c.as_c_str(), &actions, &attr, &args, &[env]) {
        Ok(pid) => pid,
        Err(err) => {
            return Ok(schema::reply(
                &request.header,
                Some(&format!("failed to spawn command: {err}")),
            ));
        }
    };

    // Capture the session immediately, before any wait/reap, so the SID cannot
    // be reused. `capture` also verifies SID == leader; this structural check is
    // the mandatory runtime verification that SETSID was applied.
    let capture = u32::try_from(child.as_raw())
        .context("child pid out of range")
        .and_then(OwnedSession::capture);

    let session = match capture {
        Ok(session) => session,
        Err(err) => {
            let cause = err.context("failed to capture child session");
            // A capture failure is always fatal, even if the leader is reaped.
            let fatal = match cleanup_and_reap(None, child, config.cleanup) {
                Ok(()) => cause.context("cleanup escalated; leader reaped"),
                Err(cleanup_err) => append_fatal(Some(cause), cleanup_err),
            };
            return Err(anyhow::Error::new(CommandCleanupFailure::new(fatal)));
        }
    };

    let stop = poll_child(child, exec_deadline, cancel.as_ref());

    if let Err(cleanup_err) = cleanup_and_reap(Some(&session), child, config.cleanup) {
        return Err(anyhow::Error::new(CommandCleanupFailure::new(cleanup_err)));
    }

    let reply = match &stop {
        Stop::Exited(WaitStatus::Exited(_, 0)) => schema::reply(&request.header, None),
        Stop::Exited(WaitStatus::Exited(_, code)) => schema::reply(
            &request.header,
            Some(&format!("command exited with status {code}")),
        ),
        Stop::Exited(WaitStatus::Signaled(_, sig, _)) => schema::reply(
            &request.header,
            Some(&format!("command terminated by signal {sig:?}")),
        ),
        Stop::Exited(_) => {
            schema::reply(&request.header, Some("command exited with unknown status"))
        }
        Stop::TimedOut => schema::reply(&request.header, Some("command timed out")),
        Stop::Cancelled => schema::reply(&request.header, Some("command cancelled")),
        Stop::ProbeError(err) => schema::reply(
            &request.header,
            Some(&format!("status probe failed: {err:#}")),
        ),
    };
    Ok(reply)
}

/// Reject empty/oversized candidate lists and out-of-range deadlines before
/// any spawn happens.
fn validate_config(config: &Config) -> Result<()> {
    if config.candidates.is_empty() || config.candidates.len() > 2 {
        bail!("candidate binary list must contain one or two paths");
    }
    for candidate in &config.candidates {
        if !candidate.is_absolute() {
            bail!(
                "candidate binary path {} is not absolute",
                candidate.display()
            );
        }
    }
    if config.execution.is_zero() || config.execution > MAX_EXECUTION {
        bail!("execution timeout out of bounds");
    }
    if config.cleanup.is_zero() || config.cleanup > MAX_CLEANUP {
        bail!("cleanup timeout out of bounds");
    }
    Ok(())
}

/// Pick the first present candidate, falling back only on `NotFound`.
fn select_binary(candidates: &[PathBuf]) -> Result<PathBuf> {
    for candidate in candidates {
        match std::fs::metadata(candidate) {
            Ok(meta) => {
                validate_binary_metadata(candidate, &meta)?;
                return Ok(candidate.clone());
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(anyhow::Error::new(err)
                    .context(format!("failed to stat {}", candidate.display())));
            }
        }
    }
    bail!("no mender binary found among candidates")
}

/// Require a regular, executable file that does not carry setuid/setgid bits.
fn validate_binary_metadata(path: &Path, meta: &std::fs::Metadata) -> Result<()> {
    if !meta.file_type().is_file() {
        bail!("{} is not a regular file", path.display());
    }
    let mode = meta.mode();
    if mode & 0o6000 != 0 {
        bail!("{} has setuid/setgid bits set", path.display());
    }
    if mode & 0o111 == 0 {
        bail!("{} is not executable", path.display());
    }
    Ok(())
}

/// Poll the child's exit state without reaping, honouring cancel + deadline.
fn poll_child(child: Pid, exec_deadline: Instant, cancel: &AtomicBool) -> Stop {
    let flags = WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT;
    loop {
        // Cancel and deadline are checked at the top of every iteration,
        // including after an `EINTR`, so interrupts cannot starve them.
        if cancel.load(Ordering::Relaxed) {
            return Stop::Cancelled;
        }
        if Instant::now() >= exec_deadline {
            return Stop::TimedOut;
        }
        match waitid(Id::Pid(child), flags) {
            Ok(status @ (WaitStatus::Exited(..) | WaitStatus::Signaled(..))) => {
                return Stop::Exited(status);
            }
            Ok(WaitStatus::StillAlive) => {}
            Ok(other) => {
                return Stop::ProbeError(anyhow::anyhow!(
                    "unexpected wait status while observing command: {other:?}"
                ));
            }
            Err(Errno::EINTR) => continue,
            Err(Errno::ECHILD) => {
                return Stop::ProbeError(anyhow::anyhow!(
                    "ownership of direct child lost during observation (ECHILD)"
                ));
            }
            Err(err) => {
                return Stop::ProbeError(anyhow::Error::new(err).context("waitid failed"));
            }
        }
        let now = Instant::now();
        if now >= exec_deadline {
            return Stop::TimedOut;
        }
        let sleep_for = POLL_INTERVAL.min(exec_deadline.saturating_duration_since(now));
        if !sleep_for.is_zero() {
            thread::sleep(sleep_for);
        }
    }
}

/// Outcome of probing whether the direct child is still ours and unreaped.
enum Ownership {
    /// `waitid` succeeded: the PID is still our child. `exited` is true when the
    /// observed status is terminal (`Exited`/`Signaled`), i.e. a zombie.
    Owned { exited: bool },
    /// `ECHILD`: the child was reaped externally; the PID may already be reused.
    Lost,
    /// Any other `waitid` error; ownership cannot be confirmed.
    Unknown(anyhow::Error),
}

/// Confirm whether `leader` is still our unreaped child, without reaping it.
///
/// Always performs at least one `WNOWAIT` probe, even if `deadline` has already
/// passed, so a bounded handoff can still confirm ownership with a single
/// constant-time observation against a responsive kernel. `EINTR` is retried
/// only while time remains on the shared cleanup `deadline`; once it expires, an
/// interrupted probe becomes an honest `Unknown` because ownership cannot be
/// confirmed.
fn confirm_owned(leader: Pid, deadline: Instant) -> Ownership {
    let flags = WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT;
    loop {
        match waitid(Id::Pid(leader), flags) {
            Ok(status) => {
                let exited = matches!(status, WaitStatus::Exited(..) | WaitStatus::Signaled(..));
                return Ownership::Owned { exited };
            }
            Err(Errno::ECHILD) => return Ownership::Lost,
            Err(Errno::EINTR) => {
                if Instant::now() >= deadline {
                    return Ownership::Unknown(anyhow::anyhow!(
                        "ownership check interrupted after cleanup deadline"
                    ));
                }
                continue;
            }
            Err(err) => {
                return Ownership::Unknown(
                    anyhow::Error::new(err).context("waitid ownership check"),
                );
            }
        }
    }
}

/// Result of a guarded best-effort leader kill.
enum KillOutcome {
    /// Ownership was lost (`ECHILD`); no further numeric-PID operations are safe.
    Lost,
    /// Ownership could not be confirmed; the numeric PID must not be touched.
    OwnershipUnknown(anyhow::Error),
    /// Ownership was confirmed but the pidfd/signal operation itself failed.
    Failed(anyhow::Error),
}

/// Best-effort direct-leader `SIGKILL` through a `pidfd` (never a broad group
/// kill), guarded by ownership confirmation before and after opening the pidfd
/// so a reused PID is never signalled. When the leader is already a confirmed
/// zombie (`Owned { exited: true }`), no signal is sent and this returns `Ok`.
fn kill_leader_if_owned(leader: Pid, deadline: Instant) -> std::result::Result<(), KillOutcome> {
    match confirm_owned(leader, deadline) {
        Ownership::Owned { exited: true } => return Ok(()),
        Ownership::Owned { exited: false } => {}
        Ownership::Lost => return Err(KillOutcome::Lost),
        Ownership::Unknown(err) => return Err(KillOutcome::OwnershipUnknown(err)),
    }
    let pid = match RustixPid::from_raw(leader.as_raw()) {
        Some(pid) => pid,
        None => {
            return Err(KillOutcome::Failed(anyhow::anyhow!(
                "invalid leader pid for pidfd"
            )));
        }
    };
    let pidfd = match pidfd_open(pid, PidfdFlags::empty()) {
        Ok(pidfd) => pidfd,
        Err(err) => {
            return Err(KillOutcome::Failed(
                anyhow::Error::new(err).context("pidfd_open failed"),
            ));
        }
    };
    // Re-confirm ownership after opening the descriptor, before signalling.
    match confirm_owned(leader, deadline) {
        Ownership::Owned { exited: true } => return Ok(()),
        Ownership::Owned { exited: false } => {}
        Ownership::Lost => return Err(KillOutcome::Lost),
        Ownership::Unknown(err) => return Err(KillOutcome::OwnershipUnknown(err)),
    }
    if let Err(err) = pidfd_send_signal(&pidfd, Signal::KILL).context("pidfd_send_signal failed") {
        return Err(KillOutcome::Failed(err));
    }
    Ok(())
}

/// Append a later error as context on an existing fatal cause.
fn append_fatal(existing: Option<anyhow::Error>, next: anyhow::Error) -> anyhow::Error {
    match existing {
        Some(prev) => prev.context(format!("{next:#}")),
        None => next,
    }
}

/// Kill/verify the (optionally captured) session and reap the leader under one
/// shared cleanup deadline computed once here.
///
/// Ordinary callers pass the captured `session`; capture-failure callers pass
/// `None`. `ECHILD` is never treated as a successful reap: it means ownership was
/// lost, so the numeric PID is abandoned (no signal, no background waiter).
fn cleanup_and_reap(session: Option<&OwnedSession>, leader: Pid, cleanup: Duration) -> Result<()> {
    let deadline = Instant::now()
        .checked_add(cleanup)
        .context("cleanup deadline overflow")?;

    let mut fatal: Option<anyhow::Error> = None;

    // Track whether the session-level verification actually succeeded. Only a
    // confirmed session kill/verify lets us skip the direct leader fallback.
    let mut session_verified = false;
    if let Some(session) = session {
        match session.kill_and_verify(deadline) {
            Ok(()) => session_verified = true,
            Err(err) => fatal = Some(err.context("session kill/verify failed")),
        }
    }

    // The direct leader fallback is only needed when no captured session existed
    // (capture failure) or its own kill/verify did not confirm cleanup. When the
    // session is verified, all session processes are dead/zombie and we go
    // straight to the bounded reap, avoiding redundant signalling (and a spurious
    // `ESRCH` on an already-exited leader).
    if !session_verified {
        match kill_leader_if_owned(leader, deadline) {
            Ok(()) => {}
            Err(KillOutcome::Lost) => {
                let err = append_fatal(
                    fatal,
                    anyhow::anyhow!("ownership of direct child lost (ECHILD)"),
                );
                return Err(err);
            }
            Err(KillOutcome::OwnershipUnknown(err)) => {
                // Never signal/reap/spawn a waiter on an unconfirmed numeric PID.
                let err = append_fatal(fatal, err.context("direct leader ownership unknown"));
                return Err(err);
            }
            Err(KillOutcome::Failed(err)) => {
                fatal = Some(append_fatal(
                    fatal,
                    err.context("direct leader kill failed"),
                ));
            }
        }
    }

    match reap_leader(leader, deadline) {
        Ok(()) => match fatal {
            Some(err) => Err(err.context("cleanup failed; leader reaped")),
            None => Ok(()),
        },
        Err(reap_err) => {
            let mut err = append_fatal(fatal, reap_err.context("leader reap failed"));
            // Hand off a single background waiter only when the leader is still a
            // confirmed un-reaped child. This bounded handoff probe still performs
            // exactly one non-reaping `WNOWAIT` observation even after the cleanup
            // deadline expired (constant-time against a responsive kernel); if
            // ownership cannot be confirmed the PID may be reused and is left be.
            if matches!(confirm_owned(leader, deadline), Ownership::Owned { .. })
                && let Err(thread_err) = spawn_background_waiter(leader)
            {
                err = err.context(format!("background waiter spawn failed: {thread_err}"));
            }
            Err(err)
        }
    }
}

/// Bounded `WNOHANG` reap of the direct leader, checking the deadline at the top
/// of every iteration so interrupts cannot starve it. `ECHILD` is a fatal error.
fn reap_leader(leader: Pid, deadline: Instant) -> Result<()> {
    loop {
        if Instant::now() >= deadline {
            bail!("timed out reaping leader");
        }
        match waitpid(Some(leader), Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(..) | WaitStatus::Signaled(..)) => return Ok(()),
            Ok(WaitStatus::StillAlive) => {}
            Ok(other) => {
                bail!("unexpected wait status while reaping leader: {other:?}");
            }
            Err(Errno::EINTR) => continue,
            Err(Errno::ECHILD) => {
                bail!("ownership of leader lost while reaping (ECHILD)");
            }
            Err(err) => return Err(anyhow::Error::new(err).context("waitpid failed")),
        }
        let now = Instant::now();
        if now >= deadline {
            bail!("timed out reaping leader");
        }
        let sleep_for = POLL_INTERVAL.min(deadline.saturating_duration_since(now));
        if !sleep_for.is_zero() {
            thread::sleep(sleep_for);
        }
    }
}

/// Spawn a detached background waiter that blocks safely on `waitpid` (retrying
/// `EINTR`) so an unreaped leader is eventually collected without spinning.
fn spawn_background_waiter(leader: Pid) -> std::io::Result<()> {
    thread::Builder::new()
        .name("mender-cmd-reaper".to_owned())
        .spawn(move || {
            loop {
                match waitpid(Some(leader), None) {
                    Ok(WaitStatus::Exited(..) | WaitStatus::Signaled(..)) => break,
                    Ok(_) => continue,
                    Err(Errno::EINTR) => continue,
                    Err(_) => break,
                }
            }
        })
        .map(|_handle| ())
}
