//! Minimal PTY shell building block.
//!
//! This module spawns a single interactive shell in a pseudo-terminal and
//! exposes a small, daemon-friendly API: initial size,
//! resize, input write, a bounded async output receiver, an explicit
//! [`PtyShell::terminate_processes`] that stops session jobs while leaving the
//! reader running, and [`PtyShell::stop`] that also cancels the reader.
//!
//! # Privilege model
//!
//! A shell is either spawned directly for the current effective uid, or — when
//! the configured user resolves to a *different* uid — delegated to the
//! trusted, fixed-path session helper. That helper is an ordinary binary and is
//! never installed setuid; it is invoked only by an already-root parent. The
//! helper path requires the parent's real, effective and saved uids to all be 0
//! and never changes credentials in this (multithreaded) process. Target
//! identity, shell, arguments and TERM reach the helper only through an
//! authenticated request, never through the child environment.
//!
//! # Blocking contract
//!
//! [`PtyShell::spawn`], [`PtyShell::write_input`], [`PtyShell::stop`],
//! [`PtyShell::terminate_processes`] and [`PtyShell::drop`] perform blocking
//! I/O (spawn, write, wait, join). They **must** be invoked from a blocking
//! context, e.g. via `tokio::task::spawn_blocking`, never directly on an async
//! runtime worker. [`PtyShell::resize`] and [`PtyShell::take_output`] are cheap
//! and non-blocking.
//!
//! # Assumptions
//!
//! * Linux procfs is available at `/proc` for session enumeration.
//! * The kernel supports the pidfd operations used by
//!   [`crate::session_process::OwnedSession`].
//! * This process may signal the spawned shell and its session members.
//! * No external child reaper reaps the shell while this handle still owns it.
//! * Bounded deadlines limit this code's polling; they do not promise that the
//!   kernel schedules or terminates processes within a real-time bound.

use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::sys::signal::{Signal, kill};
use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid};
use nix::unistd::{Pid, Uid, User, getresuid};
use portable_pty::{
    Child, ChildKiller, CommandBuilder, MasterPty, PtySize, SlavePty, native_pty_system,
};
use rustix::process::Signal as RustixSignal;
use tokio::sync::mpsc;

use crate::config::Config;
use crate::session_helper::{self, TargetRequest};
use crate::session_process::OwnedSession;

/// Default capacity (in chunks) of the bounded output channel.
pub const DEFAULT_OUTPUT_CAPACITY: usize = 64;

/// Maximum accepted length of the configured username.
const MAX_USERNAME_LEN: usize = 256;

/// Maximum bytes read from the PTY in a single read.
const READ_CHUNK: usize = 4096;

/// Sleep between `try_send` retries when the output channel is full.
const SEND_RETRY_SLEEP: Duration = Duration::from_millis(5);

/// Sleep between `read` retries when the PTY is nonblocking and empty.
const READ_RETRY_SLEEP: Duration = Duration::from_millis(5);

/// Sleep between `write` retries when the PTY would block.
const WRITE_RETRY_SLEEP: Duration = Duration::from_millis(5);

/// Upper bound on how long [`PtyShell::write_input`] will wait for the PTY to
/// accept bytes before returning an error.
const WRITE_DEADLINE: Duration = Duration::from_secs(4);

/// Overall upper bound on process termination and direct-child reaping. The
/// same deadline is shared by every phase; no phase creates a fresh budget.
const REAP_DEADLINE: Duration = Duration::from_secs(5);

/// How long cleanup waits for the child to exit after the graceful shutdown
/// request (SIGHUP via `ChildKiller::kill`) before escalating to `SIGKILL`.
const GRACEFUL_DEADLINE: Duration = Duration::from_millis(100);

/// Poll interval used while waiting for the child to be reaped.
const REAP_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Name of the background thread that continues reaping a child when the
/// bounded direct-child wait expires or errors.
const CHILD_WAITER_THREAD: &str = "pty-child-waiter";

/// Marker error indicating that PTY cleanup (session termination, direct-child
/// reaping, or both) did not complete cleanly.
///
/// This type is attached via `anyhow::Context` at the public boundaries
/// ([`PtyShell::spawn`] and [`PtyShell::stop`]) whenever cleanup itself reports
/// a failure. Callers can detect it with
/// `err.downcast_ref::<pty::CleanupFailure>().is_some()`.
///
/// An ordinary spawn error that followed a *fully successful* cleanup does
/// **not** contain this marker; likewise user validation, `openpty` and
/// pre-child spawn failures never contain it.
///
/// The underlying cleanup diagnostic is exposed through
/// [`std::error::Error::source`] and the `Display` implementation; it is not
/// accessible as a field so that callers cannot accidentally rely on its
/// concrete type. The diagnostic is stored behind an [`Arc`] so that a stored
/// failure can be replayed on later calls without any attempt to re-signal a
/// released (and potentially reused) PID.
#[derive(Clone, Debug)]
pub struct CleanupFailure {
    source: Arc<anyhow::Error>,
}

impl CleanupFailure {
    fn new(source: anyhow::Error) -> Self {
        Self {
            source: Arc::new(source),
        }
    }

    fn from_arc(source: Arc<anyhow::Error>) -> Self {
        Self { source }
    }
}

impl fmt::Display for CleanupFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cleanup incomplete: {:#}", self.source)
    }
}

impl std::error::Error for CleanupFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let err: &(dyn std::error::Error + 'static) = (*self.source).as_ref();
        Some(err)
    }
}

/// Explicit process-cleanup state, kept separate from reader cancellation.
///
/// `Active` means cleanup has not yet been attempted. `Complete` means the
/// direct child was reaped and (when a session guard exists) the session was
/// verified gone. `Failed` stores the first cleanup diagnostic so that later
/// calls replay the same typed [`CleanupFailure`] without retrying signals
/// against a potentially released or reused PID.
enum ProcessCleanup {
    Active,
    Complete,
    Failed(Arc<anyhow::Error>),
}

/// A live PTY-backed shell for the current user.
pub struct PtyShell {
    master: Box<dyn MasterPty + Send>,
    writer: Option<Box<dyn Write + Send>>,
    killer: Box<dyn ChildKiller + Send + Sync>,
    child: Option<Box<dyn Child + Send + Sync>>,
    output: Option<mpsc::Receiver<Vec<u8>>>,
    reader_stop: Arc<AtomicBool>,
    reader_handle: Option<thread::JoinHandle<()>>,
    process_id: u32,
    session: Option<OwnedSession>,
    process_cleanup: ProcessCleanup,
}

impl PtyShell {
    /// Spawn a shell described by `config`.
    ///
    /// When the configured `User` resolves to the current effective uid this
    /// uses the direct path: the shell is spawned for this process's own
    /// identity with `HOME` from the resolved account and `TERM` set to
    /// `xterm-256color`.
    ///
    /// When the configured `User` resolves to a *different* uid, spawning is
    /// delegated to the trusted, fixed-path session helper (an ordinary binary
    /// that is never setuid and is invoked only by an already-root parent).
    /// That path requires the parent's real, effective and saved uids to all be
    /// 0, and a target uid that is non-zero and not `u32::MAX`, with a `gid`
    /// other than `u32::MAX`. The helper listener is prepared *before* the child is
    /// spawned and the target identity, shell, arguments and TERM travel only
    /// through the authenticated helper request, never through the child
    /// environment. No credential changes happen in this (multithreaded)
    /// parent. Privilege switching without a root parent is rejected.
    ///
    /// If a failure occurs after the child was spawned and cleanup of that
    /// child/session *also* fails, the returned error contains a
    /// [`CleanupFailure`] marker. A failure whose cleanup completed fully
    /// returns the original error without the marker.
    ///
    /// This function blocks and must be called from a blocking context.
    pub fn spawn(config: &Config, rows: u16, cols: u16) -> Result<Self> {
        let user = resolve_user(&config.user)?;
        match select_spawn_mode(user.uid.as_raw(), Uid::effective().as_raw()) {
            SpawnMode::Direct => Self::spawn_direct(config, user, rows, cols),
            SpawnMode::Helper => Self::spawn_via_helper(config, user, rows, cols),
        }
    }

    /// Direct spawn path for the current effective uid. Unchanged semantics:
    /// the shell runs as this process and receives `HOME`/`USER`/`LOGNAME`.
    fn spawn_direct(config: &Config, user: User, rows: u16, cols: u16) -> Result<Self> {
        let home = user.dir.to_string_lossy().into_owned();
        // Select the child's working directory: a genuinely missing home falls
        // back to `/`, any other metadata outcome keeps the configured home so
        // an ordinary exec error surfaces later. No global cwd is changed here.
        let working_dir = select_direct_cwd(user.dir.as_path());
        let OpenedPty {
            master,
            slave,
            writer,
            reader,
        } = open_pty(rows, cols)?;

        let mut cmd = CommandBuilder::new(&config.shell_command);
        for arg in &config.shell_arguments {
            cmd.arg(arg);
        }
        cmd.env("HOME", &home);
        cmd.env("TERM", "xterm-256color");
        cmd.env("USER", &user.name);
        cmd.env("LOGNAME", &user.name);
        cmd.cwd(&working_dir);

        let child = slave
            .spawn_command(cmd)
            .context("failed to spawn shell on PTY")?;
        // Drop the slave handle in the parent so the child owns the only
        // remaining slave reference; otherwise reads never see EOF.
        drop(slave);

        let process_id = child.process_id().unwrap_or(0);
        let killer = child.clone_killer();

        // Capture the session identity immediately after spawn, before any
        // wait/reap, so the SID cannot be reused while we still need it.
        let session = match OwnedSession::capture(process_id) {
            Ok(session) => session,
            Err(err) => {
                let original = err.context("failed to capture PTY session");
                let cleanup = cleanup_failed_spawn(child, killer, process_id, None);
                return Err(with_cleanup_context(original, cleanup));
            }
        };

        let (tx, rx) = mpsc::channel::<Vec<u8>>(DEFAULT_OUTPUT_CAPACITY);
        let reader_stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&reader_stop);
        let reader_handle = match thread::Builder::new()
            .name("pty-reader".into())
            .spawn(move || reader_loop(reader, tx, stop_flag))
        {
            Ok(handle) => handle,
            Err(err) => {
                let original = anyhow::Error::new(err).context("failed to spawn PTY reader thread");
                // The session was captured successfully: terminate the whole
                // session, not just the direct child. Keep the leader
                // unreaped until session cleanup has finished.
                let cleanup = cleanup_failed_spawn(child, killer, process_id, Some(session));
                return Err(with_cleanup_context(original, cleanup));
            }
        };

        Ok(Self {
            master,
            writer: Some(writer),
            killer,
            child: Some(child),
            output: Some(rx),
            reader_stop,
            reader_handle: Some(reader_handle),
            process_id,
            session: Some(session),
            process_cleanup: ProcessCleanup::Active,
        })
    }

    /// Privilege-drop spawn path for a configured user whose uid differs from
    /// the current effective uid. Requires a fully-root parent and delegates to
    /// the trusted helper, whose readiness proof must succeed before the reader
    /// thread starts.
    fn spawn_via_helper(config: &Config, user: User, rows: u16, cols: u16) -> Result<Self> {
        // Never change credentials in this (multithreaded) process. Only a root
        // parent may ask the trusted helper to drop to a different target.
        let credentials = getresuid().context("root credential check failed")?;
        let root = Uid::from_raw(0);
        if credentials.real != root || credentials.effective != root || credentials.saved != root {
            bail!(
                "configured user {} has a different uid; privilege switching is not supported unless running as root",
                user.name
            );
        }
        // Validate the target identity bounds before preparing any resource.
        validate_helper_target(user.uid.as_raw(), user.gid.as_raw())?;

        // Prepare the trusted helper listener BEFORE the child is spawned. This
        // validates the fixed helper path and creates the root-owned 0700
        // listener under a private directory.
        let listener = session_helper::prepare().context("failed to prepare session helper")?;

        let OpenedPty {
            master,
            slave,
            writer,
            reader,
        } = open_pty(rows, cols)?;

        // The helper receives only its trusted path, socket and parent pid on
        // the command line. Target identity, shell, arguments and TERM travel
        // only through the authenticated request, never through the
        // environment. A minimal fixed environment keeps the helper's own
        // execution deterministic.
        let mut cmd = CommandBuilder::new(listener.helper_path());
        cmd.arg("--socket");
        cmd.arg(listener.socket_path());
        cmd.arg("--parent-pid");
        cmd.arg(listener.expected_parent_pid().to_string());
        cmd.env_clear();
        cmd.env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
        cmd.env("HOME", "/");
        cmd.env("TERM", "xterm-256color");
        cmd.cwd("/");

        let child = slave
            .spawn_command(cmd)
            .context("failed to spawn session helper on PTY")?;
        drop(slave);

        let process_id = child.process_id().unwrap_or(0);
        let killer = child.clone_killer();

        // Own the unreaped child session before the helper can run any target
        // code: the helper waits for our authenticated request. Capture the
        // SID immediately so it cannot be reused while we still need it.
        let session = match OwnedSession::capture(process_id) {
            Ok(session) => session,
            Err(err) => {
                let original = err.context("failed to capture PTY session");
                let cleanup = cleanup_failed_spawn(child, killer, process_id, None);
                return Err(with_cleanup_context(original, cleanup));
            }
        };

        let target = TargetRequest {
            user: user.name.clone(),
            uid: user.uid.as_raw(),
            gid: user.gid.as_raw(),
            shell: config.shell_command.clone(),
            arguments: config.shell_arguments.clone(),
            term: Some("xterm-256color".to_owned()),
        };

        // Complete the authenticated handshake and readiness proof. On every
        // handshake/proof/exec failure, clean up the owned child and session
        // and propagate the typed CleanupFailure marker if cleanup is
        // unverified. Never detach or drop the child on error.
        if let Err(err) = listener.complete(&session, &target) {
            let original = err.context("session helper handshake failed");
            let cleanup = cleanup_failed_spawn(child, killer, process_id, Some(session));
            return Err(with_cleanup_context(original, cleanup));
        }

        // Only after a successful handshake do we start the PTY reader thread.
        // Later failures still use the existing owned cleanup.
        let (tx, rx) = mpsc::channel::<Vec<u8>>(DEFAULT_OUTPUT_CAPACITY);
        let reader_stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&reader_stop);
        let reader_handle = match thread::Builder::new()
            .name("pty-reader".into())
            .spawn(move || reader_loop(reader, tx, stop_flag))
        {
            Ok(handle) => handle,
            Err(err) => {
                let original = anyhow::Error::new(err).context("failed to spawn PTY reader thread");
                let cleanup = cleanup_failed_spawn(child, killer, process_id, Some(session));
                return Err(with_cleanup_context(original, cleanup));
            }
        };

        Ok(Self {
            master,
            writer: Some(writer),
            killer,
            child: Some(child),
            output: Some(rx),
            reader_stop,
            reader_handle: Some(reader_handle),
            process_id,
            session: Some(session),
            process_cleanup: ProcessCleanup::Active,
        })
    }

    /// OS process id of the shell, or `0` if unavailable.
    pub fn process_id(&self) -> u32 {
        self.process_id
    }

    /// Nonblocking check whether the direct child has exited, without reaping
    /// it.
    ///
    /// Uses `waitid(..., WEXITED | WNOHANG | WNOWAIT)` so the child remains a
    /// waitable zombie: its pid (and therefore the session id reservation) is
    /// preserved until [`PtyShell::stop`] reaps it. This lets the daemon detect
    /// a natural shell exit even when a background job keeps the PTY slave
    /// open and reader EOF never arrives.
    ///
    /// Once process cleanup has completed this returns `Ok(true)` without
    /// probing the OS again. If process cleanup failed with an intermediate
    /// diagnostic, the stored [`CleanupFailure`] is replayed instead of
    /// implying that a failed cleanup proves the child exited.
    ///
    /// Otherwise returns `Ok(false)` while the child is still running,
    /// `Ok(true)` once it has exited or been signalled. Any other wait status
    /// or syscall error is returned as an error rather than being treated as
    /// "alive".
    pub fn has_exited(&self) -> Result<bool> {
        match &self.process_cleanup {
            ProcessCleanup::Complete => return Ok(true),
            ProcessCleanup::Failed(source) => {
                return Err(anyhow::Error::new(CleanupFailure::from_arc(Arc::clone(
                    source,
                ))));
            }
            ProcessCleanup::Active => {}
        }
        if self.process_id <= 1 {
            bail!("PTY child pid is unavailable");
        }
        let pid = i32::try_from(self.process_id).context("PTY child pid does not fit in i32")?;
        let pid = Pid::from_raw(pid);
        let status = waitid(
            Id::Pid(pid),
            WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT,
        )
        .context("failed to poll PTY child status")?;
        match status {
            WaitStatus::StillAlive => Ok(false),
            WaitStatus::Exited(..) | WaitStatus::Signaled(..) => Ok(true),
            other => bail!("unexpected PTY child wait status: {other:?}"),
        }
    }

    /// Resize the PTY.
    pub fn resize(&self, rows: u16, cols: u16) -> Result<()> {
        self.master
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .context("failed to resize PTY")
    }

    /// Write bytes to the shell's stdin.
    ///
    /// Blocks until all bytes are written or [`WRITE_DEADLINE`] elapses. The
    /// deadline is absolute and fixed: neither `Interrupted` retries nor
    /// positive partial progress ever extend it. On timeout an error is
    /// returned; bytes already written are not rolled back, but no partial
    /// write is silently dropped. Empty input succeeds without performing any
    /// write. Must be called from a blocking context.
    pub fn write_input(&mut self, data: &[u8]) -> Result<()> {
        let writer = match self.writer.as_mut() {
            Some(w) => w,
            None => bail!("PTY writer is closed"),
        };
        let deadline = Instant::now()
            .checked_add(WRITE_DEADLINE)
            .ok_or_else(|| anyhow::anyhow!("PTY write deadline overflowed"))?;
        write_all_until(&mut **writer, data, deadline)?;
        // Flush is best-effort; the writer is unbuffered in practice.
        match writer.flush() {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
            Err(err) => Err(anyhow::Error::new(err).context("failed to flush PTY")),
        }
    }

    /// Take the bounded output receiver. Returns `Some` only on the first
    /// call; subsequent calls return `None`.
    pub fn take_output(&mut self) -> Option<mpsc::Receiver<Vec<u8>>> {
        self.output.take()
    }

    /// Terminate the shell's session and reap the direct child, **without**
    /// cancelling the output reader.
    ///
    /// This performs exactly the process side of [`PtyShell::stop`]: it closes
    /// the PTY writer, sends a graceful shutdown request (SIGHUP) to every
    /// process in the shell's session, waits up to [`GRACEFUL_DEADLINE`]
    /// without reaping the leader, then repeatedly `SIGKILL`s and verifies the
    /// session before reaping the direct child. All phases share one
    /// [`REAP_DEADLINE`]. Descendants that create a new session can escape
    /// (see module limitations).
    ///
    /// This call does **not** change reader cancellation state: it leaves
    /// `reader_stop` and the owned output receiver exactly as they were, even
    /// if a caller had already invoked [`PtyShell::stop`], and it does not join
    /// the reader thread. The reader therefore keeps draining the kernel PTY
    /// tail and any queued output until EOF once the owned session jobs have
    /// exited. This is intended for a natural-exit path where the daemon wants
    /// the final output preserved.
    ///
    /// The caller **must** use a blocking context, must bound its own drain
    /// (a descendant that escaped `setsid` can retain the slave and prevent
    /// EOF), and must eventually call [`PtyShell::stop`] or drop the shell to
    /// cancel the reader.
    ///
    /// Idempotent w.r.t. process cleanup: after a completed cleanup this is a
    /// no-op returning `Ok(())`. After a failed cleanup the stored typed
    /// [`CleanupFailure`] is returned unchanged and no further PID is signalled
    /// (the direct child may already have been handed to a background waiter,
    /// so its PID may have been released and reused).
    pub fn terminate_processes(&mut self) -> Result<()> {
        match &self.process_cleanup {
            ProcessCleanup::Complete => return Ok(()),
            ProcessCleanup::Failed(source) => {
                return Err(anyhow::Error::new(CleanupFailure::from_arc(Arc::clone(
                    source,
                ))));
            }
            ProcessCleanup::Active => {}
        }

        // Close the writer so the child sees EOF on stdin. The reader is
        // intentionally left running so it can drain the PTY tail to EOF.
        self.writer = None;

        // One shared deadline covers session termination and direct-child
        // reaping. Do not allocate fresh budgets per phase.
        let deadline = Instant::now() + REAP_DEADLINE;
        let mut first_err: Option<anyhow::Error> = None;

        // Best-effort graceful session shutdown under the same deadline:
        // SIGHUP to every process in the shell's session, not just the direct
        // child. If no session guard is available, fall back to a direct-child
        // SIGHUP.
        match self.session.as_ref() {
            Some(session) => {
                if let Err(err) = session.signal_session_until(RustixSignal::HUP, deadline) {
                    record_error(&mut first_err, err);
                }
            }
            None => {
                if let Err(err) = self.killer.kill() {
                    record_error(
                        &mut first_err,
                        anyhow::Error::new(err).context("failed to send shutdown to PTY child"),
                    );
                }
            }
        }

        // Grace period WITHOUT reaping the leader, so the SID cannot be reused
        // while we still need to scan and signal session members.
        bounded_sleep(GRACEFUL_DEADLINE, deadline);

        // Escalate: repeated SIGKILL plus live-member verification.
        if let Some(session) = self.session.as_ref()
            && let Err(err) = session.kill_and_verify(deadline)
        {
            record_error(&mut first_err, err);
        }

        if let Some(child) = self.child.take() {
            // The child is still owned and unreaped until the helper observes
            // `try_wait` returning a status. Only this positive PID may be
            // signalled directly.
            let owned_pid = child
                .process_id()
                .or_else(|| (self.process_id > 1).then_some(self.process_id))
                .filter(|pid| *pid > 1);
            if let Some(pid) = owned_pid
                && let Err(err) = signal_child_kill(pid)
            {
                record_error(&mut first_err, err);
            }

            if let Err(err) = reap_child_bounded(child, deadline, "PTY") {
                record_error(&mut first_err, err);
            }
        }

        match first_err {
            // Store the diagnostic so later calls replay the same typed
            // failure without retrying (a potentially reused) PID.
            Some(err) => {
                let source = Arc::new(err);
                self.process_cleanup = ProcessCleanup::Failed(Arc::clone(&source));
                Err(anyhow::Error::new(CleanupFailure { source }))
            }
            None => {
                self.process_cleanup = ProcessCleanup::Complete;
                Ok(())
            }
        }
    }

    /// Cancel the reader and terminate/reap the child. Idempotent.
    ///
    /// This **always** sets the reader stop flag and drops the owned output
    /// receiver (if any) first, then delegates to
    /// [`PtyShell::terminate_processes`] for session termination and
    /// direct-child reaping. Reader cancellation is therefore independent of
    /// process cleanup: even when cleanup was already completed via
    /// [`PtyShell::terminate_processes`], a later `stop` still requests reader
    /// cancellation promptly. This method only *signals* cancellation; the
    /// reader thread actually joins in [`Drop`].
    ///
    /// Returns an error if the session could not be verified gone or the child
    /// could not be reaped within [`REAP_DEADLINE`]. Every error returned by
    /// this method's process phase contains a [`CleanupFailure`] marker
    /// (regardless of the other context layers), so callers can distinguish
    /// incomplete/unverified cleanup from ordinary I/O errors. On a
    /// direct-child timeout or wait error, a background thread is spawned to
    /// continue waiting. If that thread cannot be created, the error says so
    /// explicitly. Must be called from a blocking context.
    pub fn stop(&mut self) -> Result<()> {
        // Reader cancellation is independent of process cleanup. Always cancel
        // and drop the owned receiver, even if processes were already stopped.
        self.reader_stop.store(true, Ordering::Relaxed);
        self.output = None;

        self.terminate_processes()
    }
}

impl Drop for PtyShell {
    fn drop(&mut self) {
        // Always cancel the reader before joining it, even if
        // `terminate_processes` already ran and left the reader active.
        self.reader_stop.store(true, Ordering::Relaxed);
        self.output = None;
        let _ = self.stop();
        if let Some(handle) = self.reader_handle.take() {
            // The reader uses nonblocking reads and cancellable sends, so
            // this join is bounded by the retry sleeps.
            let _ = handle.join();
        }
    }
}

/// Write `data` to `writer`, retrying until the whole slice is accepted or the
/// absolute `deadline` passes.
///
/// The deadline is checked at the top of *every* retry, including after
/// `Interrupted` errors and after positive partial progress, so neither can
/// extend the total budget. Progress is tracked against `data.get(written..)`
/// and a writer that claims to have accepted more bytes than the supplied
/// remaining slice is rejected with an error rather than causing a slicing
/// panic or arithmetic overflow.
fn write_all_until(writer: &mut dyn Write, data: &[u8], deadline: Instant) -> Result<usize> {
    let mut written = 0usize;
    while written < data.len() {
        if Instant::now() >= deadline {
            bail!(
                "timed out writing to PTY after {} of {} bytes",
                written,
                data.len()
            );
        }
        let remaining = match data.get(written..) {
            Some(remaining) => remaining,
            None => bail!(
                "PTY write progress {} exceeded supplied {} byte buffer",
                written,
                data.len()
            ),
        };
        if remaining.is_empty() {
            break;
        }
        match writer.write(remaining) {
            Ok(0) => bail!("PTY write returned 0 bytes"),
            Ok(n) => {
                if n > remaining.len() {
                    bail!(
                        "PTY writer reported {} bytes but only {} remained",
                        n,
                        remaining.len()
                    );
                }
                written = written
                    .checked_add(n)
                    .ok_or_else(|| anyhow::anyhow!("PTY write progress overflowed"))?;
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                let now = Instant::now();
                if now >= deadline {
                    bail!(
                        "timed out writing to PTY after {} of {} bytes",
                        written,
                        data.len()
                    );
                }
                let sleep_for = WRITE_RETRY_SLEEP.min(deadline.saturating_duration_since(now));
                if !sleep_for.is_zero() {
                    thread::sleep(sleep_for);
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => {
                return Err(anyhow::Error::new(err).context("failed to write to PTY"));
            }
        }
    }
    Ok(written)
}

/// Attempt every available cleanup action for a partially created shell.
///
/// The direct child is always signalled with SIGKILL while still owned and
/// unreaped. When a session guard exists, the whole session is terminated and
/// verified before the leader is reaped. If `session` is `None` after a child
/// was spawned, session identity could not be captured: direct-child reaping
/// alone cannot prove that no session jobs survived, so an explicit cleanup
/// error is recorded even when the child is reaped successfully. Returns the
/// first cleanup error, if any; the caller combines it with the original spawn
/// error.
fn cleanup_failed_spawn(
    child: Box<dyn Child + Send + Sync>,
    mut killer: Box<dyn ChildKiller + Send + Sync>,
    process_id: u32,
    session: Option<OwnedSession>,
) -> Option<anyhow::Error> {
    let deadline = Instant::now() + REAP_DEADLINE;
    let mut first_err: Option<anyhow::Error> = None;

    if let Err(err) = killer.kill() {
        record_error(
            &mut first_err,
            anyhow::Error::new(err)
                .context("failed to send shutdown to PTY child during spawn cleanup"),
        );
    }

    if let Some(session) = session.as_ref() {
        if let Err(err) = session.signal_session_until(RustixSignal::HUP, deadline) {
            record_error(&mut first_err, err);
        }
        bounded_sleep(GRACEFUL_DEADLINE, deadline);
        if let Err(err) = session.kill_and_verify(deadline) {
            record_error(&mut first_err, err);
        }
    } else {
        // A child was spawned, but its session identity was not captured.
        // Reaping only the direct child cannot verify that background jobs in
        // the child's session are gone. Record this conservatively as a
        // cleanup failure; never signal a session or PID that was not
        // validated by `OwnedSession::capture`.
        record_error(
            &mut first_err,
            anyhow::anyhow!(
                "spawned child session identity was not captured; cannot verify session cleanup"
            ),
        );
    }

    if let Err(err) = signal_child_kill(process_id) {
        record_error(&mut first_err, err);
    }

    if let Err(err) = reap_child_bounded(child, deadline, "spawn cleanup") {
        record_error(&mut first_err, err);
    }

    first_err
}

/// Combine an original spawn error with an optional cleanup error.
///
/// A fully successful cleanup leaves the original error untouched (no
/// [`CleanupFailure`] marker). A failed cleanup attaches the marker via
/// context, keeping the original error as the top-level message and the
/// cleanup diagnostic available through `Display`/`source`.
fn with_cleanup_context(original: anyhow::Error, cleanup: Option<anyhow::Error>) -> anyhow::Error {
    match cleanup {
        Some(cleanup_err) => original.context(CleanupFailure::new(cleanup_err)),
        None => original,
    }
}

/// Poll `try_wait` until the child is reaped or `deadline` expires.
///
/// The caller must not otherwise wait on this child. On timeout or a
/// `try_wait` error, ownership is handed to a named background waiter and an
/// explicit error is returned. A `try_wait` error is never treated as proof of
/// reaping.
fn reap_child_bounded(
    mut child: Box<dyn Child + Send + Sync>,
    deadline: Instant,
    action: &'static str,
) -> Result<()> {
    loop {
        let status = child.try_wait();
        match status {
            Ok(Some(_status)) => return Ok(()),
            Ok(None) => {
                if Instant::now() >= deadline {
                    return hand_off_child(
                        child,
                        anyhow::anyhow!("timed out reaping {action} child before deadline"),
                    );
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                let sleep_for = REAP_POLL_INTERVAL.min(remaining);
                if !sleep_for.is_zero() {
                    thread::sleep(sleep_for);
                }
            }
            Err(err) => {
                let wait_err =
                    anyhow::Error::new(err).context(format!("failed to wait for {action} child"));
                return hand_off_child(child, wait_err);
            }
        }
    }
}

/// Hand `child` to a named background waiter.
///
/// The closure owns the child, so the binding inside it is declared `mut` to
/// allow `Child::wait` to take `&mut self`. Returns the supplied error on
/// success. If the waiter thread cannot be created, the returned error includes
/// that failure instead of claiming the child will eventually be reaped.
fn hand_off_child(child: Box<dyn Child + Send + Sync>, reason: anyhow::Error) -> Result<()> {
    let waiter = thread::Builder::new()
        .name(CHILD_WAITER_THREAD.into())
        .spawn(move || {
            let mut child = child;
            let _ = child.wait();
        });
    match waiter {
        Ok(_handle) => Err(reason),
        Err(spawn_err) => Err(reason.context(format!(
            "additionally failed to start background child waiter: {spawn_err}"
        ))),
    }
}

fn signal_child_kill(process_id: u32) -> Result<()> {
    let Some(pid) = checked_child_pid(process_id) else {
        return Ok(());
    };
    match kill(pid, Signal::SIGKILL) {
        Ok(()) => Ok(()),
        Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(err) => Err(anyhow::Error::new(err)
            .context(format!("failed to SIGKILL child pid {}", pid.as_raw()))),
    }
}

fn checked_child_pid(process_id: u32) -> Option<Pid> {
    let pid = i32::try_from(process_id).ok()?;
    if pid <= 1 {
        return None;
    }
    Some(Pid::from_raw(pid))
}

fn bounded_sleep(duration: Duration, deadline: Instant) {
    let now = Instant::now();
    if now >= deadline {
        return;
    }
    let remaining = deadline.saturating_duration_since(now);
    let sleep_for = duration.min(remaining);
    if !sleep_for.is_zero() {
        thread::sleep(sleep_for);
    }
}

fn record_error(first: &mut Option<anyhow::Error>, err: anyhow::Error) {
    if first.is_none() {
        *first = Some(err);
    }
}

fn reader_loop(mut reader: Box<dyn Read + Send>, tx: mpsc::Sender<Vec<u8>>, stop: Arc<AtomicBool>) {
    let mut buf = [0u8; READ_CHUNK];
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                // Defensive validation at the `Read` trait boundary: a reader
                // claiming more bytes than the supplied buffer is impossible
                // and must not panic. Close the output by returning instead.
                let Some(chunk) = buf.get(..n) else {
                    return;
                };
                let mut chunk = chunk.to_vec();
                // Cancellable bounded send: retry `try_send` while the
                // channel is full, checking the stop flag between attempts.
                loop {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    match tx.try_send(chunk) {
                        Ok(()) => break,
                        Err(mpsc::error::TrySendError::Full(returned)) => {
                            chunk = returned;
                            thread::sleep(SEND_RETRY_SLEEP);
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => return,
                    }
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(READ_RETRY_SLEEP);
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}

/// PTY handles acquired before any child is spawned.
///
/// Holding the master-side handles and setting the nonblocking flag before
/// spawning guarantees a failure in this step cannot orphan a running child.
struct OpenedPty {
    master: Box<dyn MasterPty + Send>,
    slave: Box<dyn SlavePty + Send>,
    writer: Box<dyn Write + Send>,
    reader: Box<dyn Read + Send>,
}

fn open_pty(rows: u16, cols: u16) -> Result<OpenedPty> {
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .context("failed to open PTY pair")?;

    // Acquire all master-side I/O handles *before* spawning the child so that
    // a failure here cannot orphan a running shell.
    let writer = pair
        .master
        .take_writer()
        .context("failed to take PTY writer")?;
    let reader = pair
        .master
        .try_clone_reader()
        .context("failed to clone PTY reader")?;

    // Make the master file description nonblocking so the reader thread can
    // observe the stop flag even when descendants keep the slave FD open.
    let master_fd = pair
        .master
        .as_raw_fd()
        .context("PTY master has no Unix file descriptor")?;
    set_nonblocking(master_fd).context("failed to set PTY nonblocking")?;

    Ok(OpenedPty {
        master: pair.master,
        slave: pair.slave,
        writer,
        reader,
    })
}

fn set_nonblocking(fd: std::os::fd::RawFd) -> Result<()> {
    let flags = fcntl(fd, FcntlArg::F_GETFL).context("F_GETFL failed")?;
    let flags = OFlag::from_bits_truncate(flags);
    fcntl(fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).context("F_SETFL failed")?;
    Ok(())
}

/// Bounded validation of the configured username before any NSS or PTY work.
fn validate_configured_user(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > MAX_USERNAME_LEN || name.contains('\0') {
        bail!("configuration User is invalid");
    }
    Ok(())
}

/// Outcome of inspecting the direct-path home directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectHomeStatus {
    Present,
    Missing,
    OtherError,
}

fn direct_home_status(home: &Path) -> DirectHomeStatus {
    match fs::metadata(home) {
        Ok(_) => DirectHomeStatus::Present,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => DirectHomeStatus::Missing,
        Err(_) => DirectHomeStatus::OtherError,
    }
}

/// Pure working-directory decision for the direct path. A genuinely missing
/// home (NotFound) falls back to `/`; any other metadata outcome keeps the
/// configured home so an ordinary exec error surfaces later. No global cwd is
/// changed here, so this is safe in parallel unit tests.
fn choose_direct_cwd(home: &Path, status: DirectHomeStatus) -> PathBuf {
    match status {
        DirectHomeStatus::Missing => PathBuf::from("/"),
        DirectHomeStatus::Present | DirectHomeStatus::OtherError => home.to_path_buf(),
    }
}

fn select_direct_cwd(home: &Path) -> PathBuf {
    choose_direct_cwd(home, direct_home_status(home))
}

/// Resolve the configured user name via NSS without changing any credentials.
fn resolve_user(name: &str) -> Result<User> {
    if name.trim().is_empty() {
        bail!("configuration User must be set and non-empty");
    }
    validate_configured_user(name)?;
    let user = User::from_name(name)
        .with_context(|| format!("failed to look up user {name}"))?
        .with_context(|| format!("unknown user {name}"))?;
    Ok(user)
}

/// Which spawn strategy applies for a resolved configured user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpawnMode {
    /// Configured user matches this process's effective uid.
    Direct,
    /// Configured user differs; requires a root parent and the trusted helper.
    Helper,
}

/// Pure selection between the direct and helper spawn paths.
fn select_spawn_mode(configured_uid: u32, effective_uid: u32) -> SpawnMode {
    if configured_uid == effective_uid {
        SpawnMode::Direct
    } else {
        SpawnMode::Helper
    }
}

/// Pure admission check for a helper target identity.
///
/// Root may not be selected as a drop target (that would defeat the privilege
/// drop) and the `u32::MAX` sentinels are always rejected.
fn validate_helper_target(uid: u32, gid: u32) -> Result<()> {
    if uid == 0 {
        bail!("target uid must be non-root");
    }
    if uid == u32::MAX {
        bail!("invalid target uid");
    }
    if gid == u32::MAX {
        bail!("invalid target gid");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Mutex, mpsc};

    use super::*;

    #[test]
    fn spawn_mode_selection_is_uid_based() {
        assert_eq!(select_spawn_mode(1000, 1000), SpawnMode::Direct);
        assert_eq!(select_spawn_mode(0, 0), SpawnMode::Direct);
        assert_eq!(select_spawn_mode(0, 1000), SpawnMode::Helper);
        assert_eq!(select_spawn_mode(1000, 0), SpawnMode::Helper);
        assert_eq!(select_spawn_mode(u32::MAX, 1000), SpawnMode::Helper);
    }

    #[test]
    fn helper_target_admission_rejects_sentinels() {
        assert!(validate_helper_target(1000, 1000).is_ok());
        assert!(validate_helper_target(0, 0).is_err());
        assert!(validate_helper_target(u32::MAX, 1000).is_err());
        assert!(validate_helper_target(1000, u32::MAX).is_err());
    }

    #[test]
    fn direct_cwd_policy_falls_back_only_for_missing_home() {
        let home = Path::new("/home/alice");
        assert_eq!(
            choose_direct_cwd(home, DirectHomeStatus::Present),
            home.to_path_buf()
        );
        assert_eq!(
            choose_direct_cwd(home, DirectHomeStatus::Missing),
            PathBuf::from("/")
        );
        assert_eq!(
            choose_direct_cwd(home, DirectHomeStatus::OtherError),
            home.to_path_buf()
        );
    }

    #[test]
    fn configured_user_validation_bounds_length_and_rejects_nul() {
        assert!(validate_configured_user("alice").is_ok());
        assert!(validate_configured_user(&"a".repeat(MAX_USERNAME_LEN)).is_ok());
        assert!(validate_configured_user(&"a".repeat(MAX_USERNAME_LEN + 1)).is_err());
        assert!(validate_configured_user("").is_err());
        assert!(validate_configured_user("bad\0user").is_err());
    }

    #[derive(Clone, Copy, Debug)]
    enum FakeTryWaitMode {
        Pending,
        Error,
        Reaped,
    }

    struct FakeChild {
        mode: FakeTryWaitMode,
        started: Option<mpsc::Sender<()>>,
        release: Option<Arc<Mutex<mpsc::Receiver<()>>>>,
        done: Option<mpsc::Sender<()>>,
        wait_calls: Arc<AtomicUsize>,
        process_id: Option<u32>,
    }

    impl fmt::Debug for FakeChild {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("FakeChild")
                .field("mode", &self.mode)
                .field("wait_calls", &self.wait_calls.load(Ordering::SeqCst))
                .field("process_id", &self.process_id)
                .finish()
        }
    }

    impl Child for FakeChild {
        fn try_wait(&mut self) -> io::Result<Option<portable_pty::ExitStatus>> {
            match self.mode {
                FakeTryWaitMode::Pending => Ok(None),
                FakeTryWaitMode::Error => Err(io::Error::other("synthetic try_wait failure")),
                FakeTryWaitMode::Reaped => Ok(Some(portable_pty::ExitStatus::with_exit_code(0))),
            }
        }

        fn wait(&mut self) -> io::Result<portable_pty::ExitStatus> {
            self.wait_calls.fetch_add(1, Ordering::SeqCst);
            if let Some(started) = self.started.as_ref() {
                let _ = started.send(());
            }
            if let Some(release) = self.release.as_ref() {
                let receiver = release
                    .lock()
                    .map_err(|_| io::Error::other("fake child release mutex poisoned"))?;
                let _ = receiver.recv_timeout(Duration::from_secs(2));
            }
            if let Some(done) = self.done.as_ref() {
                let _ = done.send(());
            }
            Ok(portable_pty::ExitStatus::with_exit_code(0))
        }

        fn process_id(&self) -> Option<u32> {
            self.process_id
        }
    }

    impl ChildKiller for FakeChild {
        fn kill(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn clone_killer(&self) -> Box<dyn ChildKiller + Send + Sync> {
            Box::new(NoopKiller)
        }
    }

    #[derive(Debug)]
    struct NoopKiller;

    impl ChildKiller for NoopKiller {
        fn kill(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn clone_killer(&self) -> Box<dyn ChildKiller + Send + Sync> {
            Box::new(NoopKiller)
        }
    }

    struct ReleaseGuard {
        tx: Option<mpsc::Sender<()>>,
    }

    impl ReleaseGuard {
        fn release(&mut self) {
            if let Some(tx) = self.tx.take() {
                let _ = tx.send(());
            }
        }
    }

    impl Drop for ReleaseGuard {
        fn drop(&mut self) {
            self.release();
        }
    }

    fn blocking_fake(
        mode: FakeTryWaitMode,
    ) -> (
        FakeChild,
        mpsc::Receiver<()>,
        mpsc::Receiver<()>,
        ReleaseGuard,
        Arc<AtomicUsize>,
    ) {
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let release = Arc::new(Mutex::new(release_rx));
        let wait_calls = Arc::new(AtomicUsize::new(0));
        let child = FakeChild {
            mode,
            started: Some(started_tx),
            release: Some(release),
            done: Some(done_tx),
            wait_calls: Arc::clone(&wait_calls),
            process_id: None,
        };
        let guard = ReleaseGuard {
            tx: Some(release_tx),
        };
        (child, started_rx, done_rx, guard, wait_calls)
    }

    /// A writer that always reports `Interrupted`.
    struct InterruptedWriter;

    impl Write for InterruptedWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "synthetic interrupt",
            ))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A writer that makes one byte of progress per call, but slowly.
    #[derive(Default)]
    struct SlowProgressWriter {
        bytes: usize,
    }

    impl Write for SlowProgressWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            thread::sleep(Duration::from_millis(2));
            self.bytes += 1;
            Ok(1)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A writer that claims to have accepted more bytes than it was given.
    struct OversizedWriter;

    impl Write for OversizedWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len().saturating_add(1))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A writer that records whether it was ever asked to write.
    #[derive(Default)]
    struct CountingWriter {
        calls: Arc<AtomicUsize>,
    }

    impl Write for CountingWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn write_helper_interrupted_retries_obey_fixed_deadline() {
        let mut writer = InterruptedWriter;
        let start = Instant::now();
        let result = write_all_until(&mut writer, b"payload", start + Duration::from_millis(5));
        let elapsed = start.elapsed();
        assert!(result.is_err(), "always-interrupted writer must time out");
        assert!(
            elapsed < Duration::from_secs(1),
            "interrupted retries exceeded bound: {elapsed:?}"
        );
    }

    #[test]
    fn write_helper_progress_does_not_extend_deadline() {
        let mut writer = SlowProgressWriter::default();
        let payload = [b'x'; 64];
        let start = Instant::now();
        let result = write_all_until(&mut writer, &payload, start + Duration::from_millis(4));
        let elapsed = start.elapsed();
        assert!(result.is_err(), "slow writer must hit the fixed deadline");
        assert!(
            writer.bytes < payload.len(),
            "writer consumed the whole payload despite the deadline"
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "slow writer exceeded bound: {elapsed:?}"
        );
    }

    #[test]
    fn write_helper_rejects_oversized_progress_without_panicking() {
        let mut writer = OversizedWriter;
        let result = write_all_until(&mut writer, b"abc", Instant::now() + Duration::from_secs(1));
        let err = result.expect_err("oversized progress must be rejected");
        assert!(
            format!("{err:#}").contains("only"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn write_helper_empty_slice_succeeds_without_writing() {
        let mut writer = CountingWriter::default();
        let calls = Arc::clone(&writer.calls);
        let result = write_all_until(&mut writer, &[], Instant::now() + Duration::from_millis(10));
        assert_eq!(result.expect("empty slice must succeed"), 0);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "empty slice must not invoke the writer"
        );
    }

    #[test]
    fn bounded_reap_times_out_promptly_and_hands_off_blocking_wait() {
        let (child, started_rx, done_rx, mut release, wait_calls) =
            blocking_fake(FakeTryWaitMode::Pending);
        let start = Instant::now();
        let result = reap_child_bounded(
            Box::new(child),
            Instant::now() + Duration::from_millis(25),
            "test",
        );
        let elapsed = start.elapsed();
        assert!(result.is_err(), "bounded reap should time out");
        assert!(
            elapsed < Duration::from_millis(500),
            "bounded reap took too long: {elapsed:?}"
        );

        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("background waiter did not start");
        release.release();
        done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("background waiter did not finish after release");
        assert_eq!(wait_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn bounded_reap_hands_try_wait_errors_to_background_waiter() {
        let (child, started_rx, done_rx, mut release, wait_calls) =
            blocking_fake(FakeTryWaitMode::Error);
        let start = Instant::now();
        let result = reap_child_bounded(
            Box::new(child),
            Instant::now() + Duration::from_millis(25),
            "test",
        );
        let elapsed = start.elapsed();
        let err = result.expect_err("try_wait error must be reported");
        assert!(
            format!("{err:#}").contains("synthetic try_wait failure")
                || format!("{err:#}").contains("failed to wait"),
            "unexpected error: {err:#}"
        );
        assert!(
            elapsed < Duration::from_millis(500),
            "try_wait error handling took too long: {elapsed:?}"
        );

        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("background waiter did not start");
        release.release();
        done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("background waiter did not finish after release");
        assert_eq!(wait_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn bounded_reap_of_already_reaped_child_never_calls_wait() {
        let wait_calls = Arc::new(AtomicUsize::new(0));
        let child = FakeChild {
            mode: FakeTryWaitMode::Reaped,
            started: None,
            release: None,
            done: None,
            wait_calls: Arc::clone(&wait_calls),
            process_id: None,
        };
        let result = reap_child_bounded(
            Box::new(child),
            Instant::now() + Duration::from_millis(100),
            "test",
        );
        assert!(result.is_ok(), "already-reaped child should succeed");
        assert_eq!(wait_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn uncaptured_session_after_spawn_is_marked_as_cleanup_failure() {
        let wait_calls = Arc::new(AtomicUsize::new(0));
        let child = FakeChild {
            mode: FakeTryWaitMode::Reaped,
            started: None,
            release: None,
            done: None,
            wait_calls: Arc::clone(&wait_calls),
            process_id: None,
        };
        let cleanup = cleanup_failed_spawn(Box::new(child), Box::new(NoopKiller), 0, None);
        let err = cleanup.expect("missing session identity must be a cleanup failure");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("session identity was not captured"),
            "unexpected cleanup error: {rendered}"
        );
        assert_eq!(
            wait_calls.load(Ordering::SeqCst),
            0,
            "already-reaped child must not be waited on again"
        );
    }

    #[test]
    fn cleanup_failure_marker_distinguishes_cleanup_errors_from_spawn_errors() {
        let ordinary = with_cleanup_context(anyhow::anyhow!("original spawn failure"), None);
        assert!(
            ordinary.downcast_ref::<CleanupFailure>().is_none(),
            "ordinary spawn error must not carry cleanup marker"
        );

        let marked = with_cleanup_context(
            anyhow::anyhow!("original spawn failure"),
            Some(anyhow::anyhow!("cleanup exploded")),
        );
        assert!(
            marked.downcast_ref::<CleanupFailure>().is_some(),
            "cleanup error must carry CleanupFailure marker"
        );
        let rendered = format!("{marked:#}");
        assert!(
            rendered.contains("original spawn failure"),
            "diagnostic lost original error: {rendered}"
        );
        assert!(
            rendered.contains("cleanup exploded"),
            "diagnostic lost cleanup error: {rendered}"
        );
    }

    #[test]
    fn cleanup_failure_is_clonable_and_replayable() {
        let failure = CleanupFailure::new(anyhow::anyhow!("stored cleanup diagnostic"));
        let cloned = failure.clone();
        assert_eq!(format!("{failure}"), format!("{cloned}"));
        assert!(
            format!("{cloned}").contains("stored cleanup diagnostic"),
            "cloned diagnostic lost its message"
        );
    }
}
