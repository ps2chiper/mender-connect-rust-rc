//! Session-scoped process cleanup for PTY shells.
//!
//! portable-pty starts the shell in a new session whose SID equals the shell
//! PID. An interactive shell's foreground and background jobs may live in
//! *other* process groups within that session, so signalling only the direct
//! child (or `killpg(shell_pid)`) is insufficient.
//!
//! [`OwnedSession`] captures the session leader's identity (PID + starttime)
//! immediately after spawn and, while the leader is still unreaped, enumerates
//! `/proc` to signal every process whose session matches. Each target is
//! re-validated through a `pidfd` before signalling, so PID reuse cannot
//! redirect a signal to an unrelated process.
//!
//! # Assumptions
//!
//! * Linux procfs is mounted at `/proc` and exposes `/proc/<pid>/stat` for the
//!   processes this process is permitted to inspect.
//! * The kernel supports `pidfd_open(2)` and `pidfd_send_signal(2)`.
//! * The caller has permission to signal the target session members. Missing
//!   permission is reported as an error rather than treated as success.
//! * No external child reaper reaps the session leader while this guard is in
//!   use; the leader must remain unreaped so the session id cannot be reused.
//!
//! # Limitations
//!
//! This is *not* cgroup containment. A descendant that deliberately escapes
//! the session (e.g. by calling `setsid`) will not be signalled. Full
//! containment requires cgroups or a similar mechanism and is out of scope.
//! Kernel scanning and signalling can also be delayed by scheduler or I/O
//! pressure; deadlines bound this code's work, not real-time kernel behaviour.

use std::fs;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};

/// Short bounded pause between complete cleanup scans.
const SCAN_SETTLE_SLEEP: Duration = Duration::from_millis(20);

/// Parsed subset of `/proc/<pid>/stat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcStat {
    /// Process id.
    pub pid: i32,
    /// One-character process state.
    pub state: char,
    /// Parent process id.
    pub ppid: i32,
    /// Process group id.
    pub pgrp: i32,
    /// Session id.
    pub session: i32,
    /// Process start time in clock ticks since boot.
    pub starttime: u64,
}

impl ProcStat {
    /// Parse a `/proc/<pid>/stat` line.
    ///
    /// The `comm` field may contain spaces and `)` characters, so the field
    /// boundary is located using the *last* `") "` occurrence.
    pub fn parse(pid: i32, raw: &str) -> Result<Self> {
        Self::parse_bytes(pid, raw.as_bytes())
    }

    /// Parse raw `/proc/<pid>/stat` bytes.
    ///
    /// The process name (`comm`) is treated as opaque bytes and is never
    /// required to be valid UTF-8. Only the ASCII suffix after the last
    /// `") "` delimiter is parsed. The state token must be exactly one ASCII
    /// character, as emitted by the kernel.
    pub fn parse_bytes(pid: i32, raw: &[u8]) -> Result<Self> {
        let close = raw
            .windows(2)
            .rposition(|window| window == b") ")
            .with_context(|| format!("malformed /proc/{pid}/stat: missing ') '"))?;
        let start = close
            .checked_add(2)
            .with_context(|| format!("malformed /proc/{pid}/stat: invalid field offset"))?;
        let suffix = raw
            .get(start..)
            .with_context(|| format!("malformed /proc/{pid}/stat: truncated fields"))?;
        let suffix = std::str::from_utf8(suffix)
            .with_context(|| format!("malformed /proc/{pid}/stat: non-UTF-8 field suffix"))?;
        if !suffix.is_ascii() {
            bail!("malformed /proc/{pid}/stat: non-ASCII field suffix");
        }

        let fields: Vec<&str> = suffix.split_whitespace().collect();
        // Suffix indexes: state=0, ppid=1, pgrp=2, session=3, starttime=19.
        if fields.len() <= 19 {
            bail!("malformed /proc/{pid}/stat: too few fields");
        }

        let state_field = fields
            .first()
            .with_context(|| format!("malformed /proc/{pid}/stat: missing state"))?;
        let ppid_field = fields
            .get(1)
            .with_context(|| format!("malformed /proc/{pid}/stat: missing ppid"))?;
        let pgrp_field = fields
            .get(2)
            .with_context(|| format!("malformed /proc/{pid}/stat: missing pgrp"))?;
        let session_field = fields
            .get(3)
            .with_context(|| format!("malformed /proc/{pid}/stat: missing session"))?;
        let starttime_field = fields
            .get(19)
            .with_context(|| format!("malformed /proc/{pid}/stat: missing starttime"))?;

        // The kernel emits the state as a single ASCII character. Reject any
        // longer or non-ASCII token instead of silently taking its first byte.
        let state = match state_field.as_bytes() {
            [byte] if byte.is_ascii() => char::from(*byte),
            _ => bail!("malformed /proc/{pid}/stat: state must be one ASCII character"),
        };
        let ppid = ppid_field
            .parse()
            .with_context(|| format!("bad ppid in /proc/{pid}/stat"))?;
        let pgrp = pgrp_field
            .parse()
            .with_context(|| format!("bad pgrp in /proc/{pid}/stat"))?;
        let session = session_field
            .parse()
            .with_context(|| format!("bad session in /proc/{pid}/stat"))?;
        let starttime = starttime_field
            .parse()
            .with_context(|| format!("bad starttime in /proc/{pid}/stat"))?;
        Ok(Self {
            pid,
            state,
            ppid,
            pgrp,
            session,
            starttime,
        })
    }
}

/// Read and parse `/proc/<pid>/stat` without requiring `comm` to be UTF-8.
pub fn read_stat(pid: i32) -> Result<ProcStat> {
    let raw = fs::read(format!("/proc/{pid}/stat"))
        .with_context(|| format!("failed to read /proc/{pid}/stat"))?;
    ProcStat::parse_bytes(pid, &raw)
}

/// Guard for a PTY shell's session.
///
/// Captured immediately after spawn, before any wait/reap, so the session id
/// cannot be reused while the guard is alive.
#[derive(Debug)]
pub struct OwnedSession {
    leader: i32,
    leader_starttime: u64,
}

impl OwnedSession {
    /// Capture the session led by `leader`.
    ///
    /// Rejects `leader <= 1`, our own PID, and any PID that is not currently a
    /// session leader.
    pub fn capture(leader: u32) -> Result<Self> {
        let leader = i32::try_from(leader).context("child pid out of range")?;
        if leader <= 1 {
            bail!("refusing to own session for pid {leader}");
        }
        let own = i32::try_from(std::process::id()).context("own pid does not fit in i32")?;
        if leader == own {
            bail!("refusing to own session for our own pid {leader}");
        }
        let stat = read_stat(leader)?;
        if stat.session != leader {
            bail!(
                "pid {leader} is not a session leader (session {})",
                stat.session
            );
        }
        Ok(Self {
            leader,
            leader_starttime: stat.starttime,
        })
    }

    /// Session leader PID.
    pub fn leader(&self) -> i32 {
        self.leader
    }

    /// Re-verify the captured leader's identity and return its current stat.
    ///
    /// The leader must still be the captured session leader with an unchanged
    /// starttime. This reuses the same predicate as the signalling path and
    /// never scans, signals or reaps anything, so cleanup semantics are
    /// unchanged.
    pub fn verify_leader_identity(&self) -> Result<ProcStat> {
        let stat = read_stat(self.leader)?;
        if stat.session != self.leader || stat.starttime != self.leader_starttime {
            bail!(
                "session leader {} identity changed; refusing to trust it",
                self.leader
            );
        }
        Ok(stat)
    }

    fn leader_identity_ok(&self) -> bool {
        self.verify_leader_identity().is_ok()
    }

    /// Send `sig` to every process in the owned session.
    ///
    /// The leader must remain unreaped for the duration of the call. Each
    /// target is validated through a `pidfd` (starttime + session) before the
    /// signal is delivered, so PID reuse cannot redirect it.
    ///
    /// Disappearance races (`ESRCH`/`ENOENT`) are ignored. The first real
    /// error is returned after attempting to clean up the remaining members.
    pub fn signal_session(&self, sig: Signal) -> Result<()> {
        self.scan_session(sig, None).map(|_| ())
    }

    /// Deadline-bounded one-pass session signal.
    ///
    /// This is used for best-effort graceful shutdown under an overall stop
    /// deadline. Disappearance races are ignored; real failures are returned.
    pub fn signal_session_until(&self, sig: Signal, deadline: Instant) -> Result<()> {
        self.scan_session(sig, Some(deadline)).map(|_| ())
    }

    /// Repeatedly SIGKILL the owned session and verify that no live members
    /// remain.
    ///
    /// Two complete scans separated by a short bounded sleep must observe no
    /// non-zombie/non-dead process in the session. Zombies (`Z`) and dead
    /// (`X`) members may remain unreaped. The leader must still be unreaped by
    /// the caller for the duration of this call.
    ///
    /// Returns a timeout/error if the deadline expires or a real procfs,
    /// pidfd, permission or signal failure occurs.
    pub fn kill_and_verify(&self, deadline: Instant) -> Result<()> {
        let mut clean_scans = 0u8;
        loop {
            if Instant::now() >= deadline {
                bail!(
                    "timed out waiting for session {} processes to exit",
                    self.leader
                );
            }

            let live_members = self.scan_session(Signal::KILL, Some(deadline))?;
            if live_members == 0 {
                clean_scans = clean_scans.saturating_add(1);
                if clean_scans >= 2 {
                    return Ok(());
                }
            } else {
                clean_scans = 0;
            }

            if !bounded_sleep(SCAN_SETTLE_SLEEP, deadline) {
                bail!(
                    "timed out waiting for session {} processes to exit",
                    self.leader
                );
            }
        }
    }

    fn scan_session(&self, sig: Signal, deadline: Option<Instant>) -> Result<usize> {
        if !self.leader_identity_ok() {
            bail!(
                "session leader {} identity changed; refusing to signal",
                self.leader
            );
        }

        let mut first_err: Option<anyhow::Error> = None;
        let mut live_members = 0usize;

        let entries = match fs::read_dir("/proc") {
            Ok(entries) => entries,
            Err(err) => return Err(anyhow::Error::new(err).context("failed to read /proc")),
        };

        for entry in entries {
            ensure_before_deadline(deadline)?;

            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    record_error(
                        &mut first_err,
                        anyhow::Error::new(err).context("failed to read /proc entry"),
                    );
                    continue;
                }
            };

            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Ok(pid) = name.parse::<i32>() else {
                continue;
            };
            if pid <= 1 {
                continue;
            }

            let stat = match read_stat(pid) {
                Ok(stat) => stat,
                Err(err) => {
                    if !is_disappearance(&err) {
                        record_error(&mut first_err, err);
                    }
                    continue;
                }
            };
            if stat.session != self.leader {
                continue;
            }
            if is_live_state(stat.state) {
                live_members = live_members.saturating_add(1);
            }

            let Some(target) = Pid::from_raw(pid) else {
                continue;
            };
            let pidfd = match pidfd_open(target, PidfdFlags::empty()) {
                Ok(pidfd) => pidfd,
                Err(err) if is_pidfd_disappearance(err) => continue,
                Err(err) => {
                    record_error(
                        &mut first_err,
                        anyhow::Error::new(err).context(format!("pidfd_open({pid}) failed")),
                    );
                    continue;
                }
            };

            // Re-validate through the pidfd before signalling.
            let recheck = match read_stat(pid) {
                Ok(stat) => stat,
                Err(err) => {
                    if !is_disappearance(&err) {
                        record_error(&mut first_err, err);
                    }
                    continue;
                }
            };
            if recheck.starttime != stat.starttime || recheck.session != self.leader {
                continue;
            }

            if let Err(err) = pidfd_send_signal(&pidfd, sig) {
                if is_pidfd_disappearance(err) {
                    continue;
                }
                record_error(
                    &mut first_err,
                    anyhow::Error::new(err).context(format!("pidfd_send_signal({pid}) failed")),
                );
            }
        }

        match first_err {
            Some(err) => Err(err),
            None => Ok(live_members),
        }
    }
}

fn ensure_before_deadline(deadline: Option<Instant>) -> Result<()> {
    if let Some(deadline) = deadline
        && Instant::now() >= deadline
    {
        bail!("timed out while scanning session processes");
    }
    Ok(())
}

fn bounded_sleep(duration: Duration, deadline: Instant) -> bool {
    let now = Instant::now();
    if now >= deadline {
        return false;
    }
    let remaining = deadline.saturating_duration_since(now);
    let sleep_for = duration.min(remaining);
    if !sleep_for.is_zero() {
        thread::sleep(sleep_for);
    }
    Instant::now() < deadline
}

fn is_live_state(state: char) -> bool {
    !matches!(state, 'Z' | 'X')
}

/// Whether `err` represents a process that disappeared while we were looking
/// at it.
///
/// On Linux, both `ENOENT` and `ESRCH` mean "the target is gone"; `ERANGE`-style
/// rescan conditions are surfaced elsewhere. `std::io::ErrorKind` does not
/// reliably map `ESRCH` to `NotFound`, so the raw OS error code is compared
/// against safe `libc` constants. Other procfs errors are preserved.
fn is_disappearance(err: &anyhow::Error) -> bool {
    let Some(io) = err.downcast_ref::<std::io::Error>() else {
        return false;
    };
    if io.kind() == std::io::ErrorKind::NotFound {
        return true;
    }
    match io.raw_os_error() {
        Some(code) => code == nix::libc::ENOENT || code == nix::libc::ESRCH,
        None => false,
    }
}

fn is_pidfd_disappearance(err: rustix::io::Errno) -> bool {
    err == rustix::io::Errno::SRCH || err == rustix::io::Errno::NOENT
}

fn record_error(first: &mut Option<anyhow::Error>, err: anyhow::Error) {
    if first.is_none() {
        *first = Some(err);
    }
}
