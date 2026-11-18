//! TEST-ONLY root guest PTY probe (source-only; not executed here).
//!
//! Exercises the public [`mender_connect_rust::pty::PtyShell`] API against
//! a fixed synthetic guest account (`trial`, uid/gid 65534) running the fixed
//! Python target `/pty-target.py`. All `PtyShell` calls are synchronous and
//! run on a blocking-friendly `current_thread` runtime that is used *only* to
//! await the bounded output receiver between blocking calls.
//!
//! The probe prints a single fixed JSON object of booleans/numeric counts to
//! stdout (no raw output, no environment) and returns non-zero on any failure.
//! It never signals a PID parsed from output; it only inspects `/proc` state
//! via [`mender_connect_rust::session_process::read_stat`]. All failures attempt
//! an explicit `stop` with a `Drop` fallback.
#![forbid(unsafe_code)]

use std::io::ErrorKind;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use nix::unistd::getresuid;
use serde_json::Value;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

use mender_connect_rust::config::Config;
use mender_connect_rust::pty::PtyShell;
use mender_connect_rust::session_process::read_stat;

/// Hard cap on total collected target output.
const MAX_OUTPUT: usize = 16 * 1024;
/// Overall wall-clock budget for the interactive session.
const SESSION_BUDGET: Duration = Duration::from_secs(15);

#[derive(Default)]
struct Report {
    root: bool,
    spawn: bool,
    identity: bool,
    env: bool,
    fd: bool,
    tty: bool,
    ping: bool,
    resize: bool,
    background: bool,
    leader_ended: bool,
    background_ended: bool,
    output_bytes: usize,
    ok: bool,
}

fn main() {
    let code = match run() {
        Ok(report) => {
            print_report(&report);
            if report.ok { 0 } else { 1 }
        }
        Err(_) => {
            // Fixed redacted failure report; no raw diagnostics on stdout.
            print_report(&Report::default());
            1
        }
    };
    std::process::exit(code);
}

fn require_root() -> Result<()> {
    let ids = getresuid().context("getresuid failed")?;
    if !(ids.real.is_root() && ids.effective.is_root() && ids.saved.is_root()) {
        bail!("probe requires real/effective/saved uid 0");
    }
    Ok(())
}

fn run() -> Result<Report> {
    // Refuse non-root *before* any spawn or cleanup work.
    require_root()?;
    let mut report = Report {
        root: true,
        ..Default::default()
    };

    let config = Config {
        user: "trial".to_string(),
        shell_command: "/usr/bin/python3".to_string(),
        shell_arguments: vec!["/pty-target.py".to_string()],
        ..Default::default()
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build runtime")?;

    // Begin the fixed interactive budget before spawning. The subsequent
    // bounded stop may extend total wall-clock by the Pty cleanup deadline;
    // the outer guest budget remains <= 90s.
    let deadline = Instant::now() + SESSION_BUDGET;

    // Blocking spawn; a failure here needs no cleanup.
    let mut shell = PtyShell::spawn(&config, 24, 80).context("spawn failed")?;
    report.spawn = true;
    let leader_pid = shell.process_id();

    let session = session_flow(&runtime, &mut shell, &mut report, deadline);

    // Always explicitly stop; `Drop` below is the fallback if stop fails.
    let stop_result = shell.stop();
    drop(shell);

    let background_pid = session?;
    stop_result.context("stop failed")?;

    report.leader_ended = !is_live(leader_pid).context("leader liveness check failed")?;
    if let Some(bg) = background_pid {
        report.background_ended = !is_live(bg).context("background liveness check failed")?;
    }

    report.ok = report.root
        && report.spawn
        && report.identity
        && report.env
        && report.fd
        && report.tty
        && report.ping
        && report.resize
        && report.background
        && report.leader_ended
        && report.background_ended;

    Ok(report)
}

/// Drive the interactive protocol; return the parsed background pid, if any.
fn session_flow(
    rt: &Runtime,
    shell: &mut PtyShell,
    report: &mut Report,
    deadline: Instant,
) -> Result<Option<u32>> {
    let mut rx = shell.take_output().context("missing output receiver")?;
    let mut buf: Vec<u8> = Vec::new();

    // 1. Initial identity/environment/fd/tty proof.
    await_marker(rt, &mut rx, &mut buf, deadline, &|b| {
        json_line(b, b"PROOF ").is_some()
    })?;
    let proof = json_line(&buf, b"PROOF ").context("no proof json")?;
    report.identity = json_true(&proof, "uid_ok")
        && json_true(&proof, "gid_ok")
        && json_true(&proof, "saved_ok")
        && json_true(&proof, "primary_group_ok")
        && json_true(&proof, "caps_zero");
    report.env = json_true(&proof, "env_ok");
    report.fd = json_true(&proof, "fds_ok");
    report.tty = json_true(&proof, "tty_ok");

    // 2. ping / pong round trip.
    write_cmd(shell, b"ping\n")?;
    await_marker(rt, &mut rx, &mut buf, deadline, &|b| {
        find(b, b"PONG").is_some()
    })?;
    report.ping = true;

    // 3. resize to 37x101 and confirm the target sees the new size.
    shell.resize(37, 101).context("resize failed")?;
    write_cmd(shell, b"size\n")?;
    await_marker(rt, &mut rx, &mut buf, deadline, &|b| {
        json_line(b, b"SIZE ").is_some()
    })?;
    let size = json_line(&buf, b"SIZE ").context("no size json")?;
    report.resize = json_u32(&size, "rows") == Some(37) && json_u32(&size, "cols") == Some(101);

    // 4. background job in a distinct PGID, same SID.
    let leader_pid = shell.process_id();
    write_cmd(shell, b"background\n")?;
    await_marker(rt, &mut rx, &mut buf, deadline, &|b| {
        json_line(b, b"BACKGROUND ").is_some()
    })?;
    let bg = json_line(&buf, b"BACKGROUND ").context("no background json")?;
    let pid = json_u32(&bg, "pid");
    let pgid = json_u32(&bg, "pgid");
    let sid = json_u32(&bg, "sid");
    let bg_ok = matches!(
        (pid, pgid, sid),
        (Some(p), Some(g), Some(s))
            if p > 1 && g == p && s == leader_pid && p != leader_pid
    );
    report.background = bg_ok;
    report.output_bytes = buf.len();

    match pid {
        Some(p) if bg_ok && i32::try_from(p).is_ok() => Ok(Some(p)),
        _ => Ok(None),
    }
}

fn write_cmd(shell: &mut PtyShell, data: &[u8]) -> Result<()> {
    shell.write_input(data).context("write failed")
}

/// Await target output until `want` is satisfied or the deadline elapses.
fn await_marker<F: Fn(&[u8]) -> bool>(
    rt: &Runtime,
    rx: &mut mpsc::Receiver<Vec<u8>>,
    buf: &mut Vec<u8>,
    deadline: Instant,
    want: &F,
) -> Result<()> {
    loop {
        if want(buf) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("timed out waiting for target output");
        }
        let remain = deadline.saturating_duration_since(Instant::now());
        match rt.block_on(async { tokio::time::timeout(remain, rx.recv()).await }) {
            Ok(Some(chunk)) => append_bounded(buf, &chunk)?,
            Ok(None) => bail!("output channel closed before marker"),
            Err(_) => bail!("timed out waiting for target output"),
        }
    }
}

fn append_bounded(buf: &mut Vec<u8>, chunk: &[u8]) -> Result<()> {
    let remaining = MAX_OUTPUT.saturating_sub(buf.len());
    let take = chunk.len().min(remaining);
    if let Some(slice) = chunk.get(..take) {
        buf.extend_from_slice(slice);
    }
    if chunk.len() > remaining {
        bail!("output exceeded bounded limit");
    }
    Ok(())
}

/// Nonblocking liveness check via `/proc` state only; never signals.
fn is_live(pid: u32) -> Result<bool> {
    let pid_i = i32::try_from(pid).context("pid out of range")?;
    if pid_i <= 1 {
        return Ok(false);
    }
    match read_stat(pid_i) {
        Ok(stat) => Ok(!matches!(stat.state, 'Z' | 'X')),
        Err(error) => {
            if is_missing_process_error(&error) {
                Ok(false)
            } else {
                Err(error).context("failed to inspect process state")
            }
        }
    }
}

fn is_missing_process_error(error: &anyhow::Error) -> bool {
    if let Some(io_error) = error.downcast_ref::<std::io::Error>() {
        return io_error.kind() == ErrorKind::NotFound
            || io_error.raw_os_error() == Some(nix::errno::Errno::ESRCH as i32);
    }
    error.downcast_ref::<nix::errno::Errno>() == Some(&nix::errno::Errno::ESRCH)
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Return the parsed JSON object following `marker` on the same line.
fn json_line(buf: &[u8], marker: &[u8]) -> Option<Value> {
    let pos = find(buf, marker)?;
    let start = pos.checked_add(marker.len())?;
    let rest = buf.get(start..)?;
    let end = rest.iter().position(|&b| b == b'\n')?;
    let line = rest.get(..end)?;
    serde_json::from_slice(line).ok()
}

fn json_true(obj: &Value, key: &str) -> bool {
    obj.get(key).and_then(Value::as_bool) == Some(true)
}

fn json_u32(obj: &Value, key: &str) -> Option<u32> {
    obj.get(key)
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
}

fn print_report(report: &Report) {
    // Fixed booleans/numeric counts only; no raw output or environment.
    println!(
        concat!(
            "{{\"root\":{},\"spawn\":{},\"identity\":{},\"env\":{},\"fd\":{},\"tty\":{},",
            "\"ping\":{},\"resize\":{},\"background\":{},\"leader_ended\":{},",
            "\"background_ended\":{},\"output_bytes\":{},\"ok\":{}}}"
        ),
        report.root,
        report.spawn,
        report.identity,
        report.env,
        report.fd,
        report.tty,
        report.ping,
        report.resize,
        report.background,
        report.leader_ended,
        report.background_ended,
        report.output_bytes,
        report.ok,
    );
}
