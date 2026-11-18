//! Linux-local integration tests for the PTY shell building block.

#![cfg(target_os = "linux")]

use std::time::{Duration, Instant};

use mender_connect_rust::config::Config;
use mender_connect_rust::pty::PtyShell;
use nix::unistd::Uid;

fn test_config() -> Config {
    Config {
        user: current_user_name(),
        shell_command: "/bin/bash".to_owned(),
        shell_arguments: vec!["--noprofile".into(), "--norc".into()],
        ..Config::default()
    }
}

fn current_user_name() -> String {
    let uid = Uid::current();
    nix::unistd::User::from_uid(uid)
        .expect("user lookup")
        .expect("current user exists")
        .name
}

/// Read from the output receiver until `needle` appears or the deadline
/// elapses. Returns the accumulated bytes.
async fn read_until(
    rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
    needle: &[u8],
    timeout: Duration,
) -> Vec<u8> {
    let deadline = Instant::now() + timeout;
    let mut acc = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!(
                "timed out waiting for {:?}; got {:?}",
                String::from_utf8_lossy(needle),
                String::from_utf8_lossy(&acc)
            );
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(chunk)) => {
                acc.extend_from_slice(&chunk);
                if acc.windows(needle.len()).any(|w| w == needle) {
                    return acc;
                }
            }
            Ok(None) => panic!(
                "output channel closed before {:?}; got {:?}",
                String::from_utf8_lossy(needle),
                String::from_utf8_lossy(&acc)
            ),
            Err(_) => continue,
        }
    }
}

/// Read from the output receiver until the channel reaches EOF (reader
/// observed `read == 0`) or the deadline elapses. Returns the accumulated
/// bytes on EOF; panics on timeout.
async fn read_to_eof(rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>, timeout: Duration) -> Vec<u8> {
    let deadline = Instant::now() + timeout;
    let mut acc = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!(
                "timed out draining output to EOF; got {:?}",
                String::from_utf8_lossy(&acc)
            );
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(chunk)) => acc.extend_from_slice(&chunk),
            Ok(None) => return acc,
            Err(_) => continue,
        }
    }
}

fn pid_exists(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

/// Parse `(state, session)` from `/proc/<pid>/stat`.
///
/// Fields after the (possibly space-containing) `comm` are: state, ppid, pgrp,
/// session, ... so the session id is the fourth whitespace-separated field
/// after the final `)`.
fn proc_state_session(pid: u32) -> Option<(char, u32)> {
    let data = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = data.rfind(')')?;
    let rest = data.get(close + 1..)?.trim_start();
    let mut fields = rest.split_whitespace();
    let state = fields.next()?.chars().next()?;
    let _ppid = fields.next()?;
    let _pgrp = fields.next()?;
    let session = fields.next()?.parse::<u32>().ok()?;
    Some((state, session))
}

/// Collect live (non-zombie) processes whose session id equals `sid`.
fn live_sid_members(sid: u32) -> Vec<u32> {
    let mut members = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return members;
    };
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        if pid == std::process::id() {
            continue;
        }
        if let Some((state, session)) = proc_state_session(pid) {
            if session != sid {
                continue;
            }
            if matches!(state, 'Z' | 'X') {
                continue;
            }
            members.push(pid);
        }
    }
    members
}

/// Bounded wait until no live process shares session `sid`.
async fn wait_no_live_sid(sid: u32, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let members = live_sid_members(sid);
        if members.is_empty() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "live processes remain in session {sid}: {members:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shell_executes_and_reports_pid() {
    let config = test_config();
    let mut shell = tokio::task::spawn_blocking(move || {
        let mut shell = PtyShell::spawn(&config, 24, 80).expect("spawn shell");
        shell
            .write_input(b"printf '\\101\\102\\103\\n'\n")
            .expect("write input");
        shell
    })
    .await
    .expect("spawn_blocking");

    let pid = shell.process_id();
    assert!(pid > 0, "expected a real child pid");

    let mut rx = shell.take_output().expect("output receiver");

    let out = read_until(&mut rx, b"ABC", Duration::from_secs(10)).await;
    assert!(
        out.windows(3).any(|w| w == b"ABC"),
        "expected ABC marker in output, got {:?}",
        String::from_utf8_lossy(&out)
    );

    tokio::task::spawn_blocking(move || shell.stop().expect("stop"))
        .await
        .expect("spawn_blocking");
    assert!(!pid_exists(pid), "child pid {pid} still exists after stop");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resize_is_visible_via_stty() {
    let config = test_config();
    let mut shell = tokio::task::spawn_blocking(move || {
        let mut shell = PtyShell::spawn(&config, 24, 80).expect("spawn shell");
        shell.resize(40, 100).expect("resize");
        shell
            .write_input(b"stty size; printf '\\104\\105\\106\\n'\n")
            .expect("write input");
        shell
    })
    .await
    .expect("spawn_blocking");

    let mut rx = shell.take_output().expect("output receiver");

    let out = read_until(&mut rx, b"DEF", Duration::from_secs(10)).await;
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains("40 100"),
        "expected stty size '40 100' in output, got {text:?}"
    );

    tokio::task::spawn_blocking(move || shell.stop().expect("stop"))
        .await
        .expect("spawn_blocking");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_is_idempotent_and_reaps() {
    let config = test_config();
    let mut shell = tokio::task::spawn_blocking(move || PtyShell::spawn(&config, 24, 80))
        .await
        .expect("spawn_blocking")
        .expect("spawn shell");
    let pid = shell.process_id();
    assert!(pid > 0);

    tokio::task::spawn_blocking(move || {
        shell.stop().expect("first stop");
        assert!(!pid_exists(pid), "child pid {pid} still exists after stop");
        shell.stop().expect("second stop");
        assert!(
            !pid_exists(pid),
            "child pid {pid} reappeared after second stop"
        );
    })
    .await
    .expect("spawn_blocking");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn take_output_returns_none_second_time() {
    let config = test_config();
    let mut shell = tokio::task::spawn_blocking(move || PtyShell::spawn(&config, 24, 80))
        .await
        .expect("spawn_blocking")
        .expect("spawn shell");

    assert!(shell.take_output().is_some(), "first take must be Some");
    assert!(shell.take_output().is_none(), "second take must be None");

    tokio::task::spawn_blocking(move || shell.stop().expect("stop"))
        .await
        .expect("spawn_blocking");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_output_queue_does_not_block_stop() {
    let config = test_config();
    let mut shell = tokio::task::spawn_blocking(move || {
        let mut shell = PtyShell::spawn(&config, 24, 80).expect("spawn shell");
        // Bash builtin loop printing a long constant; no extra child
        // processes are spawned by the shell itself.
        shell
            .write_input(
                b"while :; do printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\n'; done\n",
            )
            .expect("write input");
        shell
    })
    .await
    .expect("spawn_blocking");

    let pid = shell.process_id();
    assert!(pid > 0);

    // Keep the receiver alive but never drain it, so the bounded channel
    // fills and the reader thread is forced into backpressure.
    let _rx = shell.take_output().expect("output receiver");

    // Give the producer time to fill the queue.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let start = Instant::now();
    tokio::task::spawn_blocking(move || {
        shell.stop().expect("stop");
        drop(shell);
    })
    .await
    .expect("spawn_blocking");
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(2),
        "stop+drop took {elapsed:?}, expected < 2s"
    );
    assert!(!pid_exists(pid), "child pid {pid} still exists after stop");
}

/// Guard that stops and reaps a shell on drop, so a failing assertion cannot
/// leak the child or its background jobs.
struct ShellGuard(Option<PtyShell>);

impl Drop for ShellGuard {
    fn drop(&mut self) {
        if let Some(mut shell) = self.0.take() {
            let _ = std::thread::spawn(move || {
                let _ = shell.stop();
            })
            .join();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detects_natural_exit_with_background_job_holding_slave() {
    let config = test_config();
    let mut shell = tokio::task::spawn_blocking(move || {
        let mut shell = PtyShell::spawn(&config, 24, 80).expect("spawn shell");
        shell
            .write_input(b"(trap '' HUP; printf '\\102\\107\\120\\111\\104:%d\\n\\102\\107\\122\\105\\101\\104\\131\\n' \"$BASHPID\"; exec sleep 300) &\n")
            .expect("write input");
        shell
    })
    .await
    .expect("spawn_blocking");

    let leader_pid = shell.process_id();
    assert!(leader_pid > 0, "expected a real child pid");

    let mut rx = shell.take_output().expect("output receiver");

    let out = read_until(&mut rx, b"BGREADY", Duration::from_secs(10)).await;
    let text = String::from_utf8_lossy(&out);
    let bg_pid: u32 = text
        .split("BGPID:")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|pid| pid.parse().ok())
        .expect("parse background pid from output");
    assert!(bg_pid > 0, "expected a real background pid");

    // Guard ensures cleanup even if an assertion below fails.
    let mut guard = ShellGuard(Some(shell));

    // Exit the leader while the background job keeps the PTY slave open.
    guard
        .0
        .as_mut()
        .expect("shell present")
        .write_input(b"exit\n")
        .expect("write exit");

    // Poll for natural exit without reaping the leader.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let exited = guard
            .0
            .as_ref()
            .expect("shell present")
            .has_exited()
            .expect("has_exited");
        if exited {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "leader did not exit within deadline"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // The leader must still exist (not reaped) so the SID stays reserved.
    assert!(
        pid_exists(leader_pid),
        "leader pid {leader_pid} was reaped before stop"
    );
    // The background job must still be alive, holding the slave open.
    assert!(
        pid_exists(bg_pid),
        "background pid {bg_pid} should still be alive before stop"
    );

    // Stop must terminate the background job via session signalling.
    let mut shell = guard.0.take().expect("shell present");
    tokio::task::spawn_blocking(move || shell.stop().expect("stop"))
        .await
        .expect("spawn_blocking");

    let deadline = Instant::now() + Duration::from_secs(2);
    while pid_exists(bg_pid) {
        if let Ok(stat) = mender_connect_rust::session_process::read_stat(bg_pid as i32)
            && matches!(stat.state, 'Z' | 'X')
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "background pid {bg_pid} still running after stop"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Natural exit followed by `terminate_processes`: the reader must drain the
/// kernel PTY tail and queued output to EOF once the owned session jobs are
/// terminated, preserving a final octal-encoded marker. Markers are octal
/// encoded so terminal echo of the typed command can never be mistaken for the
/// real output.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn terminate_processes_drains_tail_after_natural_exit() {
    let config = test_config();
    let mut shell = tokio::task::spawn_blocking(move || {
        let mut shell = PtyShell::spawn(&config, 24, 80).expect("spawn shell");
        // Background job traps HUP and retains the PTY slave. `DRBG:<pid>` is
        // octal-encoded in the command line, decoded in the real output.
        // `DRAINDONE` is the final marker printed before the leader exits.
        shell
            .write_input(
                b"(trap '' HUP; printf '\\104\\122\\102\\107:%d\\n' \"$BASHPID\"; exec sleep 300) &\nprintf '\\104\\122\\101\\111\\116\\104\\117\\116\\105\\n'\nexit\n",
            )
            .expect("write input");
        shell
    })
    .await
    .expect("spawn_blocking");

    let leader_pid = shell.process_id();
    assert!(leader_pid > 0, "expected a real leader pid");

    let mut rx = shell.take_output().expect("output receiver");

    // Guard installed before any polling or assertions.
    let mut guard = ShellGuard(Some(shell));

    // Wait for natural leader exit without draining output.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let exited = guard
            .0
            .as_ref()
            .expect("shell present")
            .has_exited()
            .expect("has_exited");
        if exited {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "leader did not exit within deadline"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Terminate owned session/direct child, returning the shell to us, while
    // leaving the reader active so it can drain the tail to EOF.
    let mut shell = guard.0.take().expect("shell present");
    let shell = tokio::task::spawn_blocking(move || {
        shell.terminate_processes().expect("terminate_processes");
        shell
    })
    .await
    .expect("spawn_blocking");
    guard.0 = Some(shell);

    // Drain remaining output to EOF within 2s.
    let out = read_to_eof(&mut rx, Duration::from_secs(2)).await;
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains("DRAINDONE"),
        "final marker missing from drained output: {text:?}"
    );

    // Leader must be reaped; its pid must be gone.
    assert!(
        !pid_exists(leader_pid),
        "leader pid {leader_pid} still exists after terminate_processes"
    );

    // Parse the retained background pid and confirm it is gone.
    let bg_pid: u32 = text
        .split("DRBG:")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|pid| pid.parse().ok())
        .expect("parse background pid from drained output");
    assert!(bg_pid > 0, "expected a real background pid");
    assert!(
        !pid_exists(bg_pid),
        "background pid {bg_pid} still exists after terminate_processes"
    );

    // No live member of the leader's session may remain.
    wait_no_live_sid(leader_pid, Duration::from_secs(2)).await;
}

/// `terminate_processes` followed by `stop` + drop must cancel the reader even
/// though process cleanup was already complete, finishing bounded despite a
/// fully undrained output queue.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn terminate_then_stop_cancels_reader_with_full_queue() {
    let config = test_config();
    let mut shell = tokio::task::spawn_blocking(move || {
        let mut shell = PtyShell::spawn(&config, 24, 80).expect("spawn shell");
        // Bash builtin loop printing a long constant; no escaped child needed.
        shell
            .write_input(
                b"while :; do printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\n'; done\n",
            )
            .expect("write input");
        shell
    })
    .await
    .expect("spawn_blocking");

    let pid = shell.process_id();
    assert!(pid > 0);

    // Keep the receiver alive but never drain it, forcing backpressure.
    let _rx = shell.take_output().expect("output receiver");
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut guard = ShellGuard(Some(shell));
    let mut shell = guard.0.take().expect("shell present");

    // terminate_processes leaves the receiver undrained; the subsequent
    // stop must cancel the reader independently and promptly.
    let start = Instant::now();
    tokio::task::spawn_blocking(move || {
        shell.terminate_processes().expect("terminate_processes");
        shell.stop().expect("stop");
        drop(shell);
    })
    .await
    .expect("spawn_blocking");
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(2),
        "terminate+stop+drop took {elapsed:?}, expected < 2s"
    );
    assert!(!pid_exists(pid), "child pid {pid} still exists after stop");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_unknown_user() {
    let mut config = test_config();
    config.user = "definitely-not-a-real-user-xyz".to_owned();
    let err = tokio::task::spawn_blocking(move || PtyShell::spawn(&config, 24, 80))
        .await
        .expect("spawn_blocking")
        .err()
        .expect("unknown user must fail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("unknown user"),
        "unexpected error message: {msg}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_empty_user_before_spawning() {
    let mut config = test_config();
    config.user = String::new();
    let err = tokio::task::spawn_blocking(move || PtyShell::spawn(&config, 24, 80))
        .await
        .expect("spawn_blocking")
        .err()
        .expect("empty user must fail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("configuration User must be set"),
        "unexpected error message: {msg}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_different_user() {
    let mut config = test_config();
    // Pick a user that exists but is not the current one.
    let current = Uid::current();
    let other = ["root", "nobody", "daemon"].iter().find_map(|name| {
        nix::unistd::User::from_name(name)
            .ok()
            .flatten()
            .filter(|u| u.uid != current)
    });
    let other = other.expect(
        "no alternate user (root/nobody/daemon) available; cannot exercise different-user rejection",
    );
    config.user = other.name;
    let err = tokio::task::spawn_blocking(move || PtyShell::spawn(&config, 24, 80))
        .await
        .expect("spawn_blocking")
        .err()
        .expect("different user must fail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("privilege switching is not supported"),
        "unexpected error message: {msg}"
    );
}
