//! Integration tests for session-scoped process cleanup.

use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use mender_connect_rust::session_process::{OwnedSession, ProcStat, read_stat};
use rustix::process::Signal;

fn capture_session_with_retry(guard: &mut TestGuard, pid: u32) {
    let capture_deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match OwnedSession::capture(pid) {
            Ok(session) => {
                guard.session = Some(session);
                return;
            }
            Err(err) => {
                if let Some(child) = guard.child.as_mut() {
                    match child.try_wait() {
                        Ok(Some(_)) => {
                            panic!("child exited before session capture for pid {pid}");
                        }
                        Ok(None) => {}
                        Err(wait_err) => {
                            panic!("failed polling child before session capture: {wait_err}");
                        }
                    }
                } else {
                    panic!("test guard lost its child before session capture");
                }
                if Instant::now() >= capture_deadline {
                    panic!("timed out capturing session for pid {pid}: {err}");
                }
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

fn find_session_member_in_other_pgid(session_id: i32) -> Option<i32> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str()
                    && let Ok(p) = name.parse::<i32>()
                    && let Ok(stat) = read_stat(p)
                    && stat.session == session_id
                    && stat.pgrp != session_id
                {
                    return Some(p);
                }
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    None
}

fn is_gone_or_dead(pid: i32) -> bool {
    match read_stat(pid) {
        Err(_) => true,
        Ok(stat) => matches!(stat.state, 'Z' | 'X'),
    }
}

#[test]
fn parses_stat_with_spaces_and_parens_in_comm() {
    // comm = "a b) c"; the LAST ") " is the real terminator.
    let raw = "1234 (a b) c) S 1 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 98765 0 0";
    let stat = ProcStat::parse(1234, raw).expect("parse failed");
    assert_eq!(stat.pid, 1234);
    assert_eq!(stat.state, 'S');
    assert_eq!(stat.ppid, 1);
    assert_eq!(stat.pgrp, 1234);
    assert_eq!(stat.session, 1234);
    assert_eq!(stat.starttime, 98765);
}

#[test]
fn parse_bytes_handles_non_utf8_comm_and_rejects_malformed_suffixes() {
    // Opaque, non-UTF-8 comm containing both spaces and a right parenthesis.
    // The parser must locate the final ") " delimiter and parse the ASCII
    // suffix correctly without attempting to UTF-8 decode comm.
    let raw = b"1234 (a\xff) b) S 1 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 98765 0 0";
    let stat = ProcStat::parse_bytes(1234, raw).expect("parse_bytes failed");
    assert_eq!(stat.pid, 1234);
    assert_eq!(stat.state, 'S');
    assert_eq!(stat.ppid, 1);
    assert_eq!(stat.pgrp, 1234);
    assert_eq!(stat.session, 1234);
    assert_eq!(stat.starttime, 98765);

    assert!(
        ProcStat::parse_bytes(1234, b"1234 (comm S 1 2 3").is_err(),
        "missing comm delimiter must be rejected"
    );
    assert!(
        ProcStat::parse_bytes(1234, b"1234 (comm) S 1 2 3").is_err(),
        "truncated stat suffix must be rejected"
    );
    assert!(
        ProcStat::parse_bytes(
            1234,
            b"1234 (comm) S 999999999999999999999 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 98765 0 0"
        )
        .is_err(),
        "numeric overflow must be rejected"
    );
    assert!(
        ProcStat::parse_bytes(
            1234,
            b"1234 (comm) AB 1 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 98765 0 0"
        )
        .is_err(),
        "multi-character state must be rejected"
    );
}

#[test]
fn reads_own_stat() {
    let own = std::process::id() as i32;
    let stat = read_stat(own).expect("failed to read own stat");
    assert_eq!(stat.pid, own);
    assert!(stat.session > 0);
}

#[test]
fn refuses_own_pid() {
    let own = std::process::id();
    let err = OwnedSession::capture(own).expect_err("should refuse own pid");
    assert!(
        err.to_string().contains("own pid"),
        "unexpected error: {err}"
    );
}

struct TestGuard {
    child: Option<Child>,
    session: Option<OwnedSession>,
}

impl Drop for TestGuard {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            // Bounded verification: never wait indefinitely here.
            let deadline = Instant::now() + Duration::from_secs(2);
            let _ = session.kill_and_verify(deadline);
        }
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            // Bounded reap: SIGKILL cannot be ignored, but avoid an
            // unbounded wait if the child is stuck in an uninterruptible
            // state.
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) => {
                        if Instant::now() >= deadline {
                            break;
                        }
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        }
    }
}

#[test]
fn signals_session_members_in_different_pgid() {
    // `setsid` execs directly (it is not a process group leader here), so the
    // spawned PID is the session leader. `set -m` puts the background `sleep`
    // in its own process group while keeping the same session. bash is used
    // because dash cannot enable noninteractive job control.
    let mut cmd = Command::new("setsid");
    cmd.arg("bash")
        .arg("-c")
        .arg("set -m; sleep 30 & wait")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = cmd.spawn().expect("failed to spawn setsid bash");
    let pid = child.id();

    // Install the cleanup guard immediately so a panic below cannot leak the
    // spawned child.
    let mut guard = TestGuard {
        child: Some(child),
        session: None,
    };

    // `setsid` may not have exec'd yet, so retry capture until the session
    // leader is observable or the deadline elapses.
    capture_session_with_retry(&mut guard, pid);

    // Wait for a child in a different PGID but the same SID.
    let session_id = i32::try_from(pid).expect("leader pid fits in i32");
    let member_pid =
        find_session_member_in_other_pgid(session_id).expect("expected another session member");

    // Signal the whole session.
    guard
        .session
        .as_ref()
        .expect("session guard missing")
        .signal_session(Signal::KILL)
        .expect("signal_session failed");

    // The distinct-PGID member must be gone (absent or zombie) within 2s.
    let member_deadline = Instant::now() + Duration::from_secs(2);
    while !is_gone_or_dead(member_pid) {
        if Instant::now() >= member_deadline {
            panic!("session member {member_pid} still alive after SIGKILL");
        }
        thread::sleep(Duration::from_millis(20));
    }

    // The leader must exit before we perform the successful wait.
    let leader_deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let child = guard.child.as_mut().expect("leader child missing");
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if Instant::now() >= leader_deadline {
                    panic!("leader {pid} did not exit after session SIGKILL");
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(err) => panic!("failed polling leader {pid}: {err}"),
        }
    }
    guard
        .child
        .as_mut()
        .expect("leader child missing")
        .wait()
        .expect("failed to reap leader");
    guard.child = None;
    guard.session = None;
}

#[test]
fn expired_deadline_does_not_kill_owned_session_child() {
    let mut cmd = Command::new("setsid");
    cmd.arg("bash")
        .arg("-c")
        .arg("sleep 30")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = cmd.spawn().expect("failed to spawn setsid bash");
    let pid = child.id();

    // The guard exists immediately after spawn, before capture can race with
    // the setsid exec.
    let mut guard = TestGuard {
        child: Some(child),
        session: None,
    };
    capture_session_with_retry(&mut guard, pid);

    let started = Instant::now();
    let err = guard
        .session
        .as_ref()
        .expect("session guard missing")
        .kill_and_verify(Instant::now())
        .expect_err("expired deadline must fail before doing any cleanup");
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "expired-deadline verification was not bounded: {:?}",
        started.elapsed()
    );
    assert!(!err.to_string().is_empty(), "expected a useful error");

    // The controlled child must still be alive: an expired deadline is not
    // permission to signal it.
    match guard
        .child
        .as_mut()
        .expect("leader child missing")
        .try_wait()
    {
        Ok(None) => {}
        Ok(Some(status)) => panic!("child was killed despite expired deadline: {status:?}"),
        Err(wait_err) => panic!("failed polling controlled child: {wait_err}"),
    }
    let leader_pid = i32::try_from(pid).expect("leader pid fits in i32");
    let stat = read_stat(leader_pid).expect("controlled child stat should be readable");
    assert!(
        !matches!(stat.state, 'Z' | 'X'),
        "controlled child unexpectedly dead after expired-deadline verification"
    );
}

#[test]
fn kill_and_verify_reaps_session_job_and_leaves_leader_for_explicit_wait() {
    // Both the leader and the background job ignore SIGHUP. The verification
    // must therefore actually terminate by SIGKILL and verify the session,
    // while keeping the direct child unreaped until we explicitly wait.
    let mut cmd = Command::new("setsid");
    cmd.arg("bash")
        .arg("-c")
        .arg("trap '' HUP; set -m; sleep 30 & wait")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = cmd.spawn().expect("failed to spawn setsid bash");
    let pid = child.id();

    let mut guard = TestGuard {
        child: Some(child),
        session: None,
    };
    capture_session_with_retry(&mut guard, pid);

    let leader_pid = i32::try_from(pid).expect("leader pid fits in i32");
    let member_pid = find_session_member_in_other_pgid(leader_pid)
        .expect("expected a job in another PGID but the same SID");

    // First verification while the leader is still owned and unreaped.
    guard
        .session
        .as_ref()
        .expect("session guard missing")
        .kill_and_verify(Instant::now() + Duration::from_secs(5))
        .expect("first kill_and_verify failed");

    let member_deadline = Instant::now() + Duration::from_secs(2);
    while !is_gone_or_dead(member_pid) {
        if Instant::now() >= member_deadline {
            panic!("job {member_pid} survived session kill_and_verify");
        }
        thread::sleep(Duration::from_millis(20));
    }
    let first_stat = read_stat(leader_pid)
        .expect("unreaped leader must remain readable after first verification");
    assert!(
        matches!(first_stat.state, 'Z' | 'X'),
        "leader should be dead but unreaped, state was {}",
        first_stat.state
    );

    // Second verification must also succeed while the leader remains
    // unreaped, proving verification does not depend on reaping the leader.
    guard
        .session
        .as_ref()
        .expect("session guard missing")
        .kill_and_verify(Instant::now() + Duration::from_secs(5))
        .expect("second kill_and_verify failed while leader was unreaped");
    let second_stat = read_stat(leader_pid)
        .expect("unreaped leader must remain readable after second verification");
    assert!(
        matches!(second_stat.state, 'Z' | 'X'),
        "leader should still be dead but unreaped, state was {}",
        second_stat.state
    );

    // Only now explicitly reap the leader.
    guard
        .child
        .as_mut()
        .expect("leader child missing")
        .wait()
        .expect("failed to explicitly reap leader");
    guard.child = None;
    guard.session = None;
}
