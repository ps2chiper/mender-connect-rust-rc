//! Native CLI compatibility tests: global options, the version command and
//! checked stdout/stderr handling. No daemon, real bus or server is contacted.

use std::fs::File;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_mender-connect-rust");
const TIMEOUT: Duration = Duration::from_secs(30);

struct Run {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str]) -> Run {
    run_with(args, Stdio::piped())
}

fn run_with(args: &[&str], stdout: Stdio) -> Run {
    let mut child = Command::new(BIN)
        .args(args)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn child process");

    let deadline = Instant::now() + TIMEOUT;
    loop {
        match child.try_wait().expect("poll child process") {
            Some(_) => break,
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("subprocess exceeded timeout");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    let output = child.wait_with_output().expect("collect child output");
    Run {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

#[test]
fn version_subcommand_reports_without_config_or_server() {
    let out = run(&["version"]);
    assert!(out.status.success(), "version failed: {}", out.stderr);
    assert!(
        out.stdout.contains(env!("CARGO_PKG_VERSION")),
        "stdout missing package version: {}",
        out.stdout
    );
    assert!(
        out.stderr.trim().is_empty(),
        "version produced unexpected stderr: {}",
        out.stderr
    );
}

#[test]
fn version_flag_with_missing_config_paths_still_succeeds() {
    let out = run(&[
        "--version",
        "--config",
        "/nonexistent/primary.conf",
        "--fallback-config",
        "/nonexistent/fallback.conf",
    ]);
    assert!(out.status.success(), "--version failed: {}", out.stderr);
    assert!(
        out.stdout.contains(env!("CARGO_PKG_VERSION")),
        "stdout: {}",
        out.stdout
    );
}

#[test]
fn global_config_flags_accepted_before_and_after_subcommand() {
    let primary = "/nonexistent/mender-primary.conf";
    let fallback = "/nonexistent/mender-fallback.conf";

    let after = run(&[
        "config-check",
        "--config",
        primary,
        "--fallback-config",
        fallback,
    ]);
    let before = run(&[
        "--config",
        primary,
        "--fallback-config",
        fallback,
        "config-check",
    ]);

    // Both positions must attempt config loading (error, not clap usage error 2).
    assert_ne!(
        after.status.code(),
        Some(2),
        "after stderr: {}",
        after.stderr
    );
    assert_ne!(
        before.status.code(),
        Some(2),
        "before stderr: {}",
        before.stderr
    );
    assert!(!after.status.success());
    assert!(!before.status.success());
    assert_eq!(after.status.code(), before.status.code());
}

#[test]
fn short_config_aliases_are_accepted() {
    let out = run(&[
        "config-check",
        "-c",
        "/nonexistent/primary.conf",
        "-b",
        "/nonexistent/fallback.conf",
    ]);
    assert_ne!(out.status.code(), Some(2), "stderr: {}", out.stderr);
    assert!(!out.status.success());
}

#[test]
fn malformed_arguments_produce_usage_errors() {
    let out = run(&["--definitely-not-a-flag", "config-check"]);
    assert_eq!(out.status.code(), Some(2), "stderr: {}", out.stderr);
    assert!(!out.stderr.is_empty());
}

#[test]
fn debug_and_trace_flags_are_accepted_including_double_d() {
    for flag in ["-d", "--debug", "-dd", "--trace"] {
        let out = run(&[
            flag,
            "config-check",
            "-c",
            "/nonexistent/primary.conf",
            "-b",
            "/nonexistent/fallback.conf",
        ]);
        assert_ne!(
            out.status.code(),
            Some(2),
            "flag {flag} rejected as usage error: {}",
            out.stderr
        );
        assert!(!out.status.success());
    }
}

#[test]
fn version_reports_checked_stdout_failure() {
    let full = match File::create("/dev/full") {
        Ok(file) => file,
        Err(_) => return, // /dev/full unavailable on this platform
    };
    let out = run_with(&["version"], Stdio::from(full));
    assert!(
        !out.status.success(),
        "writing version to /dev/full should fail"
    );
}
