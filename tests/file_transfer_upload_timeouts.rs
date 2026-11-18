//! Integration tests for the asynchronous upload worker's timeout behaviour.
//!
//! These tests drive the real `upload` worker (no server, no sockets) through
//! Tokio mpsc channels and local temporary directories. They deliberately mix
//! the real clock (required for asynchronous regular-file I/O performed on the
//! blocking pool) with a paused clock (used only to move time forward to the
//! worker's own internal deadlines).
//!
//! The runner is the default single-threaded `#[tokio::test]` runtime, which is
//! what allows `tokio::time::pause`/`advance` to be used. Time is never left
//! paused while test-side filesystem or channel operations run, and no
//! test-side `timeout` is awaited while the clock is paused.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;
use rmpv::Value;
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use mender_connect_rust::file_transfer_schema::UploadRequest;
use mender_connect_rust::file_transfer_upload::{CommittedAckError, UploadOutcome, upload};
use mender_connect_rust::protocol::{ProtoHdr, ProtoMsg, ProtoType};

const SID: &str = "test-upload-session";
const STAGE_PREFIX: &str = ".mender-upload-";
const OLD_CONTENT: &[u8] = b"OLD";
const BOUNDED_WAIT: Duration = Duration::from_secs(2);

// ---------------------------------------------------------------------------
// Owned abort-on-Drop lifecycle guard
// ---------------------------------------------------------------------------

/// Owns the worker `JoinHandle` and aborts the task when the test scope ends
/// (including on panic or early return). The handle is never removed from the
/// guard before the task has been awaited to completion.
struct WorkerGuard {
    handle: JoinHandle<Result<UploadOutcome>>,
}

impl WorkerGuard {
    fn new(handle: JoinHandle<Result<UploadOutcome>>) -> Self {
        Self { handle }
    }

    fn handle_mut(&mut self) -> &mut JoinHandle<Result<UploadOutcome>> {
        &mut self.handle
    }

    fn is_finished(&self) -> bool {
        self.handle.is_finished()
    }
}

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Await the worker with a bounded real-time wait. Never invoked while the
/// clock is paused.
async fn finish(guard: &mut WorkerGuard) -> Result<UploadOutcome> {
    let handle = guard.handle_mut();
    match tokio::time::timeout(BOUNDED_WAIT, &mut *handle).await {
        Ok(Ok(result)) => result,
        Ok(Err(join_err)) => panic!("upload worker task failed to join: {join_err}"),
        Err(_) => panic!("upload worker did not finish within the bounded real-time wait"),
    }
}

// ---------------------------------------------------------------------------
// Message construction helpers (no protocol defaults are assumed)
// ---------------------------------------------------------------------------

fn header(proto: ProtoType, msg_type: &str, sid: &str, offset: Option<i64>) -> ProtoHdr {
    let mut properties = BTreeMap::new();
    if let Some(offset) = offset {
        properties.insert("offset".to_string(), Value::Integer(offset.into()));
    }
    ProtoHdr {
        proto,
        msg_type: msg_type.to_string(),
        session_id: sid.to_string(),
        properties,
    }
}

fn chunk_message(proto: ProtoType, sid: &str, offset: i64, body: Vec<u8>) -> ProtoMsg {
    ProtoMsg {
        header: header(proto, "file_chunk", sid, Some(offset)),
        body,
    }
}

fn dummy_message() -> ProtoMsg {
    ProtoMsg {
        header: header(ProtoType::FILE_TRANSFER, "ack", "dummy-session", None),
        body: Vec::new(),
    }
}

fn ack_offset(message: &ProtoMsg) -> Option<i64> {
    match message.header.properties.get("offset") {
        Some(Value::Integer(value)) => value.as_i64(),
        _ => None,
    }
}

fn make_request(target: &Path) -> UploadRequest {
    UploadRequest {
        path: Some(target.to_string_lossy().into_owned()),
        src_path: None,
        size: None,
        mode: Some(0o644),
        uid: None,
        gid: None,
        modtime: None,
    }
}

// ---------------------------------------------------------------------------
// Filesystem observation helpers
// ---------------------------------------------------------------------------

fn stage_entries(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let entries = fs::read_dir(dir).expect("read staging directory");
    for entry in entries {
        let entry = entry.expect("read staging directory entry");
        let name = entry.file_name();
        if name.to_string_lossy().starts_with(STAGE_PREFIX) {
            found.push(entry.path());
        }
    }
    found
}

fn assert_no_stage(dir: &Path) {
    let remaining = stage_entries(dir);
    assert!(
        remaining.is_empty(),
        "staging files were left behind: {remaining:?}"
    );
}

fn assert_old_content(target: &Path) {
    let data = fs::read(target).expect("reading the upload target");
    assert_eq!(
        data, OLD_CONTENT,
        "upload target must still hold the original content"
    );
}

fn chain_contains(err: &anyhow::Error, needle: &str) -> bool {
    err.chain().any(|cause| cause.to_string().contains(needle))
}

fn assert_pre_commit_error(err: &anyhow::Error, needle: &str) {
    assert!(
        err.downcast_ref::<CommittedAckError>().is_none(),
        "unexpected post-commit acknowledgement failure: {err:?}"
    );
    assert!(
        chain_contains(err, needle),
        "error did not mention {needle:?}: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 1: v1 inactivity timeout
// ---------------------------------------------------------------------------

#[tokio::test]
async fn v1_inactivity_timeout_aborts_and_removes_stage() {
    let dir = TempDir::new().expect("creating temporary directory");
    let target = dir.path().join("payload.bin");
    fs::write(&target, OLD_CONTENT).expect("seeding upload target");

    let (_commands_guard, commands) = mpsc::channel::<ProtoMsg>(1);
    let (output, mut output_rx) = mpsc::channel::<ProtoMsg>(4);

    let handle = tokio::spawn(upload(
        ProtoType::FILE_TRANSFER,
        SID.to_string(),
        make_request(&target),
        commands,
        output,
    ));
    let mut guard = WorkerGuard::new(handle);

    // Observe the initial v1 ack on the real clock: staging is complete and the
    // worker is now waiting on the empty command channel.
    let first = tokio::time::timeout(BOUNDED_WAIT, output_rx.recv())
        .await
        .expect("initial ack within bounded real-time wait")
        .expect("output channel alive for initial ack");
    assert_eq!(first.header.msg_type, "ack");
    assert_eq!(first.header.session_id, SID);
    assert_eq!(ack_offset(&first), Some(0));

    tokio::task::yield_now().await;

    tokio::time::pause();

    tokio::time::advance(Duration::from_secs(29)).await;
    tokio::task::yield_now().await;
    assert!(
        !guard.is_finished(),
        "worker finished before the inactivity deadline"
    );

    tokio::time::advance(Duration::from_secs(2)).await;
    for _ in 0..50 {
        if guard.is_finished() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        guard.is_finished(),
        "worker did not finish after the inactivity deadline"
    );

    tokio::time::resume();

    let err = finish(&mut guard)
        .await
        .expect_err("inactivity must abort the upload before commit");
    assert_pre_commit_error(&err, "inactivity");

    assert_old_content(&target);
    assert_no_stage(dir.path());
}

// ---------------------------------------------------------------------------
// Test 2: fixed total deadline wins despite steady progress
// ---------------------------------------------------------------------------

#[tokio::test]
async fn v1_total_deadline_wins_over_continuous_progress() {
    let dir = TempDir::new().expect("creating temporary directory");
    let target = dir.path().join("payload.bin");
    fs::write(&target, OLD_CONTENT).expect("seeding upload target");

    let (commands, command_rx) = mpsc::channel::<ProtoMsg>(1);
    let (output, mut output_rx) = mpsc::channel::<ProtoMsg>(4);

    let handle = tokio::spawn(upload(
        ProtoType::FILE_TRANSFER,
        SID.to_string(),
        make_request(&target),
        command_rx,
        output,
    ));
    let mut guard = WorkerGuard::new(handle);

    let first = tokio::time::timeout(BOUNDED_WAIT, output_rx.recv())
        .await
        .expect("initial ack within bounded real-time wait")
        .expect("output channel alive for initial ack");
    assert_eq!(first.header.msg_type, "ack");
    assert_eq!(ack_offset(&first), Some(0));

    tokio::time::pause();

    for index in 0..20i64 {
        // 20 * 29s = 580s of virtual progress, so the 600s total deadline must
        // fire even though the 30s inactivity timer never gets a chance to.
        tokio::time::advance(Duration::from_secs(29)).await;
        tokio::time::resume();

        tokio::time::timeout(
            BOUNDED_WAIT,
            commands.send(chunk_message(
                ProtoType::FILE_TRANSFER,
                SID,
                index,
                vec![b'x'],
            )),
        )
        .await
        .expect("chunk command enqueued within bounded real-time wait")
        .expect("command channel alive while sending a chunk");

        let ack = tokio::time::timeout(BOUNDED_WAIT, output_rx.recv())
            .await
            .expect("chunk ack within bounded real-time wait")
            .expect("output channel alive for chunk ack");
        assert_eq!(ack.header.msg_type, "ack");
        assert_eq!(ack_offset(&ack), Some(index));

        assert_old_content(&target);

        tokio::time::pause();
    }

    // 580s elapsed; the total deadline is still 20s away.
    tokio::time::advance(Duration::from_secs(19)).await;
    tokio::task::yield_now().await;
    assert!(
        !guard.is_finished(),
        "worker finished before the fixed total deadline"
    );

    // 599s -> 601s: the fixed total deadline must win over the inactivity timer.
    tokio::time::advance(Duration::from_secs(2)).await;
    for _ in 0..50 {
        if guard.is_finished() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        guard.is_finished(),
        "worker did not finish after the fixed total deadline"
    );

    tokio::time::resume();

    let err = finish(&mut guard)
        .await
        .expect_err("total deadline must abort the upload before commit");
    assert_pre_commit_error(&err, "total deadline");

    assert_old_content(&target);
    assert_no_stage(dir.path());
}

// ---------------------------------------------------------------------------
// Test 3: blocked initial ack hits the output send timeout before commit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn v1_blocked_initial_ack_times_out_before_commit() {
    let dir = TempDir::new().expect("creating temporary directory");
    let target = dir.path().join("payload.bin");
    fs::write(&target, OLD_CONTENT).expect("seeding upload target");

    let (_commands_guard, commands) = mpsc::channel::<ProtoMsg>(1);
    let (output, _output_rx_keepalive) = mpsc::channel::<ProtoMsg>(1);
    output
        .try_send(dummy_message())
        .expect("prefilling the capacity-one output channel");

    let handle = tokio::spawn(upload(
        ProtoType::FILE_TRANSFER,
        SID.to_string(),
        make_request(&target),
        commands,
        output,
    ));
    let mut guard = WorkerGuard::new(handle);

    // Poll on the real clock until the staging file exists.
    let mut saw_stage = false;
    for _ in 0..100 {
        if !stage_entries(dir.path()).is_empty() {
            saw_stage = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(saw_stage, "worker never created the staging file");

    // Give the worker a few bounded polls so it reaches the (pending) initial
    // ack send before we freeze the clock.
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }

    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(5)).await;
    for _ in 0..50 {
        if guard.is_finished() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        guard.is_finished(),
        "worker did not finish after the ack send timeout"
    );

    tokio::time::resume();

    let err = finish(&mut guard)
        .await
        .expect_err("blocked initial ack must abort the upload before commit");
    assert_pre_commit_error(&err, "timed out sending upload ack");

    assert_old_content(&target);
    assert_no_stage(dir.path());
}
