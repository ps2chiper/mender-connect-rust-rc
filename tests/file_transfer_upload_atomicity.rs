//! Integration tests covering the atomicity and error-classification semantics
//! of the file transfer upload worker.
//!
//! All async work runs on a real Tokio runtime with real timers; no virtual
//! clock and no `std::thread` are used. Every spawned worker is wrapped in a
//! [`TaskGuard`] that aborts the task on drop, so an assertion failure can never
//! leave a detached worker running.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::Duration;

use mender_connect_rust::file_transfer_schema::UploadRequest;
use mender_connect_rust::file_transfer_upload::{CommittedAckError, UploadOutcome, upload};
use mender_connect_rust::protocol::{ProtoHdr, ProtoMsg, ProtoType};
use rmpv::Value;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const SID: &str = "session-1";
const STAGE_PREFIX: &str = ".mender-upload-";
const JOIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Owns a spawned upload worker and aborts it if the test fails before the
/// worker has been explicitly joined.
struct TaskGuard {
    handle: JoinHandle<anyhow::Result<UploadOutcome>>,
}

impl TaskGuard {
    fn new(handle: JoinHandle<anyhow::Result<UploadOutcome>>) -> Self {
        Self { handle }
    }
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Await the worker under a hard 2s timeout, panicking (and aborting via the
/// guard's `Drop`) on timeout or on a panic inside the worker.
async fn join_guard(mut guard: TaskGuard) -> anyhow::Result<UploadOutcome> {
    let joined = tokio::time::timeout(JOIN_TIMEOUT, &mut guard.handle)
        .await
        .expect("upload worker did not finish within timeout");
    joined.expect("upload worker panicked")
}

fn build_message(
    proto: ProtoType,
    sid: &str,
    msg_type: &str,
    offset: Option<Value>,
    body: Vec<u8>,
) -> ProtoMsg {
    let mut properties = BTreeMap::new();
    if let Some(value) = offset {
        properties.insert("offset".to_string(), value);
    }
    ProtoMsg {
        header: ProtoHdr {
            proto,
            msg_type: msg_type.to_string(),
            session_id: sid.to_string(),
            properties,
        },
        body,
    }
}

fn chunk(sid: &str, offset: i64, body: Vec<u8>) -> ProtoMsg {
    build_message(
        ProtoType::FILE_TRANSFER_V2,
        sid,
        "file_chunk",
        Some(Value::Integer(offset.into())),
        body,
    )
}

fn request_for(path: &Path) -> UploadRequest {
    UploadRequest {
        path: Some(path.to_string_lossy().into_owned()),
        src_path: None,
        size: Some(3),
        uid: None,
        gid: None,
        mode: None,
        modtime: None,
    }
}

/// Snapshot of the directory entry names. Used to prove that no staging file
/// survives and the directory contains *exactly* the expected entries.
fn dir_entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .expect("read destination directory")
        .map(|entry| {
            entry
                .expect("read directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

/// Bounded observation that a staging file of exactly `expected` bytes exists.
/// Uses real `tokio::time::sleep` (1ms) so the worker task gets to make progress
/// on the current-thread runtime without assuming a command send implies
/// processing.
async fn wait_for_stage_len(dir: &Path, expected: u64) -> bool {
    let deadline = std::time::Instant::now() + JOIN_TIMEOUT;
    loop {
        if let Ok(read) = fs::read_dir(dir) {
            for entry in read.flatten() {
                let is_stage = entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(STAGE_PREFIX);
                if is_stage
                    && let Ok(meta) = entry.metadata()
                    && meta.len() == expected
                {
                    return true;
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

/// Table of invalid first commands. Each must drive the worker to `Err` that is
/// not a [`CommittedAckError`], leaving the OLD target untouched and the
/// directory containing exactly that target.
#[tokio::test]
async fn invalid_commands_error_without_touching_target() {
    let cases: Vec<(&str, ProtoMsg)> = vec![
        (
            "missing offset",
            build_message(
                ProtoType::FILE_TRANSFER_V2,
                SID,
                "file_chunk",
                None,
                b"abc".to_vec(),
            ),
        ),
        (
            "non-integer offset",
            build_message(
                ProtoType::FILE_TRANSFER_V2,
                SID,
                "file_chunk",
                Some(Value::from("0")),
                b"abc".to_vec(),
            ),
        ),
        (
            "negative offset",
            build_message(
                ProtoType::FILE_TRANSFER_V2,
                SID,
                "file_chunk",
                Some(Value::Integer((-1i64).into())),
                b"abc".to_vec(),
            ),
        ),
        (
            "skipped offset",
            build_message(
                ProtoType::FILE_TRANSFER_V2,
                SID,
                "file_chunk",
                Some(Value::Integer(1i64.into())),
                b"abc".to_vec(),
            ),
        ),
        (
            "unsigned overflow offset",
            build_message(
                ProtoType::FILE_TRANSFER_V2,
                SID,
                "file_chunk",
                Some(Value::Integer(u64::MAX.into())),
                b"abc".to_vec(),
            ),
        ),
        (
            "wrong session id",
            build_message(
                ProtoType::FILE_TRANSFER_V2,
                "other-sid",
                "file_chunk",
                Some(Value::Integer(0i64.into())),
                b"abc".to_vec(),
            ),
        ),
        (
            "wrong protocol",
            build_message(
                ProtoType::SHELL,
                SID,
                "file_chunk",
                Some(Value::Integer(0i64.into())),
                b"abc".to_vec(),
            ),
        ),
        (
            "wrong message type",
            build_message(
                ProtoType::FILE_TRANSFER_V2,
                SID,
                "ack",
                Some(Value::Integer(0i64.into())),
                Vec::new(),
            ),
        ),
        (
            "oversized chunk body",
            build_message(
                ProtoType::FILE_TRANSFER_V2,
                SID,
                "file_chunk",
                Some(Value::Integer(0i64.into())),
                vec![0u8; 4097],
            ),
        ),
        (
            "chunk exceeds declared size",
            build_message(
                ProtoType::FILE_TRANSFER_V2,
                SID,
                "file_chunk",
                Some(Value::Integer(0i64.into())),
                vec![0u8; 4],
            ),
        ),
        (
            "early empty EOF below declared size",
            build_message(
                ProtoType::FILE_TRANSFER_V2,
                SID,
                "file_chunk",
                Some(Value::Integer(0i64.into())),
                Vec::new(),
            ),
        ),
    ];

    for (name, command) in cases {
        let dir = tempfile::tempdir().expect("create tempdir");
        let target = dir.path().join("OLD");
        fs::write(&target, b"old").expect("write OLD");

        let (command_tx, command_rx) = mpsc::channel::<ProtoMsg>(8);
        let (output_tx, _output_rx) = mpsc::channel::<ProtoMsg>(8);

        let mut request = request_for(&target);
        if name == "oversized chunk body" {
            request.size = None;
        }
        let guard = TaskGuard::new(tokio::spawn(upload(
            ProtoType::FILE_TRANSFER_V2,
            SID.to_string(),
            request,
            command_rx,
            output_tx,
        )));

        command_tx
            .send(command)
            .await
            .expect("send invalid command");

        let result = join_guard(guard).await;
        let err = match result {
            Ok(_) => panic!("case `{name}` unexpectedly succeeded"),
            Err(err) => err,
        };
        assert!(
            err.downcast_ref::<CommittedAckError>().is_none(),
            "case `{name}` must not be a CommittedAckError"
        );
        assert_eq!(
            fs::read(&target).expect("read OLD"),
            b"old",
            "case `{name}` must preserve OLD"
        );
        assert_eq!(
            dir_entries(dir.path()),
            vec!["OLD".to_string()],
            "case `{name}` must leave only the target, no staging files"
        );
    }
}

/// Pre-commit peer error and command-channel closure both abort cleanly after
/// the data has been staged, preserving the OLD target and removing the stage.
#[tokio::test]
async fn precommit_error_and_channel_closure_abort_after_staging() {
    for mode in ["error", "close"] {
        let dir = tempfile::tempdir().expect("create tempdir");
        let target = dir.path().join("OLD");
        fs::write(&target, b"old").expect("write OLD");

        let (command_tx, command_rx) = mpsc::channel::<ProtoMsg>(8);
        let (output_tx, _output_rx) = mpsc::channel::<ProtoMsg>(8);

        let guard = TaskGuard::new(tokio::spawn(upload(
            ProtoType::FILE_TRANSFER_V2,
            SID.to_string(),
            request_for(&target),
            command_rx,
            output_tx,
        )));

        command_tx
            .send(chunk(SID, 0, b"abc".to_vec()))
            .await
            .expect("send first chunk");

        assert!(
            wait_for_stage_len(dir.path(), 3).await,
            "mode `{mode}`: staging file with committed bytes not observed"
        );
        assert_eq!(
            fs::read(&target).expect("read OLD"),
            b"old",
            "mode `{mode}`: OLD must be untouched while staging"
        );

        match mode {
            "error" => {
                command_tx
                    .send(build_message(
                        ProtoType::FILE_TRANSFER_V2,
                        SID,
                        "error",
                        None,
                        Vec::new(),
                    ))
                    .await
                    .expect("send peer error");
            }
            _ => drop(command_tx),
        }

        let outcome = join_guard(guard)
            .await
            .expect("worker must abort cleanly pre-commit");
        assert_eq!(outcome, UploadOutcome::Aborted, "mode `{mode}`");
        assert_eq!(
            fs::read(&target).expect("read OLD"),
            b"old",
            "mode `{mode}`: OLD must be preserved"
        );
        assert_eq!(
            dir_entries(dir.path()),
            vec!["OLD".to_string()],
            "mode `{mode}`: no staging files may remain"
        );
    }
}

/// Aborting the worker task after staging drops the temporary file and leaves
/// the previous destination intact.
#[tokio::test]
async fn task_abort_after_staging_cleans_up() {
    let dir = tempfile::tempdir().expect("create tempdir");
    let target = dir.path().join("OLD");
    fs::write(&target, b"old").expect("write OLD");

    let (command_tx, command_rx) = mpsc::channel::<ProtoMsg>(8);
    let (output_tx, _output_rx) = mpsc::channel::<ProtoMsg>(8);

    let mut guard = TaskGuard::new(tokio::spawn(upload(
        ProtoType::FILE_TRANSFER_V2,
        SID.to_string(),
        request_for(&target),
        command_rx,
        output_tx,
    )));

    command_tx
        .send(chunk(SID, 0, b"abc".to_vec()))
        .await
        .expect("send first chunk");

    assert!(
        wait_for_stage_len(dir.path(), 3).await,
        "staging file with committed bytes not observed before abort"
    );

    guard.handle.abort();
    let joined = tokio::time::timeout(JOIN_TIMEOUT, &mut guard.handle)
        .await
        .expect("aborted worker did not settle within timeout");
    let err = joined.expect_err("aborted task must yield a JoinError");
    assert!(err.is_cancelled(), "aborted task must report cancellation");

    drop(command_tx);

    assert_eq!(
        fs::read(&target).expect("read OLD"),
        b"old",
        "abort must preserve OLD"
    );
    assert_eq!(
        dir_entries(dir.path()),
        vec!["OLD".to_string()],
        "abort must remove the staging file"
    );
}

/// The data is committed before the final ACK is attempted. Dropping the output
/// receiver before EOF must therefore surface a [`CommittedAckError`] while the
/// destination already contains the uploaded bytes.
#[tokio::test]
async fn committed_data_survives_failed_final_ack() {
    let dir = tempfile::tempdir().expect("create tempdir");
    let target = dir.path().join("payload.bin");
    fs::write(&target, b"OLD").expect("seed previous destination");

    let (command_tx, command_rx) = mpsc::channel::<ProtoMsg>(8);
    let (output_tx, output_rx) = mpsc::channel::<ProtoMsg>(8);
    // Drop the receiver before EOF so the final ACK send must fail.
    drop(output_rx);

    let guard = TaskGuard::new(tokio::spawn(upload(
        ProtoType::FILE_TRANSFER_V2,
        SID.to_string(),
        request_for(&target),
        command_rx,
        output_tx,
    )));

    command_tx
        .send(chunk(SID, 0, b"abc".to_vec()))
        .await
        .expect("send data chunk");
    command_tx
        .send(chunk(SID, 3, Vec::new()))
        .await
        .expect("send EOF chunk");

    let result = join_guard(guard).await;
    let err = match result {
        Ok(_) => panic!("expected the final ACK to fail"),
        Err(err) => err,
    };
    assert!(
        err.downcast_ref::<CommittedAckError>().is_some(),
        "post-commit ACK failure must classify as CommittedAckError"
    );
    assert_eq!(
        fs::read(&target).expect("read committed file"),
        b"abc",
        "committed data must survive the failed ACK"
    );
    assert_eq!(
        dir_entries(dir.path()),
        vec!["payload.bin".to_string()],
        "successful commit must leave only the destination, no staging files"
    );
}

/// Once the atomic commit has replaced the target, a task cancellation can no
/// longer roll back the bytes and cannot return a typed error: the worker simply
/// reports a cancelled `JoinError` while the committed data stays in place.
#[tokio::test]
async fn cancellation_after_commit_cannot_roll_back() {
    let dir = tempfile::tempdir().expect("create tempdir");
    let target = dir.path().join("OLD");
    fs::write(&target, b"old").expect("write OLD");

    let (command_tx, command_rx) = mpsc::channel::<ProtoMsg>(4);
    let (output_tx, _output_rx) = mpsc::channel::<ProtoMsg>(1);

    // Fill the single output slot before the worker starts, so the final ACK
    // send can never complete while the receiver is kept alive.
    let filler = build_message(ProtoType::FILE_TRANSFER_V2, SID, "ack", None, Vec::new());
    tokio::time::timeout(JOIN_TIMEOUT, output_tx.send(filler))
        .await
        .expect("prefill output channel within timeout")
        .expect("prefill output channel");

    let mut guard = TaskGuard::new(tokio::spawn(upload(
        ProtoType::FILE_TRANSFER_V2,
        SID.to_string(),
        request_for(&target),
        command_rx,
        output_tx,
    )));

    tokio::time::timeout(
        JOIN_TIMEOUT,
        command_tx.send(chunk(SID, 0, b"abc".to_vec())),
    )
    .await
    .expect("send data chunk within timeout")
    .expect("send data chunk");
    tokio::time::timeout(JOIN_TIMEOUT, command_tx.send(chunk(SID, 3, Vec::new())))
        .await
        .expect("send EOF chunk within timeout")
        .expect("send EOF chunk");

    let deadline = std::time::Instant::now() + JOIN_TIMEOUT;
    let mut committed = false;
    while std::time::Instant::now() < deadline {
        if fs::read(&target)
            .map(|bytes| bytes.as_slice() == b"abc")
            .unwrap_or(false)
        {
            committed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(
        committed,
        "atomic commit must replace the target while the final ACK blocks"
    );

    assert!(
        !guard.handle.is_finished(),
        "worker must still be blocked on the full output channel"
    );

    guard.handle.abort();
    let joined = tokio::time::timeout(JOIN_TIMEOUT, &mut guard.handle)
        .await
        .expect("aborted worker did not settle within timeout");
    let err = joined.expect_err("aborted task must yield a JoinError");
    assert!(err.is_cancelled(), "aborted task must report cancellation");

    assert_eq!(
        fs::read(&target).expect("read committed file"),
        b"abc",
        "cancellation after commit must not roll back the committed bytes"
    );
    assert_eq!(
        dir_entries(dir.path()),
        vec!["OLD".to_string()],
        "cancellation after commit must leave only the target, no staging files"
    );

    drop(command_tx);
}
