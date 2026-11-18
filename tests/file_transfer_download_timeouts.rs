use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout};

use mender_connect_rust::file_transfer_download;
use mender_connect_rust::protocol::{ProtoHdr, ProtoMsg, ProtoType};

struct AbortGuard<T> {
    handle: Option<JoinHandle<T>>,
}

impl<T> AbortGuard<T> {
    fn new(handle: JoinHandle<T>) -> Self {
        Self {
            handle: Some(handle),
        }
    }

    fn handle_mut(&mut self) -> &mut JoinHandle<T> {
        self.handle.as_mut().expect("worker handle is present")
    }
}

impl<T> Drop for AbortGuard<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

fn control_msg(msg_type: &str, offset: u64) -> ProtoMsg {
    let properties = [(
        "offset".to_string(),
        rmpv::Value::from(i64::try_from(offset).expect("test offset fits i64")),
    )]
    .into_iter()
    .collect();

    ProtoMsg {
        header: ProtoHdr {
            proto: ProtoType::FILE_TRANSFER,
            msg_type: msg_type.to_owned(),
            session_id: "s".to_string(),
            properties,
        },
        body: Vec::new(),
    }
}

/// Scan `/proc/self/fd` and report whether any still-open descriptor points at
/// `target` (the canonicalized path of the still-existing TempDir file).
fn descriptor_open_for(target: &std::path::Path) -> bool {
    let entries = std::fs::read_dir("/proc/self/fd")
        .expect("own procfs descriptor directory must be readable");

    for entry in entries.flatten() {
        if let Ok(link_target) = std::fs::read_link(entry.path()) {
            let resolved = std::fs::canonicalize(&link_target).unwrap_or(link_target);
            if resolved == target {
                return true;
            }
        }
    }

    false
}

#[tokio::test]
async fn duplicate_acks_do_not_reset_progress_timeout() {
    let dir = tempfile::tempdir().expect("temp dir");
    let file_path = dir.path().join("payload.bin");
    std::fs::write(&file_path, vec![0x5au8; 4096]).expect("write payload");

    let (command_tx, command_rx) = mpsc::channel::<ProtoMsg>(4);
    let (output_tx, mut output_rx) = mpsc::channel::<ProtoMsg>(8);

    let worker = tokio::spawn(file_transfer_download::download(
        ProtoType::FILE_TRANSFER,
        "s".to_string(),
        file_path,
        command_rx,
        output_tx,
    ));
    let mut guard = AbortGuard::new(worker);

    let data = timeout(Duration::from_secs(2), output_rx.recv())
        .await
        .expect("data frame should arrive in real time")
        .expect("data frame");
    assert_eq!(data.body.len(), 4096);

    let eof = timeout(Duration::from_secs(2), output_rx.recv())
        .await
        .expect("EOF frame should arrive in real time")
        .expect("EOF frame");
    assert!(eof.body.is_empty());

    // Let the worker install its ACK/progress timer before freezing Tokio time.
    tokio::task::yield_now().await;
    tokio::time::pause();

    let started = Instant::now();
    let duplicate_ack = control_msg("ack", 0);

    for _ in 0..5 {
        command_tx
            .send(duplicate_ack.clone())
            .await
            .expect("send duplicate ack");
        tokio::time::advance(Duration::from_secs(5)).await;
    }

    assert!(
        !guard.handle_mut().is_finished(),
        "task must remain pending at 25s"
    );

    tokio::time::advance(Duration::from_secs(4)).await;
    assert!(
        !guard.handle_mut().is_finished(),
        "task must remain pending at 29s"
    );

    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(
        Instant::now() >= started + Duration::from_secs(31),
        "virtual time should reach 31s"
    );

    let joined = timeout(Duration::from_secs(1), guard.handle_mut())
        .await
        .expect("worker must stop at the original 30s progress deadline");
    assert!(
        joined.expect("worker task did not panic").is_err(),
        "duplicate offset-zero ACKs must not reset the progress deadline"
    );

    // Keep the bounded command sender alive through the joins.
    drop(command_tx);
}

#[tokio::test]
async fn sparse_exact_limit_file_is_accepted_and_fd_released_on_abort() {
    // Exact 256 MiB: the boundary value must be accepted, not rejected.
    const SIZE: u64 = 256 * 1024 * 1024;

    let dir = tempfile::tempdir().expect("temp dir");
    let file_path = dir.path().join("sparse.bin");

    // Allocate a sparse file without materializing 256 MiB on disk.
    {
        let file = std::fs::File::create(&file_path).expect("create sparse file");
        file.set_len(SIZE).expect("set sparse length");
    }

    let (command_tx, command_rx) = mpsc::channel::<ProtoMsg>(4);
    let (output_tx, mut output_rx) = mpsc::channel::<ProtoMsg>(1);

    let worker = tokio::spawn(file_transfer_download::download(
        ProtoType::FILE_TRANSFER_V2,
        "s".to_string(),
        file_path.clone(),
        command_rx,
        output_tx,
    ));
    let mut guard = AbortGuard::new(worker);

    // The first nonempty frame must be a full 4096-byte chunk arriving promptly,
    // which proves the exact 256 MiB limit was accepted rather than rejected.
    let deadline = Instant::now() + Duration::from_secs(2);
    let frame = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let msg = timeout(remaining, output_rx.recv())
            .await
            .expect("first nonempty frame should arrive within 2s")
            .expect("channel closed before a data frame (size limit rejected?)");
        if !msg.body.is_empty() {
            break msg;
        }
    };
    assert_eq!(
        frame.body.len(),
        4096,
        "first data frame should be a full 4096-byte chunk"
    );

    // Stop draining so the capacity-1 output channel fills and the worker blocks.
    tokio::time::sleep(Duration::from_millis(20)).await;
    let canonical = std::fs::canonicalize(&file_path).expect("canonical file path");
    assert!(
        !guard.handle_mut().is_finished(),
        "large transfer remains active"
    );
    assert!(
        descriptor_open_for(&canonical),
        "descriptor scan observes the live owned file"
    );

    guard.handle_mut().abort();
    let joined = timeout(Duration::from_secs(2), guard.handle_mut())
        .await
        .expect("aborted worker should join within 2s");
    match joined {
        Ok(result) => assert!(
            result.is_err(),
            "aborted worker must not complete successfully"
        ),
        Err(join_err) => assert!(
            join_err.is_cancelled(),
            "worker should report cancellation, not a panic"
        ),
    }

    // The owned file descriptor must be released even though the TempDir (and
    // therefore the underlying file) still exists.
    let fd_deadline = Instant::now() + Duration::from_secs(2);
    while descriptor_open_for(&canonical) {
        assert!(
            Instant::now() < fd_deadline,
            "file descriptor to the TempDir file must be released within 2s"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Keep the bounded command sender and TempDir alive through all assertions.
    drop(command_tx);
    drop(dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn data_frames_arrive_despite_duplicate_ack_flood() {
    let dir = tempfile::tempdir().expect("temp dir");
    let file_path = dir.path().join("payload.bin");
    std::fs::write(&file_path, vec![0x33u8; 1024 * 1024]).expect("write 1MiB payload");

    let (command_tx, command_rx) = mpsc::channel::<ProtoMsg>(8);
    let (output_tx, mut output_rx) = mpsc::channel::<ProtoMsg>(8);

    let worker = tokio::spawn(file_transfer_download::download(
        ProtoType::FILE_TRANSFER,
        "s".to_string(),
        file_path,
        command_rx,
        output_tx,
    ));
    let mut worker_guard = AbortGuard::new(worker);

    // A separate abort-guarded async feeder continuously floods duplicate
    // offset-zero ACKs into the command queue.
    let feeder_tx = command_tx.clone();
    let feeder = tokio::spawn(async move {
        let ack = control_msg("ack", 0);
        loop {
            if feeder_tx.send(ack.clone()).await.is_err() {
                break;
            }
            tokio::task::yield_now().await;
        }
    });
    let mut feeder_guard = AbortGuard::new(feeder);

    // The first real data frame must still arrive promptly despite the flood,
    // proving the bounded drain yields enough for the file output path.
    let deadline = Instant::now() + Duration::from_secs(2);
    let data = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let msg = timeout(remaining, output_rx.recv())
            .await
            .expect("data frame should arrive within 2s despite ack flood")
            .expect("channel closed before a data frame");
        if !msg.body.is_empty() {
            break msg;
        }
    };
    assert!(!data.body.is_empty(), "first data frame must be non-empty");

    // Cancel the worker and confirm cancellation within a bounded join.
    worker_guard.handle_mut().abort();
    let joined = timeout(Duration::from_secs(2), worker_guard.handle_mut())
        .await
        .expect("aborted worker should join within 2s");
    match joined {
        Ok(result) => assert!(
            result.is_err(),
            "aborted worker must not complete successfully"
        ),
        Err(join_err) => assert!(
            join_err.is_cancelled(),
            "worker should report cancellation, not a panic"
        ),
    }

    // Stop the feeder through its guard with a bounded join; it may exit
    // gracefully once the command channel closes, or be cancelled.
    feeder_guard.handle_mut().abort();
    let feeder_result = timeout(Duration::from_secs(2), feeder_guard.handle_mut())
        .await
        .expect("aborted feeder should join within 2s");
    let _ = feeder_result;

    drop(command_tx);
    drop(dir);
}

// Append to tests/file_transfer_download_timeouts.rs for the candidate run.
#[tokio::test]
async fn slowly_advancing_ack_does_not_extend_download_lifetime() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("payload");
    std::fs::write(&path, vec![1u8; 4096]).expect("write payload");
    let (commands, rx) = mpsc::channel(4);
    let (output, mut frames) = mpsc::channel(8);
    let mut worker = AbortGuard::new(tokio::spawn(file_transfer_download::download(
        ProtoType::FILE_TRANSFER,
        "s".into(),
        path,
        rx,
        output,
    )));
    let data = timeout(Duration::from_secs(2), frames.recv())
        .await
        .expect("frame timeout")
        .expect("frame");
    assert_eq!(data.body.len(), 4096);
    let eof = timeout(Duration::from_secs(2), frames.recv())
        .await
        .expect("EOF timeout")
        .expect("EOF");
    assert!(eof.body.is_empty());
    tokio::task::yield_now().await;
    tokio::time::pause();
    for offset in 1..=20 {
        tokio::time::advance(Duration::from_secs(29)).await;
        commands
            .send(control_msg("ack", offset))
            .await
            .expect("send progress");
        tokio::task::yield_now().await;
        assert!(
            !worker.handle_mut().is_finished(),
            "progress before total deadline"
        );
    }
    tokio::time::advance(Duration::from_secs(21)).await;
    let real_end = std::time::Instant::now() + Duration::from_secs(2);
    while !worker.handle_mut().is_finished() {
        assert!(std::time::Instant::now() < real_end, "worker deadline");
        tokio::task::yield_now().await;
    }
    let result = worker.handle_mut().await.expect("worker join");
    assert!(
        result
            .expect_err("deadline error")
            .to_string()
            .contains("download exceeded total deadline")
    );
}

#[tokio::test]
async fn v2_draining_output_does_not_extend_download_lifetime() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("payload");
    let file = std::fs::File::create(&path).expect("create file");
    file.set_len(4 * 1024 * 1024).expect("size file");
    drop(file);
    let (_commands, rx) = mpsc::channel(4);
    let (output, mut frames) = mpsc::channel(1);
    let mut worker = AbortGuard::new(tokio::spawn(file_transfer_download::download(
        ProtoType::FILE_TRANSFER_V2,
        "s".into(),
        path,
        rx,
        output,
    )));
    timeout(Duration::from_secs(2), frames.recv())
        .await
        .expect("frame timeout")
        .expect("frame");
    tokio::task::yield_now().await;
    tokio::time::pause();
    for _ in 0..199 {
        tokio::time::advance(Duration::from_secs(3)).await;
        let real_deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            match frames.try_recv() {
                Ok(_) => break,
                Err(mpsc::error::TryRecvError::Empty) => {
                    assert!(
                        std::time::Instant::now() < real_deadline,
                        "frame before deadline"
                    );
                    tokio::task::yield_now().await;
                }
                Err(mpsc::error::TryRecvError::Disconnected) => panic!("output closed early"),
            }
        }
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_secs(4)).await;
    let real_end = std::time::Instant::now() + Duration::from_secs(2);
    while !worker.handle_mut().is_finished() {
        assert!(std::time::Instant::now() < real_end, "worker deadline");
        tokio::task::yield_now().await;
    }
    let result = worker.handle_mut().await.expect("worker join");
    assert!(
        result
            .expect_err("deadline error")
            .to_string()
            .contains("download exceeded total deadline")
    );
}
