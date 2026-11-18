use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use mender_connect_rust::file_transfer_download::{DownloadOutcome, download};
use mender_connect_rust::protocol::{ProtoHdr, ProtoMsg, ProtoType};
use tokio::sync::mpsc::channel;
use tokio::time::timeout;

/// RAII guard that aborts the worker task if it is dropped before being joined.
struct AbortGuard {
    handle: Option<tokio::task::JoinHandle<anyhow::Result<DownloadOutcome>>>,
}

impl Drop for AbortGuard {
    fn drop(&mut self) {
        if let Some(handle) = &self.handle {
            handle.abort();
        }
    }
}

/// Build an ack frame carrying a cumulative byte offset for the given session/proto.
fn ack_frame(proto: ProtoType, sid: &str, offset: i64) -> ProtoMsg {
    let mut properties: BTreeMap<String, rmpv::Value> = BTreeMap::new();
    properties.insert("offset".to_string(), rmpv::Value::from(offset));
    ProtoMsg {
        header: ProtoHdr {
            proto,
            msg_type: "ack".to_string(),
            session_id: sid.to_string(),
            properties,
        },
        body: Vec::new(),
    }
}

/// Read an integer `offset` property from a frame header.
fn offset_of(frame: &ProtoMsg) -> i64 {
    match frame.header.properties.get("offset") {
        Some(rmpv::Value::Integer(v)) => v.as_i64().expect("offset i64"),
        other => panic!("missing/invalid offset property: {other:?}"),
    }
}

#[tokio::test]
async fn download_streams_file_in_chunks_until_eof() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path: PathBuf = dir.path().join("payload.bin");

    let data: Vec<u8> = (0..4097u32)
        .map(|i| if i % 2 == 0 { 0x00 } else { 0xff })
        .collect();
    std::fs::write(&path, &data).expect("write payload");

    let sid = "session-42".to_string();

    // Command channel: keep the sender alive for the duration of the test.
    let (_cmd_tx, cmd_rx) = channel::<ProtoMsg>(8);
    let (out_tx, mut out_rx) = channel::<ProtoMsg>(8);

    let path_for_worker = path.clone();
    let sid_for_worker = sid.clone();
    let worker = tokio::spawn(async move {
        download(
            ProtoType::FILE_TRANSFER_V2,
            sid_for_worker,
            path_for_worker,
            cmd_rx,
            out_tx,
        )
        .await
    });

    let mut guard = AbortGuard {
        handle: Some(worker),
    };

    let mut collected: Vec<u8> = Vec::new();
    let mut saw_eof = false;

    while !saw_eof {
        let frame = timeout(Duration::from_secs(2), out_rx.recv())
            .await
            .expect("frame timeout")
            .expect("channel closed before EOF");

        assert_eq!(frame.header.proto, ProtoType::FILE_TRANSFER_V2);
        assert_eq!(frame.header.msg_type, "file_chunk");
        assert_eq!(frame.header.session_id, sid);

        let offset = offset_of(&frame);
        assert_eq!(
            offset,
            i64::try_from(collected.len()).expect("collected length fits i64"),
            "offset must match start byte"
        );

        if frame.body.is_empty() {
            saw_eof = true;
        } else {
            assert!(frame.body.len() <= 4096, "chunk exceeds 4096 bytes");
            collected.extend_from_slice(&frame.body);
            assert!(collected.len() <= data.len(), "worker emitted excess bytes");
        }
    }

    assert_eq!(
        collected, data,
        "reassembled bytes must match file contents"
    );
    assert_eq!(collected.len(), 4097);

    // Join by borrowing the handle so the abort guard stays active on failure.
    let handle = guard.handle.as_mut().expect("worker handle present");
    let outcome = timeout(Duration::from_secs(2), &mut *handle)
        .await
        .expect("join timeout")
        .expect("worker panicked");
    let outcome = outcome.expect("download returned error");

    match outcome {
        DownloadOutcome::Complete => {}
        DownloadOutcome::Aborted => panic!("expected Complete, got Aborted"),
    }
}

#[tokio::test]
async fn download_empty_file_emits_eof_then_complete() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path: PathBuf = dir.path().join("empty.bin");

    // Deliberately empty payload.
    std::fs::write(&path, b"").expect("write empty payload");

    let sid = "empty-session".to_string();

    // Command channel: keep the sender alive for the duration of the test.
    let (_cmd_tx, cmd_rx) = channel::<ProtoMsg>(8);
    let (out_tx, mut out_rx) = channel::<ProtoMsg>(8);

    let path_for_worker = path.clone();
    let sid_for_worker = sid.clone();
    let worker = tokio::spawn(async move {
        download(
            ProtoType::FILE_TRANSFER_V2,
            sid_for_worker,
            path_for_worker,
            cmd_rx,
            out_tx,
        )
        .await
    });

    let mut guard = AbortGuard {
        handle: Some(worker),
    };

    // First frame must be an immediate EOF chunk at offset 0 with an empty body.
    let eof = timeout(Duration::from_secs(2), out_rx.recv())
        .await
        .expect("eof frame timeout")
        .expect("channel closed before EOF");

    assert_eq!(eof.header.proto, ProtoType::FILE_TRANSFER_V2);
    assert_eq!(eof.header.msg_type, "file_chunk");
    assert_eq!(eof.header.session_id, sid);
    assert_eq!(offset_of(&eof), 0, "EOF offset must be 0 for empty file");
    assert!(eof.body.is_empty(), "EOF frame body must be empty");

    // No further data frames should follow the empty EOF.
    assert!(
        !matches!(
            timeout(Duration::from_millis(100), out_rx.recv()).await,
            Ok(Some(_))
        ),
        "no frames expected after EOF"
    );

    // Join by borrowing the handle so the abort guard stays active on failure.
    let handle = guard.handle.as_mut().expect("worker handle present");
    let outcome = timeout(Duration::from_secs(2), &mut *handle)
        .await
        .expect("join timeout")
        .expect("worker panicked");
    let outcome = outcome.expect("download returned error");

    match outcome {
        DownloadOutcome::Complete => {}
        DownloadOutcome::Aborted => panic!("expected Complete, got Aborted"),
    }
}

#[tokio::test]
async fn download_v1_respects_flow_control_window() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path: PathBuf = dir.path().join("stream.bin");

    let data: Vec<u8> = (0..100_000usize)
        .map(|i| u8::try_from(i % 256).expect("byte fits u8"))
        .collect();
    std::fs::write(&path, &data).expect("write payload");

    let sid = "v1";
    const WINDOW_CHUNKS: u32 = 20;
    const CHUNK: usize = 4096;
    const WINDOW_BYTES: usize = 20 * CHUNK; // 81920

    // Command channel: keep the sender alive AND used for acknowledgements.
    let (cmd_tx, cmd_rx) = channel::<ProtoMsg>(8);
    let (out_tx, mut out_rx) = channel::<ProtoMsg>(32);

    let path_for_worker = path.clone();
    let worker = tokio::spawn(async move {
        download(
            ProtoType::FILE_TRANSFER,
            sid.to_string(),
            path_for_worker,
            cmd_rx,
            out_tx,
        )
        .await
    });

    let mut guard = AbortGuard {
        handle: Some(worker),
    };

    let mut collected: Vec<u8> = Vec::new();

    // Stage 1: exactly WINDOW_CHUNKS non-empty 4096-byte chunks.
    for i in 0..WINDOW_CHUNKS {
        let frame = timeout(Duration::from_secs(2), out_rx.recv())
            .await
            .expect("window chunk timeout")
            .expect("channel closed before window chunk");

        assert_eq!(frame.header.proto, ProtoType::FILE_TRANSFER);
        assert_eq!(frame.header.msg_type, "file_chunk");
        assert_eq!(frame.header.session_id, sid);
        assert_eq!(frame.body.len(), CHUNK, "window chunk must be 4096 bytes");

        let expected_offset = i64::from(i) * 4096;
        assert_eq!(
            offset_of(&frame),
            expected_offset,
            "unexpected chunk offset"
        );

        let start = usize::try_from(expected_offset).expect("offset fits usize");
        let end = start + CHUNK;
        assert_eq!(
            frame.body.as_slice(),
            &data[start..end],
            "chunk bytes must match file contents"
        );
        collected.extend_from_slice(&frame.body);
    }

    assert_eq!(
        collected.len(),
        WINDOW_BYTES,
        "first window fills 81920 bytes"
    );

    // The window is exhausted: no further frame should arrive.
    assert!(
        timeout(Duration::from_millis(100), out_rx.recv())
            .await
            .is_err(),
        "no further frame expected while window is exhausted"
    );

    // Ack a cumulative offset of 4096 -- this must open exactly one more chunk.
    cmd_tx
        .send(ack_frame(ProtoType::FILE_TRANSFER, sid, 4096))
        .await
        .expect("send first ack");

    let frame = timeout(Duration::from_secs(2), out_rx.recv())
        .await
        .expect("post-ack chunk timeout")
        .expect("channel closed before post-ack chunk");

    assert_eq!(frame.header.proto, ProtoType::FILE_TRANSFER);
    assert_eq!(frame.header.msg_type, "file_chunk");
    assert_eq!(frame.header.session_id, sid);
    assert_eq!(frame.body.len(), CHUNK, "post-ack chunk must be 4096 bytes");
    assert_eq!(
        offset_of(&frame),
        i64::try_from(WINDOW_BYTES).expect("window length fits i64"),
        "post-ack chunk must continue at 81920"
    );
    assert_eq!(
        frame.body.as_slice(),
        &data[WINDOW_BYTES..WINDOW_BYTES + CHUNK],
        "post-ack chunk bytes must match file contents"
    );
    collected.extend_from_slice(&frame.body);
    assert_eq!(collected.len(), WINDOW_BYTES + CHUNK);

    // Only exactly 4096 further bytes were opened.
    assert!(
        timeout(Duration::from_millis(100), out_rx.recv())
            .await
            .is_err(),
        "only one extra chunk should be opened per ack"
    );

    // Stage 2: ack cumulative received bytes and keep receiving/acking until EOF.
    cmd_tx
        .send(ack_frame(
            ProtoType::FILE_TRANSFER,
            sid,
            i64::try_from(collected.len()).expect("collected length fits i64"),
        ))
        .await
        .expect("send cumulative ack");

    let mut saw_eof = false;
    while !saw_eof {
        let frame = timeout(Duration::from_secs(2), out_rx.recv())
            .await
            .expect("tail chunk timeout")
            .expect("channel closed before EOF");

        assert_eq!(frame.header.proto, ProtoType::FILE_TRANSFER);
        assert_eq!(frame.header.msg_type, "file_chunk");
        assert_eq!(frame.header.session_id, sid);
        assert_eq!(
            offset_of(&frame),
            i64::try_from(collected.len()).expect("collected length fits i64"),
            "offset must match start byte"
        );

        if frame.body.is_empty() {
            saw_eof = true;
        } else {
            assert!(frame.body.len() <= CHUNK, "chunk exceeds 4096 bytes");
            collected.extend_from_slice(&frame.body);
            assert!(collected.len() <= data.len(), "worker emitted excess bytes");
            cmd_tx
                .send(ack_frame(
                    ProtoType::FILE_TRANSFER,
                    sid,
                    i64::try_from(collected.len()).expect("collected length fits i64"),
                ))
                .await
                .expect("send tail ack");
        }
    }

    assert_eq!(
        collected, data,
        "reassembled bytes must match file contents"
    );
    assert_eq!(collected.len(), 100_000);

    // Ack the final total if the worker is still waiting on confirmation.
    let _ = cmd_tx
        .send(ack_frame(
            ProtoType::FILE_TRANSFER,
            sid,
            i64::try_from(collected.len()).expect("collected length fits i64"),
        ))
        .await;

    // Join by borrowing the handle so the abort guard stays active on failure.
    let handle = guard.handle.as_mut().expect("worker handle present");
    let outcome = timeout(Duration::from_secs(2), &mut *handle)
        .await
        .expect("join timeout")
        .expect("worker panicked");
    let outcome = outcome.expect("download returned error");

    match outcome {
        DownloadOutcome::Complete => {}
        DownloadOutcome::Aborted => panic!("expected Complete, got Aborted"),
    }
}
