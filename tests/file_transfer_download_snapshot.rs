use std::collections::BTreeMap;
use std::io::Write;
use std::time::Duration;

use mender_connect_rust::file_transfer_download::{DownloadOutcome, download};
use mender_connect_rust::protocol::{ProtoHdr, ProtoMsg, ProtoType};
use tokio::sync::mpsc;
use tokio::time::timeout;

const DEADLINE: Duration = Duration::from_secs(2);
const WINDOW: usize = 81920;

struct Worker(tokio::task::JoinHandle<anyhow::Result<DownloadOutcome>>);

impl Drop for Worker {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn ack(offset: usize) -> ProtoMsg {
    ProtoMsg {
        header: ProtoHdr {
            proto: ProtoType::FILE_TRANSFER,
            msg_type: "ack".into(),
            session_id: "snapshot".into(),
            properties: BTreeMap::from([(
                "offset".into(),
                rmpv::Value::from(i64::try_from(offset).expect("small fixture offset")),
            )]),
        },
        body: Vec::new(),
    }
}

async fn frame(output: &mut mpsc::Receiver<ProtoMsg>, offset: usize) -> ProtoMsg {
    let frame = timeout(DEADLINE, output.recv())
        .await
        .expect("bounded frame receive")
        .expect("frame before channel close");
    assert_eq!(frame.header.proto, ProtoType::FILE_TRANSFER);
    assert_eq!(frame.header.msg_type, "file_chunk");
    assert_eq!(frame.header.session_id, "snapshot");
    assert_eq!(
        frame
            .header
            .properties
            .get("offset")
            .and_then(rmpv::Value::as_i64),
        Some(i64::try_from(offset).expect("small fixture offset"))
    );
    assert!(frame.body.len() <= 4096);
    frame
}

async fn snapshot_case(truncate: bool) {
    let directory = tempfile::tempdir().expect("owned temporary directory");
    let path = directory.path().join("mutable.bin");
    let initial = [0u8, 255, 3, 7].repeat(65536);
    std::fs::write(&path, &initial).expect("initial fixture");
    let (commands, command_rx) = mpsc::channel(8);
    let (output_tx, mut output) = mpsc::channel(32);
    let mut worker = Worker(tokio::spawn(download(
        ProtoType::FILE_TRANSFER,
        "snapshot".into(),
        path.clone(),
        command_rx,
        output_tx,
    )));
    let mut received = Vec::new();
    // No ACK is sent until the entire v1 window is consumed. The worker cannot
    // start its next read before our mutation and release of this barrier.
    for _ in 0..20 {
        let chunk = frame(&mut output, received.len()).await;
        assert_eq!(chunk.body.len(), 4096);
        received.extend_from_slice(&chunk.body);
    }
    assert_eq!(received.len(), WINDOW);
    assert!(matches!(
        output.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    if truncate {
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("owned source open")
            .set_len(0)
            .expect("truncate while ACK blocked");
    } else {
        let mut source = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("owned source open");
        source
            .write_all(&[9u8; 32768])
            .expect("append distinct tail");
    }
    timeout(DEADLINE, commands.send(ack(WINDOW)))
        .await
        .expect("bounded ACK send")
        .expect("live command receiver");
    if truncate {
        let error = timeout(DEADLINE, &mut worker.0)
            .await
            .expect("bounded worker completion")
            .expect("worker task did not panic")
            .expect_err("truncated snapshot must fail");
        let error = error.to_string();
        assert!(error.contains("early EOF"), "{error}");
        assert!(
            error.contains("81920") && error.contains("262144"),
            "{error}"
        );
        assert!(
            timeout(DEADLINE, output.recv())
                .await
                .expect("closed output")
                .is_none(),
            "truncation must not emit successful EOF or additional chunks"
        );
    } else {
        loop {
            let chunk = frame(&mut output, received.len()).await;
            if chunk.body.is_empty() {
                break;
            }
            received.extend_from_slice(&chunk.body);
            assert!(received.len() <= initial.len(), "appended tail leaked");
            timeout(DEADLINE, commands.send(ack(received.len())))
                .await
                .expect("bounded ACK send")
                .expect("worker awaits cumulative progress");
        }
        assert_eq!(received, initial);
        assert_eq!(
            timeout(DEADLINE, &mut worker.0)
                .await
                .expect("worker completion")
                .expect("worker task did not panic")
                .expect("successful snapshot"),
            DownloadOutcome::Complete
        );
        assert!(
            timeout(DEADLINE, output.recv())
                .await
                .expect("closed output")
                .is_none()
        );
    }
}

#[tokio::test]
async fn truncation_during_v1_ack_backpressure_is_error_without_success_eof() {
    snapshot_case(true).await;
}

#[tokio::test]
async fn growth_during_v1_ack_backpressure_delivers_only_initial_snapshot() {
    snapshot_case(false).await;
}
