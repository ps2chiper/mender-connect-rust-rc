use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use mender_connect_rust::file_transfer_schema::UploadRequest;
use mender_connect_rust::file_transfer_upload::{UploadOutcome, upload};
use mender_connect_rust::protocol::{ProtoHdr, ProtoMsg, ProtoType};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::task::{JoinError, JoinHandle};

const WAIT: Duration = Duration::from_secs(2);
const CHANNEL_DEPTH: usize = 4;

/// Owns the worker task handle and guarantees it is aborted if the test fails
/// before the worker has actually completed.
struct AbortGuard<T> {
    handle: Option<JoinHandle<T>>,
}

impl<T> AbortGuard<T> {
    fn new(handle: JoinHandle<T>) -> Self {
        Self {
            handle: Some(handle),
        }
    }

    /// Await the borrowed handle with a timeout. The handle is only taken out of
    /// the guard once the worker has finished, so on a timeout (failed
    /// assertion) the guard still owns it and can abort on drop.
    async fn finish(&mut self, dur: Duration) -> Option<Result<T, JoinError>> {
        let joined = {
            let handle = self.handle.as_mut()?;
            tokio::time::timeout(dur, handle).await
        };
        match joined {
            Ok(res) => {
                // Completed: safe to take; drop will no longer need to abort.
                self.handle.take();
                Some(res)
            }
            Err(_elapsed) => None,
        }
    }
}

impl<T> Drop for AbortGuard<T> {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

fn build(
    proto: &ProtoType,
    sid: &str,
    msg_type: &str,
    offset: Option<i64>,
    body: Vec<u8>,
) -> ProtoMsg {
    let mut props: BTreeMap<String, rmpv::Value> = BTreeMap::new();
    if let Some(o) = offset {
        props.insert("offset".to_string(), rmpv::Value::from(o));
    }
    ProtoMsg {
        header: ProtoHdr {
            proto: *proto,
            msg_type: msg_type.to_string(),
            session_id: sid.to_string(),
            properties: props,
        },
        body,
    }
}

fn offset_of(msg: &ProtoMsg) -> Option<i64> {
    msg.header.properties.get("offset").and_then(|v| v.as_i64())
}

// 4099 byte alternating binary payload.
fn make_payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| if i % 2 == 0 { 0x00 } else { 0xff })
        .collect()
}

// Split the payload into chunks of at most 4096 bytes, returning (start, data).
fn chunks_of(payload: &[u8]) -> Vec<(i64, Vec<u8>)> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < payload.len() {
        let end = (off + 4096).min(payload.len());
        out.push((off as i64, payload[off..end].to_vec()));
        off = end;
    }
    out
}

async fn recv(rx: &mut Receiver<ProtoMsg>) -> ProtoMsg {
    match tokio::time::timeout(WAIT, rx.recv()).await {
        Ok(Some(m)) => m,
        Ok(None) => panic!("output channel closed before a message arrived"),
        Err(_) => panic!("timed out waiting for a worker output"),
    }
}

#[tokio::test]
async fn upload_transfers_and_commits() {
    let cases: [(&str, ProtoType, Vec<u8>); 4] = [
        ("v1-empty", ProtoType::FILE_TRANSFER, Vec::new()),
        ("v1-nonempty", ProtoType::FILE_TRANSFER, make_payload(4099)),
        ("v2-empty", ProtoType::FILE_TRANSFER_V2, Vec::new()),
        (
            "v2-nonempty",
            ProtoType::FILE_TRANSFER_V2,
            make_payload(4099),
        ),
    ];

    for (name, proto, payload) in cases {
        let v1 = matches!(proto, ProtoType::FILE_TRANSFER);

        let dir = tempfile::TempDir::new().expect("tempdir");
        let target = dir.path().join("target.bin");
        fs::write(&target, b"OLD").expect("seed target");

        let req = UploadRequest {
            path: Some(target.to_string_lossy().to_string()),
            src_path: None,
            size: Some(payload.len() as i64),
            uid: None,
            gid: None,
            mode: Some(0o640),
            modtime: None,
        };

        let (cmd_tx, cmd_rx): (Sender<ProtoMsg>, Receiver<ProtoMsg>) = mpsc::channel(CHANNEL_DEPTH);
        let (out_tx, mut out_rx): (Sender<ProtoMsg>, Receiver<ProtoMsg>) =
            mpsc::channel(CHANNEL_DEPTH);

        let sid = format!("session-{name}");
        let worker_proto = proto;
        let worker_sid = sid.clone();
        let handle =
            tokio::spawn(
                async move { upload(worker_proto, worker_sid, req, cmd_rx, out_tx).await },
            );
        let mut guard = AbortGuard::new(handle);

        // No initial header is emitted. For v1 the worker emits an initial ACK 0
        // which the test receives (the test never sends an ack back).
        if v1 {
            let initial_ack = recv(&mut out_rx).await;
            assert_eq!(
                offset_of(&initial_ack),
                Some(0),
                "{name}: initial ack offset"
            );
        }

        for (chunk_off, data) in chunks_of(&payload) {
            cmd_tx
                .send(build(&proto, &sid, "file_chunk", Some(chunk_off), data))
                .await
                .expect("send chunk");

            if v1 {
                // v1 acks every chunk with the chunk START offset.
                let ack = recv(&mut out_rx).await;
                assert_eq!(offset_of(&ack), Some(chunk_off), "{name}: chunk ack offset");
            }
        }

        // V2 emits nothing until EOF: nothing may be available before the EOF frame.
        if !v1 {
            let mut saw_output = false;
            if let Ok(_msg) = out_rx.try_recv() {
                saw_output = true;
            }
            assert!(!saw_output, "{name}: v2 must not emit before EOF");
        }

        // Before EOF the destination must still hold the original contents.
        assert_eq!(
            fs::read(&target).expect("read pre-commit"),
            b"OLD",
            "{name}: target untouched before EOF"
        );

        // EOF is a file_chunk with an empty body at offset == total length.
        let total = payload.len() as i64;
        cmd_tx
            .send(build(&proto, &sid, "file_chunk", Some(total), Vec::new()))
            .await
            .expect("send eof");

        let final_ack = recv(&mut out_rx).await;
        if v1 {
            assert_eq!(
                offset_of(&final_ack),
                Some(total),
                "{name}: final ack offset"
            );
        } else {
            assert_eq!(
                offset_of(&final_ack),
                None,
                "{name}: v2 final ack has no offset"
            );
        }

        // Drop the command sender so the worker observes channel closure if needed.
        drop(cmd_tx);

        let join_res = guard
            .finish(WAIT)
            .await
            .expect("worker finished within timeout");
        let outcome = match join_res {
            Ok(r) => r.expect("upload returned error"),
            Err(_) => panic!("{name}: worker panicked"),
        };
        assert!(
            matches!(outcome, UploadOutcome::Complete),
            "{name}: expected Complete"
        );

        assert_eq!(
            fs::read(&target).expect("read final"),
            payload,
            "{name}: final content"
        );
        let meta = fs::metadata(&target).expect("metadata");
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o640,
            "{name}: mode preserved"
        );

        // Only the destination should remain in the tempdir (no leftover stage files).
        let mut names: Vec<String> = fs::read_dir(dir.path())
            .expect("read_dir")
            .map(|e| {
                e.expect("dir entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec!["target.bin".to_string()],
            "{name}: only destination should remain"
        );
    }
}
