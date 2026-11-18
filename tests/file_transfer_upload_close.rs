//! Regression tests for the live empty-upload close race: a valid EOF queued
//! immediately before a control close must still commit, while pre-EOF and
//! malformed EOF closes must not.
//!
//! These tests use the plain `FileTransferManager::close_session` API, whose
//! inline completion wait is documented as limited-use for standalone drivers.
//! The daemon instead uses `FileTransferManager::close_session_servicing`, which
//! keeps draining unrelated events during the bounded completion window; that
//! event-servicing behavior, its drain-before-fresh-event ordering, and its
//! bounded-callback forwarding are covered by the private manager unit tests in
//! `src/file_transfer_manager.rs`; the daemon-level output coordination (a sole
//! transport owner draining a bounded forwarding channel plus a real v2
//! port-forward stream over 64 frames / 300 KiB during a held completing-close
//! future) is covered by the native regression in `src/daemon.rs`.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use mender_connect_rust::file_transfer_manager::FileTransferManager;
use mender_connect_rust::file_transfer_schema as schema;
use mender_connect_rust::protocol::{self, ProtoHdr, ProtoMsg, ProtoType};
use rmpv::Value;

const V1: ProtoType = ProtoType::FILE_TRANSFER;
const V2: ProtoType = ProtoType::FILE_TRANSFER_V2;

fn header(proto: ProtoType, msg_type: &str, sid: &str, props: BTreeMap<String, Value>) -> ProtoHdr {
    ProtoHdr {
        proto,
        msg_type: msg_type.to_string(),
        session_id: sid.to_string(),
        properties: props,
    }
}

fn offset_props(off: i64) -> BTreeMap<String, Value> {
    let mut map = BTreeMap::new();
    map.insert("offset".to_string(), Value::from(off));
    map
}

fn put_req(proto: ProtoType, sid: &str, path: &str, size: i64) -> Result<ProtoMsg> {
    let upload = schema::UploadRequest {
        path: Some(path.to_string()),
        src_path: None,
        size: Some(size),
        uid: None,
        gid: None,
        mode: Some(0o640),
        modtime: None,
    };
    Ok(ProtoMsg {
        header: header(proto, "put_file", sid, BTreeMap::new()),
        body: protocol::encode(&upload)?,
    })
}

fn chunk(proto: ProtoType, sid: &str, data: &[u8], off: i64) -> ProtoMsg {
    ProtoMsg {
        header: header(proto, "file_chunk", sid, offset_props(off)),
        body: data.to_vec(),
    }
}

fn offset(msg: &ProtoMsg) -> Option<i64> {
    match msg.header.properties.get("offset") {
        Some(Value::Integer(i)) => i.as_i64(),
        _ => None,
    }
}

fn payload(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| if i % 2 == 0 { 0u8 } else { 255u8 })
        .collect()
}

fn only_target(dir: &Path) -> Result<Vec<String>> {
    let mut names: Vec<String> = std::fs::read_dir(dir)?
        .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<std::result::Result<_, _>>()?;
    names.sort();
    Ok(names)
}

async fn next(mgr: &mut FileTransferManager) -> Result<ProtoMsg> {
    tokio::time::timeout(Duration::from_secs(2), mgr.next_message()).await?
}

async fn eof_then_immediate_close_commits(proto: ProtoType, data: &[u8], sid: &str) -> Result<()> {
    let dir = tempfile::tempdir()?;
    let target = dir.path().join("target.bin");
    std::fs::write(&target, b"OLD")?;
    let target_s = target.to_string_lossy().into_owned();
    let v1 = matches!(proto, ProtoType::FILE_TRANSFER);
    let mut mgr = FileTransferManager::new();

    assert!(
        tokio::time::timeout(
            Duration::from_secs(2),
            mgr.handle(put_req(proto, sid, &target_s, i64::try_from(data.len())?)?)
        )
        .await??
        .is_empty()
    );
    if v1 {
        let a = next(&mut mgr).await?;
        assert_eq!(a.header.msg_type, "ack");
        assert_eq!(offset(&a), Some(0));
    }

    let mut off = 0i64;
    for part in data.chunks(4096) {
        assert!(
            tokio::time::timeout(
                Duration::from_secs(2),
                mgr.handle(chunk(proto, sid, part, off))
            )
            .await??
            .is_empty()
        );
        off += i64::try_from(part.len())?;
    }

    // Queue a valid EOF then close the session immediately, without reading the
    // final ACK. The accepted upload must still flush, sync and persist.
    assert!(
        tokio::time::timeout(
            Duration::from_secs(2),
            mgr.handle(chunk(proto, sid, &[], off))
        )
        .await??
        .is_empty()
    );
    tokio::time::timeout(Duration::from_secs(2), mgr.close_session(sid)).await??;

    assert_eq!(
        std::fs::read(&target)?,
        data,
        "payload must be byte-exact after close"
    );
    assert_eq!(only_target(dir.path())?, vec!["target.bin".to_string()]);
    Ok(())
}

#[tokio::test]
async fn valid_eof_before_close_commits_empty_and_nonempty() -> Result<()> {
    for round in 0..8 {
        eof_then_immediate_close_commits(V1, &[], &format!("v1-empty-{round}")).await?;
        eof_then_immediate_close_commits(V1, &payload(4099), &format!("v1-data-{round}")).await?;
        eof_then_immediate_close_commits(V2, &[], &format!("v2-empty-{round}")).await?;
        eof_then_immediate_close_commits(V2, &payload(4099), &format!("v2-data-{round}")).await?;
    }
    Ok(())
}

async fn cancel_before_eof(proto: ProtoType, sid: &str) -> Result<()> {
    let dir = tempfile::tempdir()?;
    let target = dir.path().join("target.bin");
    std::fs::write(&target, b"OLD")?;
    let target_s = target.to_string_lossy().into_owned();
    let v1 = matches!(proto, ProtoType::FILE_TRANSFER);
    let mut mgr = FileTransferManager::new();

    assert!(
        tokio::time::timeout(
            Duration::from_secs(2),
            mgr.handle(put_req(proto, sid, &target_s, 4)?)
        )
        .await??
        .is_empty()
    );
    if v1 {
        let _ = next(&mut mgr).await?;
    }
    assert!(
        tokio::time::timeout(
            Duration::from_secs(2),
            mgr.handle(chunk(proto, sid, b"ab", 0))
        )
        .await??
        .is_empty()
    );
    // Cancel before EOF: destination must be preserved and staging removed.
    tokio::time::timeout(Duration::from_secs(2), mgr.close_session(sid)).await??;

    assert_eq!(std::fs::read(&target)?, b"OLD");
    assert_eq!(
        only_target(dir.path())?,
        vec!["target.bin".to_string()],
        "staging must be removed on pre-EOF cancel"
    );
    Ok(())
}

#[tokio::test]
async fn cancel_before_eof_preserves_destination_and_removes_staging() -> Result<()> {
    cancel_before_eof(V1, "cancel-v1").await?;
    cancel_before_eof(V2, "cancel-v2").await?;
    Ok(())
}

async fn malformed_eof_never_commits(
    proto: ProtoType,
    sid: &str,
    declared: i64,
    eof_offset: i64,
) -> Result<()> {
    let dir = tempfile::tempdir()?;
    let target = dir.path().join("target.bin");
    std::fs::write(&target, b"OLD")?;
    let target_s = target.to_string_lossy().into_owned();
    let v1 = matches!(proto, ProtoType::FILE_TRANSFER);
    let mut mgr = FileTransferManager::new();

    assert!(
        tokio::time::timeout(
            Duration::from_secs(2),
            mgr.handle(put_req(proto, sid, &target_s, declared)?)
        )
        .await??
        .is_empty()
    );
    if v1 {
        let _ = next(&mut mgr).await?;
    }
    // Queue a malformed/premature EOF then close immediately.
    assert!(
        tokio::time::timeout(
            Duration::from_secs(2),
            mgr.handle(chunk(proto, sid, &[], eof_offset))
        )
        .await??
        .is_empty()
    );
    tokio::time::timeout(Duration::from_secs(2), mgr.close_session(sid)).await??;

    assert_eq!(
        std::fs::read(&target)?,
        b"OLD",
        "malformed EOF must never commit"
    );
    assert_eq!(only_target(dir.path())?, vec!["target.bin".to_string()]);
    Ok(())
}

#[tokio::test]
async fn malformed_eof_before_close_never_commits() -> Result<()> {
    // wrong offset: declared 0 but EOF reported at offset 5
    malformed_eof_never_commits(V1, "v1-off", 0, 5).await?;
    malformed_eof_never_commits(V2, "v2-off", 0, 5).await?;
    // declared size mismatch: declared 4 but EOF at offset 0
    malformed_eof_never_commits(V1, "v1-size", 4, 0).await?;
    malformed_eof_never_commits(V2, "v2-size", 4, 0).await?;
    Ok(())
}

#[tokio::test]
async fn unrelated_upload_survives_scoped_close() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let keep = dir.path().join("keep.bin");
    let go = dir.path().join("go.bin");
    std::fs::write(&keep, b"OLD")?;
    std::fs::write(&go, b"OLD")?;
    let keep_s = keep.to_string_lossy().into_owned();
    let go_s = go.to_string_lossy().into_owned();
    let mut mgr = FileTransferManager::new();

    assert!(
        tokio::time::timeout(
            Duration::from_secs(2),
            mgr.handle(put_req(V2, "keep", &keep_s, 3)?)
        )
        .await??
        .is_empty()
    );
    assert!(
        tokio::time::timeout(
            Duration::from_secs(2),
            mgr.handle(put_req(V2, "go", &go_s, 3)?)
        )
        .await??
        .is_empty()
    );

    tokio::time::timeout(Duration::from_secs(2), mgr.close_session("go")).await??;
    assert_eq!(
        std::fs::read(&go)?,
        b"OLD",
        "scoped close aborts go before EOF"
    );

    // The unrelated upload keeps operating and completes.
    assert!(
        tokio::time::timeout(
            Duration::from_secs(2),
            mgr.handle(chunk(V2, "keep", b"abc", 0))
        )
        .await??
        .is_empty()
    );
    assert!(
        tokio::time::timeout(
            Duration::from_secs(2),
            mgr.handle(chunk(V2, "keep", &[], 3))
        )
        .await??
        .is_empty()
    );
    tokio::time::timeout(Duration::from_secs(2), mgr.close_session("keep")).await??;
    assert_eq!(
        std::fs::read(&keep)?,
        b"abc",
        "unrelated upload still commits after scoped close"
    );

    // A malformed message still yields a sanitized error header.
    let reply = tokio::time::timeout(
        Duration::from_secs(2),
        mgr.handle(ProtoMsg {
            header: header(V2, "bogus", "err", BTreeMap::new()),
            body: Vec::new(),
        }),
    )
    .await??;
    assert_eq!(reply.len(), 1);
    assert_eq!(reply[0].header.msg_type, "error");
    assert_eq!(reply[0].header.session_id, "err");

    tokio::time::timeout(Duration::from_secs(2), mgr.close_all()).await??;
    Ok(())
}
