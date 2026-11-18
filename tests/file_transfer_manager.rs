//! Blackbox tests for the public `FileTransferManager` driver.

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

fn int(n: i64) -> Value {
    Value::from(n)
}

fn base_props(msgid: &str) -> BTreeMap<String, Value> {
    let mut map = BTreeMap::new();
    map.insert("msgid".to_string(), Value::from(msgid));
    map
}

fn with_offset(mut props: BTreeMap<String, Value>, off: i64) -> BTreeMap<String, Value> {
    props.insert("offset".to_string(), int(off));
    props
}

fn header(proto: ProtoType, msg_type: &str, sid: &str, props: BTreeMap<String, Value>) -> ProtoHdr {
    ProtoHdr {
        proto,
        msg_type: msg_type.to_string(),
        session_id: sid.to_string(),
        properties: props,
    }
}

fn stat_req(proto: ProtoType, sid: &str, path: &str, msgid: &str) -> Result<ProtoMsg> {
    let body = protocol::encode(&schema::StatFile {
        path: Some(path.to_string()),
    })?;
    Ok(ProtoMsg {
        header: header(proto, "stat", sid, base_props(msgid)),
        body,
    })
}

fn get_req(proto: ProtoType, sid: &str, path: &str, msgid: &str) -> Result<ProtoMsg> {
    let body = protocol::encode(&schema::GetFile {
        path: Some(path.to_string()),
    })?;
    Ok(ProtoMsg {
        header: header(proto, "get_file", sid, base_props(msgid)),
        body,
    })
}

fn put_req(
    proto: ProtoType,
    sid: &str,
    path: &str,
    size: i64,
    mode: u32,
    msgid: &str,
) -> Result<ProtoMsg> {
    let upload = schema::UploadRequest {
        path: Some(path.to_string()),
        src_path: None,
        size: Some(size),
        uid: None,
        gid: None,
        mode: Some(mode),
        modtime: None,
    };
    let body = protocol::encode(&upload)?;
    Ok(ProtoMsg {
        header: header(proto, "put_file", sid, base_props(msgid)),
        body,
    })
}

fn chunk_req(proto: ProtoType, sid: &str, data: &[u8], off: i64, msgid: &str) -> ProtoMsg {
    ProtoMsg {
        header: header(
            proto,
            "file_chunk",
            sid,
            with_offset(base_props(msgid), off),
        ),
        body: data.to_vec(),
    }
}

fn ack_req(proto: ProtoType, sid: &str, off: i64, msgid: &str) -> ProtoMsg {
    ProtoMsg {
        header: header(proto, "ack", sid, with_offset(base_props(msgid), off)),
        body: Vec::new(),
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

async fn next(mgr: &mut FileTransferManager) -> Result<ProtoMsg> {
    tokio::time::timeout(Duration::from_secs(2), mgr.next_message()).await?
}

#[cfg(unix)]
fn mode_of(path: &Path) -> Result<u32> {
    use std::os::unix::fs::PermissionsExt;
    Ok(std::fs::metadata(path)?.permissions().mode() & 0o777)
}

#[tokio::test]
async fn stat_reports_file_and_errors() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("stat.bin");
    let data = payload(4099);
    std::fs::write(&path, &data)?;
    let path_s = path.to_string_lossy().to_string();
    let mut mgr = FileTransferManager::new();

    assert!(
        mgr.handle(stat_req(V1, "stat-sid", &path_s, "m-stat")?)
            .await?
            .is_empty()
    );
    let reply = [next(&mut mgr).await?];
    assert_eq!(reply.len(), 1);
    assert!(matches!(reply[0].header.proto, ProtoType::FILE_TRANSFER));
    assert_eq!(reply[0].header.session_id, "stat-sid");
    assert_eq!(reply[0].header.msg_type, "file_info");
    assert_eq!(
        reply[0].header.properties.get("msgid"),
        Some(&Value::from("m-stat"))
    );

    let info: schema::FileInfo = protocol::decode(&reply[0].body)?;
    assert_eq!(info.path, path_s);
    assert_eq!(info.size, Some(4099));

    // Stat must not spawn a worker: nothing is ever queued.
    let idle = tokio::time::timeout(Duration::from_millis(200), mgr.next_message()).await;
    assert!(idle.is_err());

    // Unknown path -> TransferError with reflected metadata.
    let missing_s = dir.path().join("nope.bin").to_string_lossy().to_string();
    assert!(
        mgr.handle(stat_req(V1, "stat-sid", &missing_s, "m-bad")?)
            .await?
            .is_empty()
    );
    let err = [next(&mut mgr).await?];
    assert_eq!(err.len(), 1);
    let terr: schema::TransferError = protocol::decode(&err[0].body)?;
    assert!(terr.err.is_some());
    assert_eq!(terr.msgtype.as_deref(), Some("stat"));
    assert_eq!(terr.msgid.as_deref(), Some("m-bad"));

    mgr.close_all().await?;
    Ok(())
}

#[tokio::test]
async fn downloads_v1_and_v2() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("dl.bin");
    let data = payload(4099);
    std::fs::write(&path, &data)?;
    let path_s = path.to_string_lossy().to_string();

    for proto in [V1, V2] {
        let v2 = matches!(proto, ProtoType::FILE_TRANSFER_V2);
        let sid = if v2 { "dl-v2" } else { "dl-v1" };
        let mut mgr = FileTransferManager::new();

        let out = mgr.handle(get_req(proto, sid, &path_s, "g1")?).await?;
        assert!(out.is_empty());

        let c0 = next(&mut mgr).await?;
        assert!(matches!(c0.header.proto, ProtoType::FILE_TRANSFER) == !v2);
        assert_eq!(c0.header.session_id, sid);
        assert_eq!(c0.header.msg_type, "file_chunk");
        assert_eq!(offset(&c0), Some(0));
        assert_eq!(c0.body, data[..4096].to_vec());

        let c1 = next(&mut mgr).await?;
        assert_eq!(offset(&c1), Some(4096));
        assert_eq!(c1.body, data[4096..].to_vec());

        let eof = next(&mut mgr).await?;
        assert_eq!(offset(&eof), Some(4099));
        assert!(eof.body.is_empty());

        // Duplicate request while the key state determines acceptance.
        let dup = mgr.handle(get_req(proto, sid, &path_s, "g2")?).await?;
        if v2 {
            // v2 retires on EOF: duplicate is accepted and restarts the stream.
            assert!(dup.is_empty());
            let again = next(&mut mgr).await?;
            assert_eq!(offset(&again), Some(0));
            assert_eq!(again.body, data[..4096].to_vec());
        } else {
            // v1 stays busy until the final ACK: duplicate is rejected once.
            assert_eq!(dup.len(), 1);
            let ack = mgr.handle(ack_req(proto, sid, 4099, "g3")).await?;
            assert!(ack.is_empty());
            let out = mgr.handle(get_req(proto, sid, &path_s, "g4")?).await?;
            assert!(out.is_empty());
            let again = next(&mut mgr).await?;
            assert_eq!(offset(&again), Some(0));
        }
        mgr.close_all().await?;
    }
    Ok(())
}

#[tokio::test]
async fn uploads_v1_and_v2() -> Result<()> {
    let base = tempfile::tempdir()?;
    let data = payload(4099);

    for proto in [V1, V2] {
        let v1 = matches!(proto, ProtoType::FILE_TRANSFER);
        let sid = if v1 { "up-v1" } else { "up-v2" };
        let dst_dir = base.path().join(sid);
        std::fs::create_dir_all(&dst_dir)?;
        let target = dst_dir.join("target.bin");
        std::fs::write(&target, b"OLD")?;
        let target_s = target.to_string_lossy().to_string();
        let mut mgr = FileTransferManager::new();

        let out = mgr
            .handle(put_req(proto, sid, &target_s, 4099, 0o640, "p1")?)
            .await?;
        assert!(out.is_empty());

        if v1 {
            let a = next(&mut mgr).await?;
            assert_eq!(a.header.msg_type, "ack");
            assert_eq!(offset(&a), Some(0));
        }

        for (start, len) in [(0usize, 4096usize), (4096, 3)] {
            mgr.handle(chunk_req(
                proto,
                sid,
                &data[start..start + len],
                start as i64,
                "p1",
            ))
            .await?;
            if v1 {
                let a = next(&mut mgr).await?;
                assert_eq!(a.header.msg_type, "ack");
                assert_eq!(offset(&a), Some(start as i64));
            }
        }

        // Before EOF the target still holds the seeded content.
        assert_eq!(std::fs::read(&target)?, b"OLD".to_vec());

        mgr.handle(chunk_req(proto, sid, &[], 4099, "p1")).await?;
        let fin = next(&mut mgr).await?;
        assert_eq!(fin.header.msg_type, "ack");
        if v1 {
            assert_eq!(offset(&fin), Some(4099));
        } else {
            assert_eq!(offset(&fin), None);
        }

        // Committed payload and permissions.
        assert_eq!(std::fs::read(&target)?, data);
        #[cfg(unix)]
        assert_eq!(mode_of(&target)?, 0o640);

        // No staging leftovers: only the target remains in its directory.
        let mut names: Vec<String> = std::fs::read_dir(&dst_dir)?
            .map(|e| e.map(|e| e.file_name().to_string_lossy().to_string()))
            .collect::<std::result::Result<_, _>>()?;
        names.sort();
        assert_eq!(names, vec!["target.bin".to_string()]);

        // Terminal retirement: same key accepted immediately after the ACK.
        let out = mgr.handle(get_req(proto, sid, &target_s, "p2")?).await?;
        assert!(out.is_empty());
        let first = next(&mut mgr).await?;
        assert_eq!(offset(&first), Some(0));
        assert_eq!(first.body, data[..4096].to_vec());

        mgr.close_all().await?;
    }
    Ok(())
}

// Append to tests/file_transfer_manager.rs for candidate validation.
#[tokio::test]
async fn timed_out_downloads_release_manager_capacity() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("data");
    std::fs::write(&path, vec![7u8; 4096])?;
    let path = path.to_string_lossy().to_string();
    let mut mgr = FileTransferManager::new();
    let sids: Vec<String> = (0..4).map(|i| format!("deadline-{i}")).collect();
    for sid in &sids {
        assert!(mgr.handle(get_req(V1, sid, &path, sid)?).await?.is_empty());
    }
    let mut seen = std::collections::BTreeMap::<String, Vec<usize>>::new();
    for _ in 0..8 {
        let frame = next(&mut mgr).await?;
        assert_eq!(frame.header.msg_type, "file_chunk");
        assert_eq!(frame.header.proto, V1);
        assert_eq!(
            offset(&frame),
            Some(if frame.body.is_empty() { 4096 } else { 0 })
        );
        seen.entry(frame.header.session_id)
            .or_default()
            .push(frame.body.len());
    }
    for sid in &sids {
        assert_eq!(seen.get(sid), Some(&vec![4096, 0]));
    }
    let full = mgr
        .handle(get_req(V1, "deadline-new", &path, "new")?)
        .await?;
    assert_eq!(full.len(), 1);
    let err: schema::TransferError = protocol::decode(&full[0].body)?;
    assert!(
        err.err
            .as_deref()
            .unwrap_or_default()
            .contains("transfer capacity reached")
    );
    tokio::task::yield_now().await;
    tokio::time::pause();
    for offset in 1..=20 {
        tokio::time::advance(Duration::from_secs(29)).await;
        for sid in &sids {
            assert!(mgr.handle(ack_req(V1, sid, offset, sid)).await?.is_empty());
        }
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_secs(21)).await;
    let mut errors = std::collections::BTreeSet::new();
    for _ in 0..4 {
        let reply = next(&mut mgr).await?;
        assert_eq!(reply.header.proto, V1);
        assert_eq!(reply.header.msg_type, "error");
        assert_eq!(
            reply.header.properties.get("msgid"),
            Some(&Value::from(reply.header.session_id.as_str()))
        );
        assert!(!mender_connect_rust::transport::encode_outbound_message(&reply)?.is_empty());
        let err: schema::TransferError = protocol::decode(&reply.body)?;
        assert!(
            err.err
                .as_deref()
                .unwrap_or_default()
                .contains("download exceeded total deadline")
        );
        assert_eq!(err.msgid.as_deref(), Some(reply.header.session_id.as_str()));
        assert!(reply.body.len() < 4096);
        assert!(errors.insert(reply.header.session_id));
    }
    assert_eq!(errors, sids.iter().cloned().collect());
    tokio::time::resume();
    assert!(
        mgr.handle(get_req(V1, "deadline-new", &path, "new")?)
            .await?
            .is_empty()
    );
    for (expected_offset, expected_len) in [(0, 4096), (4096, 0)] {
        let frame = next(&mut mgr).await?;
        assert_eq!(frame.header.session_id, "deadline-new");
        assert_eq!(frame.header.proto, V1);
        assert_eq!(frame.header.msg_type, "file_chunk");
        assert_eq!(offset(&frame), Some(expected_offset));
        assert_eq!(frame.body.len(), expected_len);
    }
    assert!(
        mgr.handle(ack_req(V1, "deadline-new", 4096, "new"))
            .await?
            .is_empty()
    );
    tokio::time::timeout(Duration::from_secs(2), mgr.close_all()).await??;
    Ok(())
}

// Append to tests/file_transfer_manager.rs in the isolated candidate.
#[tokio::test]
async fn empty_download_ack_zero_has_no_spurious_error() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("empty");
    std::fs::write(&path, [])?;
    let mut manager = FileTransferManager::new();
    let path = path.to_string_lossy().to_string();
    assert!(
        manager
            .handle(get_req(V1, "empty-ack", &path, "get")?)
            .await?
            .is_empty()
    );
    let eof = next(&mut manager).await?;
    assert_eq!(eof.header.msg_type, "file_chunk");
    assert!(eof.body.is_empty());
    assert_eq!(offset(&eof), Some(0));
    assert_eq!(eof.header.proto, V1);
    assert_eq!(eof.header.session_id, "empty-ack");
    // Drive queued Finished events, if any, before the ACK arrives.
    assert!(
        tokio::time::timeout(Duration::from_millis(100), manager.next_message())
            .await
            .is_err()
    );
    let reply = manager.handle(ack_req(V1, "empty-ack", 0, "ack")).await?;
    assert!(
        reply.is_empty(),
        "empty completion ACK must not produce an error"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), manager.next_message())
            .await
            .is_err(),
        "no asynchronous transfer error expected"
    );
    manager.close_all().await?;
    Ok(())
}

#[tokio::test]
async fn empty_v1_download_releases_key_without_ack_and_tolerates_late_ack() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let source = dir.path().join("empty");
    let target = dir.path().join("upload");
    std::fs::write(&source, [])?;
    let source = source.to_string_lossy().to_string();
    let target = target.to_string_lossy().to_string();
    let mut manager = FileTransferManager::new();
    assert!(
        manager
            .handle(get_req(V1, "reuse", &source, "get")?)
            .await?
            .is_empty()
    );
    let eof = next(&mut manager).await?;
    assert_eq!(eof.header.msg_type, "file_chunk");
    assert!(eof.body.is_empty());
    assert_eq!(offset(&eof), Some(0));
    assert!(
        manager
            .handle(put_req(V1, "reuse", &target, 1, 0o600, "put")?)
            .await?
            .is_empty()
    );
    let ready = next(&mut manager).await?;
    assert_eq!(ready.header.msg_type, "ack");
    assert!(
        manager
            .handle(ack_req(V1, "reuse", 0, "late"))
            .await?
            .is_empty()
    );
    assert!(
        manager
            .handle(chunk_req(V1, "reuse", b"x", 0, "chunk"))
            .await?
            .is_empty()
    );
    let chunk_ack = next(&mut manager).await?;
    assert_eq!(chunk_ack.header.msg_type, "ack");
    assert!(
        manager
            .handle(chunk_req(V1, "reuse", &[], 1, "end"))
            .await?
            .is_empty()
    );
    let final_ack = next(&mut manager).await?;
    assert_eq!(final_ack.header.msg_type, "ack");
    assert_eq!(std::fs::read(target)?, b"x");
    manager.close_all().await?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn empty_download_late_ack_is_bounded_and_strict() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let source = dir.path().join("empty");
    std::fs::write(&source, [])?;
    let source = source.to_string_lossy().to_string();
    let mut manager = FileTransferManager::new();
    assert!(
        manager
            .handle(get_req(V1, "bounded", &source, "get")?)
            .await?
            .is_empty()
    );
    assert!(next(&mut manager).await?.body.is_empty());
    let invalid = manager.handle(ack_req(V1, "bounded", 1, "invalid")).await?;
    assert_eq!(invalid.len(), 1);
    assert_eq!(
        invalid.first().map(|m| m.header.msg_type.as_str()),
        Some("error")
    );
    let mut invalid_body = ack_req(V1, "bounded", 0, "invalid-body");
    invalid_body.body = vec![1];
    let invalid = manager.handle(invalid_body).await?;
    assert_eq!(
        invalid.first().map(|m| m.header.msg_type.as_str()),
        Some("error")
    );
    assert!(
        manager
            .handle(ack_req(V1, "bounded", 0, "valid"))
            .await?
            .is_empty()
    );
    tokio::time::advance(Duration::from_secs(30)).await;
    let expired = manager.handle(ack_req(V1, "bounded", 0, "expired")).await?;
    assert_eq!(expired.len(), 1);
    assert_eq!(
        expired.first().map(|m| m.header.msg_type.as_str()),
        Some("error")
    );
    manager.close_all().await?;
    Ok(())
}

#[tokio::test]
async fn empty_download_markers_are_bounded_and_cleared_on_close() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let source = dir.path().join("empty");
    std::fs::write(&source, [])?;
    let source = source.to_string_lossy().to_string();
    let mut manager = FileTransferManager::new();
    for sid in ["one", "two", "three", "four", "five"] {
        assert!(
            manager
                .handle(get_req(V1, sid, &source, "get")?)
                .await?
                .is_empty()
        );
        assert!(next(&mut manager).await?.body.is_empty());
    }
    assert_eq!(
        manager
            .handle(ack_req(V1, "one", 0, "old"))
            .await?
            .first()
            .map(|m| m.header.msg_type.as_str()),
        Some("error")
    );
    assert!(
        manager
            .handle(ack_req(V1, "five", 0, "new"))
            .await?
            .is_empty()
    );
    manager.close_session("five").await?;
    assert_eq!(
        manager
            .handle(ack_req(V1, "five", 0, "closed"))
            .await?
            .first()
            .map(|m| m.header.msg_type.as_str()),
        Some("error")
    );
    manager.close_all().await?;
    assert_eq!(
        manager
            .handle(ack_req(V1, "four", 0, "closed-all"))
            .await?
            .first()
            .map(|m| m.header.msg_type.as_str()),
        Some("error")
    );
    Ok(())
}

#[tokio::test]
async fn closing_empty_download_before_ack_releases_admission() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("empty");
    std::fs::write(&path, [])?;
    let path = path.to_string_lossy().to_string();
    let mut manager = FileTransferManager::new();
    assert!(
        manager
            .handle(get_req(V1, "empty-close", &path, "get")?)
            .await?
            .is_empty()
    );
    assert!(next(&mut manager).await?.body.is_empty());
    tokio::time::timeout(Duration::from_secs(2), manager.close_session("empty-close")).await??;
    assert!(
        manager
            .handle(get_req(V1, "empty-close", &path, "again")?)
            .await?
            .is_empty()
    );
    assert!(next(&mut manager).await?.body.is_empty());
    assert!(
        manager
            .handle(ack_req(V1, "empty-close", 0, "ack"))
            .await?
            .is_empty()
    );
    tokio::time::timeout(Duration::from_secs(2), manager.close_all()).await??;
    Ok(())
}
