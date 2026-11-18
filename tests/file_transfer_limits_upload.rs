//! Integration tests for the limited (policy) upload path.
//!
//! These drive the real [`FileTransferManager`] and its owned workers through
//! both the v1 and v2 protocols, using bounded channels, per-test tempdirs and
//! an injected NSS resolver. Every task is bounded and joined before the test
//! returns. No QEMU, credential or real server is used.

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;

use mender_connect_rust::file_transfer_manager::FileTransferManager;
use mender_connect_rust::file_transfer_schema::UploadRequest;
use mender_connect_rust::file_transfer_upload::{CommittedAckError, upload_with_limits};
use mender_connect_rust::limits_config::{
    NssResolver, RawFileTransferLimits, RawRateLimits, ResolverError,
};
use mender_connect_rust::limits_rate::{RateEngine, RateLimits, SharedRateCounter};
use mender_connect_rust::protocol::{self, ProtoHdr, ProtoMsg, ProtoType};
use mender_connect_rust::transfer_limits::TransferLimits;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const V1: ProtoType = ProtoType::FILE_TRANSFER;
const V2: ProtoType = ProtoType::FILE_TRANSFER_V2;

/// Deterministic NSS resolver with no host account dependency.
struct FakeNss;

impl NssResolver for FakeNss {
    fn lookup_user(&self, name: &str) -> std::result::Result<Option<u32>, ResolverError> {
        Ok(match name {
            "bob" => Some(4_000_000_001),
            _ => None,
        })
    }

    fn lookup_group(&self, name: &str) -> std::result::Result<Option<u32>, ResolverError> {
        Ok(match name {
            "strangers" => Some(4_000_000_002),
            _ => None,
        })
    }
}

fn raw_limits() -> RawFileTransferLimits {
    RawFileTransferLimits {
        max_file_size: Some(1 << 20),
        ..Default::default()
    }
}

fn limits_from(raw: &RawFileTransferLimits) -> Arc<TransferLimits> {
    Arc::new(TransferLimits::new(raw, &FakeNss).expect("construct limited context"))
}

fn header(proto: ProtoType, sid: &str, msg_type: &str) -> ProtoHdr {
    ProtoHdr {
        proto,
        msg_type: msg_type.to_owned(),
        session_id: sid.to_owned(),
        properties: BTreeMap::new(),
    }
}

fn put_msg(proto: ProtoType, sid: &str, request: &UploadRequest) -> Result<ProtoMsg> {
    Ok(ProtoMsg {
        header: header(proto, sid, "put_file"),
        body: protocol::encode(request)?,
    })
}

fn simple_request(target: &Path, size: Option<i64>, mode: Option<u32>) -> UploadRequest {
    UploadRequest {
        path: Some(target.to_string_lossy().into_owned()),
        src_path: None,
        size,
        uid: None,
        gid: None,
        mode,
        modtime: None,
    }
}

fn chunk(proto: ProtoType, sid: &str, data: &[u8], off: i64) -> ProtoMsg {
    let mut properties = BTreeMap::new();
    properties.insert("offset".to_owned(), rmpv::Value::from(off));
    ProtoMsg {
        header: ProtoHdr {
            proto,
            msg_type: "file_chunk".to_owned(),
            session_id: sid.to_owned(),
            properties,
        },
        body: data.to_vec(),
    }
}

fn offset(msg: &ProtoMsg) -> Option<i64> {
    match msg.header.properties.get("offset") {
        Some(rmpv::Value::Integer(integer)) => integer.as_i64(),
        _ => None,
    }
}

async fn next(mgr: &mut FileTransferManager) -> Result<ProtoMsg> {
    tokio::time::timeout(TEST_TIMEOUT, mgr.next_message()).await?
}

async fn shutdown(mgr: &mut FileTransferManager) -> Result<()> {
    tokio::time::timeout(TEST_TIMEOUT, mgr.close_all()).await??;
    Ok(())
}

async fn send_put(
    mgr: &mut FileTransferManager,
    proto: ProtoType,
    sid: &str,
    target: &Path,
    size: Option<i64>,
    mode: Option<u32>,
) -> Result<Vec<ProtoMsg>> {
    let request = simple_request(target, size, mode);
    tokio::time::timeout(TEST_TIMEOUT, mgr.handle(put_msg(proto, sid, &request)?)).await?
}

async fn send_chunk(
    mgr: &mut FileTransferManager,
    proto: ProtoType,
    sid: &str,
    data: &[u8],
    off: i64,
) -> Result<Vec<ProtoMsg>> {
    tokio::time::timeout(TEST_TIMEOUT, mgr.handle(chunk(proto, sid, data, off))).await?
}

async fn v2_upload_ok(
    mgr: &mut FileTransferManager,
    sid: &str,
    target: &Path,
    data: &[u8],
) -> Result<()> {
    let size = i64::try_from(data.len())?;
    assert!(
        send_put(mgr, V2, sid, target, Some(size), Some(0o640))
            .await?
            .is_empty(),
        "v2 put_file has no immediate reply"
    );
    let mut off = 0i64;
    for part in data.chunks(4096) {
        assert!(send_chunk(mgr, V2, sid, part, off).await?.is_empty());
        off += i64::try_from(part.len())?;
    }
    assert!(send_chunk(mgr, V2, sid, &[], off).await?.is_empty());
    let ack = next(mgr).await?;
    assert_eq!(ack.header.msg_type, "ack", "final v2 ack");
    Ok(())
}

async fn v1_upload_ok(
    mgr: &mut FileTransferManager,
    sid: &str,
    target: &Path,
    data: &[u8],
) -> Result<()> {
    let size = i64::try_from(data.len())?;
    assert!(
        send_put(mgr, V1, sid, target, Some(size), Some(0o640))
            .await?
            .is_empty()
    );
    let initial = next(mgr).await?;
    assert_eq!(initial.header.msg_type, "ack");
    assert_eq!(offset(&initial), Some(0));
    let mut off = 0i64;
    for part in data.chunks(4096) {
        assert!(send_chunk(mgr, V1, sid, part, off).await?.is_empty());
        let ack = next(mgr).await?;
        assert_eq!(offset(&ack), Some(off));
        off += i64::try_from(part.len())?;
    }
    assert!(send_chunk(mgr, V1, sid, &[], off).await?.is_empty());
    let final_ack = next(mgr).await?;
    assert_eq!(offset(&final_ack), Some(off));
    Ok(())
}

fn only_names(dir: &Path) -> Result<Vec<String>> {
    let mut names: Vec<String> = std::fs::read_dir(dir)?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<std::result::Result<_, _>>()?;
    names.sort();
    Ok(names)
}

#[tokio::test]
async fn manager_routes_v2_and_v1_nonempty_and_empty_new_files() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut raw = raw_limits();
    raw.chroot = Some(root.to_string_lossy().into_owned());
    let shared = limits_from(&raw);
    let mut mgr = FileTransferManager::with_limits(Arc::clone(&shared));

    let v2_data = b"hello v2 limited".to_vec();
    let t1 = root.join("v2-nonempty");
    v2_upload_ok(&mut mgr, "v2-nonempty", &t1, &v2_data).await?;
    assert_eq!(std::fs::read(&t1)?, v2_data);

    let t2 = root.join("v2-empty");
    v2_upload_ok(&mut mgr, "v2-empty", &t2, &[]).await?;
    assert_eq!(std::fs::read(&t2)?, Vec::<u8>::new());

    let v1_data: Vec<u8> = (0u8..=200).cycle().take(5000).collect();
    let t3 = root.join("v1-nonempty");
    v1_upload_ok(&mut mgr, "v1-nonempty", &t3, &v1_data).await?;
    assert_eq!(std::fs::read(&t3)?, v1_data);

    let t4 = root.join("v1-empty");
    v1_upload_ok(&mut mgr, "v1-empty", &t4, &[]).await?;
    assert_eq!(std::fs::read(&t4)?, Vec::<u8>::new());

    shutdown(&mut mgr).await
}

#[tokio::test]
async fn valid_eof_then_immediate_scoped_close_commits_limited() -> Result<()> {
    for (proto, sid) in [(V1, "v1-eof"), (V2, "v2-eof")] {
        let dir = tempfile::tempdir()?;
        let root = dir.path();
        let mut raw = raw_limits();
        raw.chroot = Some(root.to_string_lossy().into_owned());
        let mut mgr = FileTransferManager::with_limits(limits_from(&raw));

        let target = root.join("target.bin");
        let data = b"limited payload".to_vec();
        let size = i64::try_from(data.len())?;
        assert!(
            send_put(&mut mgr, proto, sid, &target, Some(size), Some(0o644))
                .await?
                .is_empty()
        );
        if proto == V1 {
            let ack = next(&mut mgr).await?;
            assert_eq!(offset(&ack), Some(0));
        }
        assert!(send_chunk(&mut mgr, proto, sid, &data, 0).await?.is_empty());
        if proto == V1 {
            let _ = next(&mut mgr).await?;
        }
        // Queue the EOF then close the session immediately without reading the
        // final ACK. The accepted upload must still flush, sync and commit.
        assert!(
            send_chunk(&mut mgr, proto, sid, &[], size)
                .await?
                .is_empty()
        );
        tokio::time::timeout(TEST_TIMEOUT, mgr.close_session(sid)).await??;
        assert_eq!(std::fs::read(&target)?, data, "accepted EOF must commit");
        assert_eq!(only_names(root)?, vec!["target.bin".to_string()]);
    }
    Ok(())
}

#[tokio::test]
async fn eof_scoped_close_commits_and_unrelated_upload_survives() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut raw = raw_limits();
    raw.chroot = Some(root.to_string_lossy().into_owned());
    let mut mgr = FileTransferManager::with_limits(limits_from(&raw));

    let keep = root.join("keep.bin");
    let go = root.join("go.bin");

    assert!(
        send_put(&mut mgr, V2, "go", &go, Some(4), Some(0o644))
            .await?
            .is_empty()
    );
    assert!(
        send_put(&mut mgr, V2, "keep", &keep, Some(3), Some(0o644))
            .await?
            .is_empty()
    );

    // Close "go" before EOF: it is aborted, no file appears.
    assert!(send_chunk(&mut mgr, V2, "go", b"ab", 0).await?.is_empty());
    tokio::time::timeout(TEST_TIMEOUT, mgr.close_session("go")).await??;
    assert!(!go.exists(), "pre-EOF close aborts without committing");

    // The unrelated "keep" upload keeps operating and commits.
    assert!(
        send_chunk(&mut mgr, V2, "keep", b"abc", 0)
            .await?
            .is_empty()
    );
    assert!(send_chunk(&mut mgr, V2, "keep", &[], 3).await?.is_empty());
    tokio::time::timeout(TEST_TIMEOUT, mgr.close_session("keep")).await??;
    assert_eq!(std::fs::read(&keep)?, b"abc");

    shutdown(&mut mgr).await
}

#[tokio::test]
async fn metadata_mode_applied_to_committed_file() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut raw = raw_limits();
    raw.chroot = Some(root.to_string_lossy().into_owned());
    let mut mgr = FileTransferManager::with_limits(limits_from(&raw));

    let target = root.join("meta.bin");
    let data = b"meta".to_vec();
    let size = i64::try_from(data.len())?;
    assert!(
        send_put(&mut mgr, V2, "meta", &target, Some(size), Some(0o640))
            .await?
            .is_empty()
    );
    assert!(send_chunk(&mut mgr, V2, "meta", &data, 0).await?.is_empty());
    assert!(
        send_chunk(&mut mgr, V2, "meta", &[], size)
            .await?
            .is_empty()
    );
    let _ = next(&mut mgr).await?;

    let meta = std::fs::metadata(&target)?;
    assert!(meta.file_type().is_file());
    assert_eq!(
        meta.mode() & 0o777,
        0o640,
        "requested mode applied via descriptor"
    );

    shutdown(&mut mgr).await
}

#[tokio::test]
async fn uid_sentinel_rejected_before_initial_ack() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut raw = raw_limits();
    raw.chroot = Some(root.to_string_lossy().into_owned());
    let mut mgr = FileTransferManager::with_limits(limits_from(&raw));

    let target = root.join("sentinel.bin");
    let request = UploadRequest {
        path: Some(target.to_string_lossy().into_owned()),
        src_path: None,
        size: Some(0),
        uid: Some(u32::MAX),
        gid: None,
        mode: None,
        modtime: None,
    };
    // v1: an accepted request would first emit the offset-0 ACK. A reserved
    // sentinel must instead fail before any ACK.
    assert!(
        tokio::time::timeout(TEST_TIMEOUT, mgr.handle(put_msg(V1, "sentinel", &request)?))
            .await??
            .is_empty()
    );
    let message = next(&mut mgr).await?;
    assert_eq!(
        message.header.msg_type, "error",
        "no initial ACK; structured error"
    );
    assert!(!target.exists());

    shutdown(&mut mgr).await
}

#[tokio::test]
async fn unsupported_mode_rejected_before_ack() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut raw = raw_limits();
    raw.chroot = Some(root.to_string_lossy().into_owned());
    let mut mgr = FileTransferManager::with_limits(limits_from(&raw));

    let target = root.join("mode.bin");
    // 0o2000 (setgid) is outside the understood mask and must be rejected.
    assert!(
        send_put(&mut mgr, V2, "mode", &target, Some(0), Some(0o2000))
            .await?
            .is_empty()
    );
    let message = next(&mut mgr).await?;
    assert_eq!(message.header.msg_type, "error");
    assert!(!target.exists());

    shutdown(&mut mgr).await
}

#[tokio::test]
async fn declared_size_over_limit_rejected() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut raw = raw_limits();
    raw.chroot = Some(root.to_string_lossy().into_owned());
    let mut mgr = FileTransferManager::with_limits(limits_from(&raw));

    let target = root.join("big.bin");
    assert!(
        send_put(&mut mgr, V2, "big", &target, Some(2_097_152), Some(0o644))
            .await?
            .is_empty()
    );
    let message = next(&mut mgr).await?;
    assert_eq!(message.header.msg_type, "error");
    assert!(!target.exists());

    shutdown(&mut mgr).await
}

#[tokio::test]
async fn progress_size_denial_rejects_without_writing() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut raw = raw_limits();
    raw.chroot = Some(root.to_string_lossy().into_owned());
    raw.max_file_size = Some(1024);
    let mut mgr = FileTransferManager::with_limits(limits_from(&raw));

    let target = root.join("progress.bin");
    // No declared size, so only the progress cap can reject the oversized chunk.
    assert!(
        send_put(&mut mgr, V2, "progress", &target, None, Some(0o644))
            .await?
            .is_empty()
    );
    let big = vec![7u8; 1500];
    assert!(
        send_chunk(&mut mgr, V2, "progress", &big, 0)
            .await?
            .is_empty()
    );
    let message = next(&mut mgr).await?;
    assert_eq!(message.header.msg_type, "error");
    assert!(!target.exists());

    shutdown(&mut mgr).await
}

fn seeded_denying_rx() -> SharedRateCounter {
    let now = Instant::now();
    let start = now - Duration::from_secs(10);
    let mut engine = RateEngine::new(
        RateLimits {
            enabled: true,
            max_bytes_tx_per_minute: 0,
            max_bytes_rx_per_minute: 1,
        },
        start,
    );
    let _ = engine.try_record_rx(start + Duration::from_secs(5), 5_000_000);
    let _ = engine.advance(start + Duration::from_secs(10));
    SharedRateCounter::new(engine)
}

#[tokio::test]
async fn rx_denial_rejects_chunk_without_artifact() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let counter = seeded_denying_rx();
    let mut raw = raw_limits();
    raw.chroot = Some(root.to_string_lossy().into_owned());
    raw.counters = Some(RawRateLimits {
        max_bytes_tx_per_minute: Some(0),
        max_bytes_rx_per_minute: Some(1),
    });
    let limits = Arc::new(
        TransferLimits::with_counter(&raw, &FakeNss, counter).expect("seeded limited context"),
    );
    let mut mgr = FileTransferManager::with_limits(limits);

    let target = root.join("rx.bin");
    assert!(
        send_put(&mut mgr, V2, "rx", &target, None, Some(0o644))
            .await?
            .is_empty()
    );
    assert!(
        send_chunk(&mut mgr, V2, "rx", &[0u8; 16], 0)
            .await?
            .is_empty()
    );
    let message = next(&mut mgr).await?;
    assert_eq!(message.header.msg_type, "error");
    assert!(!target.exists());

    shutdown(&mut mgr).await
}

#[tokio::test]
async fn shared_rx_counter_accumulates_across_managers() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut raw = raw_limits();
    raw.chroot = Some(root.to_string_lossy().into_owned());
    let shared = limits_from(&raw);

    let data1 = vec![1u8; 1234];
    let data2 = vec![2u8; 777];
    {
        let mut mgr = FileTransferManager::with_limits(Arc::clone(&shared));
        v2_upload_ok(&mut mgr, "rx1", &root.join("rx1"), &data1).await?;
        shutdown(&mut mgr).await?;
    }
    assert_eq!(
        shared.snapshot_now()?.bytes_received,
        u64::try_from(data1.len())?
    );
    {
        let mut mgr = FileTransferManager::with_limits(Arc::clone(&shared));
        v2_upload_ok(&mut mgr, "rx2", &root.join("rx2"), &data2).await?;
        shutdown(&mut mgr).await?;
    }
    assert_eq!(
        shared.snapshot_now()?.bytes_received,
        u64::try_from(data1.len() + data2.len())?,
        "fresh manager reuses the same shared counter"
    );
    Ok(())
}

async fn expect_preflight_error(root: &Path, target: &Path) -> Result<()> {
    let mut raw = raw_limits();
    raw.chroot = Some(root.to_string_lossy().into_owned());
    let mut mgr = FileTransferManager::with_limits(limits_from(&raw));
    assert!(
        send_put(&mut mgr, V2, "preflight", target, Some(0), Some(0o644))
            .await?
            .is_empty()
    );
    let message = next(&mut mgr).await?;
    assert_eq!(
        message.header.msg_type, "error",
        "existing target must be refused"
    );
    shutdown(&mut mgr).await
}

#[tokio::test]
async fn existing_regular_file_refused_before_ack() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let target = root.join("existing.bin");
    std::fs::write(&target, b"OLD")?;
    expect_preflight_error(root, &target).await?;
    assert_eq!(
        std::fs::read(&target)?,
        b"OLD",
        "existing file is never overwritten"
    );
    Ok(())
}

#[tokio::test]
async fn directory_target_without_src_path_refused_before_ack() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let target = root.join("existingdir");
    std::fs::create_dir(&target)?;
    // Directory shorthand is now supported, but it requires a src_path. A
    // missing src_path must be refused before the initial ACK and must leave the
    // directory untouched.
    expect_preflight_error(root, &target).await?;
    assert!(target.is_dir(), "directory target is left untouched");
    assert!(only_names(&target)?.is_empty(), "no file created inside");
    Ok(())
}

#[tokio::test]
async fn dangling_symlink_refused_before_ack() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let target = root.join("dangling");
    std::os::unix::fs::symlink("missing-target", &target)?;
    expect_preflight_error(root, &target).await?;
    let link_meta = std::fs::symlink_metadata(&target)?;
    assert!(
        link_meta.file_type().is_symlink(),
        "dangling symlink is preserved"
    );
    assert!(!root.join("missing-target").exists());
    Ok(())
}

#[tokio::test]
async fn outside_root_refused() -> Result<()> {
    let root = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    let target = outside.path().join("escape.bin");
    let mut raw = raw_limits();
    raw.chroot = Some(root.path().to_string_lossy().into_owned());
    let mut mgr = FileTransferManager::with_limits(limits_from(&raw));
    assert!(
        send_put(&mut mgr, V2, "outside", &target, Some(0), Some(0o644))
            .await?
            .is_empty()
    );
    let message = next(&mut mgr).await?;
    assert_eq!(message.header.msg_type, "error");
    assert!(!target.exists());
    shutdown(&mut mgr).await
}

#[tokio::test]
async fn escaping_parent_symlink_rejected() -> Result<()> {
    let root = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    let link = root.path().join("link");
    std::os::unix::fs::symlink(outside.path(), &link)?;
    let mut raw = raw_limits();
    raw.chroot = Some(root.path().to_string_lossy().into_owned());
    raw.follow_sym_links = Some(true);
    let mut mgr = FileTransferManager::with_limits(limits_from(&raw));
    let target = link.join("escape.bin");
    assert!(
        send_put(&mut mgr, V2, "escape", &target, Some(0), Some(0o644))
            .await?
            .is_empty()
    );
    let message = next(&mut mgr).await?;
    assert_eq!(message.header.msg_type, "error");
    assert!(!outside.path().join("escape.bin").exists());
    shutdown(&mut mgr).await
}

#[tokio::test]
async fn allowed_relative_parent_symlink_when_configured() -> Result<()> {
    let root = tempfile::tempdir()?;
    let real = root.path().join("realdir");
    std::fs::create_dir(&real)?;
    let link = root.path().join("link");
    std::os::unix::fs::symlink("realdir", &link)?;
    let mut raw = raw_limits();
    raw.chroot = Some(root.path().to_string_lossy().into_owned());
    raw.follow_sym_links = Some(true);
    let mut mgr = FileTransferManager::with_limits(limits_from(&raw));
    let target = link.join("inside.bin");
    let data = b"through the link".to_vec();
    v2_upload_ok(&mut mgr, "rel", &target, &data).await?;
    assert_eq!(std::fs::read(real.join("inside.bin"))?, data);
    shutdown(&mut mgr).await
}

#[tokio::test]
async fn cancellation_before_eof_leaves_no_artifact() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut raw = raw_limits();
    raw.chroot = Some(root.to_string_lossy().into_owned());
    let mut mgr = FileTransferManager::with_limits(limits_from(&raw));
    let target = root.join("cancel.bin");
    assert!(
        send_put(&mut mgr, V2, "cancel", &target, Some(4), Some(0o644))
            .await?
            .is_empty()
    );
    assert!(
        send_chunk(&mut mgr, V2, "cancel", b"ab", 0)
            .await?
            .is_empty()
    );
    tokio::time::timeout(TEST_TIMEOUT, mgr.close_session("cancel")).await??;
    assert!(!target.exists());
    assert!(only_names(root)?.is_empty(), "no staging artifacts remain");
    shutdown(&mut mgr).await
}

#[tokio::test]
async fn malformed_eof_leaves_no_artifact() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut raw = raw_limits();
    raw.chroot = Some(root.to_string_lossy().into_owned());
    let mut mgr = FileTransferManager::with_limits(limits_from(&raw));
    let target = root.join("mal.bin");
    // declared 4 but EOF reported at offset 0
    assert!(
        send_put(&mut mgr, V2, "mal", &target, Some(4), Some(0o644))
            .await?
            .is_empty()
    );
    assert!(send_chunk(&mut mgr, V2, "mal", &[], 0).await?.is_empty());
    let message = next(&mut mgr).await?;
    assert_eq!(message.header.msg_type, "error");
    assert!(!target.exists());
    shutdown(&mut mgr).await
}

#[tokio::test]
async fn final_ack_failure_after_commit_retains_visible_file() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut raw = raw_limits();
    raw.chroot = Some(root.to_string_lossy().into_owned());
    let limits = limits_from(&raw);
    let target = root.join("committed.bin");
    let data = b"committed".to_vec();
    let sid = "finalack".to_string();
    let request = simple_request(&target, Some(i64::try_from(data.len())?), Some(0o644));

    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(8);
    let (out_tx, out_rx) = tokio::sync::mpsc::channel::<ProtoMsg>(8);
    // Drop the output receiver so the final ACK fails after a successful commit.
    drop(out_rx);
    cmd_tx
        .send(chunk(V2, &sid, &data, 0))
        .await
        .map_err(|_| anyhow::anyhow!("queue data chunk"))?;
    cmd_tx
        .send(chunk(V2, &sid, &[], i64::try_from(data.len())?))
        .await
        .map_err(|_| anyhow::anyhow!("queue eof"))?;
    drop(cmd_tx);

    let outcome = tokio::time::timeout(
        TEST_TIMEOUT,
        upload_with_limits(V2, sid, request, cmd_rx, out_tx, Some(limits)),
    )
    .await?;
    let error = match outcome {
        Ok(_) => return Err(anyhow::anyhow!("expected a final ACK failure")),
        Err(error) => error,
    };
    assert!(
        error.downcast_ref::<CommittedAckError>().is_some(),
        "final ACK failure must surface as a CommittedAckError marker"
    );
    assert_eq!(
        std::fs::read(&target)?,
        data,
        "committed file remains visible"
    );
    Ok(())
}
