//! Integration tests for the limited download/stat execution context.
//!
//! These drive the real [`FileTransferManager`] and its owned workers for both
//! the v1 and v2 file-transfer protocols, using bounded channels, tempdirs owned
//! by each test and an injected NSS resolver. Nothing here contacts a real
//! server, host account or private key; every task is bounded and joined before
//! the test returns.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};

use mender_connect_rust::file_transfer_manager::FileTransferManager;
use mender_connect_rust::file_transfer_schema::{FileInfo, GetFile, StatFile, UploadRequest};
use mender_connect_rust::limits_config::{
    NssResolver, RawFileTransferLimits, RawRateLimits, ResolverError,
};
use mender_connect_rust::limits_rate::{RateEngine, RateLimits, SharedRateCounter};
use mender_connect_rust::protocol::{self, ProtoHdr, ProtoMsg, ProtoType};
use mender_connect_rust::transfer_limits::TransferLimits;

const TEST_TIMEOUT: Duration = Duration::from_secs(3);

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

fn get_file_msg(proto: ProtoType, sid: &str, path: &Path) -> Result<ProtoMsg> {
    let body = protocol::encode(&GetFile {
        path: Some(path.to_string_lossy().into_owned()),
    })?;
    Ok(ProtoMsg {
        header: header(proto, sid, "get_file"),
        body,
    })
}

fn stat_msg(proto: ProtoType, sid: &str, path: &Path) -> Result<ProtoMsg> {
    let body = protocol::encode(&StatFile {
        path: Some(path.to_string_lossy().into_owned()),
    })?;
    Ok(ProtoMsg {
        header: header(proto, sid, "stat"),
        body,
    })
}

/// Decode every string carried by a structured error body.
fn error_strings(body: &[u8]) -> Option<Vec<String>> {
    fn collect(value: &rmpv::Value, out: &mut Vec<String>) {
        match value {
            rmpv::Value::String(text) => {
                if let Some(text) = text.as_str() {
                    out.push(text.to_owned());
                }
            }
            rmpv::Value::Array(items) => {
                for item in items {
                    collect(item, out);
                }
            }
            rmpv::Value::Map(pairs) => {
                for (key, value) in pairs {
                    collect(key, out);
                    collect(value, out);
                }
            }
            _ => {}
        }
    }

    let mut cursor = body;
    let value = rmpv::decode::read_value(&mut cursor).ok()?;
    let mut out = Vec::new();
    collect(&value, &mut out);
    Some(out)
}

/// True only for the exact transient "stat busy" error for this request.
fn is_stat_busy(reply: &ProtoMsg, proto: ProtoType, sid: &str) -> bool {
    reply.header.msg_type == "error"
        && reply.header.proto == proto
        && reply.header.session_id == sid
        && error_strings(&reply.body)
            .map(|values| values.iter().any(|value| value.trim() == "stat busy"))
            .unwrap_or(false)
}

/// Perform one stat exchange under a single absolute deadline.
///
/// Immediate "stat busy" replies are the only ones retried; every other
/// immediate reply is surfaced to the caller for its assertions.
async fn stat_exchange(
    manager: &mut FileTransferManager,
    proto: ProtoType,
    sid: &str,
    path: &Path,
) -> Result<ProtoMsg> {
    let deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        let replies = manager.handle(stat_msg(proto, sid, path)?).await?;
        if replies.is_empty() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(anyhow!("stat exchange exceeded {TEST_TIMEOUT:?}"));
            }
            return tokio::time::timeout(remaining, manager.next_message()).await?;
        }
        if replies.len() == 1 && is_stat_busy(&replies[0], proto, sid) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(anyhow!("stat permit stayed busy until {TEST_TIMEOUT:?}"));
            }
            tokio::task::yield_now().await;
            tokio::time::sleep(std::cmp::min(remaining, Duration::from_millis(5))).await;
            continue;
        }
        if replies.len() == 1 {
            return replies
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("unexpected empty stat reply"));
        }
        return Err(anyhow!(
            "unexpected {} immediate stat replies",
            replies.len()
        ));
    }
}

fn ack_msg(proto: ProtoType, sid: &str, offset: i64) -> ProtoMsg {
    let mut properties = BTreeMap::new();
    properties.insert("offset".to_owned(), rmpv::Value::from(offset));
    ProtoMsg {
        header: ProtoHdr {
            proto,
            msg_type: "ack".to_owned(),
            session_id: sid.to_owned(),
            properties,
        },
        body: Vec::new(),
    }
}

async fn shutdown(manager: &mut FileTransferManager) -> Result<()> {
    tokio::time::timeout(TEST_TIMEOUT, manager.close_all()).await??;
    Ok(())
}

/// Drive a v2 download to completion, returning the streamed bytes.
async fn download_v2(manager: &mut FileTransferManager, sid: &str, path: &Path) -> Result<Vec<u8>> {
    let replies = manager
        .handle(get_file_msg(ProtoType::FILE_TRANSFER_V2, sid, path)?)
        .await?;
    assert!(replies.is_empty(), "get_file has no immediate reply");
    let mut data = Vec::new();
    loop {
        let message = tokio::time::timeout(TEST_TIMEOUT, manager.next_message()).await??;
        match message.header.msg_type.as_str() {
            "error" => return Err(anyhow!("unexpected download error")),
            "file_chunk" => {
                if message.body.is_empty() {
                    return Ok(data);
                }
                data.extend_from_slice(&message.body);
            }
            other => return Err(anyhow!("unexpected message {other}")),
        }
    }
}

/// Drive a v1 download, acknowledging every chunk, returning the streamed bytes.
async fn download_v1(manager: &mut FileTransferManager, sid: &str, path: &Path) -> Result<Vec<u8>> {
    let replies = manager
        .handle(get_file_msg(ProtoType::FILE_TRANSFER, sid, path)?)
        .await?;
    assert!(replies.is_empty(), "get_file has no immediate reply");
    let mut data = Vec::new();
    loop {
        let message = tokio::time::timeout(TEST_TIMEOUT, manager.next_message()).await??;
        if message.header.msg_type == "error" {
            return Err(anyhow!("unexpected download error"));
        }
        if message.header.msg_type != "file_chunk" {
            return Err(anyhow!("unexpected message type"));
        }
        let offset = message
            .header
            .properties
            .get("offset")
            .and_then(rmpv::Value::as_i64)
            .ok_or_else(|| anyhow!("missing chunk offset"))?;
        let eof = message.body.is_empty();
        if !eof {
            data.extend_from_slice(&message.body);
        }
        manager
            .handle(ack_msg(ProtoType::FILE_TRANSFER, sid, offset))
            .await?;
        if eof {
            return Ok(data);
        }
    }
}

async fn expect_download_error(
    manager: &mut FileTransferManager,
    proto: ProtoType,
    sid: &str,
    path: &Path,
) -> Result<()> {
    manager.handle(get_file_msg(proto, sid, path)?).await?;
    let message = tokio::time::timeout(TEST_TIMEOUT, manager.next_message()).await??;
    assert_eq!(
        message.header.msg_type, "error",
        "expected a structured transfer error"
    );
    Ok(())
}

#[tokio::test]
async fn allowed_v2_download_is_byte_exact_with_eof() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let data: Vec<u8> = (0u8..=200).cycle().take(9000).collect();
    let file = dir.path().join("payload.bin");
    std::fs::write(&file, &data)?;

    let mut raw = raw_limits();
    raw.chroot = Some(dir.path().to_string_lossy().into_owned());
    let mut manager = FileTransferManager::with_limits(limits_from(&raw));

    let received = download_v2(&mut manager, "v2", &file).await?;
    assert_eq!(received, data, "streamed bytes must match exactly");
    shutdown(&mut manager).await
}

#[tokio::test]
async fn allowed_v1_download_is_byte_exact_with_ack_eof() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let data: Vec<u8> = (0u8..=250).cycle().take(20_000).collect();
    let file = dir.path().join("payload.bin");
    std::fs::write(&file, &data)?;

    let mut raw = raw_limits();
    raw.chroot = Some(dir.path().to_string_lossy().into_owned());
    let mut manager = FileTransferManager::with_limits(limits_from(&raw));

    let received = download_v1(&mut manager, "v1", &file).await?;
    assert_eq!(received, data, "streamed bytes must match exactly");
    shutdown(&mut manager).await
}

#[tokio::test]
async fn owner_denial_is_structured_error() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("secret");
    std::fs::write(&file, b"hello")?;

    let mut raw = raw_limits();
    raw.chroot = Some(dir.path().to_string_lossy().into_owned());
    raw.owner_get = Some(vec!["bob".to_owned()]);
    let mut manager = FileTransferManager::with_limits(limits_from(&raw));

    expect_download_error(&mut manager, ProtoType::FILE_TRANSFER_V2, "owner", &file).await?;
    shutdown(&mut manager).await
}

#[tokio::test]
async fn group_denial_is_structured_error() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("secret");
    std::fs::write(&file, b"hello")?;

    let mut raw = raw_limits();
    raw.chroot = Some(dir.path().to_string_lossy().into_owned());
    raw.group_get = Some(vec!["strangers".to_owned()]);
    let mut manager = FileTransferManager::with_limits(limits_from(&raw));

    expect_download_error(&mut manager, ProtoType::FILE_TRANSFER, "group", &file).await?;
    shutdown(&mut manager).await
}

#[tokio::test]
async fn size_denial_is_structured_error() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("big");
    std::fs::write(&file, vec![0u8; 4096])?;

    let mut raw = raw_limits();
    raw.chroot = Some(dir.path().to_string_lossy().into_owned());
    raw.max_file_size = Some(1024);
    let mut manager = FileTransferManager::with_limits(limits_from(&raw));

    expect_download_error(&mut manager, ProtoType::FILE_TRANSFER_V2, "size", &file).await?;
    shutdown(&mut manager).await
}

#[tokio::test]
async fn outside_root_and_component_prefix_are_rejected() -> Result<()> {
    let root = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    let outside_file = outside.path().join("elsewhere");
    std::fs::write(&outside_file, b"outside")?;

    let mut raw = raw_limits();
    raw.chroot = Some(root.path().to_string_lossy().into_owned());
    let limits = limits_from(&raw);

    let mut manager = FileTransferManager::with_limits(Arc::clone(&limits));
    expect_download_error(
        &mut manager,
        ProtoType::FILE_TRANSFER_V2,
        "outside",
        &outside_file,
    )
    .await?;
    shutdown(&mut manager).await?;

    // A sibling whose path shares the root's string prefix but not its
    // component prefix must be rejected too.
    let prefix = root.path().with_file_name(format!(
        "{}-sibling",
        root.path()
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    ));
    let prefixed = prefix.join("file");
    let mut manager = FileTransferManager::with_limits(limits);
    expect_download_error(&mut manager, ProtoType::FILE_TRANSFER, "prefix", &prefixed).await?;
    shutdown(&mut manager).await
}

#[tokio::test]
async fn refused_symlink_is_rejected() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let real = dir.path().join("real");
    std::fs::write(&real, b"data")?;
    let link = dir.path().join("link");
    std::os::unix::fs::symlink("real", &link)?;

    let mut raw = raw_limits();
    raw.chroot = Some(dir.path().to_string_lossy().into_owned());
    raw.follow_sym_links = Some(false);
    let mut manager = FileTransferManager::with_limits(limits_from(&raw));

    expect_download_error(&mut manager, ProtoType::FILE_TRANSFER_V2, "refused", &link).await?;
    shutdown(&mut manager).await
}

#[tokio::test]
async fn escaping_symlink_is_rejected() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    let outside_file = outside.path().join("elsewhere");
    std::fs::write(&outside_file, b"outside")?;
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&outside_file, &link)?;

    let mut raw = raw_limits();
    raw.chroot = Some(dir.path().to_string_lossy().into_owned());
    raw.follow_sym_links = Some(true);
    let mut manager = FileTransferManager::with_limits(limits_from(&raw));

    expect_download_error(&mut manager, ProtoType::FILE_TRANSFER_V2, "escape", &link).await?;
    shutdown(&mut manager).await
}

#[tokio::test]
async fn allowed_relative_symlink_is_followed() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let data = b"through the link".to_vec();
    let real = dir.path().join("real");
    std::fs::write(&real, &data)?;
    let link = dir.path().join("link");
    std::os::unix::fs::symlink("real", &link)?;

    let mut raw = raw_limits();
    raw.chroot = Some(dir.path().to_string_lossy().into_owned());
    raw.follow_sym_links = Some(true);
    let mut manager = FileTransferManager::with_limits(limits_from(&raw));

    let received = download_v2(&mut manager, "follow", &link).await?;
    assert_eq!(received, data, "relative in-root symlink resolves");
    shutdown(&mut manager).await
}

fn make_fifo(path: &Path) -> Result<()> {
    let c_path = CString::new(path.as_os_str().as_bytes())?;
    rustix::fs::mknodat(
        rustix::fs::CWD,
        c_path.as_c_str(),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_bits_truncate(0o600),
        0u64,
    )?;
    Ok(())
}

#[tokio::test]
async fn missing_directory_and_fifo_are_rejected() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let subdir = dir.path().join("subdir");
    std::fs::create_dir(&subdir)?;
    let fifo = dir.path().join("pipe");
    make_fifo(&fifo)?;
    let missing = dir.path().join("absent");

    let mut raw = raw_limits();
    raw.chroot = Some(dir.path().to_string_lossy().into_owned());
    let limits = limits_from(&raw);

    for (sid, path) in [
        ("missing", &missing),
        ("directory", &subdir),
        ("fifo", &fifo),
    ] {
        let mut manager = FileTransferManager::with_limits(Arc::clone(&limits));
        expect_download_error(&mut manager, ProtoType::FILE_TRANSFER_V2, sid, path).await?;
        shutdown(&mut manager).await?;
    }
    Ok(())
}

#[tokio::test]
async fn limited_stat_returns_descriptor_metadata_and_timestamp() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("stats.bin");
    std::fs::write(&file, vec![7u8; 1234])?;
    let fs_meta = std::fs::metadata(&file)?;

    let mut raw = raw_limits();
    raw.chroot = Some(dir.path().to_string_lossy().into_owned());
    let mut manager = FileTransferManager::with_limits(limits_from(&raw));

    let message = stat_exchange(&mut manager, ProtoType::FILE_TRANSFER_V2, "stat", &file).await?;
    assert_eq!(message.header.msg_type, "file_info");
    let info: FileInfo = protocol::decode(&message.body)?;
    assert_eq!(info.size, Some(1234));
    assert_eq!(info.uid, Some(fs_meta.uid()));
    assert_eq!(info.gid, Some(fs_meta.gid()));
    let mode = info.mode.ok_or_else(|| anyhow!("missing mode"))?;
    assert_eq!(
        mode & 0o777,
        fs_meta.mode() & 0o777,
        "permission bits preserved"
    );
    assert_eq!(
        mode & (1 << 31),
        0,
        "regular file must not advertise dir bit"
    );
    assert!(info.modtime.is_some(), "timestamp must be present");
    assert_eq!(info.path, file.to_string_lossy());
    shutdown(&mut manager).await
}

#[tokio::test]
async fn limited_stat_denial_is_structured_error() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("stat-denied");
    std::fs::write(&file, b"data")?;

    let mut raw = raw_limits();
    raw.chroot = Some(dir.path().to_string_lossy().into_owned());
    raw.owner_get = Some(vec!["bob".to_owned()]);
    let mut manager = FileTransferManager::with_limits(limits_from(&raw));

    let message =
        stat_exchange(&mut manager, ProtoType::FILE_TRANSFER, "stat-denied", &file).await?;
    assert_eq!(message.header.msg_type, "error");
    let reasons = error_strings(&message.body)
        .ok_or_else(|| anyhow!("stat denial must carry a decodable structured error"))?;
    assert!(
        !reasons.iter().any(|reason| reason.trim() == "stat busy"),
        "owner denial must not be reported as a transient busy error: {reasons:?}"
    );
    let lowered: Vec<String> = reasons
        .iter()
        .map(|reason| reason.to_ascii_lowercase())
        .collect();
    assert!(
        lowered.iter().any(|reason| reason.contains("owner")
            || reason.contains("permission")
            || reason.contains("denied")
            || reason.contains("not permitted")),
        "expected an owner-denial reason, got {reasons:?}"
    );
    shutdown(&mut manager).await
}

#[tokio::test]
async fn default_manager_stat_bypasses_limits() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("unlimited");
    std::fs::write(&file, b"data")?;

    let mut manager = FileTransferManager::new();
    let message =
        stat_exchange(&mut manager, ProtoType::FILE_TRANSFER_V2, "default", &file).await?;
    assert_eq!(message.header.msg_type, "file_info");
    shutdown(&mut manager).await
}

#[tokio::test]
async fn limited_upload_outside_root_is_refused_without_staging() -> Result<()> {
    let root = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    let target = outside.path().join("upload-target");

    let mut raw = raw_limits();
    raw.chroot = Some(root.path().to_string_lossy().into_owned());
    let mut manager = FileTransferManager::with_limits(limits_from(&raw));

    let body = protocol::encode(&UploadRequest {
        path: Some(target.to_string_lossy().into_owned()),
        src_path: None,
        size: Some(0),
        uid: None,
        gid: None,
        mode: None,
        modtime: None,
    })?;
    // The worker starts (no immediate refusal) but must fail before any initial
    // ACK or staging allocation because the target is outside the trusted root.
    let replies = manager
        .handle(ProtoMsg {
            header: header(ProtoType::FILE_TRANSFER_V2, "upload", "put_file"),
            body,
        })
        .await?;
    assert!(replies.is_empty(), "worker adjudicates asynchronously");
    let message = tokio::time::timeout(Duration::from_secs(3), manager.next_message()).await??;
    assert_eq!(
        message.header.msg_type, "error",
        "outside-root upload must be refused"
    );
    assert!(
        !target.exists(),
        "no file or staging may be created outside root"
    );
    let mut inside: Vec<String> = std::fs::read_dir(root.path())?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<std::result::Result<_, _>>()?;
    inside.sort();
    assert!(inside.is_empty(), "no staging artifacts inside root");
    shutdown(&mut manager).await
}

fn seeded_denying_counter() -> SharedRateCounter {
    let now = Instant::now();
    let start = now - Duration::from_secs(10);
    let mut engine = RateEngine::new(
        RateLimits {
            enabled: true,
            max_bytes_tx_per_minute: 1,
            max_bytes_rx_per_minute: 0,
        },
        start,
    );
    // Push the soft average above the configured limit using the manual clock,
    // then advance to "now" so real-time recording observes the seeded state.
    let _ = engine.try_record_tx(start + Duration::from_secs(5), 5_000_000);
    let _ = engine.advance(start + Duration::from_secs(10));
    SharedRateCounter::new(engine)
}

#[tokio::test]
async fn rate_denial_is_structured_error() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("payload");
    std::fs::write(&file, vec![0u8; 128])?;

    let counter = seeded_denying_counter();
    let mut raw = raw_limits();
    raw.counters = Some(RawRateLimits {
        max_bytes_tx_per_minute: Some(1),
        max_bytes_rx_per_minute: Some(0),
    });
    let limits = Arc::new(
        TransferLimits::with_counter(&raw, &FakeNss, counter).expect("seeded limited context"),
    );
    let mut manager = FileTransferManager::with_limits(limits);

    expect_download_error(&mut manager, ProtoType::FILE_TRANSFER_V2, "rate", &file).await?;
    shutdown(&mut manager).await
}

#[tokio::test]
async fn fresh_manager_reusing_context_retains_rate_totals() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let first = dir.path().join("first");
    let second = dir.path().join("second");
    let first_data = vec![1u8; 3000];
    let second_data = vec![2u8; 2500];
    std::fs::write(&first, &first_data)?;
    std::fs::write(&second, &second_data)?;

    let mut raw = raw_limits();
    raw.chroot = Some(dir.path().to_string_lossy().into_owned());
    let shared = limits_from(&raw);

    let mut manager = FileTransferManager::with_limits(Arc::clone(&shared));
    assert_eq!(
        download_v2(&mut manager, "first", &first).await?,
        first_data
    );
    let after_first = shared.snapshot_now()?;
    assert_eq!(after_first.bytes_sent, first_data.len() as u64);
    shutdown(&mut manager).await?;

    let mut manager = FileTransferManager::with_limits(Arc::clone(&shared));
    assert_eq!(
        download_v2(&mut manager, "second", &second).await?,
        second_data
    );
    let after_second = shared.snapshot_now()?;
    assert_eq!(
        after_second.bytes_sent,
        (first_data.len() + second_data.len()) as u64,
        "a fresh manager shares the same counter"
    );
    shutdown(&mut manager).await
}

#[test]
fn with_counter_rejects_mismatched_engine_and_accepts_identical() {
    let mut raw = raw_limits();
    raw.counters = Some(RawRateLimits {
        max_bytes_tx_per_minute: Some(1),
        max_bytes_rx_per_minute: Some(0),
    });
    let expected = RateLimits {
        enabled: true,
        max_bytes_tx_per_minute: 1,
        max_bytes_rx_per_minute: 0,
    };

    // An identically configured counter is accepted.
    let identical = SharedRateCounter::new(RateEngine::new(expected, Instant::now()));
    assert!(TransferLimits::with_counter(&raw, &FakeNss, identical).is_ok());

    // A disabled counter must not silently bypass the configured limits.
    let disabled = SharedRateCounter::new(RateEngine::new(
        RateLimits {
            enabled: false,
            ..expected
        },
        Instant::now(),
    ));
    assert!(TransferLimits::with_counter(&raw, &FakeNss, disabled).is_err());

    // A TX threshold mismatch is rejected.
    let tx_bad = SharedRateCounter::new(RateEngine::new(
        RateLimits {
            max_bytes_tx_per_minute: 2,
            ..expected
        },
        Instant::now(),
    ));
    assert!(TransferLimits::with_counter(&raw, &FakeNss, tx_bad).is_err());

    // An RX threshold mismatch is rejected.
    let rx_bad = SharedRateCounter::new(RateEngine::new(
        RateLimits {
            max_bytes_rx_per_minute: 5,
            ..expected
        },
        Instant::now(),
    ));
    assert!(TransferLimits::with_counter(&raw, &FakeNss, rx_bad).is_err());
}
