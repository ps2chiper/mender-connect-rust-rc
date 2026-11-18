//! Blackbox regressions for sanitized successful `stat` (`file_info`) replies.
//!
//! These tests drive the public [`FileTransferManager`] together with the real
//! `transport` and `protocol` APIs. They assert observable behavior only: a
//! successful `stat` reply must preserve the request protocol, admitted session
//! identity, and a bounded string `msgid`, while dropping every other inbound
//! property (offsets, unknown metadata, padding, oversized or non-string
//! correlation values). The reply must then survive the daemon's actual
//! outbound encoder and stay within the shared frame budget.
//!
//! The `stat` lane uses a process-wide single permit, so every case here runs
//! sequentially inside one `#[tokio::test]` to avoid a flaky parallel
//! stat-busy race.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::Result;
use mender_connect_rust::file_transfer_manager::FileTransferManager;
use mender_connect_rust::file_transfer_schema::{FileInfo, StatFile, TransferError, UploadRequest};
use mender_connect_rust::protocol::{self, ProtoHdr, ProtoMsg, ProtoType};
use mender_connect_rust::transport::{
    MAX_INBOUND_MESSAGE_SIZE, encode_outbound_message, validate_inbound_message,
};
use rmpv::Value;
use tokio::time::timeout;

const V1: ProtoType = ProtoType::FILE_TRANSFER;
const V2: ProtoType = ProtoType::FILE_TRANSFER_V2;
const CALL_TIMEOUT: Duration = Duration::from_secs(4);

/// Build a `stat` request whose header can carry arbitrary (possibly invalid)
/// metadata. Only `msgid`, `offset`, and an optional `pad` property are set.
fn stat_request(
    proto: ProtoType,
    sid: &str,
    path: &str,
    msgid: Option<Value>,
    offset: Option<Value>,
    pad: usize,
) -> Result<ProtoMsg> {
    let mut properties = BTreeMap::new();
    if let Some(msgid) = msgid {
        properties.insert("msgid".to_owned(), msgid);
    }
    if let Some(offset) = offset {
        properties.insert("offset".to_owned(), offset);
    }
    if pad > 0 {
        properties.insert("pad".to_owned(), Value::from("x".repeat(pad)));
    }
    let body = protocol::encode(&StatFile {
        path: Some(path.to_owned()),
    })?;
    Ok(ProtoMsg {
        header: ProtoHdr {
            proto,
            msg_type: "stat".to_owned(),
            session_id: sid.to_owned(),
            properties,
        },
        body,
    })
}

/// Submit a `stat` request and return the single reply the manager yields,
/// whether it is delivered synchronously from `handle` or asynchronously from
/// `next_message`.
async fn run_stat(mgr: &mut FileTransferManager, request: ProtoMsg) -> Result<ProtoMsg> {
    let immediate = timeout(CALL_TIMEOUT, mgr.handle(request)).await??;
    if let Some(first) = immediate.into_iter().next() {
        return Ok(first);
    }
    timeout(CALL_TIMEOUT, mgr.next_message()).await?
}

fn payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| u8::try_from(index % 251).unwrap_or(0))
        .collect()
}

/// Largest padding whose encoded request (with a valid `offset`) still fits in
/// the frame budget.
///
/// The length is measured with the ordinary message encoder on a frame that
/// carries a *valid* `offset`. The outbound per-frame validator rejects
/// malformed `offset` values, so a padded frame with a malformed offset must
/// never be sized through that validator; sizing a valid variant avoids it.
fn pad_to_near_limit(proto: ProtoType, sid: &str, path: &str, msgid: &str) -> Result<usize> {
    let target = MAX_INBOUND_MESSAGE_SIZE;
    let mut low = 0usize;
    let mut high = target;
    while low < high {
        let mid = low + (high - low).div_ceil(2);
        let frame = stat_request(
            proto,
            sid,
            path,
            Some(Value::from(msgid)),
            Some(Value::from(0i64)),
            mid,
        )?;
        let len = protocol::encode_message(&frame)?.len();
        if len <= target {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    Ok(low)
}

/// A successful `stat` on an existing tempfile must not reflect the request's
/// `offset` (whether a plain value or a malformed one) or any other metadata,
/// and the reply must encode through the daemon's actual outbound encoder.
async fn stat_reply_sanitizes_offsets() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("stat.bin");
    let data = payload(4099);
    std::fs::write(&path, &data)?;
    let path_s = path.to_string_lossy().into_owned();
    let size = i64::try_from(data.len())?;

    let offsets = [
        Value::from(0i64),
        Value::from("not-an-integer"),
        Value::from(-7i64),
        Value::from(u64::MAX),
    ];

    for (index, offset) in offsets.into_iter().enumerate() {
        for proto in [V1, V2] {
            let msgid = format!("m-off-{index}");
            let request = stat_request(
                proto,
                "stat-sid",
                &path_s,
                Some(Value::from(msgid.as_str())),
                Some(offset.clone()),
                0,
            )?;

            // The frame is admitted by routing validation (offset is not a
            // routing identifier).
            validate_inbound_message(&request)?;

            let mut mgr = FileTransferManager::new();
            let reply = run_stat(&mut mgr, request).await?;

            assert_eq!(reply.header.proto, proto);
            assert_eq!(reply.header.session_id, "stat-sid");
            assert_eq!(reply.header.msg_type, "file_info");
            assert!(
                !reply.header.properties.contains_key("offset"),
                "offset must never be reflected in a successful file_info reply"
            );
            assert_eq!(
                reply.header.properties.get("msgid"),
                Some(&Value::from(msgid.as_str()))
            );

            // The daemon would actually send this; it must encode unchanged.
            encode_outbound_message(&reply)?;

            let info: FileInfo = protocol::decode(&reply.body)?;
            assert_eq!(info.path, path_s);
            assert_eq!(info.size, Some(size));

            timeout(CALL_TIMEOUT, mgr.close_all()).await??;
        }
    }
    Ok(())
}

/// A near-frame-limit, admitted request carrying large irrelevant metadata must
/// still yield a bounded `file_info` reply that encodes within the shared frame
/// budget.
async fn stat_reply_near_limit() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("big.bin");
    let data = payload(1024);
    std::fs::write(&path, &data)?;
    let path_s = path.to_string_lossy().into_owned();
    let size = i64::try_from(data.len())?;

    let msgid = "a".repeat(128);
    for proto in [V1, V2] {
        let pad = pad_to_near_limit(proto, "near", &path_s, &msgid)?;
        let request = stat_request(
            proto,
            "near",
            &path_s,
            Some(Value::from(msgid.as_str())),
            Some(Value::from(0i64)),
            pad,
        )?;

        // The near-limit request is admitted by routing validation and the
        // shared frame budget.
        validate_inbound_message(&request)?;
        let request_len = protocol::encode_message(&request)?.len();
        assert!(
            request_len <= MAX_INBOUND_MESSAGE_SIZE,
            "fixture request exceeds the frame budget: {request_len}"
        );
        encode_outbound_message(&request)?;

        let mut mgr = FileTransferManager::new();
        let reply = run_stat(&mut mgr, request).await?;

        assert_eq!(reply.header.msg_type, "file_info");
        // The large irrelevant metadata is dropped, keeping the reply bounded.
        assert!(
            !reply.header.properties.contains_key("pad"),
            "padding metadata must not be reflected"
        );
        assert!(!reply.header.properties.contains_key("offset"));
        assert_eq!(
            reply.header.properties.get("msgid"),
            Some(&Value::from(msgid.as_str()))
        );

        let encoded = encode_outbound_message(&reply)?;
        assert!(
            encoded.len() <= MAX_INBOUND_MESSAGE_SIZE,
            "sanitized file_info reply exceeded the frame budget"
        );

        let info: FileInfo = protocol::decode(&reply.body)?;
        assert_eq!(info.path, path_s);
        assert_eq!(info.size, Some(size));

        timeout(CALL_TIMEOUT, mgr.close_all()).await??;
    }
    Ok(())
}

/// A valid 128-byte multibyte `msgid` is preserved byte-for-byte; a non-string
/// or oversized `msgid` is omitted.
///
/// These are *direct* public-manager cases: they bypass transport admission
/// (which would itself reject a non-string or oversized routing identifier), so
/// they specifically prove the reply sanitizer — not the transport layer — drops
/// the offending value. No UTF-8 byte slicing is performed; the value is handled
/// as a `str`.
async fn stat_reply_msgid_policy() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("msgid.bin");
    let data = payload(2048);
    std::fs::write(&path, &data)?;
    let path_s = path.to_string_lossy().into_owned();
    let size = i64::try_from(data.len())?;

    // 64 two-byte characters == 128 bytes of valid multibyte UTF-8.
    let multibyte = "\u{e9}".repeat(64);
    assert_eq!(multibyte.len(), 128);

    for proto in [V1, V2] {
        // A malformed offset rides along to prove it is also dropped.
        let request = stat_request(
            proto,
            "msgid-sid",
            &path_s,
            Some(Value::from(multibyte.as_str())),
            Some(Value::from("bogus-offset")),
            0,
        )?;

        let mut mgr = FileTransferManager::new();
        let reply = run_stat(&mut mgr, request).await?;
        assert_eq!(reply.header.msg_type, "file_info");
        assert_eq!(
            reply.header.properties.get("msgid"),
            Some(&Value::from(multibyte.as_str())),
            "a valid 128-byte multibyte msgid must be preserved intact"
        );
        assert!(!reply.header.properties.contains_key("offset"));
        encode_outbound_message(&reply)?;
        let info: FileInfo = protocol::decode(&reply.body)?;
        assert_eq!(info.path, path_s);
        assert_eq!(info.size, Some(size));
        timeout(CALL_TIMEOUT, mgr.close_all()).await??;
    }

    // Direct manager cases: non-string and oversized msgid must be omitted.
    let oversized = "a".repeat(129);
    let bad_msgids = [Value::from(42i64), Value::from(oversized.as_str())];
    for bad in bad_msgids {
        for proto in [V1, V2] {
            let request = stat_request(
                proto,
                "msgid-sid",
                &path_s,
                Some(bad.clone()),
                Some(Value::from(0i64)),
                0,
            )?;

            let mut mgr = FileTransferManager::new();
            let reply = run_stat(&mut mgr, request).await?;
            assert_eq!(reply.header.msg_type, "file_info");
            assert!(
                !reply.header.properties.contains_key("msgid"),
                "non-string or oversized msgid must be omitted from a file_info reply"
            );
            encode_outbound_message(&reply)?;
            let info: FileInfo = protocol::decode(&reply.body)?;
            assert_eq!(info.path, path_s);
            assert_eq!(info.size, Some(size));
            timeout(CALL_TIMEOUT, mgr.close_all()).await??;
        }
    }

    Ok(())
}

/// A `stat` on a missing file must still yield a sanitized, encodable `error`
/// reply even when the request carries extraneous metadata.
async fn stat_reply_missing_file() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let missing = dir.path().join("nope.bin").to_string_lossy().into_owned();

    for proto in [V1, V2] {
        let request = stat_request(
            proto,
            "miss-sid",
            &missing,
            Some(Value::from("m-miss")),
            Some(Value::from("not-an-integer")),
            512,
        )?;
        validate_inbound_message(&request)?;

        let mut mgr = FileTransferManager::new();
        let reply = run_stat(&mut mgr, request).await?;

        assert_eq!(reply.header.proto, proto);
        assert_eq!(reply.header.session_id, "miss-sid");
        assert_eq!(reply.header.msg_type, "error");
        assert!(!reply.header.properties.contains_key("offset"));
        assert!(!reply.header.properties.contains_key("pad"));
        assert_eq!(
            reply.header.properties.get("msgid"),
            Some(&Value::from("m-miss"))
        );

        encode_outbound_message(&reply)?;

        let body: TransferError = protocol::decode(&reply.body)?;
        assert!(body.err.is_some());
        assert_eq!(body.msgtype.as_deref(), Some("stat"));
        assert_eq!(body.msgid.as_deref(), Some("m-miss"));

        timeout(CALL_TIMEOUT, mgr.close_all()).await??;
    }
    Ok(())
}

/// An unrelated active v2 upload must still complete byte-exact after a
/// successful `stat` reply is processed and encoded in the middle of the
/// transfer.
async fn stat_reply_with_active_upload() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let target = dir.path().join("up.bin");
    let other = dir.path().join("other.bin");
    std::fs::write(&other, b"hello")?;
    let other_s = other.to_string_lossy().into_owned();

    let data = payload(5000);
    let target_s = target.to_string_lossy().into_owned();
    let total = i64::try_from(data.len())?;

    let mut mgr = FileTransferManager::new();

    // Start a v2 upload.
    let put_body = protocol::encode(&UploadRequest {
        path: Some(target_s.clone()),
        src_path: None,
        size: Some(total),
        uid: None,
        gid: None,
        mode: Some(0o644),
        modtime: None,
    })?;
    let put = ProtoMsg {
        header: ProtoHdr {
            proto: V2,
            msg_type: "put_file".to_owned(),
            session_id: "up".to_owned(),
            properties: upload_msgid("p1", 0),
        },
        body: put_body,
    };
    assert!(timeout(CALL_TIMEOUT, mgr.handle(put)).await??.is_empty());

    let first = upload_chunk("up", &data[..2048], 0, "p1");
    assert!(timeout(CALL_TIMEOUT, mgr.handle(first)).await??.is_empty());

    // A successful stat on an unrelated existing file, with malformed metadata.
    let stat = stat_request(
        V2,
        "upstat",
        &other_s,
        Some(Value::from("s1")),
        Some(Value::from("junk-offset")),
        256,
    )?;
    validate_inbound_message(&stat)?;
    let stat_reply = run_stat(&mut mgr, stat).await?;
    assert_eq!(stat_reply.header.msg_type, "file_info");
    assert_eq!(stat_reply.header.session_id, "upstat");
    // Encoding the successful stat reply must not disturb the upload.
    encode_outbound_message(&stat_reply)?;
    let info: FileInfo = protocol::decode(&stat_reply.body)?;
    assert_eq!(info.path, other_s);
    assert_eq!(info.size, Some(5));

    // Finish the upload.
    let rest = upload_chunk("up", &data[2048..], 2048, "p1");
    assert!(timeout(CALL_TIMEOUT, mgr.handle(rest)).await??.is_empty());

    let eof = upload_chunk("up", &[], total, "p1");
    assert!(timeout(CALL_TIMEOUT, mgr.handle(eof)).await??.is_empty());

    let ack = timeout(CALL_TIMEOUT, mgr.next_message()).await??;
    assert_eq!(ack.header.msg_type, "ack");

    // Byte-exact commit with no staging leftovers.
    assert_eq!(std::fs::read(&target)?, data);
    assert_eq!(std::fs::read_dir(dir.path())?.count(), 2);

    timeout(CALL_TIMEOUT, mgr.close_all()).await??;
    Ok(())
}

fn upload_msgid(msgid: &str, offset: i64) -> BTreeMap<String, Value> {
    let mut map = BTreeMap::new();
    map.insert("msgid".to_owned(), Value::from(msgid));
    map.insert("offset".to_owned(), Value::from(offset));
    map
}

fn upload_chunk(sid: &str, data: &[u8], offset: i64, msgid: &str) -> ProtoMsg {
    ProtoMsg {
        header: ProtoHdr {
            proto: V2,
            msg_type: "file_chunk".to_owned(),
            session_id: sid.to_owned(),
            properties: upload_msgid(msgid, offset),
        },
        body: data.to_vec(),
    }
}

/// All `stat` cases run sequentially within this single test because the `stat`
/// lane is bounded by a process-wide single permit.
#[tokio::test]
async fn stat_reply_regressions() -> Result<()> {
    stat_reply_sanitizes_offsets().await?;
    stat_reply_near_limit().await?;
    stat_reply_msgid_policy().await?;
    stat_reply_missing_file().await?;
    stat_reply_with_active_upload().await?;
    Ok(())
}
