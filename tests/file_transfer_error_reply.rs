//! Blackbox regressions for the sanitized file-transfer error reply.
//!
//! These tests exercise the public [`FileTransferManager`] together with the
//! real `transport` and `protocol` APIs. They never touch crate-private helper
//! functions or mirror the implementation; instead they assert observable
//! behavior: a rejected or failed request must produce an `error` reply that
//! the actual outbound encoder can encode within the shared frame budget, while
//! unrelated active transfers keep working.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::Result;
use mender_connect_rust::file_transfer_manager::FileTransferManager;
use mender_connect_rust::file_transfer_schema::{TransferError, UploadRequest};
use mender_connect_rust::protocol::{self, ProtoHdr, ProtoMsg, ProtoType};
use mender_connect_rust::transport::{
    MAX_INBOUND_MESSAGE_SIZE, encode_outbound_message, validate_inbound_message,
};
use rmpv::Value;
use tokio::time::timeout;

const V1: ProtoType = ProtoType::FILE_TRANSFER;
const V2: ProtoType = ProtoType::FILE_TRANSFER_V2;
const CALL_TIMEOUT: Duration = Duration::from_secs(4);

fn base(msgid: &str) -> BTreeMap<String, Value> {
    let mut map = BTreeMap::new();
    map.insert("msgid".to_owned(), Value::from(msgid));
    map
}

fn chunk_request(proto: ProtoType, sid: &str, data: &[u8], offset: i64, msgid: &str) -> ProtoMsg {
    let mut properties = base(msgid);
    properties.insert("offset".to_owned(), Value::from(offset));
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

/// Build a `file_chunk` on an unknown session with an arbitrary `offset` value
/// plus an extra unrelated property that must never be reflected.
fn chunk_with_offset(proto: ProtoType, sid: &str, msgid: Option<&str>, offset: Value) -> ProtoMsg {
    let mut properties = BTreeMap::new();
    if let Some(msgid) = msgid {
        properties.insert("msgid".to_owned(), Value::from(msgid));
    }
    properties.insert("offset".to_owned(), offset);
    properties.insert("junk".to_owned(), Value::from("ignored"));
    ProtoMsg {
        header: ProtoHdr {
            proto,
            msg_type: "file_chunk".to_owned(),
            session_id: sid.to_owned(),
            properties,
        },
        body: Vec::new(),
    }
}

fn chunk_with_offset_and_msgid(
    proto: ProtoType,
    sid: &str,
    offset: Value,
    msgid: Value,
) -> ProtoMsg {
    let mut properties = BTreeMap::new();
    properties.insert("msgid".to_owned(), msgid);
    properties.insert("offset".to_owned(), offset);
    ProtoMsg {
        header: ProtoHdr {
            proto,
            msg_type: "file_chunk".to_owned(),
            session_id: sid.to_owned(),
            properties,
        },
        body: Vec::new(),
    }
}

fn chunk_padded(proto: ProtoType, sid: &str, msgid: &str, offset: i64, pad: usize) -> ProtoMsg {
    let mut properties = base(msgid);
    properties.insert("offset".to_owned(), Value::from(offset));
    properties.insert("pad".to_owned(), Value::from("x".repeat(pad)));
    ProtoMsg {
        header: ProtoHdr {
            proto,
            msg_type: "file_chunk".to_owned(),
            session_id: sid.to_owned(),
            properties,
        },
        body: Vec::new(),
    }
}

fn put_request(
    proto: ProtoType,
    sid: &str,
    path: &str,
    size: i64,
    msgid: &str,
) -> Result<ProtoMsg> {
    let body = protocol::encode(&UploadRequest {
        path: Some(path.to_owned()),
        src_path: None,
        size: Some(size),
        uid: None,
        gid: None,
        mode: Some(0o644),
        modtime: None,
    })?;
    Ok(ProtoMsg {
        header: ProtoHdr {
            proto,
            msg_type: "put_file".to_owned(),
            session_id: sid.to_owned(),
            properties: base(msgid),
        },
        body,
    })
}

fn request_len(request: &ProtoMsg) -> Result<usize> {
    Ok(protocol::encode_message(request)?.len())
}

/// Largest padding whose encoded request still fits within the frame budget.
fn pad_to_near_limit(proto: ProtoType, sid: &str, msgid: &str, offset: i64) -> Result<usize> {
    let target = MAX_INBOUND_MESSAGE_SIZE;
    let mut low = 0usize;
    let mut high = target;
    while low < high {
        let mid = low + (high - low).div_ceil(2);
        if request_len(&chunk_padded(proto, sid, msgid, offset, mid))? <= target {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    Ok(low)
}

#[tokio::test]
async fn unknown_transfer_bad_offset_replies_are_encodable() -> Result<()> {
    for proto in [V1, V2] {
        let offsets = [
            Value::from("not-an-integer"),
            Value::from(-5i64),
            Value::from(u64::MAX),
        ];
        for (index, offset) in offsets.into_iter().enumerate() {
            let msgid = format!("m-{index}");
            let request = chunk_with_offset(proto, "ghost", Some(&msgid), offset);

            // The malformed offset is not a routing identifier, so the frame is
            // admitted by routing validation.
            validate_inbound_message(&request)?;

            let mut mgr = FileTransferManager::new();
            let replies = timeout(CALL_TIMEOUT, mgr.handle(request)).await??;
            assert_eq!(replies.len(), 1, "a single error reply is expected");

            let reply = replies
                .first()
                .ok_or_else(|| anyhow::anyhow!("expected exactly one error reply, got none"))?;

            // Protocol and admitted session identity are preserved.
            assert_eq!(reply.header.proto, proto);
            assert_eq!(reply.header.session_id, "ghost");
            assert_eq!(reply.header.msg_type, "error");

            // The offset and any unrelated inbound properties are omitted.
            assert!(
                !reply.header.properties.contains_key("offset"),
                "offset property must not be reflected in an error reply"
            );
            assert!(
                !reply.header.properties.contains_key("junk"),
                "unrelated inbound properties must not be reflected"
            );
            // The bounded, valid msgid is preserved in both header and body.
            assert_eq!(
                reply.header.properties.get("msgid"),
                Some(&Value::from(msgid.as_str()))
            );

            let body: TransferError = protocol::decode(&reply.body)?;
            assert_eq!(body.msgtype.as_deref(), Some("file_chunk"));
            assert_eq!(body.msgid.as_deref(), Some(msgid.as_str()));

            // The reply the daemon would actually send must encode within budget.
            encode_outbound_message(reply)?;

            timeout(CALL_TIMEOUT, mgr.close_all()).await??;
        }
    }
    Ok(())
}

#[tokio::test]
async fn near_limit_request_error_reply_stays_in_budget() -> Result<()> {
    let msgid = "a".repeat(128);
    for proto in [V1, V2] {
        let pad = pad_to_near_limit(proto, "ghost", &msgid, 0)?;
        let request = chunk_padded(proto, "ghost", &msgid, 0, pad);

        // The near-limit request is otherwise admitted by the shared budget.
        validate_inbound_message(&request)?;
        encode_outbound_message(&request)?;

        let mut mgr = FileTransferManager::new();
        let replies = timeout(CALL_TIMEOUT, mgr.handle(request)).await??;
        assert_eq!(replies.len(), 1);
        let reply = replies
            .first()
            .ok_or_else(|| anyhow::anyhow!("expected an error reply"))?;

        // Large inbound metadata is dropped, so the reply fits the budget.
        assert!(!reply.header.properties.contains_key("pad"));
        assert_eq!(
            reply.header.properties.get("msgid"),
            Some(&Value::from(msgid.as_str()))
        );

        let encoded = encode_outbound_message(reply)?;
        assert!(
            encoded.len() <= MAX_INBOUND_MESSAGE_SIZE,
            "vendor error reply exceeded the frame budget"
        );

        let body: TransferError = protocol::decode(&reply.body)?;
        assert_eq!(body.msgid.as_deref(), Some(msgid.as_str()));

        timeout(CALL_TIMEOUT, mgr.close_all()).await??;
    }
    Ok(())
}

#[tokio::test]
async fn nonstring_and_oversized_msgid_are_omitted() -> Result<()> {
    let oversized = "a".repeat(129);
    let cases = [Value::from(42i64), Value::from(oversized.as_str())];

    for msgid in cases {
        for proto in [V1, V2] {
            // Reach the helper through the public manager with a correlation
            // value the sanitizer must drop rather than reflect.
            let request =
                chunk_with_offset_and_msgid(proto, "ghost", Value::from(0i64), msgid.clone());

            let mut mgr = FileTransferManager::new();
            let replies = timeout(CALL_TIMEOUT, mgr.handle(request)).await??;
            assert_eq!(replies.len(), 1);
            let reply = replies
                .first()
                .ok_or_else(|| anyhow::anyhow!("expected an error reply"))?;

            assert!(
                !reply.header.properties.contains_key("msgid"),
                "non-string or oversized msgid must be omitted from the header"
            );
            let body: TransferError = protocol::decode(&reply.body)?;
            assert!(
                body.msgid.is_none(),
                "non-string or oversized msgid must be omitted from the body"
            );

            // A sanitized reply always encodes.
            encode_outbound_message(reply)?;

            timeout(CALL_TIMEOUT, mgr.close_all()).await??;
        }
    }
    Ok(())
}

#[tokio::test]
async fn active_upload_survives_rejected_request() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let target = dir.path().join("target.bin");
    let data: Vec<u8> = (0..5000u32)
        .map(|index| u8::try_from(index % 251).expect("bounded fixture byte"))
        .collect();
    let target_s = target.to_string_lossy().into_owned();
    let total = i64::try_from(data.len())?;

    let mut mgr = FileTransferManager::new();

    let put = put_request(V2, "up", &target_s, total, "p1")?;
    assert!(timeout(CALL_TIMEOUT, mgr.handle(put)).await??.is_empty());

    let first = chunk_request(V2, "up", &data[..2048], 0, "p1");
    assert!(timeout(CALL_TIMEOUT, mgr.handle(first)).await??.is_empty());

    // A rejected request on an unrelated unknown session with an invalid offset.
    // Its reply must survive handling and outbound encoding without disturbing
    // the active upload.
    let bad = chunk_with_offset(V2, "ghost", Some("m-bad"), Value::from("bogus"));
    validate_inbound_message(&bad)?;
    let replies = timeout(CALL_TIMEOUT, mgr.handle(bad)).await??;
    assert_eq!(replies.len(), 1);
    for reply in &replies {
        // Before the fix this encoding step fails on the invalid offset.
        encode_outbound_message(reply)?;
    }

    let rest = chunk_request(V2, "up", &data[2048..], 2048, "p1");
    assert!(timeout(CALL_TIMEOUT, mgr.handle(rest)).await??.is_empty());

    let eof = chunk_request(V2, "up", &[], total, "p1");
    assert!(timeout(CALL_TIMEOUT, mgr.handle(eof)).await??.is_empty());

    let ack = timeout(CALL_TIMEOUT, mgr.next_message()).await??;
    assert_eq!(ack.header.msg_type, "ack");

    // Byte-exact commit with no staging leftovers.
    assert_eq!(std::fs::read(&target)?, data);
    assert_eq!(std::fs::read_dir(dir.path())?.count(), 1);

    timeout(CALL_TIMEOUT, mgr.close_all()).await??;
    Ok(())
}
