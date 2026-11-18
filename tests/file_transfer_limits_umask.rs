//! Manager-level regression for the omitted-mode umask ceiling.
//!
//! Drives the real [`FileTransferManager`] over both the v1 and v2 protocols
//! with a zero-byte upload that omits the wire mode while the policy configures
//! `Umask = 0777`. After the EOF and a scoped session close the committed file's
//! permission bits must be `000`: the configured ceiling cannot be bypassed by
//! an absent mode. The private staging default is `0600`, so a default
//! `Umask = 0` upload must retain `0600`.
//!
//! Only file metadata (owner-independent `stat` bits) is inspected, never the
//! protected contents. Bounded channels/timeouts are used, the temp root is
//! owned and NSS is injected. No host data, accounts, network or QEMU is used.

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;

use mender_connect_rust::file_transfer_manager::FileTransferManager;
use mender_connect_rust::file_transfer_schema::UploadRequest;
use mender_connect_rust::limits_config::{NssResolver, RawFileTransferLimits, ResolverError};
use mender_connect_rust::protocol::{self, ProtoHdr, ProtoMsg, ProtoType};
use mender_connect_rust::transfer_limits::TransferLimits;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const V1: ProtoType = ProtoType::FILE_TRANSFER;
const V2: ProtoType = ProtoType::FILE_TRANSFER_V2;

/// Deterministic NSS resolver with no host account dependency.
struct FakeNss;

impl NssResolver for FakeNss {
    fn lookup_user(&self, _name: &str) -> std::result::Result<Option<u32>, ResolverError> {
        Ok(None)
    }

    fn lookup_group(&self, _name: &str) -> std::result::Result<Option<u32>, ResolverError> {
        Ok(None)
    }
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

fn eof_chunk(proto: ProtoType, sid: &str, off: i64) -> ProtoMsg {
    let mut properties = BTreeMap::new();
    properties.insert("offset".to_owned(), rmpv::Value::from(off));
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

fn offset(msg: &ProtoMsg) -> Option<i64> {
    match msg.header.properties.get("offset") {
        Some(rmpv::Value::Integer(integer)) => integer.as_i64(),
        _ => None,
    }
}

fn omitted_mode_request(target: &Path) -> UploadRequest {
    UploadRequest {
        path: Some(target.to_string_lossy().into_owned()),
        src_path: None,
        size: Some(0),
        uid: None,
        gid: None,
        mode: None,
        modtime: None,
    }
}

async fn next(mgr: &mut FileTransferManager) -> Result<ProtoMsg> {
    tokio::time::timeout(TEST_TIMEOUT, mgr.next_message()).await?
}

async fn shutdown(mgr: &mut FileTransferManager) -> Result<()> {
    tokio::time::timeout(TEST_TIMEOUT, mgr.close_all()).await??;
    Ok(())
}

/// Drive a zero-byte upload whose wire request omits the mode, then close the
/// session without draining the final ACK, and assert the committed mode bits.
async fn zero_byte_omitted_mode(umask: &str, expected_bits: u32) -> Result<()> {
    for (proto, sid) in [(V1, "umask-v1"), (V2, "umask-v2")] {
        let dir = tempfile::tempdir()?;
        let root = dir.path();
        let raw = RawFileTransferLimits {
            chroot: Some(root.to_string_lossy().into_owned()),
            umask: Some(umask.to_owned()),
            ..Default::default()
        };
        let limits = Arc::new(TransferLimits::new(&raw, &FakeNss).expect("limited context"));
        let mut mgr = FileTransferManager::with_limits(limits);

        let target = root.join(format!("{sid}-zero.bin"));
        let request = omitted_mode_request(&target);
        assert!(
            tokio::time::timeout(TEST_TIMEOUT, mgr.handle(put_msg(proto, sid, &request)?))
                .await??
                .is_empty(),
            "put_file has no immediate reply"
        );
        if proto == V1 {
            let ack = next(&mut mgr).await?;
            assert_eq!(ack.header.msg_type, "ack");
            assert_eq!(offset(&ack), Some(0));
        }

        // Zero-length EOF chunk at offset 0.
        assert!(
            tokio::time::timeout(TEST_TIMEOUT, mgr.handle(eof_chunk(proto, sid, 0)))
                .await??
                .is_empty()
        );

        // Scoped close without draining the final ACK: the committed file must
        // still reflect the configured umask.
        tokio::time::timeout(TEST_TIMEOUT, mgr.close_session(sid)).await??;

        let mode = std::fs::metadata(&target)?.mode() & 0o777;
        assert_eq!(mode, expected_bits, "committed mode for {sid}");

        shutdown(&mut mgr).await?;
    }
    Ok(())
}

#[tokio::test]
async fn omitted_mode_full_umask_commits_zero_permission_bits() -> Result<()> {
    zero_byte_omitted_mode("0777", 0o000).await
}

#[tokio::test]
async fn omitted_mode_default_umask_retains_private_default() -> Result<()> {
    zero_byte_omitted_mode("0", 0o600).await
}
