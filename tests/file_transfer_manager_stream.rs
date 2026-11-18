use anyhow::Result;
use mender_connect_rust::file_transfer_manager::FileTransferManager;
use mender_connect_rust::file_transfer_schema::{TransferError, UploadRequest};
use mender_connect_rust::protocol::{self, ProtoHdr, ProtoMsg, ProtoType};
use std::collections::BTreeMap;
use std::fs;
use std::time::Duration;
use tokio::time::timeout;

fn message(typ: &str, body: Vec<u8>, offset: Option<i64>) -> ProtoMsg {
    let mut properties = BTreeMap::new();
    if let Some(offset) = offset {
        properties.insert("offset".to_owned(), offset.into());
    }
    ProtoMsg {
        header: ProtoHdr {
            proto: ProtoType::FILE_TRANSFER_V2,
            msg_type: typ.to_owned(),
            session_id: "unpaced-upload".to_owned(),
            properties,
        },
        body,
    }
}

fn assert_accepted(replies: Vec<ProtoMsg>) {
    let errors: Vec<_> = replies
        .iter()
        .map(|reply| protocol::decode::<TransferError>(&reply.body))
        .collect();
    assert!(replies.is_empty(), "valid stream rejected: {errors:?}");
}

#[tokio::test]
async fn unpaced_v2_upload_backpressures_without_losing_chunks() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let target = dir.path().join("target");
    fs::write(&target, b"OLD")?;
    let data: Vec<u8> = (0..161_000)
        .map(|index| u8::try_from(index % 251).expect("bounded fixture byte"))
        .collect();
    let request = UploadRequest {
        path: Some(target.to_string_lossy().into_owned()),
        src_path: None,
        size: Some(i64::try_from(data.len())?),
        uid: None,
        gid: None,
        mode: Some(0o640),
        modtime: None,
    };
    let mut manager = FileTransferManager::new();
    assert_accepted(
        timeout(
            Duration::from_secs(6),
            manager.handle(message("put_file", protocol::encode(&request)?, None)),
        )
        .await??,
    );
    let mut offset = 0i64;
    for chunk in data.chunks(4096) {
        assert_accepted(
            timeout(
                Duration::from_secs(6),
                manager.handle(message("file_chunk", chunk.to_vec(), Some(offset))),
            )
            .await??,
        );
        offset += i64::try_from(chunk.len())?;
    }
    assert_eq!(fs::read(&target)?, b"OLD");
    assert_accepted(
        timeout(
            Duration::from_secs(6),
            manager.handle(message("file_chunk", Vec::new(), Some(offset))),
        )
        .await??,
    );
    let ack = timeout(Duration::from_secs(2), manager.next_message()).await??;
    assert_eq!(ack.header.msg_type, "ack");
    assert_eq!(ack.header.proto, ProtoType::FILE_TRANSFER_V2);
    assert_eq!(ack.header.session_id, "unpaced-upload");
    assert!(!ack.header.properties.contains_key("offset"));
    assert_eq!(fs::read(&target)?, data);
    assert_eq!(fs::read_dir(dir.path())?.count(), 1);
    timeout(Duration::from_secs(2), manager.close_all()).await??;
    Ok(())
}
