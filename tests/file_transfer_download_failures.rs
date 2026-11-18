use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, anyhow};
use mender_connect_rust::file_transfer_download::{DownloadOutcome, download};
use mender_connect_rust::protocol::{ProtoHdr, ProtoMsg, ProtoType};
use nix::sys::stat::Mode;
use nix::unistd::mkfifo;
use tempfile::tempdir;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;

struct AbortOnDrop<T>(JoinHandle<T>);

impl<T> AbortOnDrop<T> {
    fn new(handle: JoinHandle<T>) -> Self {
        Self(handle)
    }

    fn handle(&mut self) -> &mut JoinHandle<T> {
        &mut self.0
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Clone, Copy, Debug)]
enum BadAck {
    OffsetMinusOne,
    OffsetAboveSent,
    AbsentOffset,
    StringOffset,
    WrongSid,
    WrongProto,
    WrongMsgType,
}

fn make_ack(case: BadAck) -> ProtoMsg {
    let (sid, proto, msg_type, offset) = match case {
        BadAck::OffsetMinusOne => (
            "s",
            ProtoType::FILE_TRANSFER,
            "ack",
            Some(rmpv::Value::from(-1i64)),
        ),
        BadAck::OffsetAboveSent => (
            "s",
            ProtoType::FILE_TRANSFER,
            "ack",
            Some(rmpv::Value::from(4097i64)),
        ),
        BadAck::AbsentOffset => ("s", ProtoType::FILE_TRANSFER, "ack", None),
        BadAck::StringOffset => (
            "s",
            ProtoType::FILE_TRANSFER,
            "ack",
            Some(rmpv::Value::from("not-an-offset")),
        ),
        BadAck::WrongSid => (
            "other",
            ProtoType::FILE_TRANSFER,
            "ack",
            Some(rmpv::Value::from(4096i64)),
        ),
        BadAck::WrongProto => (
            "s",
            ProtoType::FILE_TRANSFER_V2,
            "ack",
            Some(rmpv::Value::from(4096i64)),
        ),
        BadAck::WrongMsgType => (
            "s",
            ProtoType::FILE_TRANSFER,
            "data",
            Some(rmpv::Value::from(4096i64)),
        ),
    };

    let mut header = ProtoHdr {
        proto,
        msg_type: msg_type.to_string(),
        session_id: sid.to_string(),
        ..ProtoHdr::default()
    };
    if let Some(value) = offset {
        header.properties.insert("offset".to_string(), value);
    }

    ProtoMsg {
        header,
        body: Vec::new(),
    }
}

#[tokio::test]
async fn v1_rejects_invalid_final_ack() -> Result<()> {
    for case in [
        BadAck::OffsetMinusOne,
        BadAck::OffsetAboveSent,
        BadAck::AbsentOffset,
        BadAck::StringOffset,
        BadAck::WrongSid,
        BadAck::WrongProto,
        BadAck::WrongMsgType,
    ] {
        let temp = tempdir()?;
        let source = temp.path().join("source.bin");
        std::fs::write(&source, vec![0x5Au8; 4096])?;

        let (out_tx, mut out_rx) = mpsc::channel(16);
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let mut guard = AbortOnDrop::new(tokio::spawn(async move {
            download(
                ProtoType::FILE_TRANSFER,
                "s".to_string(),
                source,
                cmd_rx,
                out_tx,
            )
            .await
        }));

        let data = timeout(Duration::from_secs(2), out_rx.recv())
            .await?
            .ok_or_else(|| anyhow!("missing data frame for {:?}", case))?;
        assert_eq!(data.body.len(), 4096, "case {:?}", case);

        let eof = timeout(Duration::from_secs(2), out_rx.recv())
            .await?
            .ok_or_else(|| anyhow!("missing eof frame for {:?}", case))?;
        assert!(eof.body.is_empty(), "case {:?}", case);

        cmd_tx.send(make_ack(case)).await?;

        let joined = timeout(Duration::from_secs(2), guard.handle()).await?;
        let worker_result: Result<DownloadOutcome> = joined?;
        assert!(worker_result.is_err(), "case {:?} was accepted", case);

        drop(cmd_tx);
    }

    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum BadV2 {
    Directory,
    FinalSymlink,
    Fifo,
    Sparse,
    InvalidProto,
    EmptySid,
    NulPath,
}

#[tokio::test]
async fn v2_rejects_invalid_local_inputs() -> Result<()> {
    for case in [
        BadV2::Directory,
        BadV2::FinalSymlink,
        BadV2::Fifo,
        BadV2::Sparse,
        BadV2::InvalidProto,
        BadV2::EmptySid,
        BadV2::NulPath,
    ] {
        let temp = tempdir()?;
        let mut proto = ProtoType::FILE_TRANSFER_V2;
        let mut sid = "s".to_string();

        let path = match case {
            BadV2::Directory => {
                let dir = temp.path().join("dir");
                std::fs::create_dir(&dir)?;
                dir
            }
            BadV2::FinalSymlink => {
                let target = temp.path().join("target");
                std::fs::write(&target, b"target")?;
                let link = temp.path().join("link");
                symlink(&target, &link)?;
                link
            }
            BadV2::Fifo => {
                let fifo = temp.path().join("fifo");
                mkfifo(&fifo, Mode::S_IRUSR | Mode::S_IWUSR)?;
                fifo
            }
            BadV2::Sparse => {
                let sparse = temp.path().join("sparse");
                let file = std::fs::File::create(&sparse)?;
                file.set_len(256 * 1024 * 1024 + 1)?;
                sparse
            }
            BadV2::InvalidProto => {
                proto = ProtoType::SHELL;
                let regular = temp.path().join("regular");
                std::fs::write(&regular, b"regular")?;
                regular
            }
            BadV2::EmptySid => {
                sid.clear();
                let regular = temp.path().join("regular");
                std::fs::write(&regular, b"regular")?;
                regular
            }
            BadV2::NulPath => {
                let mut bytes = temp.path().join("nul").into_os_string().into_vec();
                bytes.push(0);
                PathBuf::from(OsString::from_vec(bytes))
            }
        };

        let (out_tx, _out_rx) = mpsc::channel(16);
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let mut guard = AbortOnDrop::new(tokio::spawn(async move {
            download(proto, sid, path, cmd_rx, out_tx).await
        }));

        let joined = timeout(Duration::from_secs(2), guard.handle()).await?;
        let worker_result: Result<DownloadOutcome> = joined?;
        assert!(worker_result.is_err(), "case {:?} was accepted", case);

        drop(cmd_tx);
    }

    Ok(())
}

#[tokio::test]
async fn peer_error_cancels_download_for_both_protocols() -> Result<()> {
    const MAX_BYTES: usize = 512 * 1024;

    for proto in [ProtoType::FILE_TRANSFER, ProtoType::FILE_TRANSFER_V2] {
        let temp = tempdir()?;
        let source = temp.path().join("source.bin");
        std::fs::write(&source, vec![0xA5u8; MAX_BYTES])?;

        let (out_tx, mut out_rx) = mpsc::channel(4);
        let (cmd_tx, cmd_rx) = mpsc::channel(8);
        let mut guard = AbortOnDrop::new(tokio::spawn(async move {
            download(proto, "s".to_string(), source, cmd_rx, out_tx).await
        }));

        let first = timeout(Duration::from_secs(2), async {
            loop {
                match out_rx.recv().await {
                    Some(frame) if !frame.body.is_empty() => {
                        return Ok::<ProtoMsg, anyhow::Error>(frame);
                    }
                    Some(_) => continue,
                    None => {
                        return Err(anyhow!(
                            "case {:?} output closed before a data frame",
                            proto
                        ));
                    }
                }
            }
        })
        .await??;

        let header = ProtoHdr {
            proto,
            msg_type: "error".to_string(),
            session_id: "s".to_string(),
            ..ProtoHdr::default()
        };
        cmd_tx
            .send(ProtoMsg {
                header,
                body: Vec::new(),
            })
            .await?;

        let wait = async {
            let mut total = first.body.len();
            if total > MAX_BYTES {
                return Err(anyhow!("case {:?} exceeded byte bound before error", proto));
            }

            let mut output_open = true;
            loop {
                tokio::select! {
                    joined = guard.handle() => {
                        let worker_result: Result<DownloadOutcome> = joined
                            .map_err(|err| anyhow!("case {:?} worker task failed: {err}", proto))?;
                        assert!(
                            matches!(worker_result, Ok(DownloadOutcome::Aborted)),
                            "case {:?} did not report an aborted download",
                            proto
                        );
                        return Ok::<(), anyhow::Error>(());
                    }
                    maybe = async {
                        if output_open {
                            out_rx.recv().await
                        } else {
                            std::future::pending::<Option<ProtoMsg>>().await
                        }
                    } => {
                        match maybe {
                            Some(frame) => {
                                total = total
                                    .checked_add(frame.body.len())
                                    .ok_or_else(|| anyhow!("case {:?} byte count overflow", proto))?;
                                if total > MAX_BYTES {
                                    return Err(anyhow!(
                                        "case {:?} exceeded received byte bound",
                                        proto
                                    ));
                                }
                            }
                            None => output_open = false,
                        }
                    }
                }
            }
        };

        timeout(Duration::from_secs(2), wait).await??;
        drop(cmd_tx);
    }

    Ok(())
}
