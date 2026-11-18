use std::time::Duration;

use anyhow::{Result, anyhow};
use mender_connect_rust::{
    file_transfer_schema::UploadRequest,
    file_transfer_upload::{UploadOutcome, upload},
    protocol::{ProtoMsg, ProtoType},
};
use nix::unistd::{Gid, Uid};
use tempfile::TempDir;
use tokio::sync::mpsc;

/// RAII guard that aborts the spawned worker if the test unwinds early.
struct AbortGuard(tokio::task::JoinHandle<Result<UploadOutcome>>);
impl Drop for AbortGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

enum Mut {
    Proto,
    EmptySid,
    LongSid,
    NoPath,
    EmptyPath,
    NulPath,
    Size(i64),
    Mode(u32),
    Uid(u32),
    Gid(u32),
}

#[tokio::test]
async fn rejects_invalid_upload_requests_before_commit() -> Result<()> {
    const LIMIT: i64 = 256 * 1024 * 1024 + 1;
    let uid = Uid::effective().as_raw();
    let gid = Gid::effective().as_raw();

    let cases: Vec<(&str, Mut)> = vec![
        ("invalid proto", Mut::Proto),
        ("empty sid", Mut::EmptySid),
        ("129-byte sid", Mut::LongSid),
        ("missing path", Mut::NoPath),
        ("empty path", Mut::EmptyPath),
        ("NUL path", Mut::NulPath),
        ("negative size", Mut::Size(-1)),
        ("oversized", Mut::Size(LIMIT)),
        ("setuid mode", Mut::Mode(0o4000)),
        ("foreign uid", Mut::Uid(uid ^ 1)),
        ("foreign gid", Mut::Gid(gid ^ 1)),
    ];

    for (name, mutation) in cases {
        let tmp = TempDir::new()?;
        let target = tmp.path().join("target.bin");
        tokio::fs::write(&target, b"OLD").await?;
        let target_str = target.to_string_lossy().into_owned();

        let mut proto = ProtoType::FILE_TRANSFER_V2;
        let mut sid = "valid-session-id".to_string();
        let mut path = Some(target_str.clone());
        let mut size: Option<i64> = None;
        let mut uid_opt: Option<u32> = None;
        let mut gid_opt: Option<u32> = None;
        let mut mode: Option<u32> = None;
        match &mutation {
            Mut::Proto => proto = ProtoType::SHELL,
            Mut::EmptySid => sid = String::new(),
            Mut::LongSid => sid = "a".repeat(129),
            Mut::NoPath => path = None,
            Mut::EmptyPath => path = Some(String::new()),
            Mut::NulPath => path = Some("bad\u{0}path".to_string()),
            Mut::Size(s) => size = Some(*s),
            Mut::Mode(m) => mode = Some(*m),
            Mut::Uid(u) => uid_opt = Some(*u),
            Mut::Gid(g) => gid_opt = Some(*g),
        }

        let request = UploadRequest {
            path,
            src_path: None,
            size,
            uid: uid_opt,
            gid: gid_opt,
            mode,
            modtime: None,
        };

        let (cmd_tx, cmd_rx) = mpsc::channel::<ProtoMsg>(8);
        let (out_tx, _out_rx) = mpsc::channel::<ProtoMsg>(8);
        let mut guard = AbortGuard(tokio::spawn(async move {
            upload(proto, sid, request, cmd_rx, out_tx).await
        }));

        let joined = tokio::time::timeout(Duration::from_secs(2), &mut guard.0)
            .await
            .map_err(|_| anyhow!("case {name}: worker did not finish"))?;
        let worker: Result<UploadOutcome> = match joined {
            Ok(result) => result,
            Err(e) => {
                return Err(anyhow!(
                    "case {name}: worker task panicked instead of returning Err: {e}"
                ));
            }
        };
        assert!(
            worker.is_err(),
            "case {name}: expected pre-commit rejection, got Ok"
        );

        // Guards still alive: target untouched and no staging files left behind.
        assert_eq!(
            tokio::fs::read(&target).await?,
            b"OLD",
            "case {name}: target was modified"
        );
        let mut entries = tokio::fs::read_dir(tmp.path()).await?;
        while let Some(entry) = entries.next_entry().await? {
            let fname = entry.file_name().to_string_lossy().into_owned();
            assert!(
                !fname.starts_with(".mender-upload-"),
                "case {name}: leftover staging file {fname}"
            );
        }
        drop(cmd_tx);
    }
    Ok(())
}
