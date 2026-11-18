//! Integration tests for limited-upload overwrite and directory-target
//! shorthand.
//!
//! These drive the real [`FileTransferManager`] and its owned workers through
//! both the v1 and v2 protocols, plus a direct [`upload_with_limits`] worker for
//! concurrency cases. Every task is bounded and joined before the test returns.
//! Per-test tempdirs and an injected NSS resolver are used; no QEMU, credential,
//! real server or foreign chown is involved.

use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};

use mender_connect_rust::file_transfer_manager::FileTransferManager;
use mender_connect_rust::file_transfer_schema::UploadRequest;
use mender_connect_rust::file_transfer_upload::upload_with_limits;
use mender_connect_rust::limits_config::{NssResolver, RawFileTransferLimits, ResolverError};
use mender_connect_rust::limits_fs::{RelativePath, RootDir, SymlinkMode};
use mender_connect_rust::limits_fs_upload::{MetadataPlan, UploadError, resolve_upload_target};
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

fn base_raw(root: &Path, allow_overwrite: bool) -> RawFileTransferLimits {
    RawFileTransferLimits {
        chroot: Some(root.to_string_lossy().into_owned()),
        allow_overwrite: Some(allow_overwrite),
        max_file_size: Some(1 << 20),
        ..Default::default()
    }
}

fn limits_of(root: &Path, allow_overwrite: bool) -> Arc<TransferLimits> {
    Arc::new(TransferLimits::new(&base_raw(root, allow_overwrite), &FakeNss).expect("context"))
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

fn request_with(
    target: &Path,
    src: Option<&str>,
    size: Option<i64>,
    mode: Option<u32>,
) -> UploadRequest {
    UploadRequest {
        path: Some(target.to_string_lossy().into_owned()),
        src_path: src.map(|value| value.to_owned()),
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

async fn send_put_request(
    mgr: &mut FileTransferManager,
    proto: ProtoType,
    sid: &str,
    request: &UploadRequest,
) -> Result<Vec<ProtoMsg>> {
    tokio::time::timeout(TEST_TIMEOUT, mgr.handle(put_msg(proto, sid, request)?)).await?
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

async fn expect_error_before_ack(
    mgr: &mut FileTransferManager,
    proto: ProtoType,
    sid: &str,
    request: &UploadRequest,
) -> Result<()> {
    assert!(
        send_put_request(mgr, proto, sid, request).await?.is_empty(),
        "no immediate reply expected"
    );
    let message = next(mgr).await?;
    assert_eq!(message.header.msg_type, "error");
    Ok(())
}

async fn upload_ok(
    mgr: &mut FileTransferManager,
    proto: ProtoType,
    sid: &str,
    request: &UploadRequest,
    data: &[u8],
) -> Result<()> {
    assert!(send_put_request(mgr, proto, sid, request).await?.is_empty());
    if proto == V1 {
        let ack = next(mgr).await?;
        assert_eq!(offset(&ack), Some(0));
    }
    let mut off = 0i64;
    for part in data.chunks(4096) {
        assert!(send_chunk(mgr, proto, sid, part, off).await?.is_empty());
        if proto == V1 {
            let ack = next(mgr).await?;
            assert_eq!(offset(&ack), Some(off));
        }
        off += i64::try_from(part.len())?;
    }
    assert!(send_chunk(mgr, proto, sid, &[], off).await?.is_empty());
    let ack = next(mgr).await?;
    assert_eq!(ack.header.msg_type, "ack");
    Ok(())
}

fn only_names(dir: &Path) -> Result<Vec<String>> {
    let mut names: Vec<String> = std::fs::read_dir(dir)?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<std::result::Result<_, _>>()?;
    names.sort();
    Ok(names)
}

fn named_leftovers(dir: &Path) -> Result<usize> {
    Ok(only_names(dir)?
        .iter()
        .filter(|name| name.starts_with(".mender-stage-"))
        .count())
}

/// Drive one full upload through the direct worker with a fixed chunk plan.
async fn run_worker(
    limits: Arc<TransferLimits>,
    proto: ProtoType,
    sid: String,
    request: UploadRequest,
    chunks: Vec<(Vec<u8>, i64)>,
) -> Result<()> {
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(64);
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<ProtoMsg>(64);
    let worker = tokio::spawn(upload_with_limits(
        proto,
        sid.clone(),
        request,
        cmd_rx,
        out_tx,
        Some(limits),
    ));
    for (data, off) in chunks {
        cmd_tx
            .send(chunk(proto, &sid, &data, off))
            .await
            .map_err(|_| anyhow!("queue chunk"))?;
    }
    drop(cmd_tx);
    let drain = tokio::spawn(async move { while out_rx.recv().await.is_some() {} });
    let outcome = tokio::time::timeout(TEST_TIMEOUT, worker).await??;
    let _ = tokio::time::timeout(TEST_TIMEOUT, drain).await;
    outcome.map(|_| ())
}

#[tokio::test]
async fn overwrite_nonempty_and_empty_both_protocols() -> Result<()> {
    for proto in [V1, V2] {
        let dir = tempfile::tempdir()?;
        let root = dir.path();
        let mut mgr = FileTransferManager::with_limits(limits_of(root, true));
        let target = root.join("target.bin");
        std::fs::write(&target, b"OLD-OLD-OLD")?;

        let data = b"new nonempty payload".to_vec();
        let sid = format!("ow-nonempty-{proto}");
        let request = request_with(&target, None, Some(i64::try_from(data.len())?), Some(0o640));
        upload_ok(&mut mgr, proto, &sid, &request, &data).await?;
        assert_eq!(std::fs::read(&target)?, data);
        assert_eq!(
            named_leftovers(root)?,
            0,
            "no stage leftovers after replace"
        );

        let sid2 = format!("ow-empty-{proto}");
        let request2 = request_with(&target, None, Some(0), Some(0o600));
        upload_ok(&mut mgr, proto, &sid2, &request2, &[]).await?;
        assert_eq!(std::fs::read(&target)?, Vec::<u8>::new());
        assert_eq!(only_names(root)?, vec!["target.bin".to_string()]);

        shutdown(&mut mgr).await?;
    }
    Ok(())
}

#[tokio::test]
async fn overwrite_applies_mode_and_owner() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut mgr = FileTransferManager::with_limits(limits_of(root, true));
    let target = root.join("meta.bin");
    std::fs::write(&target, b"OLD")?;

    let data = b"meta-overwrite".to_vec();
    let request = request_with(&target, None, Some(i64::try_from(data.len())?), Some(0o640));
    upload_ok(&mut mgr, V2, "meta-ow", &request, &data).await?;

    let meta = std::fs::metadata(&target)?;
    assert!(meta.file_type().is_file());
    assert_eq!(meta.mode() & 0o777, 0o640, "requested mode applied");
    assert_eq!(
        meta.uid(),
        nix::unistd::Uid::effective().as_raw(),
        "owner is the effective daemon uid"
    );

    shutdown(&mut mgr).await
}

#[tokio::test]
async fn overwrite_eof_then_scoped_close_commits() -> Result<()> {
    for proto in [V1, V2] {
        let dir = tempfile::tempdir()?;
        let root = dir.path();
        let mut mgr = FileTransferManager::with_limits(limits_of(root, true));
        let target = root.join("target.bin");
        std::fs::write(&target, b"OLD")?;

        let data = b"scoped overwrite payload".to_vec();
        let size = i64::try_from(data.len())?;
        let request = request_with(&target, None, Some(size), Some(0o644));
        assert!(
            send_put_request(&mut mgr, proto, "eof", &request)
                .await?
                .is_empty()
        );
        if proto == V1 {
            let _ = next(&mut mgr).await?;
        }
        assert!(
            send_chunk(&mut mgr, proto, "eof", &data, 0)
                .await?
                .is_empty()
        );
        if proto == V1 {
            let _ = next(&mut mgr).await?;
        }
        assert!(
            send_chunk(&mut mgr, proto, "eof", &[], size)
                .await?
                .is_empty()
        );
        tokio::time::timeout(TEST_TIMEOUT, mgr.close_session("eof")).await??;
        assert_eq!(std::fs::read(&target)?, data, "accepted EOF must commit");
        assert_eq!(only_names(root)?, vec!["target.bin".to_string()]);

        shutdown(&mut mgr).await?;
    }
    Ok(())
}

#[tokio::test]
async fn explicit_file_accepts_and_ignores_src_path() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut mgr = FileTransferManager::with_limits(limits_of(root, false));
    let target = root.join("explicit.bin");

    let data = b"explicit".to_vec();
    let request = request_with(
        &target,
        Some("/any/prefix/ignored.name"),
        Some(i64::try_from(data.len())?),
        Some(0o644),
    );
    upload_ok(&mut mgr, V1, "explicit", &request, &data).await?;
    assert_eq!(std::fs::read(&target)?, data);
    assert_eq!(only_names(root)?, vec!["explicit.bin".to_string()]);

    shutdown(&mut mgr).await
}

#[tokio::test]
async fn directory_shorthand_including_root_itself() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();

    // Existing directory inside the root: only the basename is used.
    {
        let sub = root.join("sub");
        std::fs::create_dir(&sub)?;
        let mut mgr = FileTransferManager::with_limits(limits_of(root, false));
        let data = b"into sub".to_vec();
        let request = request_with(
            &sub,
            Some("/deep/prefix/name.bin"),
            Some(i64::try_from(data.len())?),
            Some(0o644),
        );
        upload_ok(&mut mgr, V2, "dirsub", &request, &data).await?;
        assert_eq!(std::fs::read(sub.join("name.bin"))?, data);
        shutdown(&mut mgr).await?;
    }

    // Peer destination equal to the configured root itself.
    {
        let mut mgr = FileTransferManager::with_limits(limits_of(root, false));
        let data = b"into root".to_vec();
        let request = request_with(
            root,
            Some("/x/y/rootname.bin"),
            Some(i64::try_from(data.len())?),
            Some(0o644),
        );
        upload_ok(&mut mgr, V1, "dirroot", &request, &data).await?;
        assert_eq!(std::fs::read(root.join("rootname.bin"))?, data);
        shutdown(&mut mgr).await?;
    }

    Ok(())
}

#[tokio::test]
async fn owner_and_group_denial_before_ack() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let target = root.join("owned.bin");
    std::fs::write(&target, b"OLD")?;

    // Owner constraint mismatch is rejected before the initial ACK.
    {
        let mut raw = base_raw(root, true);
        raw.owner_put = Some("bob".to_owned());
        let limits = Arc::new(TransferLimits::new(&raw, &FakeNss)?);
        let mut mgr = FileTransferManager::with_limits(limits);
        let request = request_with(&target, None, Some(0), Some(0o644));
        expect_error_before_ack(&mut mgr, V1, "owner", &request).await?;
        assert_eq!(std::fs::read(&target)?, b"OLD");
        shutdown(&mut mgr).await?;
    }

    // Group constraint mismatch is rejected before the initial ACK.
    {
        let mut raw = base_raw(root, true);
        raw.group_put = Some("strangers".to_owned());
        let limits = Arc::new(TransferLimits::new(&raw, &FakeNss)?);
        let mut mgr = FileTransferManager::with_limits(limits);
        let request = request_with(&target, None, Some(0), Some(0o644));
        expect_error_before_ack(&mut mgr, V1, "group", &request).await?;
        assert_eq!(std::fs::read(&target)?, b"OLD");
        shutdown(&mut mgr).await?;
    }

    Ok(())
}

#[tokio::test]
async fn final_symlink_dangling_and_nonregular_refused() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut mgr = FileTransferManager::with_limits(limits_of(root, true));

    // A final symlink to a regular file is refused explicitly.
    let real = root.join("real.bin");
    std::fs::write(&real, b"REAL")?;
    let link = root.join("link.bin");
    std::os::unix::fs::symlink(&real, &link)?;
    let request = request_with(&link, None, Some(0), Some(0o644));
    expect_error_before_ack(&mut mgr, V2, "symlink", &request).await?;
    assert_eq!(std::fs::read(&real)?, b"REAL", "symlink target untouched");

    // A dangling symlink is refused explicitly.
    let dangling = root.join("dangling.bin");
    std::os::unix::fs::symlink("missing", &dangling)?;
    let request = request_with(&dangling, None, Some(0), Some(0o644));
    expect_error_before_ack(&mut mgr, V2, "dangling", &request).await?;

    // A non-regular (unix socket) target is refused explicitly.
    let sock = root.join("socket");
    let listener = std::os::unix::net::UnixListener::bind(&sock)?;
    let request = request_with(&sock, None, Some(0), Some(0o644));
    expect_error_before_ack(&mut mgr, V2, "sock", &request).await?;
    drop(listener);

    shutdown(&mut mgr).await
}

#[tokio::test]
async fn escaping_parent_symlink_refused_with_follow_enabled() -> Result<()> {
    let root = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    let link = root.path().join("link");
    std::os::unix::fs::symlink(outside.path(), &link)?;

    let mut raw = base_raw(root.path(), true);
    raw.follow_sym_links = Some(true);
    let limits = Arc::new(TransferLimits::new(&raw, &FakeNss)?);
    let mut mgr = FileTransferManager::with_limits(limits);

    let target = link.join("escape.bin");
    let request = request_with(&target, None, Some(0), Some(0o644));
    expect_error_before_ack(&mut mgr, V2, "escape", &request).await?;
    assert!(!outside.path().join("escape.bin").exists());

    shutdown(&mut mgr).await
}

#[tokio::test]
async fn unsafe_group_writable_replacement_parent_refused() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let open = root.join("open");
    std::fs::create_dir(&open)?;
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777))?;
    let target = open.join("file.bin");
    std::fs::write(&target, b"OLD")?;

    let mut mgr = FileTransferManager::with_limits(limits_of(root, true));
    let request = request_with(&target, None, Some(0), Some(0o644));
    expect_error_before_ack(&mut mgr, V2, "unsafe", &request).await?;
    assert_eq!(
        std::fs::read(&target)?,
        b"OLD",
        "unsafe parent is not modified"
    );
    assert_eq!(named_leftovers(&open)?, 0, "no named leftovers");

    shutdown(&mut mgr).await
}

#[tokio::test]
async fn cancellation_and_malformed_eof_preserve_original() -> Result<()> {
    // Cancellation before EOF preserves the original file.
    {
        let dir = tempfile::tempdir()?;
        let root = dir.path();
        let target = root.join("cancel.bin");
        std::fs::write(&target, b"OLD")?;
        let mut mgr = FileTransferManager::with_limits(limits_of(root, true));
        let request = request_with(&target, None, Some(8), Some(0o644));
        assert!(
            send_put_request(&mut mgr, V2, "cancel", &request)
                .await?
                .is_empty()
        );
        assert!(
            send_chunk(&mut mgr, V2, "cancel", b"ab", 0)
                .await?
                .is_empty()
        );
        tokio::time::timeout(TEST_TIMEOUT, mgr.close_session("cancel")).await??;
        assert_eq!(std::fs::read(&target)?, b"OLD");
        assert_eq!(only_names(root)?, vec!["cancel.bin".to_string()]);
        shutdown(&mut mgr).await?;
    }

    // A malformed EOF preserves the original file.
    {
        let dir = tempfile::tempdir()?;
        let root = dir.path();
        let target = root.join("mal.bin");
        std::fs::write(&target, b"OLD")?;
        let mut mgr = FileTransferManager::with_limits(limits_of(root, true));
        let request = request_with(&target, None, Some(4), Some(0o644));
        assert!(
            send_put_request(&mut mgr, V2, "mal", &request)
                .await?
                .is_empty()
        );
        assert!(send_chunk(&mut mgr, V2, "mal", &[], 0).await?.is_empty());
        let message = next(&mut mgr).await?;
        assert_eq!(message.header.msg_type, "error");
        assert_eq!(std::fs::read(&target)?, b"OLD");
        shutdown(&mut mgr).await?;
    }

    Ok(())
}

#[tokio::test]
async fn post_ack_collision_does_not_overwrite_new_entry() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut mgr = FileTransferManager::with_limits(limits_of(root, true));
    let target = root.join("collide.bin");

    // v1 emits an initial ACK after admission, so the target was absent at
    // admission. Insert a new entry before EOF; the atomic no-overwrite link must
    // refuse it rather than overwriting.
    let request = request_with(&target, None, Some(0), Some(0o644));
    assert!(
        send_put_request(&mut mgr, V1, "collide", &request)
            .await?
            .is_empty()
    );
    let ack = next(&mut mgr).await?;
    assert_eq!(offset(&ack), Some(0));

    std::fs::write(&target, b"NEWER")?;
    assert!(
        send_chunk(&mut mgr, V1, "collide", &[], 0)
            .await?
            .is_empty()
    );
    let message = next(&mut mgr).await?;
    assert_eq!(message.header.msg_type, "error");
    assert_eq!(
        std::fs::read(&target)?,
        b"NEWER",
        "new entry not overwritten"
    );

    shutdown(&mut mgr).await
}

#[test]
fn replacement_stage_cannot_overwrite_via_commit_new() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root_path = dir.path();
    let root = RootDir::open(root_path).map_err(|err| anyhow!(err.to_string()))?;
    let target = root_path.join("keep.bin");
    std::fs::write(&target, b"ORIGINAL")?;

    let relative = RelativePath::parse(b"keep.bin").map_err(|err| anyhow!(err.to_string()))?;
    let prepared = resolve_upload_target(
        &root,
        Some(&relative),
        root_path,
        None,
        SymlinkMode::RefuseAll,
    )
    .map_err(|err| anyhow!(err.to_string()))?;
    assert!(
        prepared.is_replacement(),
        "target must be admitted as a replacement"
    );

    let mut stage = prepared
        .begin_stage()
        .map_err(|err| anyhow!(err.to_string()))?;
    stage.write_all(b"REPLACEMENT-ATTEMPT")?;

    // A replacement-prepared stage must never clobber through the strictly
    // no-overwrite commit: the atomic new-link path reports AlreadyExists.
    let err = stage
        .commit_new_with_metadata(MetadataPlan::none())
        .expect_err("a replacement-prepared stage must not overwrite");
    assert_eq!(err, UploadError::AlreadyExists);
    assert_eq!(std::fs::read(&target)?, b"ORIGINAL", "original unchanged");
    assert_eq!(named_leftovers(root_path)?, 0, "no named leftovers");
    Ok(())
}

#[tokio::test]
async fn concurrent_creates_and_replacements_are_complete() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let limits = limits_of(root, true);

    // Concurrent new-file creates to distinct targets.
    let mut creates = Vec::new();
    for i in 0u8..4 {
        let limits = Arc::clone(&limits);
        let target = root.join(format!("create-{i}.bin"));
        let payload = vec![i + 1; 3000];
        let size = i64::try_from(payload.len())?;
        let request = request_with(&target, None, Some(size), Some(0o644));
        creates.push(tokio::spawn(async move {
            run_worker(
                limits,
                V2,
                format!("c{i}"),
                request,
                vec![(payload.clone(), 0i64), (Vec::new(), size)],
            )
            .await
        }));
    }
    for task in creates {
        tokio::time::timeout(TEST_TIMEOUT, task)
            .await??
            .expect("create upload completes");
    }
    for i in 0u8..4 {
        assert_eq!(
            std::fs::read(root.join(format!("create-{i}.bin")))?,
            vec![i + 1; 3000]
        );
    }

    // Concurrent replacements of the same target: each must publish a complete
    // payload, never a mixed byte stream.
    let shared = root.join("shared.bin");
    std::fs::write(&shared, b"OLD")?;
    let payloads: Vec<Vec<u8>> = (0u8..4).map(|i| vec![i + 10; 3500]).collect();
    let mut replaces = Vec::new();
    for (i, payload) in payloads.iter().enumerate() {
        let limits = Arc::clone(&limits);
        let target = shared.clone();
        let payload = payload.clone();
        let size = i64::try_from(payload.len())?;
        let request = request_with(&target, None, Some(size), Some(0o644));
        replaces.push(tokio::spawn(async move {
            run_worker(
                limits,
                V2,
                format!("r{i}"),
                request,
                vec![(payload.clone(), 0i64), (Vec::new(), size)],
            )
            .await
        }));
    }
    for task in replaces {
        let _ = tokio::time::timeout(TEST_TIMEOUT, task).await?;
    }
    let got = std::fs::read(&shared)?;
    assert!(
        payloads.contains(&got),
        "final content must be one complete payload"
    );
    assert_eq!(named_leftovers(root)?, 0, "no named stage leftovers");

    Ok(())
}
