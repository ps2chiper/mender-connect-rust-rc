//! Integration tests for the staged-create foundation.
//!
//! These exercise the public [`mender_connect_rust::limits_fs_upload`] API
//! against real temporary directories. They run as the current (asserted
//! unprivileged) user and require an `O_TMPFILE`-capable filesystem; an
//! unsupported filesystem is surfaced as a failure rather than skipped.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::thread;

use mender_connect_rust::limits_fs::{RelativePath, RootDir, SymlinkMode};
use mender_connect_rust::limits_fs_upload::MAX_UPLOAD_BYTES;
use mender_connect_rust::limits_fs_upload::{MetadataPlan, UploadError, begin_staged_create};
use rustix::io::FdFlags;
use rustix::io::fcntl_getfd;

fn assert_not_root() {
    let uid = nix::unistd::geteuid().as_raw();
    assert_ne!(uid, 0, "these tests must run as an unprivileged user");
}

fn rel(value: &str) -> RelativePath {
    match RelativePath::parse(value.as_bytes()) {
        Ok(path) => path,
        Err(err) => panic!("test supplied an invalid relative path: {err}"),
    }
}

#[test]
fn creates_zero_byte_file() {
    assert_not_root();
    let dir = tempfile::tempdir().expect("tempdir");
    let root = RootDir::open(dir.path()).expect("root");
    let path = rel("empty.bin");

    let stage = begin_staged_create(&root, &path, SymlinkMode::RefuseAll).expect("begin");
    stage.commit_new().expect("commit");

    let target = dir.path().join("empty.bin");
    let meta = fs::metadata(&target).expect("metadata");
    assert!(meta.is_file());
    assert_eq!(meta.len(), 0);
}

#[test]
fn writes_exact_bytes_and_private_mode() {
    assert_not_root();
    let dir = tempfile::tempdir().expect("tempdir");
    let root = RootDir::open(dir.path()).expect("root");
    let path = rel("payload.bin");
    let payload: Vec<u8> = (0u8..=255).collect();

    let mut stage = begin_staged_create(&root, &path, SymlinkMode::RefuseAll).expect("begin");
    stage.write_all(&payload).expect("write");
    stage.commit_new().expect("commit");

    let target = dir.path().join("payload.bin");
    let data = fs::read(&target).expect("read");
    assert_eq!(data, payload);
    let mode = fs::metadata(&target)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode & 0o077, 0, "no group/other permission bits");
    assert_eq!(mode & 0o600, 0o600, "owner read/write present");
}

#[test]
fn refuses_and_leaves_existing_regular() {
    assert_not_root();
    let dir = tempfile::tempdir().expect("tempdir");
    let root = RootDir::open(dir.path()).expect("root");
    let target = dir.path().join("exists.txt");
    fs::write(&target, b"original").expect("seed");
    let path = rel("exists.txt");

    let mut stage = begin_staged_create(&root, &path, SymlinkMode::RefuseAll).expect("begin");
    stage.write_all(b"replacement").expect("write");
    let err = stage.commit_new().expect_err("must not overwrite");
    assert_eq!(err, UploadError::AlreadyExists);
    assert_eq!(fs::read(&target).expect("read"), b"original");
}

#[test]
fn refuses_and_leaves_existing_directory() {
    assert_not_root();
    let dir = tempfile::tempdir().expect("tempdir");
    let root = RootDir::open(dir.path()).expect("root");
    fs::create_dir(dir.path().join("adir")).expect("mkdir");
    let path = rel("adir");

    let mut stage = begin_staged_create(&root, &path, SymlinkMode::RefuseAll).expect("begin");
    stage.write_all(b"x").expect("write");
    let err = stage.commit_new().expect_err("must not replace dir");
    assert_eq!(err, UploadError::AlreadyExists);
    assert!(dir.path().join("adir").is_dir());
}

#[test]
fn refuses_and_leaves_existing_symlink() {
    assert_not_root();
    let dir = tempfile::tempdir().expect("tempdir");
    let root = RootDir::open(dir.path()).expect("root");
    fs::write(dir.path().join("target"), b"content").expect("seed");
    symlink("target", dir.path().join("link")).expect("symlink");
    let path = rel("link");

    let mut stage = begin_staged_create(&root, &path, SymlinkMode::RefuseAll).expect("begin");
    stage.write_all(b"x").expect("write");
    let err = stage.commit_new().expect_err("must not replace symlink");
    assert_eq!(err, UploadError::AlreadyExists);
    let still_link = fs::symlink_metadata(dir.path().join("link")).expect("lstat");
    assert!(still_link.file_type().is_symlink());
    assert_eq!(
        fs::read(dir.path().join("target")).expect("read"),
        b"content"
    );
}

#[test]
fn refuses_and_leaves_dangling_symlink() {
    assert_not_root();
    let dir = tempfile::tempdir().expect("tempdir");
    let root = RootDir::open(dir.path()).expect("root");
    symlink("missing", dir.path().join("dangling")).expect("symlink");
    let path = rel("dangling");

    let mut stage = begin_staged_create(&root, &path, SymlinkMode::RefuseAll).expect("begin");
    stage.write_all(b"x").expect("write");
    let err = stage
        .commit_new()
        .expect_err("must not replace dangling link");
    assert_eq!(err, UploadError::AlreadyExists);
    let still_link = fs::symlink_metadata(dir.path().join("dangling")).expect("lstat");
    assert!(still_link.file_type().is_symlink());
}

#[test]
fn rejects_invalid_paths() {
    assert!(RelativePath::parse(b"/abs").is_err());
    assert!(RelativePath::parse(b"a/../b").is_err());
    assert!(RelativePath::parse(b"a\0b").is_err());
    assert!(RelativePath::parse(b"").is_err());
}

#[test]
fn parent_relative_symlink_modes() {
    assert_not_root();
    let dir = tempfile::tempdir().expect("tempdir");
    let root = RootDir::open(dir.path()).expect("root");
    fs::create_dir(dir.path().join("real")).expect("mkdir");
    symlink("real", dir.path().join("link")).expect("symlink");
    let path = rel("link/file.txt");

    let refused = begin_staged_create(&root, &path, SymlinkMode::RefuseAll);
    assert!(refused.is_err(), "RefuseAll must reject a symlinked parent");

    let mut stage =
        begin_staged_create(&root, &path, SymlinkMode::RelativeWithinRoot).expect("begin");
    stage.write_all(b"hi").expect("write");
    stage.commit_new().expect("commit");
    assert_eq!(
        fs::read(dir.path().join("real/file.txt")).expect("read"),
        b"hi"
    );
}

#[test]
fn refuses_escaping_and_absolute_symlink_parent() {
    assert_not_root();
    let common = tempfile::tempdir().expect("common tempdir");
    let root_path = common.path().join("root");
    let outside_path = common.path().join("outside");
    fs::create_dir(&root_path).expect("mkdir root");
    fs::create_dir(&outside_path).expect("mkdir outside");
    let root = RootDir::open(&root_path).expect("root");
    // The relative escape points at a directory that really exists next to the
    // root, so a successful containment check cannot be confused with ENOENT.
    symlink("../outside", root_path.join("escape")).expect("relative escape");
    symlink(&outside_path, root_path.join("abs")).expect("absolute");

    for mode in [SymlinkMode::RelativeWithinRoot, SymlinkMode::RefuseAll] {
        let escape = begin_staged_create(&root, &rel("escape/file.txt"), mode);
        assert!(escape.is_err(), "relative escaping parent must be refused");
        let absolute = begin_staged_create(&root, &rel("abs/file.txt"), mode);
        assert!(absolute.is_err(), "absolute symlink parent must be refused");
    }
}

#[test]
fn dropped_stage_leaves_no_entry() {
    assert_not_root();
    let dir = tempfile::tempdir().expect("tempdir");
    let root = RootDir::open(dir.path()).expect("root");
    let path = rel("ghost.txt");
    {
        let mut stage = begin_staged_create(&root, &path, SymlinkMode::RefuseAll).expect("begin");
        stage.write_all(b"data").expect("write");
        // Dropped here without commit.
    }
    let entries: Vec<_> = fs::read_dir(dir.path()).expect("read_dir").collect();
    assert!(
        entries.is_empty(),
        "a dropped stage must leave the directory empty"
    );
}

#[test]
fn concurrent_commits_exactly_one_wins() {
    assert_not_root();
    let dir = tempfile::tempdir().expect("tempdir");
    let root_path = dir.path().to_path_buf();
    let root = RootDir::open(dir.path()).expect("root");
    let path = rel("race.bin");

    // Prepare both fully written stages before spawning any worker so that a
    // fallible setup step can never deadlock a synchronisation barrier, and so
    // no worker can panic while another is already waiting.
    let mut stages = Vec::new();
    for index in 0..2u8 {
        let mut stage = begin_staged_create(&root, &path, SymlinkMode::RefuseAll).expect("begin");
        let payload = vec![b'A' + index; 4096];
        stage.write_all(&payload).expect("write");
        stages.push(stage);
    }

    // Finite commit workers: no barrier is needed, the atomic race is valid on
    // its own and each worker returns after a single commit attempt.
    let mut handles = Vec::new();
    for stage in stages {
        handles.push(thread::spawn(move || stage.commit_new()));
    }

    // Join every worker before asserting, even if an earlier result is an
    // error, so that no thread is left detached on failure.
    let results: Vec<_> = handles.into_iter().map(|handle| handle.join()).collect();

    let mut wins = 0u32;
    let mut exists = 0u32;
    for result in results {
        match result {
            Ok(Ok(())) => wins += 1,
            Ok(Err(UploadError::AlreadyExists)) => exists += 1,
            Ok(Err(other)) => panic!("unexpected commit error: {other}"),
            Err(_) => panic!("worker thread panicked"),
        }
    }
    assert_eq!(wins, 1, "exactly one commit must win");
    assert_eq!(
        exists, 1,
        "exactly one commit must observe an existing target"
    );

    let data = fs::read(root_path.join("race.bin")).expect("read final");
    assert_eq!(data.len(), 4096, "final file must be one complete payload");
    if let Some(first) = data.first().copied() {
        assert!(data.iter().all(|byte| *byte == first), "payload not torn");
        assert!(first == b'A' || first == b'B');
    } else {
        panic!("final file is empty");
    }
}

#[test]
fn descriptors_are_close_on_exec() {
    assert_not_root();
    let dir = tempfile::tempdir().expect("tempdir");
    let root = RootDir::open(dir.path()).expect("root");
    let path = rel("cloexec.txt");

    let stage = begin_staged_create(&root, &path, SymlinkMode::RefuseAll).expect("begin");
    let stage_flags = fcntl_getfd(stage.stage_fd()).expect("stage fcntl");
    assert!(
        stage_flags.contains(FdFlags::CLOEXEC),
        "stage must be CLOEXEC"
    );
    let parent_flags = fcntl_getfd(stage.parent_fd()).expect("parent fcntl");
    assert!(
        parent_flags.contains(FdFlags::CLOEXEC),
        "parent must be CLOEXEC"
    );
}

#[test]
fn sparse_file_at_bound_succeeds() {
    assert_not_root();
    let dir = tempfile::tempdir().expect("tempdir");
    let root = RootDir::open(dir.path()).expect("root");
    let path = rel("sparse.bin");

    let stage = begin_staged_create(&root, &path, SymlinkMode::RefuseAll).expect("begin");
    rustix::fs::ftruncate(stage.stage_fd(), MAX_UPLOAD_BYTES).expect("ftruncate to the bound");
    stage.commit_new().expect("commit at the bound");

    let meta = fs::metadata(dir.path().join("sparse.bin")).expect("metadata");
    assert_eq!(meta.len(), MAX_UPLOAD_BYTES);
}

#[test]
fn sparse_file_over_bound_refused() {
    assert_not_root();
    let dir = tempfile::tempdir().expect("tempdir");
    let root = RootDir::open(dir.path()).expect("root");
    let path = rel("sparse.bin");

    let stage = begin_staged_create(&root, &path, SymlinkMode::RefuseAll).expect("begin");
    rustix::fs::ftruncate(stage.stage_fd(), MAX_UPLOAD_BYTES + 1)
        .expect("ftruncate over the bound");
    let err = stage
        .commit_new()
        .expect_err("over the bound must be refused");
    assert_eq!(err, UploadError::CommitSizeOutOfRange);
    assert!(
        !dir.path().join("sparse.bin").exists(),
        "no entry may be created for an oversized stage"
    );
}

fn current_uid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

fn current_gid() -> u32 {
    nix::unistd::getegid().as_raw()
}

#[test]
fn applies_current_owner_and_mode() {
    assert_not_root();
    let dir = tempfile::tempdir().expect("tempdir");
    let root = RootDir::open(dir.path()).expect("root");
    let path = rel("meta.bin");

    let mut stage = begin_staged_create(&root, &path, SymlinkMode::RefuseAll).expect("begin");
    stage.write_all(b"payload").expect("write");
    let plan = MetadataPlan::new(Some(current_uid()), Some(current_gid()), Some(0o640));
    stage
        .commit_new_with_metadata(plan)
        .expect("commit with metadata");

    let target = dir.path().join("meta.bin");
    let meta = fs::metadata(&target).expect("metadata");
    assert_eq!(meta.uid(), current_uid());
    assert_eq!(meta.gid(), current_gid());
    assert_eq!(meta.permissions().mode() & 0o7777, 0o640);
    assert_eq!(fs::read(&target).expect("read"), b"payload");
}

#[test]
fn none_mode_keeps_default_private() {
    assert_not_root();
    let dir = tempfile::tempdir().expect("tempdir");
    let root = RootDir::open(dir.path()).expect("root");
    let path = rel("plain.bin");

    let mut stage = begin_staged_create(&root, &path, SymlinkMode::RefuseAll).expect("begin");
    stage.write_all(b"data").expect("write");
    // Owner set to the current user (a no-op) with no mode request: the stage
    // keeps its default private 0o600 permissions.
    let plan = MetadataPlan::new(Some(current_uid()), Some(current_gid()), None);
    stage.commit_new_with_metadata(plan).expect("commit");

    let mode = fs::metadata(dir.path().join("plain.bin"))
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "None mode keeps the default private 0o600");
}

#[test]
fn sentinel_owner_refused_no_entry() {
    assert_not_root();
    let dir = tempfile::tempdir().expect("tempdir");
    let root = RootDir::open(dir.path()).expect("root");

    let path = rel("baduid.bin");
    let mut stage = begin_staged_create(&root, &path, SymlinkMode::RefuseAll).expect("begin");
    stage.write_all(b"x").expect("write");
    let plan = MetadataPlan::new(Some(u32::MAX), None, Some(0o644));
    let err = stage
        .commit_new_with_metadata(plan)
        .expect_err("sentinel uid must be refused");
    assert_eq!(err, UploadError::InvalidMetadataOwner);
    assert!(!dir.path().join("baduid.bin").exists());

    let path2 = rel("badgid.bin");
    let mut stage2 = begin_staged_create(&root, &path2, SymlinkMode::RefuseAll).expect("begin");
    stage2.write_all(b"x").expect("write");
    let plan2 = MetadataPlan::new(None, Some(u32::MAX), Some(0o644));
    let err2 = stage2
        .commit_new_with_metadata(plan2)
        .expect_err("sentinel gid must be refused");
    assert_eq!(err2, UploadError::InvalidMetadataOwner);
    assert!(!dir.path().join("badgid.bin").exists());
}

#[test]
fn invalid_mode_bits_refused_no_entry() {
    assert_not_root();
    // POSIX setgid, sticky, a Go os.FileMode-encoded type bit and raw file-type
    // bits all lie outside the permitted 0o4777 mask and must be refused.
    for (index, bad_mode) in [0o2000u32, 0o1000, 0o1_000_000, 0o100_000, 0o170_000]
        .into_iter()
        .enumerate()
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = RootDir::open(dir.path()).expect("root");
        let name = format!("badmode{index}.bin");
        let path = rel(&name);
        let mut stage = begin_staged_create(&root, &path, SymlinkMode::RefuseAll).expect("begin");
        stage.write_all(b"x").expect("write");
        let plan = MetadataPlan::new(None, None, Some(bad_mode));
        let err = stage
            .commit_new_with_metadata(plan)
            .expect_err("invalid mode bits must be refused");
        assert_eq!(err, UploadError::InvalidMetadataMode);
        assert!(
            !dir.path().join(&name).exists(),
            "invalid mode must leave no entry"
        );
    }
}

#[test]
fn suid_mode_with_current_owner_preserved() {
    assert_not_root();
    let dir = tempfile::tempdir().expect("tempdir");
    let root = RootDir::open(dir.path()).expect("root");
    let path = rel("suid.bin");

    let mut stage = begin_staged_create(&root, &path, SymlinkMode::RefuseAll).expect("begin");
    stage.write_all(b"data-payload").expect("write");
    // A normalised POSIX setuid mode applied to a file we own: fchown runs
    // first (a no-op here), then fchmod stores the setuid bit.
    let plan = MetadataPlan::new(Some(current_uid()), Some(current_gid()), Some(0o4755));
    stage
        .commit_new_with_metadata(plan)
        .expect("commit with setuid mode");

    let meta = fs::metadata(dir.path().join("suid.bin")).expect("metadata");
    let mode = meta.permissions().mode() & 0o7777;
    assert_eq!(mode & 0o4000, 0o4000, "setuid bit must be stored");
    assert_eq!(mode & 0o777, 0o755, "permission bits stored as requested");
}

#[test]
fn different_owner_fchown_failure_leaves_no_entry() {
    assert_not_root();
    let dir = tempfile::tempdir().expect("tempdir");
    let root = RootDir::open(dir.path()).expect("root");
    let path = rel("owner.bin");

    let mut stage = begin_staged_create(&root, &path, SymlinkMode::RefuseAll).expect("begin");
    stage.write_all(b"x").expect("write");
    // Changing the owner to root (uid 0) is refused for an unprivileged caller.
    let plan = MetadataPlan::new(Some(0), Some(0), Some(0o640));
    let err = stage
        .commit_new_with_metadata(plan)
        .expect_err("privileged fchown must fail");
    assert_eq!(err, UploadError::OwnershipApplyFailed);
    assert!(
        !dir.path().join("owner.bin").exists(),
        "failed ownership must leave no entry"
    );
}

#[test]
fn boundary_zero_mode_accepted() {
    assert_not_root();
    let dir = tempfile::tempdir().expect("tempdir");
    let root = RootDir::open(dir.path()).expect("root");
    let path = rel("nomode.bin");

    let mut stage = begin_staged_create(&root, &path, SymlinkMode::RefuseAll).expect("begin");
    stage.write_all(b"payload").expect("write");
    // Mode 0 sits at the valid boundary (fully inside 0o4777) and is stored
    // exactly, leaving the published file unreadable by design.
    let plan = MetadataPlan::new(Some(current_uid()), Some(current_gid()), Some(0));
    stage.commit_new_with_metadata(plan).expect("commit mode 0");

    let mode = fs::metadata(dir.path().join("nomode.bin"))
        .expect("metadata")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(mode, 0, "requested mode 0 stored without truncation");
}

#[test]
fn atomic_no_overwrite_with_metadata_stays_unchanged() {
    assert_not_root();
    let dir = tempfile::tempdir().expect("tempdir");
    let root = RootDir::open(dir.path()).expect("root");
    let target = dir.path().join("keep.txt");
    fs::write(&target, b"original").expect("seed");
    let original_mode = fs::metadata(&target)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o7777;
    let path = rel("keep.txt");

    let mut stage = begin_staged_create(&root, &path, SymlinkMode::RefuseAll).expect("begin");
    stage.write_all(b"replacement").expect("write");
    let plan = MetadataPlan::new(Some(current_uid()), Some(current_gid()), Some(0o640));
    let err = stage
        .commit_new_with_metadata(plan)
        .expect_err("must not overwrite the existing target");
    assert_eq!(err, UploadError::AlreadyExists);

    assert_eq!(fs::read(&target).expect("read"), b"original");
    assert_eq!(
        fs::metadata(&target)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o7777,
        original_mode,
        "existing target metadata must be unchanged"
    );
}

#[test]
fn bounded_write_refuses_over_cap_before_advancing() {
    assert_not_root();
    let dir = tempfile::tempdir().expect("tempdir");
    let root = RootDir::open(dir.path()).expect("root");
    let path = rel("bound.bin");

    let mut stage = begin_staged_create(&root, &path, SymlinkMode::RefuseAll).expect("begin");
    // Move the shared file offset to the bound via the borrowed FD; this is
    // trusted test-only manipulation that exercises the actual-offset bound.
    let moved = rustix::fs::seek(
        stage.stage_fd(),
        rustix::fs::SeekFrom::Start(MAX_UPLOAD_BYTES),
    )
    .expect("seek to the bound");
    assert_eq!(moved, MAX_UPLOAD_BYTES);

    let err = stage
        .write_all(b"x")
        .expect_err("write over the bound must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

    let pos = rustix::fs::seek(stage.stage_fd(), rustix::fs::SeekFrom::Current(0)).expect("tell");
    assert_eq!(
        pos, MAX_UPLOAD_BYTES,
        "offset must not advance on a refused write"
    );
    assert!(
        !dir.path().join("bound.bin").exists(),
        "no entry may be created for a refused write"
    );
}
