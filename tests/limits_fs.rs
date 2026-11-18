//! Integration tests for the filesystem download/stat foundation.
//!
//! These tests exercise the real kernel/filesystem behavior against actual
//! temporary directories owned by the current user. They do not mock or mirror
//! the implementation. The bounded symlink loop demonstrates (but does not
//! prove) that an outside sentinel is never read; it is not a security proof.

use std::error::Error;
use std::fs;
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::symlink;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use nix::fcntl::{FcntlArg, fcntl};
use nix::sys::stat::Mode;
use nix::unistd::mkfifo;

use mender_connect_rust::limits_fs::{FsError, RelativePath, RootDir, SymlinkMode};

const FD_CLOEXEC: i32 = 1;

const INSIDE: &[u8] = b"inside-ok";
const SWAP_LIMIT: u64 = 2000;
const READ_LIMIT: usize = 2000;

fn root_of(dir: &tempfile::TempDir) -> Result<RootDir, Box<dyn Error>> {
    Ok(RootDir::open(dir.path())?)
}

/// Perform one controlled open+read that must succeed with exactly the inside
/// bytes. Used to prove the race test cannot pass vacuously.
fn read_once_exact(root: &RootDir, path: &RelativePath) -> Result<(), String> {
    let download = root
        .open_download(path, SymlinkMode::RelativeWithinRoot)
        .map_err(|e| format!("expected a successful open, got {e:?}"))?;
    let mut buf = Vec::new();
    let mut file = download.file();
    file.read_to_end(&mut buf)
        .map_err(|e| format!("read failed: {e}"))?;
    if buf.as_slice() != INSIDE {
        return Err(format!("read {} bytes with unexpected content", buf.len()));
    }
    Ok(())
}

/// Bounded read loop that collects failures without panicking. A successful
/// open must read exactly the inside bytes; only typed containment errors are
/// tolerated (openat2 rename races may legitimately surface as `OpenFailed`).
fn reader_loop(root: &RootDir, path: &RelativePath) -> Result<(), String> {
    for _ in 0..READ_LIMIT {
        match root.open_download(path, SymlinkMode::RelativeWithinRoot) {
            Ok(download) => {
                let mut buf = Vec::new();
                let mut file = download.file();
                file.read_to_end(&mut buf)
                    .map_err(|e| format!("read failed: {e}"))?;
                if buf.as_slice() != INSIDE {
                    return Err(format!(
                        "successful open read unexpected {} bytes",
                        buf.len()
                    ));
                }
            }
            Err(err) => {
                if !matches!(
                    err,
                    FsError::SymlinkEscapesRoot
                        | FsError::NotFound
                        | FsError::NotRegularFile
                        | FsError::OpenFailed
                ) {
                    return Err(format!("unexpected error {err:?}"));
                }
            }
        }
    }
    Ok(())
}

/// Bounded attacker-style worker. Each iteration prepares a fresh regular file
/// with constant content and a fresh outside symlink under their own names and
/// then atomically renames them into place. The published regular inode is
/// never modified or truncated, and no write ever happens through a symlink.
fn swapper_run(
    root_path: &std::path::Path,
    entry: &std::path::Path,
    outside: &std::path::Path,
    stop: &AtomicBool,
) -> Result<(), String> {
    for i in 0..SWAP_LIMIT {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let prepared = root_path.join(format!("regular-{i}.tmp"));
        fs::write(&prepared, INSIDE).map_err(|e| format!("write prepared: {e}"))?;
        fs::rename(&prepared, entry).map_err(|e| format!("publish regular: {e}"))?;

        let link = root_path.join(format!("escape-{i}.tmp"));
        symlink(outside, &link).map_err(|e| format!("prepare symlink: {e}"))?;
        fs::rename(&link, entry).map_err(|e| format!("publish symlink: {e}"))?;
    }
    Ok(())
}

#[test]
fn regular_data_and_stat() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    fs::write(dir.path().join("data.txt"), b"hello")?;
    let root = root_of(&dir)?;
    let path = RelativePath::parse(b"data.txt")?;
    let meta = root.stat(&path, SymlinkMode::RefuseAll)?;
    assert_eq!(meta.size(), 5);
    assert_eq!(meta.mode() & 0o170000, 0o100000);
    Ok(())
}

#[test]
fn safe_relative_symlink_download() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    fs::write(dir.path().join("target.txt"), b"symlink-data")?;
    symlink("target.txt", dir.path().join("link"))?;
    let root = root_of(&dir)?;
    let path = RelativePath::parse(b"link")?;
    let download = root.open_download(&path, SymlinkMode::RelativeWithinRoot)?;
    let mut buf = Vec::new();
    let mut file = download.file();
    file.read_to_end(&mut buf)?;
    assert_eq!(buf.as_slice(), b"symlink-data");
    Ok(())
}

#[test]
fn escaping_relative_symlink_rejected() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    fs::write(dir.path().join("outside.txt"), b"outside")?;
    let root_path = dir.path().join("root");
    fs::create_dir(&root_path)?;
    symlink("../outside.txt", root_path.join("escape"))?;
    let root = RootDir::open(&root_path)?;
    let path = RelativePath::parse(b"escape")?;
    assert!(
        root.open_download(&path, SymlinkMode::RelativeWithinRoot)
            .is_err()
    );
    Ok(())
}

#[test]
fn absolute_symlink_rejected() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    fs::write(dir.path().join("outside.txt"), b"outside")?;
    let root_path = dir.path().join("root");
    fs::create_dir(&root_path)?;
    let absolute_target = dir.path().join("outside.txt");
    symlink(&absolute_target, root_path.join("abs"))?;
    let root = RootDir::open(&root_path)?;
    let path = RelativePath::parse(b"abs")?;
    assert!(
        root.open_download(&path, SymlinkMode::RelativeWithinRoot)
            .is_err()
    );
    Ok(())
}

#[test]
fn refuse_all_rejects_safe_symlink() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    fs::write(dir.path().join("target.txt"), b"data")?;
    symlink("target.txt", dir.path().join("link"))?;
    let root = root_of(&dir)?;
    let path = RelativePath::parse(b"link")?;
    assert_eq!(
        root.stat(&path, SymlinkMode::RefuseAll).err(),
        Some(FsError::SymlinkNotPermitted)
    );
    Ok(())
}

#[test]
fn missing_target() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let root = root_of(&dir)?;
    let path = RelativePath::parse(b"nope.txt")?;
    assert_eq!(
        root.stat(&path, SymlinkMode::RefuseAll).err(),
        Some(FsError::NotFound)
    );
    Ok(())
}

#[test]
fn directory_is_not_regular() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    fs::create_dir(dir.path().join("sub"))?;
    let root = root_of(&dir)?;
    let path = RelativePath::parse(b"sub")?;
    assert_eq!(
        root.stat(&path, SymlinkMode::RefuseAll).err(),
        Some(FsError::NotRegularFile)
    );
    Ok(())
}

#[test]
fn fifo_open_returns_promptly_without_writer() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    mkfifo(&dir.path().join("pipe"), Mode::S_IRUSR | Mode::S_IWUSR)?;
    let root = root_of(&dir)?;
    let path = RelativePath::parse(b"pipe")?;

    // Run the open on a worker thread and bound the wait, so a regression that
    // blocks on the FIFO cannot hang the whole suite.
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(
            root.open_download(&path, SymlinkMode::RefuseAll)
                .map(|_| ()),
        );
    });
    let received = rx.recv_timeout(Duration::from_secs(10));
    assert_eq!(received.ok(), Some(Err(FsError::NotRegularFile)));
    Ok(())
}

#[test]
fn path_validation() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        RelativePath::parse(b"").err(),
        Some(FsError::InvalidPathEmpty)
    );
    assert_eq!(
        RelativePath::parse(b"/etc/passwd").err(),
        Some(FsError::PathAbsolute)
    );
    assert_eq!(
        RelativePath::parse(b"..").err(),
        Some(FsError::PathHasParent)
    );
    assert_eq!(
        RelativePath::parse(b"a/../b").err(),
        Some(FsError::PathHasParent)
    );
    assert_eq!(
        RelativePath::parse(b"a\0b").err(),
        Some(FsError::PathContainsNul)
    );

    let exact = vec![b'a'; 4096];
    assert!(RelativePath::parse(&exact).is_ok());
    let over = vec![b'a'; 4097];
    assert_eq!(RelativePath::parse(&over).err(), Some(FsError::PathTooLong));
    Ok(())
}

#[test]
fn root_path_validation() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;

    assert!(matches!(RootDir::open(""), Err(FsError::RootEmpty)));
    assert!(matches!(
        RootDir::open("relative/dir"),
        Err(FsError::RootNotAbsolute)
    ));
    assert!(matches!(
        RootDir::open(std::path::Path::new("/tmp/mender\0root")),
        Err(FsError::RootContainsNul)
    ));

    // Nonexistent root lives inside our own tempdir, never a global path.
    let missing = dir.path().join("missing-child");
    assert!(matches!(
        RootDir::open(&missing),
        Err(FsError::RootNotFound)
    ));

    let file = dir.path().join("file.txt");
    fs::write(&file, b"x")?;
    assert!(matches!(
        RootDir::open(&file),
        Err(FsError::RootNotDirectory)
    ));
    Ok(())
}

#[test]
fn descriptors_are_cloexec() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    fs::write(dir.path().join("data.txt"), b"x")?;
    let root = root_of(&dir)?;
    let root_flags = fcntl(root.as_fd().as_raw_fd(), FcntlArg::F_GETFD)?;
    assert_ne!(root_flags & FD_CLOEXEC, 0);

    let path = RelativePath::parse(b"data.txt")?;
    let download = root.open_download(&path, SymlinkMode::RefuseAll)?;
    let download_flags = fcntl(download.as_fd().as_raw_fd(), FcntlArg::F_GETFD)?;
    assert_ne!(download_flags & FD_CLOEXEC, 0);
    Ok(())
}

#[test]
fn metadata_stays_pinned_through_replacement() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let original = dir.path().join("file.bin");
    fs::write(&original, b"first")?;
    let root = root_of(&dir)?;
    let path = RelativePath::parse(b"file.bin")?;
    let download = root.open_download(&path, SymlinkMode::RefuseAll)?;
    assert_eq!(download.metadata().size(), 5);

    let moved = dir.path().join("moved.bin");
    fs::rename(&original, &moved)?;
    fs::write(&original, b"SECOND-LONGER-CONTENT")?;

    let mut buf = Vec::new();
    let mut file = download.file();
    file.read_to_end(&mut buf)?;
    assert_eq!(buf.as_slice(), b"first");
    assert_eq!(download.metadata().size(), 5);
    Ok(())
}

#[test]
fn bounded_symlink_swap_never_reads_outside_sentinel() -> Result<(), Box<dyn Error>> {
    // The outside sentinel lives in its own separate, owned tempdir so no real
    // host file is ever referenced.
    let outside_dir = tempfile::tempdir()?;
    let inside_dir = tempfile::tempdir()?;
    let sentinel = b"OUTSIDE-SENTINEL-SECRET".to_vec();
    let outside = outside_dir.path().join("sentinel.txt");
    fs::write(&outside, &sentinel)?;

    let root_path = inside_dir.path().join("root");
    fs::create_dir(&root_path)?;
    let entry = root_path.join("race.txt");
    let initial = root_path.join("initial.txt");
    fs::write(&initial, INSIDE)?;
    fs::rename(&initial, &entry)?;

    let root = RootDir::open(&root_path)?;
    let path = RelativePath::parse(b"race.txt")?;

    // Controlled successful open before the race starts.
    read_once_exact(&root, &path).map_err(|e| -> Box<dyn Error> { e.into() })?;

    // The scoped worker joins a finite loop on every path, even if the reader
    // hits a failure.
    let stop = AtomicBool::new(false);
    let outcome: Result<(), String> = std::thread::scope(|scope| {
        let worker = scope.spawn(|| swapper_run(&root_path, &entry, &outside, &stop));
        let read_result = reader_loop(&root, &path);
        stop.store(true, Ordering::Relaxed);
        let worker_result = match worker.join() {
            Ok(result) => result,
            Err(_) => Err("swapper thread panicked".to_string()),
        };
        read_result.and(worker_result)
    });
    outcome.map_err(|e| -> Box<dyn Error> { e.into() })?;

    // After the worker has stopped, restore a fully-prepared regular file and
    // prove a successful read still yields exactly the inside bytes.
    let restore = root_path.join("restore.txt");
    fs::write(&restore, INSIDE)?;
    fs::rename(&restore, &entry)?;
    read_once_exact(&root, &path).map_err(|e| -> Box<dyn Error> { e.into() })?;
    Ok(())
}
