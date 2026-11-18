//! Descriptor-based Linux download and stat foundation for a future download
//! (and, later, upload) worker.
//!
//! # Scope
//!
//! This milestone is a small, self-contained *download/stat foundation*. It is
//! intentionally **not** wired into the daemon, configuration loader or
//! file-transfer workers, and it does **not** implement upload or enable
//! `Limits.Enabled`. It exposes:
//!
//! * [`RootDir`] — an owned, retained directory handle acquired once from a
//!   trusted configured absolute directory (`O_RDONLY|O_DIRECTORY|O_CLOEXEC`).
//! * [`SymlinkMode`] — whether every symlink is refused, or only relative
//!   symlinks that stay beneath the root are allowed.
//! * [`RelativePath`] — a validated, bounded, relative path (no absolute
//!   input, no NUL, no `..`, no empty value, at most [`MAX_PATH_LEN`] raw
//!   bytes).
//! * [`Metadata`] — immutable, descriptor-derived facts (`size`, `uid`, `gid`,
//!   `mode`, `dev`, `ino`) with checked conversions.
//! * [`Download`] — an opened regular target exposing a [`std::fs::File`] and
//!   the descriptor-derived facts captured at open time.
//!
//! # Opening strategy (why the order matters)
//!
//! Opening `O_RDONLY` *before* `fstat` can block on a FIFO and can touch a
//! device. To avoid that, every target is pinned first with
//! `O_PATH|O_CLOEXEC` via `openat2`, then `fstat` proves it is a regular file,
//! and only then is that same live descriptor reopened through
//! `/proc/self/fd/<fd>` with `O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_NOCTTY`. The
//! reopened descriptor is `fstat`ed again to verify identity (`st_dev`,
//! `st_ino`) and type. The procfs path is derived solely from our own pinned
//! descriptor number — it is never derived from user input — and no mount
//! namespace is changed. If the kernel lacks `openat2` resolve flags or procfs
//! is unavailable, resolution fails closed; there is no silent fallback.
//!
//! Path resolution is kernel-enforced with `openat2` using
//! `RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS` (plus `RESOLVE_NO_SYMLINKS` when
//! refusing). Absolute symlinks are rejected by the kernel rather than being
//! silently reinterpreted through `RESOLVE_IN_ROOT`. There is no userland
//! `canonicalize`/check-then-open fallback.
//!
//! # Containment limitations (read carefully)
//!
//! * Resolution is enforced **under the root at open time only**.
//! * Directories moved **out** of the root remain reachable through already
//!   opened descriptors. This is a genuine containment limitation.
//! * The root, its ancestors and the mount namespace **must be trusted and
//!   stable** for these guarantees to mean anything.
//! * A same-credential (or root) adversary is **outside** the supported threat
//!   model.
//! * Hardlinks can alias files outside the root: directory scope here is
//!   *pathname scope*, not inode provenance.
//! * The immutable [`Metadata`] captured at open time is a snapshot; it is not
//!   an assertion of current on-disk state forever.
//! * The download file's content and size may change after `fstat`; a future
//!   worker **must** cap actual bytes streamed.
//!
//! This module does **not** claim complete policy or containment under local
//! rename attacks.

use std::ffi::{CStr, CString};
use std::fmt;
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use rustix::fs::openat;
use rustix::fs::openat2;
use rustix::fs::{CWD, FileType, Mode, OFlags, ResolveFlags, Stat, fstat};
use rustix::io::Errno;

/// Maximum accepted raw path length in bytes.
pub const MAX_PATH_LEN: usize = 4096;

/// How symlinks are handled during resolution beneath the root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymlinkMode {
    /// Refuse every symlink (`RESOLVE_NO_SYMLINKS`).
    RefuseAll,
    /// Allow only relative symlinks that remain beneath the root. Absolute
    /// symlinks and escaping relative symlinks are rejected by the kernel.
    RelativeWithinRoot,
}

impl SymlinkMode {
    pub(crate) fn resolve_flags(self) -> ResolveFlags {
        match self {
            Self::RefuseAll => {
                ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS
            }
            Self::RelativeWithinRoot => ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS,
        }
    }
}

/// Typed, redacted filesystem errors.
///
/// Every message is a fixed string; no path, id or raw value is reflected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    /// The configured root path was empty.
    RootEmpty,
    /// The configured root path contained a NUL byte.
    RootContainsNul,
    /// The configured root path was not absolute.
    RootNotAbsolute,
    /// The configured root did not exist.
    RootNotFound,
    /// The configured root was not a directory.
    RootNotDirectory,
    /// Opening the configured root failed.
    RootOpenFailed,
    /// The target path was empty.
    InvalidPathEmpty,
    /// The target path exceeded [`MAX_PATH_LEN`].
    PathTooLong,
    /// The target path contained a NUL byte.
    PathContainsNul,
    /// The target path was absolute.
    PathAbsolute,
    /// The target path contained a `..` component.
    PathHasParent,
    /// The target was not found beneath the root.
    NotFound,
    /// Permission was denied during resolution.
    PermissionDenied,
    /// The running kernel does not support the required resolve flags.
    KernelUnsupported,
    /// Opening the pinned descriptor failed.
    OpenFailed,
    /// Reopening the pinned descriptor failed.
    ReopenFailed,
    /// procfs was unavailable for the reopen step.
    ProcUnavailable,
    /// The resolved target was not a regular file.
    NotRegularFile,
    /// A symlink was encountered while refusing all symlinks.
    SymlinkNotPermitted,
    /// A symlink resolved outside the root.
    SymlinkEscapesRoot,
    /// The reopened descriptor did not match the pinned descriptor.
    MetadataMismatch,
    /// A metadata value did not fit the exposed numeric range.
    MetadataRange,
}

impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::RootEmpty => "the configured root path is empty",
            Self::RootContainsNul => "the configured root path contains a NUL byte",
            Self::RootNotAbsolute => "the configured root path is not absolute",
            Self::RootNotFound => "the configured root does not exist",
            Self::RootNotDirectory => "the configured root is not a directory",
            Self::RootOpenFailed => "the configured root could not be opened",
            Self::InvalidPathEmpty => "the target path is empty",
            Self::PathTooLong => "the target path is too long",
            Self::PathContainsNul => "the target path contains a NUL byte",
            Self::PathAbsolute => "the target path is absolute",
            Self::PathHasParent => "the target path contains a parent component",
            Self::NotFound => "the target was not found beneath the root",
            Self::PermissionDenied => "permission denied during resolution",
            Self::KernelUnsupported => "the kernel does not support the required resolve flags",
            Self::OpenFailed => "the target could not be opened",
            Self::ReopenFailed => "the pinned target could not be reopened",
            Self::ProcUnavailable => "procfs is unavailable for reopening",
            Self::NotRegularFile => "the target is not a regular file",
            Self::SymlinkNotPermitted => "symlinks are not permitted",
            Self::SymlinkEscapesRoot => "the symlink escapes the root",
            Self::MetadataMismatch => "the reopened descriptor does not match the pinned one",
            Self::MetadataRange => "a metadata value is out of range",
        };
        f.write_str(message)
    }
}

impl std::error::Error for FsError {}

/// A validated, bounded, relative target path.
///
/// Constructed with [`RelativePath::parse`]; the bytes are validated once and
/// stored as a `CString`, so they are never reinterpreted afterwards.
#[derive(Debug, Clone)]
pub struct RelativePath {
    raw: CString,
}

impl RelativePath {
    /// Validate raw relative path bytes.
    ///
    /// Rejects empty input, absolute input, interior NUL bytes, any `..`
    /// component and input longer than [`MAX_PATH_LEN`].
    pub fn parse(input: &[u8]) -> Result<Self, FsError> {
        if input.is_empty() {
            return Err(FsError::InvalidPathEmpty);
        }
        if input.len() > MAX_PATH_LEN {
            return Err(FsError::PathTooLong);
        }
        if input.first() == Some(&b'/') {
            return Err(FsError::PathAbsolute);
        }
        for component in input.split(|byte| *byte == b'/') {
            if component == b".." {
                return Err(FsError::PathHasParent);
            }
        }
        let raw = CString::new(input).map_err(|_| FsError::PathContainsNul)?;
        Ok(Self { raw })
    }

    pub(crate) fn as_c_str(&self) -> &CStr {
        self.raw.as_c_str()
    }
}

/// Immutable, descriptor-derived metadata for a regular target.
///
/// These are a snapshot captured from `fstat` at open time, not a live view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Metadata {
    size: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    dev: u64,
    ino: u64,
}

impl Metadata {
    /// Size in bytes at `fstat` time.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Owning user id.
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// Owning group id.
    pub fn gid(&self) -> u32 {
        self.gid
    }

    /// Raw mode word.
    pub fn mode(&self) -> u32 {
        self.mode
    }

    /// Device number.
    pub fn dev(&self) -> u64 {
        self.dev
    }

    /// Inode number.
    pub fn ino(&self) -> u64 {
        self.ino
    }
}

fn metadata_from(stat: &Stat) -> Result<Metadata, FsError> {
    let size = u64::try_from(stat.st_size).map_err(|_| FsError::MetadataRange)?;
    Ok(Metadata {
        size,
        uid: stat.st_uid,
        gid: stat.st_gid,
        mode: stat.st_mode,
        dev: stat.st_dev,
        ino: stat.st_ino,
    })
}

fn map_openat2_err(err: Errno) -> FsError {
    if err == Errno::XDEV {
        FsError::SymlinkEscapesRoot
    } else if err == Errno::LOOP {
        FsError::SymlinkNotPermitted
    } else if err == Errno::NOENT || err == Errno::NOTDIR {
        FsError::NotFound
    } else if err == Errno::ACCESS || err == Errno::PERM {
        FsError::PermissionDenied
    } else if err == Errno::NAMETOOLONG {
        FsError::PathTooLong
    } else if err == Errno::INVAL || err == Errno::NOSYS {
        FsError::KernelUnsupported
    } else {
        FsError::OpenFailed
    }
}

fn map_stat_err(err: Errno) -> FsError {
    if err == Errno::BADF {
        FsError::OpenFailed
    } else {
        FsError::MetadataRange
    }
}

fn map_reopen_err(err: Errno) -> FsError {
    if err == Errno::NOENT || err == Errno::NOTDIR || err == Errno::ACCESS || err == Errno::PERM {
        FsError::ProcUnavailable
    } else {
        FsError::ReopenFailed
    }
}

/// An owned, retained handle on a trusted configured root directory.
///
/// Acquired once at construction; every subsequent operation is
/// descriptor-relative to this handle.
#[derive(Debug)]
pub struct RootDir {
    dir: OwnedFd,
}

impl RootDir {
    /// Acquire the root handle from a configured **absolute** directory path.
    ///
    /// Relative, empty or NUL-containing paths are rejected with a typed
    /// error. The path is resolved by the caller's (trusted) directory and
    /// mount namespace. The handle is opened
    /// `O_RDONLY|O_DIRECTORY|O_CLOEXEC` and verified to be a directory.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, FsError> {
        let path = path.as_ref();
        let bytes = path.as_os_str().as_bytes();
        if bytes.is_empty() {
            return Err(FsError::RootEmpty);
        }
        if !path.is_absolute() {
            return Err(FsError::RootNotAbsolute);
        }
        let c_path = CString::new(bytes).map_err(|_| FsError::RootContainsNul)?;
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
        let dir = openat(CWD, c_path.as_c_str(), flags, Mode::empty()).map_err(|err| {
            if err == Errno::NOENT {
                FsError::RootNotFound
            } else if err == Errno::NOTDIR {
                FsError::RootNotDirectory
            } else if err == Errno::ACCESS || err == Errno::PERM {
                FsError::PermissionDenied
            } else {
                FsError::RootOpenFailed
            }
        })?;
        let stat = fstat(&dir).map_err(map_stat_err)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
            return Err(FsError::RootNotDirectory);
        }
        Ok(Self { dir })
    }

    fn open_pinned(
        &self,
        path: &RelativePath,
        mode: SymlinkMode,
    ) -> Result<(OwnedFd, Stat), FsError> {
        let flags = OFlags::PATH | OFlags::CLOEXEC;
        let pinned = openat2(
            &self.dir,
            path.as_c_str(),
            flags,
            Mode::empty(),
            mode.resolve_flags(),
        )
        .map_err(map_openat2_err)?;
        let stat = fstat(&pinned).map_err(map_stat_err)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(FsError::NotRegularFile);
        }
        Ok((pinned, stat))
    }

    /// Return descriptor-derived metadata for a regular target.
    pub fn stat(&self, path: &RelativePath, mode: SymlinkMode) -> Result<Metadata, FsError> {
        let (_pinned, stat) = self.open_pinned(path, mode)?;
        metadata_from(&stat)
    }

    /// Open a regular target for download.
    ///
    /// The target is pinned `O_PATH`, proven regular, then reopened through
    /// `/proc/self/fd/<fd>` with `O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_NOCTTY` and
    /// re-verified for identity and type.
    pub fn open_download(
        &self,
        path: &RelativePath,
        mode: SymlinkMode,
    ) -> Result<Download, FsError> {
        let (pinned, before) = self.open_pinned(path, mode)?;
        let raw = pinned.as_raw_fd();
        let proc_path = format!("/proc/self/fd/{raw}");
        let reopen_flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOCTTY;
        let reopened =
            openat(CWD, proc_path.as_str(), reopen_flags, Mode::empty()).map_err(map_reopen_err)?;
        let after = fstat(&reopened).map_err(map_stat_err)?;
        if after.st_dev != before.st_dev
            || after.st_ino != before.st_ino
            || FileType::from_raw_mode(after.st_mode) != FileType::RegularFile
        {
            return Err(FsError::MetadataMismatch);
        }
        let facts = metadata_from(&after)?;
        let file = File::from(reopened);
        Ok(Download { file, facts })
    }
}

impl AsFd for RootDir {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.dir.as_fd()
    }
}

/// An opened regular download target.
///
/// Exposes the retained [`std::fs::File`] and the immutable facts captured at
/// open time. The content and size may change after `fstat`; a future worker
/// must cap the actual bytes streamed.
#[derive(Debug)]
pub struct Download {
    file: File,
    facts: Metadata,
}

impl Download {
    /// The retained file handle.
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Consume the download, yielding the owned file handle.
    pub fn into_file(self) -> File {
        self.file
    }

    /// Descriptor-derived facts captured at open time (a snapshot).
    pub fn metadata(&self) -> &Metadata {
        &self.facts
    }
}

impl AsFd for Download {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}
