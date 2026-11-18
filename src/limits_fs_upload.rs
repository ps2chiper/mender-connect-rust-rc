//! Descriptor-relative staged creation and replacement of regular files.
//!
//! # Scope
//!
//! This layer implements limited upload staging and publication on top of the
//! descriptor-based [`crate::limits_fs`] layer. The transfer worker applies
//! policy and selects create or replacement behavior before calling it.
//!
//! A [`StagedCreate`] is produced by [`begin_staged_create`] and holds:
//!
//! * an unnamed `O_TMPFILE|O_RDWR|O_CLOEXEC` staging file with mode `0o600`
//!   (no named staging fallback — an unsupported filesystem is a typed,
//!   fail-closed error),
//! * a retained `O_CLOEXEC` handle on the resolved **parent** directory,
//! * the validated single-component **basename** to publish.
//!
//! The stage is written through the [`std::io::Write`] implementation on
//! [`StagedCreate`], which bounds the actual file offset to
//! [`MAX_UPLOAD_BYTES`] before each write. The final size is additionally
//! re-checked with `fstat` at commit time.
//!
//! # Commit
//!
//! [`StagedCreate::commit_new`] publishes the file with `linkat` of the live
//! retained staging descriptor via a generated `/proc/self/fd/<N>` source
//! pathname and `AT_SYMLINK_FOLLOW`. `AT_EMPTY_PATH` is **not** used because it
//! needs `CAP_DAC_READ_SEARCH` and fails for ordinary users. The source is
//! always our own held descriptor and the target is the validated single
//! basename inside the pinned parent. The file is `fsync`ed before the link and
//! the parent directory is `fsync`ed after it.
//!
//! The commit result distinguishes a **pre-publication** failure (no entry was
//! created; the stage is dropped and nothing is left behind) from
//! [`UploadError::PublishedButDurabilityUnknown`], returned when the entry was
//! successfully linked but the subsequent parent `fsync` failed. In the latter
//! case the file *is* published; no false rollback is claimed.
//!
//! For [`StagedCreate::commit_new`], an existing target of **any** type —
//! regular file, directory, symlink or a dangling symlink — makes the commit
//! fail with [`UploadError::AlreadyExists`] without touching it.
//!
//! # Limited-upload admission
//!
//! Limited uploads reject an unsafe directory chain before a stage is allocated
//! or acknowledged. Every directory from the configured root through the selected
//! upload parent must be owned by the effective daemon uid or by root and must
//! carry no group/other write permission. The configured root itself is always
//! checked, including when it is not the selected upload parent. The check walks
//! the actual held directory descriptors upward with `..`, bounded in depth, and
//! rejects reaching the filesystem root before the configured root. Ancestry
//! above the configured root is never inspected.
//!
//! POSIX ACL masks are reflected in the group permission bits on filesystems that
//! implement ACLs this way; this layer does not claim to detect every extended or
//! non-POSIX filesystem policy. Root daemons therefore reject upload trees whose
//! directories are owned by another user, and group-writable limited upload trees
//! fail closed. Permitted ownership changes on the staged object are unaffected.
//!
//! # Containment limitations (read carefully)
//!
//! * The held parent is reopened beneath the pinned root and compared before
//!   publication. This detects earlier moves or substitutions, but a move can
//!   still occur after that check and before publication. Moving the root itself
//!   is also outside this check. Stable, trusted ancestors, same-credential
//!   callers and a trusted root remain necessary; this is not universal
//!   race-free containment.
//! * Hardlink provenance is not guaranteed: an on-disk hardlink can alias an
//!   inode outside the root. Directory scope here is *pathname* scope.
//! * The procfs namespace is assumed trusted (no mount-namespace changes are
//!   made here).
//! * Stages start private and requested metadata is applied only through a
//!   validated plan before publication.
//! * Ancestor safety is an admission-time filesystem policy check. It does not
//!   prove hardlink provenance, cannot make arbitrary concurrent renames
//!   race-free, and does not constrain movement of the configured root or
//!   same-credential/root actors. Those remain trusted assumptions.

use std::ffi::{CStr, CString, OsStr};
use std::fmt;
use std::fs::File;
use std::io::{self, Seek, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use rustix::fs::{
    AtFlags, CWD, FileType, Mode, OFlags, ResolveFlags, Stat, fstat, linkat, openat2, renameat,
    statat, unlinkat,
};
use rustix::io::Errno;

use crate::file_transfer_schema::source_basename;
use crate::limits::CommitPlan;
use crate::limits_fs::{MAX_PATH_LEN, RelativePath, RootDir, SymlinkMode};

/// Hard maximum accepted final upload size in bytes (256 MiB).
///
/// The actual size is measured once with `fstat` at commit time and refused if
/// larger. This bound is only a check, not a limit on what a trusted caller may
/// write into the stage.
pub const MAX_UPLOAD_BYTES: u64 = 256 * 1024 * 1024;

/// Typed, redacted staged-create errors.
///
/// Every message is a fixed string; no path, id or raw value is reflected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadError {
    /// The supplied relative path did not split into a usable basename.
    PathInvalid,
    /// The parent directory could not be found beneath the root.
    ParentNotFound,
    /// A parent component was not a directory.
    ParentNotDirectory,
    /// A symlink was encountered while refusing all symlinks.
    ParentSymlinkNotPermitted,
    /// A parent symlink resolved outside the root.
    ParentSymlinkEscapesRoot,
    /// Permission was denied while resolving the parent.
    ParentPermissionDenied,
    /// Opening the parent directory failed.
    ParentOpenFailed,
    /// The admitted parent no longer resolves to the same directory beneath the root.
    ParentChangedAfterAdmission,
    /// The running kernel lacks the required resolve flags.
    KernelUnsupported,
    /// The staging filesystem does not support `O_TMPFILE`.
    TmpfileUnsupported,
    /// Creating the unnamed staging file failed.
    CreateFailed,
    /// `fstat` of the staging file failed at commit time.
    CommitStatFailed,
    /// The staged object is not a regular file.
    CommitNotRegular,
    /// The staged size is negative or exceeds [`MAX_UPLOAD_BYTES`].
    CommitSizeOutOfRange,
    /// Flushing the staging file before publication failed.
    CommitSyncFailed,
    /// A target of some type already exists.
    AlreadyExists,
    /// Publishing the link failed (no entry was created).
    PublishFailed,
    /// The file was published but the parent directory could not be flushed.
    PublishedButDurabilityUnknown,
    /// The requested owner metadata is invalid (e.g. the `u32::MAX` sentinel).
    InvalidMetadataOwner,
    /// The requested mode bits are outside the permitted `0o4777` mask.
    InvalidMetadataMode,
    /// Applying the requested ownership failed before publication.
    OwnershipApplyFailed,
    /// Applying the requested mode failed before publication.
    ModeApplyFailed,
    /// A final directory target requires a `src_path`.
    DirectoryRequiresSrcPath,
    /// The `src_path` did not yield a usable upload basename.
    DirectoryBasenameInvalid,
    /// A final target symlink or other non-regular file was refused.
    TargetNotRegular,
    /// The final target changed type or identity after admission.
    TargetChangedAfterAdmission,
    /// The replacement parent is owned by another user or is group/other writable.
    UnsafeReplacementParent,
    /// An upload ancestor is owned by another user or is group/other writable.
    UnsafeUploadAncestor,
    /// Publication failed and the short-lived staging link may remain.
    PossibleLeftover,
    /// The resolved target path exceeded the maximum length.
    TargetPathTooLong,
    /// The resolved target basename exceeded the maximum length.
    TargetBasenameTooLong,
    /// A descriptor-reported target size was out of range.
    TargetSizeInvalid,
}

impl fmt::Display for UploadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::PathInvalid => "the relative path did not yield a usable basename",
            Self::ParentNotFound => "the parent directory was not found beneath the root",
            Self::ParentNotDirectory => "a parent component is not a directory",
            Self::ParentSymlinkNotPermitted => "symlinks are not permitted in the parent path",
            Self::ParentSymlinkEscapesRoot => "a parent symlink escapes the root",
            Self::ParentPermissionDenied => "permission denied while resolving the parent",
            Self::ParentOpenFailed => "the parent directory could not be opened",
            Self::ParentChangedAfterAdmission => "the parent directory changed after admission",
            Self::KernelUnsupported => "the kernel does not support the required resolve flags",
            Self::TmpfileUnsupported => "the staging filesystem does not support O_TMPFILE",
            Self::CreateFailed => "the unnamed staging file could not be created",
            Self::CommitStatFailed => "the staging file could not be inspected",
            Self::CommitNotRegular => "the staged object is not a regular file",
            Self::CommitSizeOutOfRange => "the staged size is out of range",
            Self::CommitSyncFailed => "the staging file could not be flushed",
            Self::AlreadyExists => "a target already exists",
            Self::PublishFailed => "publishing the file failed",
            Self::PublishedButDurabilityUnknown => {
                "the file was published but its durability is unknown"
            }
            Self::InvalidMetadataOwner => "the requested owner metadata is invalid",
            Self::InvalidMetadataMode => "the requested mode metadata is invalid",
            Self::OwnershipApplyFailed => "applying the requested ownership failed",
            Self::ModeApplyFailed => "applying the requested mode failed",
            Self::DirectoryRequiresSrcPath => "a directory target requires a source path",
            Self::DirectoryBasenameInvalid => "the source path is not a usable basename",
            Self::TargetNotRegular => "the final target is not a regular file",
            Self::TargetChangedAfterAdmission => "the target changed after admission",
            Self::UnsafeReplacementParent => "the replacement parent is not safe to modify",
            Self::UnsafeUploadAncestor => "an upload ancestor is not safely owned or writable",
            Self::PossibleLeftover => "publication failed; a staging link may remain",
            Self::TargetPathTooLong => "the resolved target path is too long",
            Self::TargetBasenameTooLong => "the resolved target basename is too long",
            Self::TargetSizeInvalid => "the target size is out of range",
        };
        f.write_str(message)
    }
}

impl std::error::Error for UploadError {}

/// A shape-validated request to apply owner and/or POSIX mode metadata to a
/// staged file immediately before it is published.
///
/// A `MetadataPlan` is produced by a **trusted** upstream policy
/// compiler/worker. This type only guarantees the *shape* of the request:
///
/// * owner ids are not the `u32::MAX` sentinel, and
/// * requested mode bits lie inside the permitted `0o4777` mask (no POSIX setgid
///   or sticky bits, no Go `os.FileMode`-encoded type bits, no raw file-type
///   bits and no other out-of-mask bits).
///
/// The layer that consumes the plan verifies only that shape; it makes **no**
/// provenance or authorisation claim about a raw plan. A normalised POSIX
/// setuid bit (`0o4000`) is already authorised upstream by the `LimitsPolicy`
/// before it reaches this type.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MetadataPlan {
    uid: Option<u32>,
    gid: Option<u32>,
    mode: Option<u32>,
}

impl MetadataPlan {
    /// A plan that applies no metadata (the stage keeps its default `0o600`).
    pub fn none() -> Self {
        Self {
            uid: None,
            gid: None,
            mode: None,
        }
    }

    /// Build a plan from optional owner ids and mode bits.
    ///
    /// The values are shape-checked by [`MetadataPlan::validate`] before any IO
    /// is performed.
    pub fn new(uid: Option<u32>, gid: Option<u32>, mode: Option<u32>) -> Self {
        Self { uid, gid, mode }
    }

    /// The requested owner uid, if any.
    pub fn uid(&self) -> Option<u32> {
        self.uid
    }

    /// The requested owner gid, if any.
    pub fn gid(&self) -> Option<u32> {
        self.gid
    }

    /// The requested POSIX mode bits, if any.
    pub fn mode(&self) -> Option<u32> {
        self.mode
    }

    /// Verify the *shape* of the plan without performing any IO.
    fn validate(&self) -> Result<(), UploadError> {
        if self.uid == Some(u32::MAX) || self.gid == Some(u32::MAX) {
            return Err(UploadError::InvalidMetadataOwner);
        }
        if let Some(mode) = self.mode {
            // Reject any bit outside setuid + rwxrwxrwx (setgid, sticky, Go
            // encoded type bits, raw file-type bits, ...). No silent truncation.
            if mode & !0o4777u32 != 0 {
                return Err(UploadError::InvalidMetadataMode);
            }
        }
        Ok(())
    }
}

/// Convert an upstream [`CommitPlan`] into a shape-checked [`MetadataPlan`].
///
/// The plan's shape is validated with the same private check used before any
/// IO, so a reserved `u32::MAX` owner id or an out-of-mask mode bit is rejected
/// before a stage is touched.
impl TryFrom<CommitPlan> for MetadataPlan {
    type Error = UploadError;

    fn try_from(plan: CommitPlan) -> Result<Self, UploadError> {
        let metadata = MetadataPlan::new(plan.ownership.uid, plan.ownership.gid, plan.mode);
        metadata.validate()?;
        Ok(metadata)
    }
}

/// Descriptor-derived facts about an existing regular-file target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExistingTarget {
    /// Owning user id.
    pub uid: u32,
    /// Owning group id.
    pub gid: u32,
    /// Size in bytes at admission.
    pub size: u64,
    /// Whether the target was a regular file.
    pub is_regular: bool,
    /// Whether the target path itself was a symlink.
    pub is_symlink: bool,
}

/// An in-progress staged creation of a new or replacement regular file.
///
/// The unnamed staging file and the pinned parent directory are both held as
/// owned, `O_CLOEXEC` descriptors. Dropping a `StagedCreate` without committing
/// closes the stage automatically and leaves no named entry behind.
#[derive(Debug)]
#[must_use = "a staged create left unused silently discards the stage"]
pub struct StagedCreate {
    file: File,
    parent: OwnedFd,
    basename: CString,
    replace: bool,
    existing: Option<ExistingTarget>,
    location: ParentLocation,
}

/// Retained root and validated relative path for best-effort relocation detection.
#[derive(Debug)]
struct ParentLocation {
    root: OwnedFd,
    path: CString,
    mode: SymlinkMode,
}

impl ParentLocation {
    fn new(root: &RootDir, path: CString, mode: SymlinkMode) -> Result<Self, UploadError> {
        let root = root
            .as_fd()
            .try_clone_to_owned()
            .map_err(|_| UploadError::ParentOpenFailed)?;
        Ok(Self { root, path, mode })
    }

    fn check(&self, original: &OwnedFd) -> Result<(), UploadError> {
        let reopened = openat2(
            &self.root,
            self.path.as_c_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            self.mode.resolve_flags(),
        )
        .map_err(|_| UploadError::ParentChangedAfterAdmission)?;
        let old = fstat(original).map_err(|_| UploadError::ParentChangedAfterAdmission)?;
        let current = fstat(&reopened).map_err(|_| UploadError::ParentChangedAfterAdmission)?;
        if old.st_dev != current.st_dev || old.st_ino != current.st_ino {
            return Err(UploadError::ParentChangedAfterAdmission);
        }
        Ok(())
    }
}

impl StagedCreate {
    /// The staging file descriptor (for `CLOEXEC` inspection).
    pub fn stage_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }

    /// The pinned parent directory descriptor (for `CLOEXEC` inspection).
    pub fn parent_fd(&self) -> BorrowedFd<'_> {
        self.parent.as_fd()
    }

    /// Advisory static preflight: confirm no entry (of any type, including a
    /// dangling symlink) already exists at the target basename inside the pinned
    /// parent.
    ///
    /// Uses `statat` with `SYMLINK_NOFOLLOW` relative to the pinned parent.
    /// `ENOENT` is the only accepted "absent" result; any existing object (any
    /// type) yields [`UploadError::AlreadyExists`] and any other error fails
    /// closed. This is *not* a security boundary: the atomic `linkat` in
    /// [`Self::commit_new_with_metadata`] remains authoritative against a
    /// concurrent insertion, and a collision after ACK is a reported commit
    /// error, never an overwrite.
    pub fn ensure_target_absent(&self) -> Result<(), UploadError> {
        match statat(
            &self.parent,
            self.basename.as_c_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Err(Errno::NOENT) => Ok(()),
            Ok(_) => Err(UploadError::AlreadyExists),
            Err(_) => Err(UploadError::PublishFailed),
        }
    }

    /// Atomically publish the staged file as a **new** entry.
    ///
    /// The retained staging file is `fsync`ed, then `linkat`ed into the pinned
    /// parent under the single validated basename using a generated
    /// `/proc/self/fd/<N>` source and `AT_SYMLINK_FOLLOW`. The parent directory
    /// is then `fsync`ed.
    ///
    /// On any pre-publication error no entry is created and the stage is
    /// dropped. If the link succeeds but the parent `fsync` fails,
    /// [`UploadError::PublishedButDurabilityUnknown`] is returned and the file
    /// remains published.
    pub fn commit_new(self) -> Result<(), UploadError> {
        self.commit_new_with_metadata(MetadataPlan::none())
    }

    /// Atomically publish the staged file as a **new** entry after applying an
    /// optional, shape-validated [`MetadataPlan`].
    ///
    /// This method is strictly **no-overwrite**: even when the stage was
    /// prepared for a replacement target, publication always forces the atomic
    /// new-link path, so an existing entry makes the commit fail with
    /// [`UploadError::AlreadyExists`] and is never replaced. The plan is
    /// validated *before* any IO. If validation fails the stage is left
    /// untouched and no entry is created. When a plan requests ownership and/or
    /// a mode, `fchown` is applied first, then the final `fchmod`, then the file
    /// is flushed, linked and the parent synced, preserving the pre-publication
    /// versus [`UploadError::PublishedButDurabilityUnknown`] distinction.
    ///
    /// This method only verifies the *shape* of the plan; whether the request
    /// is authorised (for example a normalised POSIX setuid bit) is decided by
    /// the trusted upstream policy compiler/worker that produced it.
    pub fn commit_new_with_metadata(self, plan: MetadataPlan) -> Result<(), UploadError> {
        plan.validate()?;
        self.commit_common(plan, false)
    }

    /// Mode-aware publication used by the context-prepared create/replace
    /// backend: publish as a new entry for a create stage, or replace the
    /// admitted regular file for a replacement stage.
    ///
    /// The replacement path revalidates the target snapshot (regular file, same
    /// owner/group) and the parent safety condition before the atomic rename.
    /// The plan is validated *before* any IO. New-only callers must use
    /// [`Self::commit_new_with_metadata`] instead, which never replaces.
    pub fn commit_with_metadata(self, plan: MetadataPlan) -> Result<(), UploadError> {
        plan.validate()?;
        let allow_replace = self.replace;
        self.commit_common(plan, allow_replace)
    }

    fn commit_common(self, plan: MetadataPlan, allow_replace: bool) -> Result<(), UploadError> {
        let stat = fstat(&self.file).map_err(|_| UploadError::CommitStatFailed)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(UploadError::CommitNotRegular);
        }
        if stat.st_size < 0 {
            return Err(UploadError::CommitSizeOutOfRange);
        }
        let size = u64::try_from(stat.st_size).map_err(|_| UploadError::CommitSizeOutOfRange)?;
        if size > MAX_UPLOAD_BYTES {
            return Err(UploadError::CommitSizeOutOfRange);
        }

        // Ownership first, then the final mode, per POSIX safe ordering.
        if plan.uid.is_some() || plan.gid.is_some() {
            let uid = plan.uid.map(nix::unistd::Uid::from_raw);
            let gid = plan.gid.map(nix::unistd::Gid::from_raw);
            nix::unistd::fchown(self.file.as_raw_fd(), uid, gid)
                .map_err(|_| UploadError::OwnershipApplyFailed)?;
        }
        if let Some(mode) = plan.mode {
            apply_mode(&self.file, mode)?;
        }

        // Flush the file contents and metadata before it becomes reachable.
        self.file
            .sync_all()
            .map_err(|_| UploadError::CommitSyncFailed)?;

        // This detects a prior move, but a concurrent move after this check is
        // still possible. Stable trusted ancestry remains a requirement.
        self.location.check(&self.parent)?;

        // Source path is derived solely from our own held descriptor; it is
        // never derived from caller input.
        let source = format!("/proc/self/fd/{}", self.file.as_raw_fd());

        if allow_replace && self.replace {
            self.commit_replace(&source)
        } else {
            self.commit_new_link(&source)
        }
    }

    fn commit_new_link(self, source: &str) -> Result<(), UploadError> {
        // Atomic no-overwrite link of the retained stage descriptor. A concurrent
        // insertion after admission surfaces as `AlreadyExists`, never an
        // overwrite.
        let link_result = linkat(
            CWD,
            source,
            &self.parent,
            self.basename.as_c_str(),
            AtFlags::SYMLINK_FOLLOW,
        );
        match link_result {
            Ok(()) => {}
            Err(err) => {
                if err == Errno::EXIST {
                    return Err(UploadError::AlreadyExists);
                }
                return Err(UploadError::PublishFailed);
            }
        }

        // The entry now exists; a parent flush failure must not be reported as a
        // pre-publication failure.
        let parent = File::from(self.parent);
        parent
            .sync_all()
            .map_err(|_| UploadError::PublishedButDurabilityUnknown)?;
        Ok(())
    }

    fn commit_replace(self, source: &str) -> Result<(), UploadError> {
        // Descriptor-derived snapshot revalidation: the target must still be a
        // regular file owned by the same user/group admitted earlier. This is a
        // snapshot comparison, not an atomic owner-conditional rename.
        let stat = match statat(
            &self.parent,
            self.basename.as_c_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(stat) => stat,
            Err(_) => return Err(UploadError::TargetChangedAfterAdmission),
        };
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(UploadError::TargetNotRegular);
        }
        if let Some(existing) = &self.existing
            && (stat.st_uid != existing.uid || stat.st_gid != existing.gid)
        {
            return Err(UploadError::TargetChangedAfterAdmission);
        }
        // Re-check the replacement-parent safety condition before publishing.
        check_parent_safe(&self.parent)?;

        // Create a short-lived named link of our retained stage FD, then rename
        // it over the target within the SAME held parent. The guard borrow ends
        // before the parent descriptor is moved into the final fsync.
        {
            let mut linked = None;
            for _ in 0..8 {
                let candidate = random_stage_name()?;
                match linkat(
                    CWD,
                    source,
                    &self.parent,
                    candidate.as_c_str(),
                    AtFlags::SYMLINK_FOLLOW,
                ) {
                    Ok(()) => {
                        linked = Some(candidate);
                        break;
                    }
                    Err(Errno::EXIST) => continue,
                    Err(_) => return Err(UploadError::PublishFailed),
                }
            }
            let name = linked.ok_or(UploadError::PublishFailed)?;
            let mut guard = LinkedName::new(&self.parent, name);

            if renameat(
                &self.parent,
                guard.name.as_c_str(),
                &self.parent,
                self.basename.as_c_str(),
            )
            .is_err()
            {
                // Explicit cleanup: report a possible leftover if it also fails
                // rather than claiming a guaranteed rollback.
                let cleanup = unlinkat(&self.parent, guard.name.as_c_str(), AtFlags::empty());
                guard.disarm();
                return Err(match cleanup {
                    Ok(()) => UploadError::PublishFailed,
                    Err(_) => UploadError::PossibleLeftover,
                });
            }
            guard.disarm();
        }

        let parent = File::from(self.parent);
        parent
            .sync_all()
            .map_err(|_| UploadError::PublishedButDurabilityUnknown)?;
        Ok(())
    }
}

impl Write for StagedCreate {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let position = self.file.stream_position()?;
        let requested = u64::try_from(buf.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "size overflow"))?;
        let end = position
            .checked_add(requested)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "size overflow"))?;
        if end > MAX_UPLOAD_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "write would exceed the maximum upload size",
            ));
        }
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

fn apply_mode(file: &File, mode: u32) -> Result<(), UploadError> {
    let bits = Mode::from_bits(mode).ok_or(UploadError::InvalidMetadataMode)?;
    rustix::fs::fchmod(file, bits).map_err(|_| UploadError::ModeApplyFailed)
}

fn map_parent_err(err: Errno) -> UploadError {
    if err == Errno::XDEV {
        UploadError::ParentSymlinkEscapesRoot
    } else if err == Errno::LOOP {
        UploadError::ParentSymlinkNotPermitted
    } else if err == Errno::NOENT {
        UploadError::ParentNotFound
    } else if err == Errno::NOTDIR {
        UploadError::ParentNotDirectory
    } else if err == Errno::ACCESS || err == Errno::PERM {
        UploadError::ParentPermissionDenied
    } else if err == Errno::INVAL || err == Errno::NOSYS {
        UploadError::KernelUnsupported
    } else {
        UploadError::ParentOpenFailed
    }
}

fn map_tmpfile_err(err: Errno) -> UploadError {
    if err == Errno::OPNOTSUPP || err == Errno::ISDIR {
        UploadError::TmpfileUnsupported
    } else {
        UploadError::CreateFailed
    }
}

/// Split a validated relative path into a parent path and a single basename.
///
/// The parent may be empty (a leaf directly beneath the root); the result is
/// then the internal `.` relative to the root. The basename is validated to be
/// non-empty and neither `.` nor `..`.
fn split_basename(path: &RelativePath) -> Result<(CString, CString), UploadError> {
    let bytes = path.as_c_str().to_bytes();
    let (parent_bytes, base_bytes): (&[u8], &[u8]) =
        match bytes.iter().rposition(|byte| *byte == b'/') {
            Some(index) => {
                let (left, right) = bytes
                    .split_at_checked(index)
                    .ok_or(UploadError::PathInvalid)?;
                let base = right.strip_prefix(b"/").ok_or(UploadError::PathInvalid)?;
                (left, base)
            }
            None => (b"".as_slice(), bytes),
        };

    if base_bytes.is_empty() || base_bytes == b"." || base_bytes == b".." {
        return Err(UploadError::PathInvalid);
    }

    let parent = if parent_bytes.is_empty() {
        CString::new(".").map_err(|_| UploadError::PathInvalid)?
    } else {
        CString::new(parent_bytes).map_err(|_| UploadError::PathInvalid)?
    };
    let basename = CString::new(base_bytes).map_err(|_| UploadError::PathInvalid)?;
    Ok((parent, basename))
}

/// A validated, descriptor-resolved upload target ready to be staged.
///
/// The parent directory is pinned as an owned descriptor; it is reopened beneath
/// the pinned root immediately before publication to detect prior moves. `namespace`
/// is the absolute target path used purely for the lexical policy check.
#[derive(Debug)]
pub struct PreparedTarget {
    parent: OwnedFd,
    basename: CString,
    namespace: PathBuf,
    existing: Option<ExistingTarget>,
    replace: bool,
    location: ParentLocation,
}

impl PreparedTarget {
    /// The resolved absolute target namespace (directory + basename).
    pub fn namespace(&self) -> &Path {
        &self.namespace
    }

    /// Descriptor-derived facts about an existing target, if any.
    pub fn existing(&self) -> Option<ExistingTarget> {
        self.existing
    }

    /// Whether this target replaces an existing regular file.
    pub fn is_replacement(&self) -> bool {
        self.replace
    }

    /// Create the unnamed `O_TMPFILE` staging file inside the pinned parent.
    ///
    /// The upload ancestry is checked before allocation, and a replacement
    /// target additionally checks the replacement-parent safety condition. An
    /// unsafe tree or parent is refused rather than falling back.
    pub fn begin_stage(self) -> Result<StagedCreate, UploadError> {
        if self.replace {
            check_parent_safe(&self.parent)?;
        }
        check_upload_ancestors(
            &self.location.root,
            &self.parent,
            self.location.path.as_c_str(),
            self.location.mode,
        )?;
        let staged = openat2(
            &self.parent,
            c".",
            OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
            ResolveFlags::empty(),
        )
        .map_err(map_tmpfile_err)?;
        Ok(StagedCreate {
            file: File::from(staged),
            parent: self.parent,
            basename: self.basename,
            replace: self.replace,
            existing: self.existing,
            location: self.location,
        })
    }
}

/// Begin staging a **new** regular file beneath the held root.
///
/// Resolves and pins the parent directory under `root`, then allocates an
/// unnamed `O_TMPFILE|O_RDWR|O_CLOEXEC` staging file (`0o600`) inside it. The
/// returned [`StagedCreate`] never replaces an existing entry: every commit path
/// reachable from it is new-only, so an existing target of any type makes the
/// commit fail closed with [`UploadError::AlreadyExists`] without touching it.
///
/// Path resolution and the parent pin happen here; the stage itself is only
/// linked at commit time.
pub fn begin_staged_create(
    root: &RootDir,
    relative: &RelativePath,
    mode: SymlinkMode,
) -> Result<StagedCreate, UploadError> {
    let (parent_path, basename) = split_basename(relative)?;
    let location = ParentLocation::new(root, parent_path.clone(), mode)?;
    let parent = open_dir(root, parent_path.as_c_str(), mode)?;
    check_upload_ancestors(&location.root, &parent, parent_path.as_c_str(), mode)?;
    let staged = openat2(
        &parent,
        c".",
        OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
        ResolveFlags::empty(),
    )
    .map_err(map_tmpfile_err)?;
    Ok(StagedCreate {
        file: File::from(staged),
        parent,
        basename,
        replace: false,
        existing: None,
        location,
    })
}

/// Maximum accepted basename length in bytes (POSIX `NAME_MAX`).
const MAX_BASENAME_LEN: usize = 255;

/// Bound on the number of descriptor-walked upload ancestry components.
const MAX_ANCESTOR_COMPONENTS: usize = 512;

/// A best-effort RAII guard that unlinks a short-lived named link on any
/// pre-rename error path. Disarm only after the successful rename.
struct LinkedName<'a> {
    parent: &'a OwnedFd,
    name: CString,
    armed: bool,
}

impl<'a> LinkedName<'a> {
    fn new(parent: &'a OwnedFd, name: CString) -> Self {
        Self {
            parent,
            name,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for LinkedName<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = unlinkat(self.parent, self.name.as_c_str(), AtFlags::empty());
        }
    }
}

/// Generate a fresh `>=128`-bit random staging-link name (32 hex digits).
fn random_stage_name() -> Result<CString, UploadError> {
    let value: u128 = rand::random();
    CString::new(format!(".mender-stage-{value:032x}")).map_err(|_| UploadError::PathInvalid)
}

/// Verify that a replacement parent is owned by the effective daemon uid (or
/// explicitly trusted root) and carries no group/other write bits.
fn check_parent_safe(parent: &OwnedFd) -> Result<(), UploadError> {
    ensure_safe_dir(parent).map_err(|_| UploadError::UnsafeReplacementParent)
}

fn ensure_safe_dir(dir: &OwnedFd) -> Result<(), UploadError> {
    let stat = fstat(dir).map_err(|_| UploadError::UnsafeUploadAncestor)?;
    let effective = nix::unistd::Uid::effective().as_raw();
    if stat.st_uid != effective && stat.st_uid != 0 {
        return Err(UploadError::UnsafeUploadAncestor);
    }
    if stat.st_mode & 0o022 != 0 {
        return Err(UploadError::UnsafeUploadAncestor);
    }
    Ok(())
}

/// Walk the actual held upload parent and every held directory descriptor up to
/// the pinned root, checking each directory for trusted ownership and the
/// absence of group/other write permission.
///
/// The walk starts at the parent descriptor rather than at lexical path prefixes,
/// so a followed symlink cannot hide an unsafe resolved intermediate directory.
/// The pinned root is always checked, including when it is not the upload parent.
/// Reaching the filesystem root before the pinned root, or exceeding the bounded
/// walk depth, fails closed. Ancestors above the configured root are never
/// inspected and remain trusted assumptions.
fn check_upload_ancestors(
    root: &OwnedFd,
    parent: &OwnedFd,
    parent_path: &CStr,
    _mode: SymlinkMode,
) -> Result<(), UploadError> {
    check_upload_ancestors_with(root, parent, parent_path)
}

fn check_upload_ancestors_with(
    root: &OwnedFd,
    parent: &OwnedFd,
    parent_path: &CStr,
) -> Result<(), UploadError> {
    if parent_path.to_bytes().len() > MAX_PATH_LEN {
        return Err(UploadError::TargetPathTooLong);
    }

    let root_stat = fstat(root).map_err(|_| UploadError::ParentChangedAfterAdmission)?;
    ensure_safe_dir(parent)?;
    let mut current_stat = fstat(parent).map_err(|_| UploadError::ParentChangedAfterAdmission)?;
    let mut current_fd = parent
        .as_fd()
        .try_clone_to_owned()
        .map_err(|_| UploadError::ParentOpenFailed)?;

    if same_dir(&current_stat, &root_stat) {
        return Ok(());
    }

    for _ in 0..MAX_ANCESTOR_COMPONENTS {
        let up = open_ancestor_dir(&current_fd)?;
        let up_stat = fstat(&up).map_err(|_| UploadError::ParentChangedAfterAdmission)?;
        if same_dir(&up_stat, &current_stat) {
            // The filesystem root was reached without first reaching the pinned
            // configured root, so the held parent is not beneath that root.
            return Err(UploadError::ParentChangedAfterAdmission);
        }
        ensure_safe_dir(&up)?;
        if same_dir(&up_stat, &root_stat) {
            return Ok(());
        }
        current_stat = up_stat;
        current_fd = up;
    }

    Err(UploadError::TargetPathTooLong)
}

fn open_ancestor_dir(dir: &OwnedFd) -> Result<OwnedFd, UploadError> {
    openat2(
        dir,
        c"..",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::empty(),
    )
    .map_err(|_| UploadError::UnsafeUploadAncestor)
}

fn same_dir(left: &Stat, right: &Stat) -> bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
}

fn facts_from(stat: &Stat) -> Result<ExistingTarget, UploadError> {
    let file_type = FileType::from_raw_mode(stat.st_mode);
    let size = u64::try_from(stat.st_size).map_err(|_| UploadError::TargetSizeInvalid)?;
    Ok(ExistingTarget {
        uid: stat.st_uid,
        gid: stat.st_gid,
        size,
        is_regular: file_type == FileType::RegularFile,
        is_symlink: file_type == FileType::Symlink,
    })
}

fn open_dir(root: &RootDir, parent: &CStr, mode: SymlinkMode) -> Result<OwnedFd, UploadError> {
    openat2(
        root.as_fd(),
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        mode.resolve_flags(),
    )
    .map_err(map_parent_err)
}

pub fn resolve_upload_target(
    root: &RootDir,
    relative: Option<&RelativePath>,
    root_path: &Path,
    src_path: Option<&str>,
    mode: SymlinkMode,
) -> Result<PreparedTarget, UploadError> {
    let Some(relative) = relative else {
        // The peer destination equals the configured root: a directory target.
        let basename = directory_basename(src_path)?;
        let parent = root
            .as_fd()
            .try_clone_to_owned()
            .map_err(|_| UploadError::ParentOpenFailed)?;
        let existing = match stat_leaf(&parent, basename.as_c_str())? {
            None => None,
            Some(stat) => {
                let facts = facts_from(&stat)?;
                if !facts.is_regular {
                    return Err(UploadError::TargetNotRegular);
                }
                Some(facts)
            }
        };
        let namespace = bound_namespace(root_path.join(OsStr::from_bytes(basename.to_bytes())))?;
        return Ok(PreparedTarget {
            parent,
            basename,
            namespace,
            replace: existing.is_some(),
            existing,
            location: ParentLocation::new(root, c".".to_owned(), mode)?,
        });
    };

    let (parent_path, base) = split_basename(relative)?;
    let parent = open_dir(root, parent_path.as_c_str(), mode)?;
    let dir_abs =
        bound_namespace(root_path.join(OsStr::from_bytes(relative.as_c_str().to_bytes())))?;

    match stat_leaf(&parent, base.as_c_str())? {
        None => Ok(PreparedTarget {
            parent,
            basename: base,
            namespace: dir_abs,
            existing: None,
            replace: false,
            location: ParentLocation::new(root, parent_path.clone(), mode)?,
        }),
        Some(stat) => {
            let facts = facts_from(&stat)?;
            if facts.is_regular {
                Ok(PreparedTarget {
                    parent,
                    basename: base,
                    namespace: dir_abs,
                    existing: Some(facts),
                    replace: true,
                    location: ParentLocation::new(root, parent_path.clone(), mode)?,
                })
            } else if FileType::from_raw_mode(stat.st_mode) == FileType::Directory {
                // Directory target: prove the directory descriptor, then append
                // the validated source basename inside it.
                let dir = openat2(
                    &parent,
                    base.as_c_str(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                    mode.resolve_flags(),
                )
                .map_err(map_parent_err)?;
                let basename = directory_basename(src_path)?;
                let existing = match stat_leaf(&dir, basename.as_c_str())? {
                    None => None,
                    Some(leaf) => {
                        let leaf_facts = facts_from(&leaf)?;
                        if !leaf_facts.is_regular {
                            return Err(UploadError::TargetNotRegular);
                        }
                        Some(leaf_facts)
                    }
                };
                let namespace =
                    bound_namespace(dir_abs.join(OsStr::from_bytes(basename.to_bytes())))?;
                Ok(PreparedTarget {
                    parent: dir,
                    basename,
                    namespace,
                    replace: existing.is_some(),
                    existing,
                    location: ParentLocation::new(root, relative.as_c_str().to_owned(), mode)?,
                })
            } else {
                // Final symlink or other non-regular target refused explicitly.
                Err(UploadError::TargetNotRegular)
            }
        }
    }
}

fn directory_basename(src_path: Option<&str>) -> Result<CString, UploadError> {
    let src = src_path.ok_or(UploadError::DirectoryRequiresSrcPath)?;
    let base = source_basename(src).map_err(|_| UploadError::DirectoryBasenameInvalid)?;
    let bytes = base.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_BASENAME_LEN {
        return Err(UploadError::TargetBasenameTooLong);
    }
    CString::new(bytes).map_err(|_| UploadError::DirectoryBasenameInvalid)
}

fn stat_leaf(parent: &OwnedFd, name: &CStr) -> Result<Option<Stat>, UploadError> {
    match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Ok(Some(stat)),
        Err(Errno::NOENT) => Ok(None),
        Err(_) => Err(UploadError::PublishFailed),
    }
}

fn bound_namespace(path: PathBuf) -> Result<PathBuf, UploadError> {
    if path.as_os_str().as_bytes().len() > MAX_PATH_LEN {
        return Err(UploadError::TargetPathTooLong);
    }
    Ok(path)
}

#[cfg(test)]
mod ancestry_tests {
    use std::error::Error;
    use std::fs;
    use std::fs::File;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use tempfile::TempDir;

    use super::*;

    fn open_test_dir(root: &OwnedFd, path: &CStr) -> Result<OwnedFd, UploadError> {
        openat2(
            root,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::empty(),
        )
        .map_err(map_parent_err)
    }

    fn temp_tree() -> Result<TempDir, Box<dyn Error>> {
        Ok(tempfile::tempdir()?)
    }

    fn set_mode(path: &Path, mode: u32) -> Result<(), Box<dyn Error>> {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        Ok(())
    }

    fn expect_unsafe(result: Result<(), UploadError>) -> Result<(), Box<dyn Error>> {
        match result {
            Err(UploadError::UnsafeUploadAncestor) => Ok(()),
            Err(other) => Err(format!("unexpected error: {other}").into()),
            Ok(()) => Err("expected an unsafe upload ancestor".into()),
        }
    }

    #[test]
    fn rejects_writable_intermediate_with_safe_leaf_and_preserves_sentinel()
    -> Result<(), Box<dyn Error>> {
        let tree = temp_tree()?;
        let base = tree.path();
        let middle = base.join("middle");
        let leaf = middle.join("leaf");
        fs::create_dir(&middle)?;
        fs::create_dir(&leaf)?;
        set_mode(base, 0o700)?;
        set_mode(&middle, 0o777)?;
        set_mode(&leaf, 0o700)?;

        let sentinel = leaf.join("sentinel");
        fs::write(&sentinel, b"original bytes")?;

        let base_file: OwnedFd = File::open(base)?.into();
        let root = open_test_dir(&base_file, c".")?;
        let parent = open_test_dir(&root, c"middle/leaf")?;
        let result = check_upload_ancestors_with(&root, &parent, c"middle/leaf");
        expect_unsafe(result)?;
        if fs::read(&sentinel)? != b"original bytes" {
            return Err("sentinel bytes changed on rejection".into());
        }

        set_mode(&middle, 0o700)?;
        check_upload_ancestors_with(&root, &parent, c"middle/leaf")?;
        Ok(())
    }

    #[test]
    fn rejects_writable_root_when_it_is_the_upload_parent() -> Result<(), Box<dyn Error>> {
        let tree = temp_tree()?;
        let base = tree.path();
        set_mode(base, 0o777)?;
        let base_file: OwnedFd = File::open(base)?.into();
        let root = open_test_dir(&base_file, c".")?;
        let result = check_upload_ancestors_with(&root, &root, c".");
        expect_unsafe(result)?;

        set_mode(base, 0o700)?;
        check_upload_ancestors_with(&root, &root, c".")?;
        Ok(())
    }

    #[test]
    fn rejects_writable_root_ancestor_of_safe_child() -> Result<(), Box<dyn Error>> {
        let tree = temp_tree()?;
        let base = tree.path();
        let middle = base.join("middle");
        let leaf = middle.join("leaf");
        fs::create_dir(&middle)?;
        fs::create_dir(&leaf)?;
        set_mode(base, 0o777)?;
        set_mode(&middle, 0o700)?;
        set_mode(&leaf, 0o700)?;

        let base_file: OwnedFd = File::open(base)?.into();
        let root = open_test_dir(&base_file, c".")?;
        let parent = open_test_dir(&root, c"middle/leaf")?;
        let result = check_upload_ancestors_with(&root, &parent, c"middle/leaf");
        expect_unsafe(result)?;

        set_mode(base, 0o700)?;
        check_upload_ancestors_with(&root, &parent, c"middle/leaf")?;
        Ok(())
    }

    #[test]
    fn rejects_resolved_symlink_unsafe_intermediate() -> Result<(), Box<dyn Error>> {
        let tree = temp_tree()?;
        let base = tree.path();
        let root_path = base.join("root");
        let unsafe_dir = base.join("unsafe");
        let leaf = unsafe_dir.join("leaf");
        fs::create_dir(&root_path)?;
        fs::create_dir(&unsafe_dir)?;
        fs::create_dir(&leaf)?;
        set_mode(base, 0o700)?;
        set_mode(&root_path, 0o700)?;
        set_mode(&unsafe_dir, 0o777)?;
        set_mode(&leaf, 0o700)?;
        std::os::unix::fs::symlink("../unsafe/leaf", root_path.join("link"))?;

        let base_file: OwnedFd = File::open(base)?.into();
        let root = open_test_dir(&base_file, c"root")?;
        // Empty resolve flags follow the symlink, so the held parent descriptor
        // resolves to unsafe/leaf outside the configured root. A lexical prefix
        // check would incorrectly inspect only root/link and skip unsafe.
        let parent = open_test_dir(&root, c"link")?;
        let result = check_upload_ancestors_with(&root, &parent, c"link");
        expect_unsafe(result)?;
        Ok(())
    }
}
