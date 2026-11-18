//! Limited (opt-in) file-transfer execution context.
//!
//! [`TransferLimits`] packages an immutable, already-enabled [`LimitsPolicy`]
//! together with a retained kernel directory handle ([`RootDir`]), the
//! validated trusted root path, the selected [`SymlinkMode`] and exactly one
//! shared rate counter. Configuration accepts `Limits.Enabled = true`, and the
//! runtime constructs exactly one `Arc<TransferLimits>` before the
//! authentication/reconnect loop, sharing clones across managers and
//! reconnects. Construction and use here never mutate process-global state.
//!
//! All peer paths are mapped beneath the trusted root with the lexical
//! [`resolve_peer_path`] helper (using the **original absolute** peer path so the
//! chroot check sees the real namespace) and then resolved with the
//! kernel-enforced descriptor APIs in [`crate::limits_fs`]. The pure policy is
//! always consulted with the original absolute path.
//!
//! Cloning an `Arc<TransferLimits>` shares the same [`SharedRateCounter`], so
//! rate totals accumulate across manager instances and reconnects.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::file_transfer_schema::FileInfo;
use crate::limits::{DownloadInput, FileFacts, LimitsError, LimitsPolicy, UploadInput};
use crate::limits_config::{
    ConfigLimitsError, NssResolver, RawFileTransferLimits, build_policy, resolve_peer_path,
};
use crate::limits_fs::{FsError, RootDir, SymlinkMode};
use crate::limits_fs_upload::{MetadataPlan, StagedCreate, UploadError, resolve_upload_target};
use crate::limits_rate::{RateEngine, RateError, RateLimits, RateSnapshot, SharedRateCounter};

/// Fixed-message, redacted errors from the limited execution context.
///
/// Every variant renders a fixed string; no peer path, owner/group identity or
/// credential material is ever included in a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferLimitsError {
    /// The compiled policy or root mapping rejected the request.
    Config(ConfigLimitsError),
    /// The descriptor-based filesystem layer rejected the request.
    Filesystem(FsError),
    /// The pure download policy denied the request.
    Policy(LimitsError),
    /// Rate accounting failed closed.
    RateFailure(RateError),
    /// The descriptor-safe staged-create layer rejected the request.
    Upload(UploadError),
    /// Overwriting an existing target is not supported in this batch.
    OverwriteUnsupported,
    /// The configured or hard byte cap was exceeded.
    SizeExceeded,
    /// A size value did not fit the wire representation.
    SizeOverflow,
    /// The injected shared counter configuration does not match the raw limits.
    RateCounterMismatch,
    /// Descriptor metadata could not be read.
    Io,
}

impl fmt::Display for TransferLimitsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => write!(f, "{error}"),
            Self::Filesystem(error) => write!(f, "{error}"),
            Self::Policy(error) => write!(f, "{error}"),
            Self::RateFailure(error) => write!(f, "{error}"),
            Self::Upload(error) => write!(f, "{error}"),
            Self::OverwriteUnsupported => {
                f.write_str("the overwrite of an existing file is not supported")
            }
            Self::SizeExceeded => f.write_str("the file size is over the limit"),
            Self::SizeOverflow => f.write_str("the file size is out of range"),
            Self::RateCounterMismatch => f.write_str(
                "the shared rate counter configuration does not match the limits policy",
            ),
            Self::Io => f.write_str("the file metadata could not be read"),
        }
    }
}

impl std::error::Error for TransferLimitsError {}

impl From<ConfigLimitsError> for TransferLimitsError {
    fn from(error: ConfigLimitsError) -> Self {
        Self::Config(error)
    }
}

impl From<FsError> for TransferLimitsError {
    fn from(error: FsError) -> Self {
        Self::Filesystem(error)
    }
}

impl From<LimitsError> for TransferLimitsError {
    fn from(error: LimitsError) -> Self {
        Self::Policy(error)
    }
}

impl From<RateError> for TransferLimitsError {
    fn from(error: RateError) -> Self {
        Self::RateFailure(error)
    }
}

impl From<UploadError> for TransferLimitsError {
    fn from(error: UploadError) -> Self {
        Self::Upload(error)
    }
}

/// A verified, policy-adjudicated regular file opened beneath the trusted root.
#[derive(Debug)]
pub struct PreparedDownload {
    file: std::fs::File,
    size: u64,
}

impl PreparedDownload {
    /// Consume the prepared download, yielding the owned descriptor and its
    /// snapshot size.
    pub fn into_parts(self) -> (std::fs::File, u64) {
        (self.file, self.size)
    }

    /// Snapshot size captured from the verified descriptor.
    pub fn size(&self) -> u64 {
        self.size
    }
}

/// A validated, policy-adjudicated **new** upload target that has already been
/// staged.
///
/// Produced only by [`TransferLimits::begin_limited_upload`], which validates the
/// request against the policy and then creates the descriptor-safe staging file
/// through the *same* context's held root before returning. The stage and its
/// metadata plan therefore always belong to one context; callers cannot pair a
/// plan with a different root.
pub struct PreparedUpload {
    stage: StagedCreate,
    plan: MetadataPlan,
}

impl PreparedUpload {
    /// Consume the prepared upload, yielding the owned stage and its paired
    /// shape-checked metadata plan.
    pub fn into_parts(self) -> (StagedCreate, MetadataPlan) {
        (self.stage, self.plan)
    }
}

/// Immutable limited-transfer execution context.
pub struct TransferLimits {
    policy: LimitsPolicy,
    root: RootDir,
    root_path: PathBuf,
    symlink: SymlinkMode,
    counter: SharedRateCounter,
}

impl fmt::Debug for TransferLimits {
    /// Redacted debug output: never prints paths, roots, identities or the
    /// shared counter contents.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransferLimits")
            .field("policy_enabled", &self.policy.is_enabled())
            .field("root", &"<redacted>")
            .field("symlink", &self.symlink)
            .field("counter", &"<shared>")
            .finish()
    }
}

fn rate_limits_from(raw: &RawFileTransferLimits) -> RateLimits {
    RateLimits {
        enabled: true,
        max_bytes_tx_per_minute: raw
            .counters
            .as_ref()
            .and_then(|counters| counters.max_bytes_tx_per_minute)
            .unwrap_or(0),
        max_bytes_rx_per_minute: raw
            .counters
            .as_ref()
            .and_then(|counters| counters.max_bytes_rx_per_minute)
            .unwrap_or(0),
    }
}

/// Convert a POSIX `st_mode` word into a Go `os.FileMode` word.
///
/// Mirrors the schema's conversion but operates on the descriptor-derived raw
/// mode so the limited stat path never re-reads the peer path.
fn go_mode_from_posix(mode: u32) -> u32 {
    let mut go = mode & 0o777;
    if mode & 0o4000 != 0 {
        go |= 1 << 23;
    }
    if mode & 0o2000 != 0 {
        go |= 1 << 22;
    }
    if mode & 0o1000 != 0 {
        go |= 1 << 20;
    }
    match mode & 0o170000 {
        0o040000 => go |= 1 << 31,
        0o120000 => go |= 1 << 27,
        0o020000 => go |= (1 << 26) | (1 << 21),
        0o060000 => go |= 1 << 26,
        0o010000 => go |= 1 << 25,
        0o140000 => go |= 1 << 24,
        _ => {}
    }
    go
}

impl TransferLimits {
    /// Build an enabled context from raw configuration and an injected resolver.
    ///
    /// The rate counter is anchored at the current instant; the runtime creates
    /// exactly one such context before the authentication/reconnect loop and
    /// shares clones across managers and reconnects.
    pub fn new(
        raw: &RawFileTransferLimits,
        resolver: &impl NssResolver,
    ) -> Result<Self, TransferLimitsError> {
        let counter =
            SharedRateCounter::new(RateEngine::new(rate_limits_from(raw), Instant::now()));
        Self::with_counter(raw, resolver, counter)
    }

    /// Build an enabled context around a caller-supplied shared counter.
    ///
    /// This is the injection point the runtime (or a deterministic test) uses
    /// to supply the single shared counter, ensuring totals accumulate across
    /// every manager that clones the resulting `Arc`.
    pub fn with_counter(
        raw: &RawFileTransferLimits,
        resolver: &impl NssResolver,
        counter: SharedRateCounter,
    ) -> Result<Self, TransferLimitsError> {
        let expected = rate_limits_from(raw);
        if counter.configured_limits()? != expected {
            return Err(TransferLimitsError::RateCounterMismatch);
        }
        let policy = build_policy(true, raw, resolver)?;
        let root_path = match raw.chroot.as_deref() {
            Some(path) if !path.is_empty() => PathBuf::from(path),
            _ => PathBuf::from("/"),
        };
        let root = RootDir::open(&root_path)?;
        let symlink = if raw.follow_sym_links.unwrap_or(false) {
            SymlinkMode::RelativeWithinRoot
        } else {
            SymlinkMode::RefuseAll
        };
        Ok(Self {
            policy,
            root,
            root_path,
            symlink,
            counter,
        })
    }

    /// The immutable compiled policy.
    pub fn policy(&self) -> &LimitsPolicy {
        &self.policy
    }

    /// The shared rate counter.
    pub fn counter(&self) -> &SharedRateCounter {
        &self.counter
    }

    /// The validated trusted root path.
    pub fn root_path(&self) -> &Path {
        &self.root_path
    }

    /// The selected symlink resolution mode.
    pub fn symlink_mode(&self) -> SymlinkMode {
        self.symlink
    }

    /// Real-time snapshot of the shared counters (diagnostics only).
    pub fn snapshot_now(&self) -> Result<RateSnapshot, RateError> {
        self.counter.snapshot_now()
    }

    /// Whether an actual-streamed byte count is within the configured cap.
    pub fn progress_allowed(&self, size: u64) -> bool {
        self.policy.check_progress_size(size).is_ok()
    }

    /// Resolve, validate and policy-adjudicate an upload target beneath the
    /// trusted root, before any initial ACK or staging allocation.
    ///
    /// The target is resolved through the held root first: an explicit filename
    /// (with an optional, discarded `src_path`), a peer path equal to the
    /// configured root, or an existing directory inside the root (in which case
    /// the validated `source_basename` of `src_path` is appended inside the
    /// proven directory). Existing target owner/group/type/size facts come from
    /// the held parent + leaf `NOFOLLOW` and are passed into the pure policy with
    /// the resolved absolute target namespace, so no-overwrite and owner/group
    /// denials happen before the initial ACK. The reserved `u32::MAX` owner ids
    /// are rejected up front. The resulting
    /// [`CommitPlan`](crate::limits::CommitPlan) becomes a shape-checked
    /// [`MetadataPlan`] paired with its own resolved stage.
    pub fn begin_limited_upload(
        &self,
        peer: &str,
        src_path: Option<&str>,
        declared: Option<u64>,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> Result<PreparedUpload, TransferLimitsError> {
        if uid == Some(u32::MAX) || gid == Some(u32::MAX) {
            return Err(TransferLimitsError::Upload(
                UploadError::InvalidMetadataOwner,
            ));
        }
        let relative = match resolve_peer_path(&self.root_path, peer) {
            Ok(relative) => Some(relative),
            Err(ConfigLimitsError::PathIsRoot) => None,
            Err(error) => return Err(error.into()),
        };
        // Resolve and inspect the target through the held root before any
        // staging allocation; the directory descriptor stays pinned afterwards.
        let target = resolve_upload_target(
            &self.root,
            relative.as_ref(),
            &self.root_path,
            src_path,
            self.symlink,
        )?;
        // The policy is consulted with the resolved absolute namespace and the
        // descriptor-derived existing facts, still before any ACK.
        let namespace = target
            .namespace()
            .to_str()
            .ok_or(TransferLimitsError::Config(
                ConfigLimitsError::PathNotAbsolute,
            ))?
            .to_owned();
        let existing = target.existing().map(|facts| FileFacts {
            owner_uid: facts.uid,
            owner_gid: facts.gid,
            size: facts.size,
            is_regular: facts.is_regular,
            is_symlink: facts.is_symlink,
        });
        let plan = self.policy.check_upload(&UploadInput {
            target_path: &namespace,
            declared_size: declared,
            mode,
            requested_uid: uid,
            requested_gid: gid,
            existing,
        })?;
        let metadata = MetadataPlan::try_from(plan)?;
        // Only after validation succeeds is the stage allocated through the same
        // held root. The atomic commit link/rename remains authoritative against
        // a later concurrent change; dropping the stage on failure leaves no
        // named entry behind.
        let stage = target.begin_stage()?;
        Ok(PreparedUpload {
            stage,
            plan: metadata,
        })
    }

    /// Map, open and policy-check a peer download beneath the trusted root.
    ///
    /// The **original absolute** peer path is passed to the pure policy so the
    /// chroot check sees the real namespace. The returned descriptor is the
    /// kernel-verified regular file with the facts captured at open time.
    pub fn prepare_download(&self, peer: &str) -> Result<PreparedDownload, TransferLimitsError> {
        let relative = resolve_peer_path(&self.root_path, peer)?;
        let download = self.root.open_download(&relative, self.symlink)?;
        let facts = {
            let metadata = download.metadata();
            FileFacts {
                owner_uid: metadata.uid(),
                owner_gid: metadata.gid(),
                size: metadata.size(),
                is_regular: true,
                is_symlink: false,
            }
        };
        self.policy.check_download(&DownloadInput {
            source_path: peer,
            facts,
        })?;
        Ok(PreparedDownload {
            file: download.into_file(),
            size: facts.size,
        })
    }

    /// Resolve, open, verify and policy-check a peer metadata request.
    ///
    /// The full size, uid, gid and Go mode are taken from the opened verified
    /// descriptor; the MessagePack timestamp is derived from the same
    /// descriptor's modified time. The peer path is never stat-ed again.
    pub fn stat(&self, peer: &str) -> Result<FileInfo, TransferLimitsError> {
        let relative = resolve_peer_path(&self.root_path, peer)?;
        let download = self.root.open_download(&relative, self.symlink)?;
        let facts = {
            let metadata = download.metadata();
            FileFacts {
                owner_uid: metadata.uid(),
                owner_gid: metadata.gid(),
                size: metadata.size(),
                is_regular: true,
                is_symlink: false,
            }
        };
        self.policy.check_download(&DownloadInput {
            source_path: peer,
            facts,
        })?;

        let std_metadata = download
            .file()
            .metadata()
            .map_err(|_| TransferLimitsError::Io)?;
        let size = i64::try_from(facts.size).map_err(|_| TransferLimitsError::SizeOverflow)?;
        let modtime = match std_metadata.modified() {
            Ok(time) => Some(
                crate::file_transfer_schema::timestamp_value(time)
                    .map_err(|_| TransferLimitsError::Io)?,
            ),
            Err(_) => return Err(TransferLimitsError::Io),
        };
        Ok(FileInfo {
            path: peer.to_owned(),
            size: Some(size),
            uid: Some(facts.owner_uid),
            gid: Some(facts.owner_gid),
            mode: Some(go_mode_from_posix(download.metadata().mode())),
            modtime,
        })
    }
}
