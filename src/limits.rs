//! Pure, typed file-transfer limits policy foundation.
//!
//! This module models the upstream `Limits.FileTransfer` restrictions as a
//! side-effect-free value type. It performs **no** I/O, process, NSS or
//! background work: every decision is a pure function of an already-validated
//! policy plus explicit caller-supplied facts.
//!
//! # Status / wiring
//!
//! This module remains a pure policy: every decision is a side-effect-free
//! function of validated options plus caller-supplied facts. Configuration now
//! accepts `Limits.Enabled = true`, and the runtime builds exactly one shared
//! `Arc<TransferLimits>` before the authentication/reconnect loop. That shared
//! context applies the policy to download, stat, new and overwrite upload, and
//! directory-target decisions, and shares the RX/TX rate counters across
//! managers and reconnects. No filesystem, process or runtime work is performed
//! here; those effects belong to the descriptor-based execution layer.
//!
//! The always-on worker hard limits (the 256 MiB maximum transfer and the
//! regular-file-only streaming rules) live in the workers and are **not**
//! removed or duplicated here; this module models only the configurable
//! upstream policy on top of them. Per-minute byte accounting is enforced by
//! the shared runtime rate counter; here the configured counter limits are
//! stored opaquely and never enforced with any global mutable state or
//! background ticker.
//!
//! # Deliberate security corrections vs. upstream
//!
//! We do **not** claim byte-for-byte parity with upstream. The following are
//! deliberate, documented corrections:
//!
//! * **Dual setuid representation.** Go's `os.FileMode` encodes setuid as
//!   `1 << 23`, while POSIX `chmod` uses `0o4000`. Upstream `UploadFile`
//!   inspects the Go bit but `PreserveModes` inspects the POSIX bit, so a mode
//!   can bypass the `AllowSuid = false` check or be silently preserved. We
//!   reject the privileged setuid bits under **either** representation when
//!   `AllowSuid` is false, so neither alias can bypass the check.
//! * **Unsupported bits fail closed.** Any bit outside `0o777` plus the two
//!   understood setuid aliases (POSIX setgid/sticky, Go type bits, and any
//!   unknown bits) is rejected rather than ignored.
//! * **Umask is a ceiling.** The applied mode is `requested_perm & !umask` and
//!   can never *add* permission bits that were not requested. Upstream
//!   `PreserveModes` overwrites the requested permissions with
//!   `0o777 & !umask`, which can grant bits the peer never asked for; we
//!   deviate on purpose.
//! * **Absent mode still honours the ceiling.** When an enabled policy omits a
//!   wire mode, the workers stage a private `0o600` file. We plan that base
//!   masked by the configured umask (`0o600 & !umask`) instead of leaving the
//!   staging default untouched, so a configured ceiling cannot be bypassed by
//!   a mode-less request. Upstream offers no equivalent guarantee for
//!   mode-less uploads; this is a deliberate compatibility restriction, not a
//!   parity claim.
//! * **Size cap is inclusive.** A byte count equal to `MaxFileSize` is allowed
//!   (`size <= max`); upstream's progress check was exclusive
//!   (`offset >= max` fails). We choose the sensible inclusive boundary for
//!   both declared and progress checks.
//!
//! # Not a security proof
//!
//! Lexical chroot decisions and caller-supplied [`FileFacts`] are necessary but
//! **not sufficient** for confinement. A path can be swapped, or a link
//! followed, between observation and use. Race-safe confinement requires the
//! later descriptor-relative enforcement layer that supplies these facts from a
//! verified file descriptor.
//!
//! # applyDefaults semantics
//!
//! Upstream `applyDefaults` unconditionally sets `PreserveMode = true` and
//! `PreserveOwner = true`, overriding user input. [`LimitsOptions::default`]
//! mirrors that (`preserve_mode`/`preserve_owner` default to `true`) while the
//! resulting policy itself defaults to *disabled*.

use std::fmt;
use std::path::{Component, Path, PathBuf};

/// Maximum accepted chroot path length in bytes.
pub const MAX_CHROOT_LEN: usize = 4096;

/// Maximum accepted number of allowed owner or group entries.
pub const MAX_ID_ALLOWLIST: usize = 256;

/// Go `os.FileMode` setuid bit.
const GO_MODE_SETUID: u32 = 1 << 23;
/// POSIX setuid permission bit (as used by `chmod`).
const POSIX_SETUID: u32 = 0o4000;
/// Permission bits mask.
const PERM_MASK: u32 = 0o777;
/// Every mode bit this policy understands and is willing to act on.
const KNOWN_MODE_BITS: u32 = PERM_MASK | GO_MODE_SETUID | POSIX_SETUID;

/// Private permission bits the workers create a staging file with before any
/// configured metadata is applied. Used as the base mode when the peer omits a
/// wire mode so the configured umask ceiling still applies.
const STAGED_DEFAULT_MODE: u32 = 0o600;

/// Typed, constant-message errors for the limits policy.
///
/// Every message is a fixed string so no sensitive value (owner names, paths,
/// sizes or raw mode words) is ever reflected back to a peer or log sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitsError {
    /// The configured chroot is not an absolute path.
    ChrootNotAbsolute,
    /// The configured chroot path exceeds the length bound.
    ChrootTooLong,
    /// The target path is lexically outside the configured chroot.
    ChrootViolation,
    /// The file size is over the configured limit.
    FileTooBig,
    /// The file owner does not match the configured constraint.
    FileOwnerMismatch,
    /// The file group does not match the configured constraint.
    FileGroupMismatch,
    /// Following a link is forbidden.
    FollowLinksForbidden,
    /// Overwriting an existing target is forbidden.
    ForbiddenToOverwrite,
    /// The setuid mode bit is forbidden.
    SuidModeForbidden,
    /// The requested mode contains unsupported bits.
    UnsupportedModeBits,
    /// A configured or requested path contains a NUL byte.
    PathContainsNul,
    /// The requested mode ambiguously sets both setuid encodings.
    AmbiguousModeEncoding,
    /// Only regular files are allowed.
    NotRegularFile,
    /// The configured umask is out of range.
    UmaskOutOfRange,
    /// Too many allowed owner entries were configured.
    TooManyOwnerGetEntries,
    /// Too many allowed group entries were configured.
    TooManyGroupGetEntries,
}

impl fmt::Display for LimitsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ChrootNotAbsolute => "the configured chroot is not an absolute path",
            Self::ChrootTooLong => "the configured chroot path is too long",
            Self::ChrootViolation => "the target file path is outside chroot",
            Self::FileTooBig => "the file size is over the limit",
            Self::FileOwnerMismatch => "the file owner does not match",
            Self::FileGroupMismatch => "the file group does not match",
            Self::FollowLinksForbidden => "forbidden to follow the link",
            Self::ForbiddenToOverwrite => "forbidden to overwrite the file",
            Self::SuidModeForbidden => "the set uid mode is forbidden",
            Self::UnsupportedModeBits => "the requested mode contains unsupported bits",
            Self::PathContainsNul => "the path contains a NUL byte",
            Self::AmbiguousModeEncoding => "the requested mode uses ambiguous setuid encodings",
            Self::NotRegularFile => "only regular files are allowed",
            Self::UmaskOutOfRange => "the configured umask is out of range",
            Self::TooManyOwnerGetEntries => "too many allowed owner entries",
            Self::TooManyGroupGetEntries => "too many allowed group entries",
        };
        f.write_str(message)
    }
}

impl std::error::Error for LimitsError {}

/// Raw, already-resolved policy options supplied by a configuration adapter.
///
/// Owner and group constraints are **explicit, already-resolved numeric ids**.
/// This module performs no NSS lookup, filesystem access or process work; the
/// mapping from configured names to ids is the caller's responsibility.
#[derive(Debug, Clone)]
pub struct LimitsOptions {
    /// Whether the policy should be enforced at all.
    pub enabled: bool,
    /// Optional absolute chroot prefix.
    pub chroot: Option<PathBuf>,
    /// Whether symlinks may be followed.
    pub follow_symlinks: bool,
    /// Whether an existing target may be overwritten.
    pub overwrite: bool,
    /// Forced owner uid for new files (overwrite filter and commit target).
    pub owner_put: Option<u32>,
    /// Forced group gid for new files (overwrite filter and commit target).
    pub group_put: Option<u32>,
    /// Allowed owner uids for downloads (empty means any owner).
    pub owner_get: Vec<u32>,
    /// Allowed group gids for downloads (empty means any group).
    pub group_get: Vec<u32>,
    /// Umask applied as a permission ceiling, `0..=0o777`.
    pub umask: u16,
    /// Maximum file size in bytes; `0` means unlimited.
    pub max_file_size: u64,
    /// Maximum transmitted bytes per minute; `0` means unlimited.
    pub max_bytes_tx_per_minute: u64,
    /// Maximum received bytes per minute; `0` means unlimited.
    pub max_bytes_rx_per_minute: u64,
    /// Whether setuid uploads are permitted.
    pub allow_suid: bool,
    /// Whether only regular files may be transferred.
    pub regular_files_only: bool,
    /// Whether the requested mode should be preserved on commit.
    pub preserve_mode: bool,
    /// Whether the requested owner should be preserved on commit.
    pub preserve_owner: bool,
}

impl Default for LimitsOptions {
    fn default() -> Self {
        // Mirrors upstream `applyDefaults`, which unconditionally enables
        // PreserveMode and PreserveOwner. The policy itself remains disabled by
        // default (`enabled: false`).
        Self {
            enabled: false,
            chroot: None,
            follow_symlinks: false,
            overwrite: false,
            owner_put: None,
            group_put: None,
            owner_get: Vec::new(),
            group_get: Vec::new(),
            umask: 0,
            max_file_size: 0,
            max_bytes_tx_per_minute: 0,
            max_bytes_rx_per_minute: 0,
            allow_suid: false,
            regular_files_only: false,
            preserve_mode: true,
            preserve_owner: true,
        }
    }
}

/// Pure, non-authoritative facts about a target file.
///
/// These values describe metadata (owner, group, size and type). They are
/// supplied later by a verified descriptor-relative layer and are **not** a
/// security proof on their own: a path can be swapped between this observation
/// and the eventual operation. An admissible verdict based only on these facts
/// is therefore not race-safe confinement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileFacts {
    /// Owning user id.
    pub owner_uid: u32,
    /// Owning group id.
    pub owner_gid: u32,
    /// Size in bytes.
    pub size: u64,
    /// Whether the resolved target is a regular file.
    pub is_regular: bool,
    /// Whether the target path itself is a symlink.
    pub is_symlink: bool,
}

/// Inputs for an upload admissibility decision.
#[derive(Debug, Clone)]
pub struct UploadInput<'a> {
    /// Lexical target path, as supplied by the peer.
    pub target_path: &'a str,
    /// Declared upload size, if the peer provided one.
    pub declared_size: Option<u64>,
    /// Requested mode word (either Go `os.FileMode` or POSIX encoding).
    pub mode: Option<u32>,
    /// Requested owner uid, if any.
    pub requested_uid: Option<u32>,
    /// Requested owner gid, if any.
    pub requested_gid: Option<u32>,
    /// Facts about an already-existing target, if it exists.
    pub existing: Option<FileFacts>,
}

/// Inputs for a download admissibility decision.
#[derive(Debug, Clone)]
pub struct DownloadInput<'a> {
    /// Lexical source path, as supplied by the peer.
    pub source_path: &'a str,
    /// Facts about the source file.
    pub facts: FileFacts,
}

/// Desired ownership to apply on commit; `None` means leave unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OwnershipPlan {
    /// Desired owner uid.
    pub uid: Option<u32>,
    /// Desired owner gid.
    pub gid: Option<u32>,
}

/// Desired metadata to apply on commit for an accepted upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CommitPlan {
    /// POSIX mode to `chmod` (permission bits plus an authorized `0o4000`
    /// setuid bit), or `None` if the mode should be left to the worker.
    pub mode: Option<u32>,
    /// Ownership to apply, if any.
    pub ownership: OwnershipPlan,
}

impl CommitPlan {
    fn passthrough() -> Self {
        Self::default()
    }
}

/// Validated file-transfer limits (only present when the policy is enabled).
#[derive(Debug, Clone)]
struct FileTransferLimits {
    chroot: Option<PathBuf>,
    follow_symlinks: bool,
    overwrite: bool,
    owner_put: Option<u32>,
    group_put: Option<u32>,
    owner_get: Vec<u32>,
    group_get: Vec<u32>,
    umask: u16,
    max_file_size: u64,
    max_bytes_tx_per_minute: u64,
    max_bytes_rx_per_minute: u64,
    allow_suid: bool,
    regular_files_only: bool,
    preserve_mode: bool,
    preserve_owner: bool,
}

impl FileTransferLimits {
    fn validate(options: LimitsOptions) -> Result<Self, LimitsError> {
        let chroot = match options.chroot {
            Some(path) => {
                if !path.is_absolute() {
                    return Err(LimitsError::ChrootNotAbsolute);
                }
                let native = path.as_os_str().as_encoded_bytes();
                if native.contains(&0) {
                    return Err(LimitsError::PathContainsNul);
                }
                if native.len() > MAX_CHROOT_LEN {
                    return Err(LimitsError::ChrootTooLong);
                }
                Some(path)
            }
            None => None,
        };

        if u32::from(options.umask) > PERM_MASK {
            return Err(LimitsError::UmaskOutOfRange);
        }
        if options.owner_get.len() > MAX_ID_ALLOWLIST {
            return Err(LimitsError::TooManyOwnerGetEntries);
        }
        if options.group_get.len() > MAX_ID_ALLOWLIST {
            return Err(LimitsError::TooManyGroupGetEntries);
        }

        Ok(Self {
            chroot,
            follow_symlinks: options.follow_symlinks,
            overwrite: options.overwrite,
            owner_put: options.owner_put,
            group_put: options.group_put,
            owner_get: options.owner_get,
            group_get: options.group_get,
            umask: options.umask,
            max_file_size: options.max_file_size,
            max_bytes_tx_per_minute: options.max_bytes_tx_per_minute,
            max_bytes_rx_per_minute: options.max_bytes_rx_per_minute,
            allow_suid: options.allow_suid,
            regular_files_only: options.regular_files_only,
            preserve_mode: options.preserve_mode,
            preserve_owner: options.preserve_owner,
        })
    }

    /// A byte count is admissible when it does not exceed the configured
    /// maximum, or when the maximum is `0` (unlimited).
    fn size_allowed(&self, size: u64) -> bool {
        self.max_file_size == 0 || size <= self.max_file_size
    }

    fn check_chroot(&self, target: &str) -> Result<(), LimitsError> {
        if target.as_bytes().contains(&0) {
            return Err(LimitsError::PathContainsNul);
        }
        let chroot = match &self.chroot {
            Some(chroot) => chroot,
            None => return Ok(()),
        };
        let normalized_chroot =
            normalize_lexical(chroot.as_path()).ok_or(LimitsError::ChrootNotAbsolute)?;
        let normalized_target =
            normalize_lexical(Path::new(target)).ok_or(LimitsError::ChrootViolation)?;
        if normalized_target == normalized_chroot
            || normalized_target.starts_with(normalized_chroot.as_path())
        {
            Ok(())
        } else {
            Err(LimitsError::ChrootViolation)
        }
    }
}

/// Result of parsing a requested mode word.
struct ModeRequest {
    perm: u32,
    suid: bool,
}

/// Parse a requested mode word, rejecting privileged or unsupported bits.
fn parse_mode(mode: u32, allow_suid: bool) -> Result<ModeRequest, LimitsError> {
    if mode & !KNOWN_MODE_BITS != 0 {
        return Err(LimitsError::UnsupportedModeBits);
    }
    let go_suid = mode & GO_MODE_SETUID != 0;
    let posix_suid = mode & POSIX_SETUID != 0;
    if go_suid && posix_suid {
        return Err(LimitsError::AmbiguousModeEncoding);
    }
    let suid = go_suid || posix_suid;
    if suid && !allow_suid {
        return Err(LimitsError::SuidModeForbidden);
    }
    Ok(ModeRequest {
        perm: mode & PERM_MASK,
        suid,
    })
}

/// Remove the configured umask bits from a base permission word.
///
/// This only ever clears bits, so it can never grant a permission the base
/// mode did not already carry.
fn apply_umask(base: u32, umask: u16) -> u32 {
    base & !u32::from(umask) & PERM_MASK
}

/// Compute the desired POSIX mode from a parsed request and the umask ceiling.
fn compute_desired_mode(request: ModeRequest, umask: u16) -> u32 {
    let mut mode = apply_umask(request.perm, umask);
    if request.suid {
        mode |= POSIX_SETUID;
    }
    mode
}

/// Normalize an absolute path lexically, resolving `.` and `..` without any
/// filesystem access. Returns `None` for relative paths or paths that attempt
/// to escape their root.
fn normalize_lexical(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let mut result = PathBuf::from("/");
    let mut depth: usize = 0;
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                if depth == 0 {
                    return None;
                }
                if result.pop() {
                    depth -= 1;
                }
            }
            Component::Normal(part) => {
                result.push(part);
                depth += 1;
            }
            Component::Prefix(_) => return None,
        }
    }
    Some(result)
}

/// A validated, side-effect-free file-transfer limits policy.
///
/// Construct with [`LimitsPolicy::from_options`] or derive the disabled default
/// with [`LimitsPolicy::disabled`]/[`LimitsPolicy::default`]. All query methods
/// are pure and never touch the filesystem, NSS, processes or global state.
#[derive(Debug, Clone, Default)]
pub struct LimitsPolicy {
    inner: Option<FileTransferLimits>,
}

impl LimitsPolicy {
    /// A policy that enforces no restrictions.
    pub fn disabled() -> Self {
        Self { inner: None }
    }

    /// Validate raw options into a policy.
    ///
    /// When `options.enabled` is `false`, the policy is disabled and the
    /// remaining fields are not validated (the restrictions-off behavior).
    pub fn from_options(options: LimitsOptions) -> Result<Self, LimitsError> {
        if !options.enabled {
            return Ok(Self::disabled());
        }
        Ok(Self {
            inner: Some(FileTransferLimits::validate(options)?),
        })
    }

    /// Whether the policy enforces any restrictions.
    pub fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// Configured maximum transmitted bytes per minute, or `None` when the
    /// policy is disabled.
    pub fn max_bytes_tx_per_minute(&self) -> Option<u64> {
        self.inner
            .as_ref()
            .map(|limits| limits.max_bytes_tx_per_minute)
    }

    /// Configured maximum received bytes per minute, or `None` when the policy
    /// is disabled.
    pub fn max_bytes_rx_per_minute(&self) -> Option<u64> {
        self.inner
            .as_ref()
            .map(|limits| limits.max_bytes_rx_per_minute)
    }

    /// Adjudicate a declared upload size against the inclusive size cap.
    pub fn check_declared_size(&self, size: u64) -> Result<(), LimitsError> {
        match &self.inner {
            Some(limits) if !limits.size_allowed(size) => Err(LimitsError::FileTooBig),
            _ => Ok(()),
        }
    }

    /// Adjudicate a streaming progress byte count against the inclusive size
    /// cap. Uses the same inclusive boundary as [`Self::check_declared_size`].
    pub fn check_progress_size(&self, size: u64) -> Result<(), LimitsError> {
        match &self.inner {
            Some(limits) if !limits.size_allowed(size) => Err(LimitsError::FileTooBig),
            _ => Ok(()),
        }
    }

    /// Adjudicate an upload and, when accepted, return the metadata to apply on
    /// commit.
    pub fn check_upload(&self, input: &UploadInput<'_>) -> Result<CommitPlan, LimitsError> {
        let limits = match &self.inner {
            Some(limits) => limits,
            None => return Ok(CommitPlan::passthrough()),
        };

        if let Some(size) = input.declared_size
            && !limits.size_allowed(size)
        {
            return Err(LimitsError::FileTooBig);
        }

        limits.check_chroot(input.target_path)?;

        if let Some(facts) = &input.existing {
            if facts.is_symlink && !limits.follow_symlinks {
                return Err(LimitsError::FollowLinksForbidden);
            }
            if !limits.overwrite {
                return Err(LimitsError::ForbiddenToOverwrite);
            }
            if let Some(uid) = limits.owner_put
                && facts.owner_uid != uid
            {
                return Err(LimitsError::FileOwnerMismatch);
            }
            if let Some(gid) = limits.group_put
                && facts.owner_gid != gid
            {
                return Err(LimitsError::FileGroupMismatch);
            }
        }

        // Validate the requested mode regardless of whether it will be
        // preserved, so privileged/unsupported bits are always rejected.
        let mode_request = match input.mode {
            Some(mode) => Some(parse_mode(mode, limits.allow_suid)?),
            None => None,
        };
        // The configured umask is a permission ceiling that must apply even
        // when the wire request omits a mode. With no explicit request the
        // workers stage a private `0o600` file, so we plan exactly that base
        // with the configured umask bits removed and never grant new bits.
        let mode = if limits.preserve_mode {
            match mode_request {
                Some(request) => Some(compute_desired_mode(request, limits.umask)),
                None => Some(apply_umask(STAGED_DEFAULT_MODE, limits.umask)),
            }
        } else {
            // Direct (non-config) `preserve_mode = false`: rather than leaving
            // the raw staging default untouched and ignoring the ceiling, plan
            // the safe staging default with the configured mask applied.
            Some(apply_umask(STAGED_DEFAULT_MODE, limits.umask))
        };

        let uid = match (limits.owner_put, limits.preserve_owner) {
            (Some(forced), _) => Some(forced),
            (None, true) => input.requested_uid,
            (None, false) => None,
        };
        let gid = match (limits.group_put, limits.preserve_owner) {
            (Some(forced), _) => Some(forced),
            (None, true) => input.requested_gid,
            (None, false) => None,
        };

        Ok(CommitPlan {
            mode,
            ownership: OwnershipPlan { uid, gid },
        })
    }

    /// Adjudicate a download.
    pub fn check_download(&self, input: &DownloadInput<'_>) -> Result<(), LimitsError> {
        let limits = match &self.inner {
            Some(limits) => limits,
            None => return Ok(()),
        };

        if limits.regular_files_only && !input.facts.is_regular {
            return Err(LimitsError::NotRegularFile);
        }

        limits.check_chroot(input.source_path)?;

        if !limits.owner_get.is_empty() && !limits.owner_get.contains(&input.facts.owner_uid) {
            return Err(LimitsError::FileOwnerMismatch);
        }
        if !limits.group_get.is_empty() && !limits.group_get.contains(&input.facts.owner_gid) {
            return Err(LimitsError::FileGroupMismatch);
        }

        if input.facts.is_symlink && !limits.follow_symlinks {
            return Err(LimitsError::FollowLinksForbidden);
        }

        if !limits.size_allowed(input.facts.size) {
            return Err(LimitsError::FileTooBig);
        }

        Ok(())
    }
}
