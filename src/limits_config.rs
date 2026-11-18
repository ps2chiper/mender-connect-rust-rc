//! Configuration-to-policy adapter for the file-transfer `Limits` policy.
//!
//! This module is the bridge between the raw configuration values parsed by
//! [`crate::config`] and the pure, side-effect-free [`crate::limits`] policy.
//! It performs **no** runtime activation by itself: [`crate::config::Config::validate`]
//! still fails closed whenever `Limits.Enabled` is true, and nothing here is
//! wired into the daemon or the transfer workers yet.
//!
//! # Responsibilities
//!
//! * [`RawFileTransferLimits`] — the raw, `Option`-typed fields exactly as they
//!   appear in `Limits.FileTransfer`. Every field is kept (including explicit
//!   `false` values and nested counters) so fallback/primary merging is exact.
//! * [`NssResolver`]/[`LiveNss`] — an injectable, side-effect-bounded owner/group
//!   name resolver. The live implementation only performs trusted NSS lookups;
//!   it performs no filesystem or process work.
//! * [`build_policy`] — compiles the raw fields into a [`LimitsPolicy`], with
//!   bounded validation of untrusted names, lists, umask, chroot and sizes.
//! * [`resolve_peer_path`] — maps a peer-supplied path beneath a trusted root to
//!   a validated [`RelativePath`]. This is a *mapping* only; the kernel-enforced
//!   `openat2` layer remains the actual containment enforcer. Nothing here is a
//!   lexical proof of confinement.

use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use nix::unistd::{Group, User};
use serde::Deserialize;

use crate::limits::{LimitsError, LimitsOptions, LimitsPolicy};
use crate::limits_fs::{FsError, MAX_PATH_LEN, RelativePath};

/// Maximum accepted length, in bytes, of a single owner/group name.
pub const MAX_NAME_LEN: usize = 256;
/// Maximum accepted number of entries in an owner/group allow-list.
pub const MAX_LIST_LEN: usize = 256;
/// Maximum accepted length, in bytes, of a chroot path.
pub const MAX_CHROOT_LEN: usize = 4096;
/// Maximum accepted umask value (octal `0777`).
pub const MAX_UMASK: u16 = 0o777;

/// Nested per-minute byte counters under `Limits.FileTransfer.Counters`.
///
/// Each field is optional so a fallback file's counters merge per-field with the
/// primary file's counters instead of being replaced wholesale.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct RawRateLimits {
    pub max_bytes_tx_per_minute: Option<u64>,
    pub max_bytes_rx_per_minute: Option<u64>,
}

impl RawRateLimits {
    fn merge(&mut self, other: Self) {
        if other.max_bytes_tx_per_minute.is_some() {
            self.max_bytes_tx_per_minute = other.max_bytes_tx_per_minute;
        }
        if other.max_bytes_rx_per_minute.is_some() {
            self.max_bytes_rx_per_minute = other.max_bytes_rx_per_minute;
        }
    }
}

/// Raw file-transfer limits exactly as configured.
///
/// The field names match the upstream Go JSON keys (case-insensitively
/// canonicalized by [`crate::config`]). Every field is optional so that
/// fallback files and primary files merge per-field, including the nested
/// [`RawRateLimits`] counters. Explicit `false` values are preserved (they are
/// not dropped) so the compatibility decision of `PreserveMode`/`PreserveOwner`
/// can be made, and tested, in the adapter.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct RawFileTransferLimits {
    pub chroot: Option<String>,
    pub follow_sym_links: Option<bool>,
    pub allow_overwrite: Option<bool>,
    pub owner_put: Option<String>,
    pub group_put: Option<String>,
    pub owner_get: Option<Vec<String>>,
    pub group_get: Option<Vec<String>>,
    pub umask: Option<String>,
    pub max_file_size: Option<u64>,
    pub counters: Option<RawRateLimits>,
    pub allow_suid: Option<bool>,
    pub regular_files_only: Option<bool>,
    pub preserve_mode: Option<bool>,
    pub preserve_owner: Option<bool>,
}

impl RawFileTransferLimits {
    /// Merge `other` over `self`, field by field (including nested counters).
    ///
    /// A `None` field in `other` never overwrites an existing value, matching the
    /// fallback semantics of the configuration loader.
    pub(crate) fn merge(&mut self, other: Self) {
        if other.chroot.is_some() {
            self.chroot = other.chroot;
        }
        if other.follow_sym_links.is_some() {
            self.follow_sym_links = other.follow_sym_links;
        }
        if other.allow_overwrite.is_some() {
            self.allow_overwrite = other.allow_overwrite;
        }
        if other.owner_put.is_some() {
            self.owner_put = other.owner_put;
        }
        if other.group_put.is_some() {
            self.group_put = other.group_put;
        }
        if other.owner_get.is_some() {
            self.owner_get = other.owner_get;
        }
        if other.group_get.is_some() {
            self.group_get = other.group_get;
        }
        if other.umask.is_some() {
            self.umask = other.umask;
        }
        if other.max_file_size.is_some() {
            self.max_file_size = other.max_file_size;
        }
        if other.allow_suid.is_some() {
            self.allow_suid = other.allow_suid;
        }
        if other.regular_files_only.is_some() {
            self.regular_files_only = other.regular_files_only;
        }
        if other.preserve_mode.is_some() {
            self.preserve_mode = other.preserve_mode;
        }
        if other.preserve_owner.is_some() {
            self.preserve_owner = other.preserve_owner;
        }
        if let Some(other_counters) = other.counters {
            match self.counters.as_mut() {
                Some(counters) => counters.merge(other_counters),
                None => self.counters = Some(other_counters),
            }
        }
    }
}

/// Error returned by an [`NssResolver`] lookup.
///
/// The single variant carries no detail so no name can leak into a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverError {
    /// The lookup failed (the NSS backend reported an error).
    LookupFailed,
}

impl fmt::Display for ResolverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the name could not be resolved")
    }
}

impl std::error::Error for ResolverError {}

/// Injectable owner/group name resolver.
///
/// Only ever consulted by [`build_policy`] when the policy is enabled. Tests
/// inject a deterministic fake; production uses [`LiveNss`].
pub trait NssResolver {
    /// Resolve a user name to its numeric id, or `None` when unknown.
    fn lookup_user(&self, name: &str) -> Result<Option<u32>, ResolverError>;
    /// Resolve a group name to its numeric id, or `None` when unknown.
    fn lookup_group(&self, name: &str) -> Result<Option<u32>, ResolverError>;
}

/// Production resolver backed by trusted NSS lookups.
///
/// This performs only `User::from_name` / `Group::from_name` lookups; it does no
/// filesystem or process work and does not change any global state.
#[derive(Debug, Clone, Copy, Default)]
pub struct LiveNss;

impl NssResolver for LiveNss {
    fn lookup_user(&self, name: &str) -> Result<Option<u32>, ResolverError> {
        match User::from_name(name) {
            Ok(Some(user)) => Ok(Some(user.uid.as_raw())),
            Ok(None) => Ok(None),
            Err(_) => Err(ResolverError::LookupFailed),
        }
    }

    fn lookup_group(&self, name: &str) -> Result<Option<u32>, ResolverError> {
        match Group::from_name(name) {
            Ok(Some(group)) => Ok(Some(group.gid.as_raw())),
            Ok(None) => Ok(None),
            Err(_) => Err(ResolverError::LookupFailed),
        }
    }
}

/// Fixed-message, redacted errors from the configuration adapter.
///
/// No error ever reflects a peer name, path or raw value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigLimitsError {
    /// An owner or group name exceeded [`MAX_NAME_LEN`].
    NameTooLong,
    /// An owner or group name contained a NUL byte.
    NameContainsNul,
    /// An owner/group allow-list exceeded [`MAX_LIST_LEN`] entries.
    ListTooLong,
    /// An owner/group allow-list contained an empty entry.
    EmptyName,
    /// A configured owner name did not resolve.
    UnknownOwner,
    /// A configured group name did not resolve.
    UnknownGroup,
    /// A resolved id was the reserved `u32::MAX` sentinel.
    InvalidUidGid,
    /// The NSS resolver reported a failure.
    ResolverFailure,
    /// The configured chroot path was not absolute.
    ChrootNotAbsolute,
    /// The configured chroot path exceeded [`MAX_CHROOT_LEN`].
    ChrootTooLong,
    /// The configured chroot path contained a NUL byte.
    ChrootContainsNul,
    /// The configured chroot path contained a parent (`..`) component.
    ChrootHasParent,
    /// The configured umask was malformed, out of range or prefixed.
    InvalidUmask,
    /// The limits policy layer rejected the compiled options.
    PolicyRejected,
    /// The trusted root path was empty.
    RootEmpty,
    /// The trusted root path was not absolute.
    RootNotAbsolute,
    /// The trusted root path contained a NUL byte.
    RootContainsNul,
    /// The trusted root path exceeded [`MAX_PATH_LEN`].
    RootTooLong,
    /// The trusted root path contained a parent (`..`) component.
    RootHasParent,
    /// The peer path was empty.
    PathEmpty,
    /// The peer path was not absolute.
    PathNotAbsolute,
    /// The peer path contained a NUL byte.
    PathContainsNul,
    /// The peer path exceeded [`MAX_PATH_LEN`].
    PathTooLong,
    /// The peer path contained a `..` component.
    PathHasParent,
    /// The peer path was not beneath the trusted root.
    PathNotBeneathRoot,
    /// The peer path resolved to the root itself (not a file).
    PathIsRoot,
}

impl fmt::Display for ConfigLimitsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::NameTooLong => "an owner or group name is too long",
            Self::NameContainsNul => "an owner or group name contains a NUL byte",
            Self::ListTooLong => "an owner or group allow-list is too long",
            Self::EmptyName => "an owner or group allow-list contains an empty entry",
            Self::UnknownOwner => "a configured owner name is unknown",
            Self::UnknownGroup => "a configured group name is unknown",
            Self::InvalidUidGid => "a resolved owner or group id is invalid",
            Self::ResolverFailure => "an owner or group lookup failed",
            Self::ChrootNotAbsolute => "the configured chroot is not an absolute path",
            Self::ChrootTooLong => "the configured chroot path is too long",
            Self::ChrootContainsNul => "the configured chroot path contains a NUL byte",
            Self::ChrootHasParent => "the configured chroot path contains a parent component",
            Self::InvalidUmask => "the configured umask is invalid",
            Self::PolicyRejected => "the configured limits policy is invalid",
            Self::RootEmpty => "the trusted root path is empty",
            Self::RootNotAbsolute => "the trusted root path is not absolute",
            Self::RootContainsNul => "the trusted root path contains a NUL byte",
            Self::RootTooLong => "the trusted root path is too long",
            Self::RootHasParent => "the trusted root path contains a parent component",
            Self::PathEmpty => "the peer path is empty",
            Self::PathNotAbsolute => "the peer path is not absolute",
            Self::PathContainsNul => "the peer path contains a NUL byte",
            Self::PathTooLong => "the peer path is too long",
            Self::PathHasParent => "the peer path contains a parent component",
            Self::PathNotBeneathRoot => "the peer path is not beneath the trusted root",
            Self::PathIsRoot => "the peer path resolves to the root itself",
        };
        f.write_str(message)
    }
}

impl std::error::Error for ConfigLimitsError {}

/// Validate a single owner/group name's bounds and content.
fn validate_name(name: &str) -> Result<(), ConfigLimitsError> {
    let bytes = name.as_bytes();
    if bytes.contains(&0) {
        return Err(ConfigLimitsError::NameContainsNul);
    }
    if bytes.len() > MAX_NAME_LEN {
        return Err(ConfigLimitsError::NameTooLong);
    }
    Ok(())
}

/// Parse an octal umask string, rejecting malformed input, overflow, values
/// above [`MAX_UMASK`], and any prefix the upstream configuration never produces.
///
/// An empty string is treated the same as an absent value (`0`, the default),
/// matching upstream empty-configuration semantics.
fn parse_umask(text: &str) -> Result<u16, ConfigLimitsError> {
    if text.is_empty() {
        return Ok(0);
    }
    for byte in text.bytes() {
        if !(b'0'..=b'7').contains(&byte) {
            return Err(ConfigLimitsError::InvalidUmask);
        }
    }
    let value = u16::from_str_radix(text, 8).map_err(|_| ConfigLimitsError::InvalidUmask)?;
    if value > MAX_UMASK {
        return Err(ConfigLimitsError::InvalidUmask);
    }
    Ok(value)
}

fn resolve_optional_user(
    resolver: &impl NssResolver,
    name: Option<&str>,
) -> Result<Option<u32>, ConfigLimitsError> {
    match name {
        None | Some("") => Ok(None),
        Some(name) => {
            validate_name(name)?;
            match resolver
                .lookup_user(name)
                .map_err(|_| ConfigLimitsError::ResolverFailure)?
            {
                Some(id) if id == u32::MAX => Err(ConfigLimitsError::InvalidUidGid),
                Some(id) => Ok(Some(id)),
                None => Err(ConfigLimitsError::UnknownOwner),
            }
        }
    }
}

fn resolve_optional_group(
    resolver: &impl NssResolver,
    name: Option<&str>,
) -> Result<Option<u32>, ConfigLimitsError> {
    match name {
        None | Some("") => Ok(None),
        Some(name) => {
            validate_name(name)?;
            match resolver
                .lookup_group(name)
                .map_err(|_| ConfigLimitsError::ResolverFailure)?
            {
                Some(id) if id == u32::MAX => Err(ConfigLimitsError::InvalidUidGid),
                Some(id) => Ok(Some(id)),
                None => Err(ConfigLimitsError::UnknownGroup),
            }
        }
    }
}

fn resolve_user_list(
    resolver: &impl NssResolver,
    names: Option<&[String]>,
) -> Result<Vec<u32>, ConfigLimitsError> {
    let names = match names {
        None => return Ok(Vec::new()),
        Some(names) => names,
    };
    if names.len() > MAX_LIST_LEN {
        return Err(ConfigLimitsError::ListTooLong);
    }
    let mut resolved = Vec::with_capacity(names.len());
    for name in names {
        if name.is_empty() {
            return Err(ConfigLimitsError::EmptyName);
        }
        validate_name(name)?;
        match resolver
            .lookup_user(name)
            .map_err(|_| ConfigLimitsError::ResolverFailure)?
        {
            Some(id) if id == u32::MAX => return Err(ConfigLimitsError::InvalidUidGid),
            Some(id) => resolved.push(id),
            None => return Err(ConfigLimitsError::UnknownOwner),
        }
    }
    Ok(resolved)
}

fn resolve_group_list(
    resolver: &impl NssResolver,
    names: Option<&[String]>,
) -> Result<Vec<u32>, ConfigLimitsError> {
    let names = match names {
        None => return Ok(Vec::new()),
        Some(names) => names,
    };
    if names.len() > MAX_LIST_LEN {
        return Err(ConfigLimitsError::ListTooLong);
    }
    let mut resolved = Vec::with_capacity(names.len());
    for name in names {
        if name.is_empty() {
            return Err(ConfigLimitsError::EmptyName);
        }
        validate_name(name)?;
        match resolver
            .lookup_group(name)
            .map_err(|_| ConfigLimitsError::ResolverFailure)?
        {
            Some(id) if id == u32::MAX => return Err(ConfigLimitsError::InvalidUidGid),
            Some(id) => resolved.push(id),
            None => return Err(ConfigLimitsError::UnknownGroup),
        }
    }
    Ok(resolved)
}

fn map_limits_error(error: LimitsError) -> ConfigLimitsError {
    match error {
        LimitsError::ChrootNotAbsolute => ConfigLimitsError::ChrootNotAbsolute,
        LimitsError::ChrootTooLong => ConfigLimitsError::ChrootTooLong,
        LimitsError::PathContainsNul => ConfigLimitsError::ChrootContainsNul,
        LimitsError::UmaskOutOfRange => ConfigLimitsError::InvalidUmask,
        LimitsError::TooManyOwnerGetEntries | LimitsError::TooManyGroupGetEntries => {
            ConfigLimitsError::ListTooLong
        }
        _ => ConfigLimitsError::PolicyRejected,
    }
}

/// Compile raw configuration limits into a validated [`LimitsPolicy`].
///
/// When `enabled` is `false` a disabled policy is returned immediately and the
/// resolver is **never** consulted, so no NSS lookup or filesystem work happens
/// on the unchanged daemon path. When `enabled` is `true` every raw field is
/// validated and compiled.
///
/// # Upstream compatibility decision
///
/// Upstream `applyDefaults` unconditionally forces `PreserveMode = true` and
/// `PreserveOwner = true`, overriding an explicit `false` in the configuration.
/// We reproduce that decision here: [`RawFileTransferLimits::preserve_mode`] and
/// [`RawFileTransferLimits::preserve_owner`] are kept as configured (so a test
/// can observe the raw value), but the compiled policy always uses `true`.
///
/// # Bounds
///
/// Owner/group names are bounded to [`MAX_NAME_LEN`] bytes with no NUL, and
/// allow-lists to [`MAX_LIST_LEN`] entries. Unknown names, resolver failures and
/// the reserved `u32::MAX` id are explicit errors. An all-zero policy is
/// unlimited; `u64::MAX` counters are accepted (a later counter overflow is a
/// typed rate-layer error, not a configuration error).
pub fn build_policy(
    enabled: bool,
    raw: &RawFileTransferLimits,
    resolver: &impl NssResolver,
) -> Result<LimitsPolicy, ConfigLimitsError> {
    if !enabled {
        return Ok(LimitsPolicy::disabled());
    }

    let chroot: Option<PathBuf> = match raw.chroot.as_deref() {
        None | Some("") => None,
        Some(path) => {
            let bytes = path.as_bytes();
            if bytes.contains(&0) {
                return Err(ConfigLimitsError::ChrootContainsNul);
            }
            if bytes.len() > MAX_CHROOT_LEN {
                return Err(ConfigLimitsError::ChrootTooLong);
            }
            if !Path::new(path).is_absolute() {
                return Err(ConfigLimitsError::ChrootNotAbsolute);
            }
            for component in Path::new(path).components() {
                if matches!(component, Component::ParentDir) {
                    return Err(ConfigLimitsError::ChrootHasParent);
                }
            }
            Some(PathBuf::from(path))
        }
    };

    let umask = match raw.umask.as_deref() {
        None => 0,
        Some(text) => parse_umask(text)?,
    };

    let owner_put = resolve_optional_user(resolver, raw.owner_put.as_deref())?;
    let group_put = resolve_optional_group(resolver, raw.group_put.as_deref())?;
    let owner_get = resolve_user_list(resolver, raw.owner_get.as_deref())?;
    let group_get = resolve_group_list(resolver, raw.group_get.as_deref())?;

    let options = LimitsOptions {
        enabled: true,
        chroot,
        follow_symlinks: raw.follow_sym_links.unwrap_or(false),
        overwrite: raw.allow_overwrite.unwrap_or(false),
        owner_put,
        group_put,
        owner_get,
        group_get,
        umask,
        max_file_size: raw.max_file_size.unwrap_or(0),
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
        allow_suid: raw.allow_suid.unwrap_or(false),
        regular_files_only: raw.regular_files_only.unwrap_or(false),
        // Upstream forces both of these true regardless of configuration.
        preserve_mode: true,
        preserve_owner: true,
    };

    LimitsPolicy::from_options(options).map_err(map_limits_error)
}

fn validate_root(root: &Path) -> Result<(), ConfigLimitsError> {
    let bytes = root.as_os_str().as_bytes();
    if bytes.is_empty() {
        return Err(ConfigLimitsError::RootEmpty);
    }
    if bytes.contains(&0) {
        return Err(ConfigLimitsError::RootContainsNul);
    }
    if bytes.len() > MAX_PATH_LEN {
        return Err(ConfigLimitsError::RootTooLong);
    }
    if !root.is_absolute() {
        return Err(ConfigLimitsError::RootNotAbsolute);
    }
    for component in root.components() {
        if matches!(component, Component::ParentDir) {
            return Err(ConfigLimitsError::RootHasParent);
        }
    }
    Ok(())
}

fn map_fs_error(error: FsError) -> ConfigLimitsError {
    match error {
        FsError::InvalidPathEmpty => ConfigLimitsError::PathEmpty,
        FsError::PathTooLong => ConfigLimitsError::PathTooLong,
        FsError::PathContainsNul => ConfigLimitsError::PathContainsNul,
        FsError::PathAbsolute => ConfigLimitsError::PathNotAbsolute,
        FsError::PathHasParent => ConfigLimitsError::PathHasParent,
        _ => ConfigLimitsError::PathNotBeneathRoot,
    }
}

/// Map a peer-supplied absolute path beneath a trusted root to a validated
/// [`RelativePath`].
///
/// The `root` is assumed to be a trusted, absolute, normalized directory chosen
/// by the caller (e.g. the configured chroot, or `/` when no chroot is
/// configured). As a defensive deviation, a root containing any `..` component
/// is rejected with a typed error before any mapping, because an un-normalized
/// root would be stripped inconsistently with [`crate::limits_fs`]. The `peer`
/// path must be absolute; it is rejected if empty, if it
/// contains a NUL or exceeds [`MAX_PATH_LEN`], and defensively if it contains any
/// `..` component. The root is stripped by **path components** (never by string
/// prefix), so a root of `/work` rejects `/work-other/...`. A path equal to the
/// root is rejected because the root itself is not a valid file.
///
/// This is a lexical mapping only. It performs no filesystem access,
/// canonicalization or kernel checks, and it is **not** a proof of confinement:
/// the kernel-enforced `openat2` layer in [`crate::limits_fs`] remains the actual
/// resolution authority.
pub fn resolve_peer_path(root: &Path, peer: &str) -> Result<RelativePath, ConfigLimitsError> {
    validate_root(root)?;

    let peer_bytes = peer.as_bytes();
    if peer_bytes.is_empty() {
        return Err(ConfigLimitsError::PathEmpty);
    }
    if peer_bytes.len() > MAX_PATH_LEN {
        return Err(ConfigLimitsError::PathTooLong);
    }
    if peer_bytes.contains(&0) {
        return Err(ConfigLimitsError::PathContainsNul);
    }

    let peer_path = Path::new(peer);
    if !peer_path.is_absolute() {
        return Err(ConfigLimitsError::PathNotAbsolute);
    }
    for component in peer_path.components() {
        if matches!(component, Component::ParentDir) {
            return Err(ConfigLimitsError::PathHasParent);
        }
    }

    let relative = peer_path
        .strip_prefix(root)
        .map_err(|_| ConfigLimitsError::PathNotBeneathRoot)?;
    let relative_bytes = relative.as_os_str().as_bytes();
    if relative_bytes.is_empty() {
        return Err(ConfigLimitsError::PathIsRoot);
    }

    RelativePath::parse(relative_bytes).map_err(map_fs_error)
}
