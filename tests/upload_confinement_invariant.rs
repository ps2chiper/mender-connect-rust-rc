//! Integration tests for limited-upload ancestry confinement admission.
//!
//! These tests exercise the hardened admission invariant of the staged upload
//! layer through its public surface only:
//!
//! * every directory **from the held configured root through** the selected
//!   upload parent — including the configured root itself, whether or not it is
//!   the selected upload parent — must be owned by the effective daemon uid (or
//!   root) **and** carry no group/other write permission,
//! * the check walks the actual held parent descriptor upward with `..` to the
//!   configured root, so a writable configured root above a safe child is
//!   rejected too (there is no "trusted boundary" exemption),
//! * the unsafe chain is rejected *before* a stage exists or is acknowledged,
//! * no pre-existing bytes (original / sentinel content) are modified on
//!   rejection,
//! * restoring safe permissions permits admission again,
//! * all admission construction paths are covered:
//!   1. `begin_staged_create` (new file),
//!   2. `PreparedTarget::begin_stage` for a new leaf target,
//!   3. `PreparedTarget::begin_stage` for an existing regular-file replacement,
//!   4. `PreparedTarget::begin_stage` for the root directory shorthand target,
//! * a confined-symlink escape (`root/link -> unsafe/leaf`) under
//!   `SymlinkMode::RelativeWithinRoot` is refused before a stage is allocated
//!   and never reaches the unsafe, group/other-writable resolved directory.
//!
//! The tests use `Result`-based control flow, `tempfile::tempdir` RAII trees and
//! bounded operations only. They contain no `unsafe`, no `unwrap`/`expect` and
//! no explicit panics, and they never touch credentials or external systems.
//!
//! # Documented residual assumptions (mirrored from the module docs)
//!
//! * Ancestry safety is an admission-time filesystem policy check over directory
//!   descriptors. It does not prove hardlink provenance: an on-disk hardlink can
//!   alias an inode outside the root, so the enforced scope is *pathname* scope.
//! * It cannot make arbitrary concurrent renames race-free, and it does not
//!   constrain movement of the configured root itself: the configured root and
//!   everything **above** it (ancestors outside the root) remain trusted and are
//!   never inspected by this layer.
//! * Root daemons reject other-user-owned upload directories; group-writable
//!   limited upload trees fail closed.
//! * Same-euid and root actors, and trusted mounts (including the assumed-trusted
//!   procfs namespace used for publication), remain trusted.
//! * POSIX ACL masks are reflected in the group write bits only on filesystems
//!   that implement ACLs that way; no claim is made for every filesystem.

use std::error::Error;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use tempfile::tempdir;

use mender_connect_rust::limits_fs::{RelativePath, RootDir, SymlinkMode};
use mender_connect_rust::limits_fs_upload::{
    UploadError, begin_staged_create, resolve_upload_target,
};

type TestResult = Result<(), Box<dyn Error>>;

/// Create (recursively) a directory beneath `base` and return its path.
fn make_dir(base: &Path, relative: &str) -> Result<PathBuf, Box<dyn Error>> {
    let path = base.join(relative);
    fs::create_dir_all(&path)?;
    Ok(path)
}

/// Apply POSIX permission bits to `path`.
fn set_mode(path: &Path, mode: u32) -> TestResult {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

/// Write `bytes` to `path`, returning the path.
fn write_file(path: &Path, bytes: &[u8]) -> Result<PathBuf, Box<dyn Error>> {
    fs::write(path, bytes)?;
    Ok(path.to_path_buf())
}

/// Read the bytes stored at `path`.
fn read_file(path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(fs::read(path)?)
}

/// Open the configured root as the `RootDir` handle used by the layer.
///
/// The configured root is the resolution boundary and is *checked* itself; only
/// its ancestry (everything above it) is outside this layer's inspection.
fn open_root(root_path: &Path) -> Result<RootDir, Box<dyn Error>> {
    Ok(RootDir::open(root_path)?)
}

/// Parse a relative upload path beneath the held root.
fn parse_relative(path: &str) -> Result<RelativePath, Box<dyn Error>> {
    Ok(RelativePath::parse(path.as_bytes())?)
}

/// The symlink policy used by the descriptor-based tests: all parent symlinks
/// refused.
fn refuse_symlinks() -> SymlinkMode {
    SymlinkMode::RefuseAll
}

/// Assert that an admission attempt failed closed with `UnsafeUploadAncestor`.
fn expect_unsafe_ancestor<T>(result: Result<T, UploadError>) -> TestResult {
    match result {
        Err(UploadError::UnsafeUploadAncestor) => Ok(()),
        Err(UploadError::UnsafeReplacementParent) => Ok(()),
        Err(other) => Err(format!("unexpected admission error: {other}").into()),
        Ok(_) => Err("admission accepted an unsafe upload ancestry".into()),
    }
}

/// Assert that an admission attempt was refused for *some* typed reason.
fn expect_rejected<T>(result: Result<T, UploadError>) -> TestResult {
    match result {
        Err(_) => Ok(()),
        Ok(_) => Err("admission was unexpectedly accepted".into()),
    }
}

#[test]
fn rejects_writable_intermediate_ancestor_with_safe_leaf() -> TestResult {
    let tree = tempdir()?;
    let base = tree.path();
    let middle = make_dir(base, "middle")?;
    let leaf = make_dir(base, "middle/leaf")?;
    set_mode(base, 0o700)?;
    set_mode(&middle, 0o777)?;
    set_mode(&leaf, 0o700)?;

    let sentinel = write_file(&leaf.join("payload.bin"), b"original bytes")?;

    let root = open_root(base)?;
    let target = parse_relative("middle/leaf/payload.bin")?;

    // The leaf itself is safe; only the intermediate ancestor is unsafe.
    expect_unsafe_ancestor(begin_staged_create(&root, &target, refuse_symlinks()))?;

    if read_file(&sentinel)? != b"original bytes" {
        return Err("sentinel bytes changed on rejection".into());
    }

    // Restoring safe permissions permits admission again.
    set_mode(&middle, 0o700)?;
    let stage = begin_staged_create(&root, &target, refuse_symlinks())?;
    drop(stage);

    if read_file(&sentinel)? != b"original bytes" {
        return Err("sentinel bytes changed on successful admission".into());
    }
    Ok(())
}

#[test]
fn rejects_group_writable_upload_parent_itself() -> TestResult {
    let tree = tempdir()?;
    let base = tree.path();
    let leaf = make_dir(base, "leaf")?;
    set_mode(base, 0o700)?;
    set_mode(&leaf, 0o775)?;

    let root = open_root(base)?;
    let target = parse_relative("leaf/payload.bin")?;

    // The selected upload parent is the unsafe directory here.
    expect_unsafe_ancestor(begin_staged_create(&root, &target, refuse_symlinks()))?;

    set_mode(&leaf, 0o750)?;
    let stage = begin_staged_create(&root, &target, refuse_symlinks())?;
    drop(stage);
    Ok(())
}

#[test]
fn rejects_writable_root_when_it_is_the_upload_parent() -> TestResult {
    let tree = tempdir()?;
    let base = tree.path();
    set_mode(base, 0o777)?;

    let root = open_root(base)?;
    let target = parse_relative("payload.bin")?;

    // The parent is the root itself, so it is checked like any upload parent.
    expect_unsafe_ancestor(begin_staged_create(&root, &target, refuse_symlinks()))?;

    set_mode(base, 0o700)?;
    let stage = begin_staged_create(&root, &target, refuse_symlinks())?;
    drop(stage);
    Ok(())
}

#[test]
fn rejects_writable_root_even_when_every_child_is_safe() -> TestResult {
    let tree = tempdir()?;
    let base = tree.path();
    let middle = make_dir(base, "middle")?;
    let leaf = make_dir(base, "middle/leaf")?;
    // The configured root is *always* checked by the corrected policy. A
    // writable root above a safe child is therefore still rejected; there is no
    // "trusted boundary" exemption for the root's own permission bits.
    set_mode(base, 0o777)?;
    set_mode(&middle, 0o700)?;
    set_mode(&leaf, 0o700)?;

    let sentinel = write_file(&leaf.join("payload.bin"), b"original bytes")?;

    let root = open_root(base)?;
    let target = parse_relative("middle/leaf/payload.bin")?;

    expect_unsafe_ancestor(begin_staged_create(&root, &target, refuse_symlinks()))?;

    if read_file(&sentinel)? != b"original bytes" {
        return Err("sentinel bytes changed on rejection".into());
    }

    set_mode(base, 0o700)?;
    let stage = begin_staged_create(&root, &target, refuse_symlinks())?;
    drop(stage);
    Ok(())
}

#[test]
fn fully_safe_tree_is_admitted_and_publishes_bytes() -> TestResult {
    let tree = tempdir()?;
    let base = tree.path();
    let middle = make_dir(base, "middle")?;
    let leaf = make_dir(base, "middle/leaf")?;
    set_mode(base, 0o700)?;
    set_mode(&middle, 0o700)?;
    set_mode(&leaf, 0o700)?;

    let root = open_root(base)?;
    let target = parse_relative("middle/leaf/payload.bin")?;

    let mut stage = begin_staged_create(&root, &target, refuse_symlinks())?;
    stage.write_all(b"trusted payload")?;
    stage.commit_new()?;

    if read_file(&leaf.join("payload.bin"))? != b"trusted payload" {
        return Err("published bytes do not match the staged bytes".into());
    }
    Ok(())
}

#[test]
fn prepared_target_new_leaf_enforces_ancestry() -> TestResult {
    let tree = tempdir()?;
    let base = tree.path();
    let middle = make_dir(base, "middle")?;
    let leaf = make_dir(base, "middle/leaf")?;
    set_mode(base, 0o700)?;
    set_mode(&middle, 0o770)?;
    set_mode(&leaf, 0o700)?;

    let root = open_root(base)?;
    let target = parse_relative("middle/leaf/new.bin")?;

    // Resolution itself only pins the parent; admission happens at begin_stage.
    let prepared = resolve_upload_target(&root, Some(&target), base, None, refuse_symlinks())?;
    if prepared.existing().is_some() || prepared.is_replacement() {
        return Err("a new leaf target must not be reported as a replacement".into());
    }
    expect_unsafe_ancestor(prepared.begin_stage())?;

    set_mode(&middle, 0o700)?;
    let prepared = resolve_upload_target(&root, Some(&target), base, None, refuse_symlinks())?;
    let stage = prepared.begin_stage()?;
    drop(stage);
    Ok(())
}

#[test]
fn prepared_target_replacement_enforces_ancestry_and_preserves_bytes() -> TestResult {
    let tree = tempdir()?;
    let base = tree.path();
    let middle = make_dir(base, "middle")?;
    let leaf = make_dir(base, "middle/leaf")?;
    set_mode(base, 0o700)?;
    set_mode(&middle, 0o777)?;
    set_mode(&leaf, 0o700)?;

    let sentinel = write_file(&leaf.join("existing.bin"), b"original bytes")?;

    let root = open_root(base)?;
    let target = parse_relative("middle/leaf/existing.bin")?;

    let prepared = resolve_upload_target(&root, Some(&target), base, None, refuse_symlinks())?;
    if !prepared.is_replacement() || prepared.existing().is_none() {
        return Err("an existing regular file must be admitted as a replacement".into());
    }
    // The replacement parent (the leaf) is safe; the intermediate is not.
    expect_unsafe_ancestor(prepared.begin_stage())?;

    if read_file(&sentinel)? != b"original bytes" {
        return Err("replacement target bytes changed on rejection".into());
    }

    set_mode(&middle, 0o700)?;
    let prepared = resolve_upload_target(&root, Some(&target), base, None, refuse_symlinks())?;
    let stage = prepared.begin_stage()?;
    drop(stage);

    if read_file(&sentinel)? != b"original bytes" {
        return Err("replacement target bytes changed on re-admission".into());
    }
    Ok(())
}

#[test]
fn prepared_target_root_shorthand_checks_the_root_as_upload_parent() -> TestResult {
    let tree = tempdir()?;
    let base = tree.path();
    set_mode(base, 0o777)?;
    let sentinel = write_file(&base.join("artifact.bin"), b"original bytes")?;

    let root = open_root(base)?;

    let prepared = resolve_upload_target(
        &root,
        None,
        base,
        Some("/virtual/source/artifact.bin"),
        refuse_symlinks(),
    )?;
    // The directory shorthand selects the configured root as the upload parent.
    expect_unsafe_ancestor(prepared.begin_stage())?;
    if read_file(&sentinel)? != b"original bytes" {
        return Err("shorthand target bytes changed on rejection".into());
    }

    set_mode(base, 0o700)?;
    let prepared = resolve_upload_target(
        &root,
        None,
        base,
        Some("/virtual/source/artifact.bin"),
        refuse_symlinks(),
    )?;
    let stage = prepared.begin_stage()?;
    drop(stage);
    Ok(())
}

#[test]
fn every_admission_path_rejects_an_unsafe_tree() -> TestResult {
    // A single unsafe intermediate ancestor must fail closed on all four
    // admission construction paths before any stage is allocated.
    let tree = tempdir()?;
    let base = tree.path();
    let middle = make_dir(base, "middle")?;
    let leaf = make_dir(base, "middle/leaf")?;
    set_mode(base, 0o777)?;
    set_mode(&middle, 0o707)?;
    set_mode(&leaf, 0o700)?;
    let original = write_file(&leaf.join("existing.bin"), b"original bytes")?;

    let root = open_root(base)?;

    let new_target = parse_relative("middle/leaf/fresh.bin")?;
    expect_unsafe_ancestor(begin_staged_create(&root, &new_target, refuse_symlinks()))?;

    let prepared = resolve_upload_target(&root, Some(&new_target), base, None, refuse_symlinks())?;
    expect_unsafe_ancestor(prepared.begin_stage())?;

    let replace_target = parse_relative("middle/leaf/existing.bin")?;
    let prepared =
        resolve_upload_target(&root, Some(&replace_target), base, None, refuse_symlinks())?;
    expect_unsafe_ancestor(prepared.begin_stage())?;

    // The root shorthand selects the configured root as the parent; with the
    // root group/other writable it must be rejected like any upload parent.
    let prepared = resolve_upload_target(
        &root,
        None,
        base,
        Some("/virtual/source/fresh.bin"),
        refuse_symlinks(),
    )?;
    expect_unsafe_ancestor(prepared.begin_stage())?;

    if read_file(&original)? != b"original bytes" {
        return Err("original bytes changed while every path was rejected".into());
    }

    // Restoring safe permissions on the root and the intermediate makes the
    // shorthand admissible again.
    set_mode(base, 0o700)?;
    set_mode(&middle, 0o700)?;
    let prepared = resolve_upload_target(
        &root,
        None,
        base,
        Some("/virtual/source/fresh.bin"),
        refuse_symlinks(),
    )?;
    let stage = prepared.begin_stage()?;
    drop(stage);

    if read_file(&original)? != b"original bytes" {
        return Err("original bytes changed after safe re-admission".into());
    }
    Ok(())
}

#[test]
fn confined_symlink_to_unsafe_ancestor_is_refused_before_stage() -> TestResult {
    // Production admission regression: `root/link -> unsafe/leaf`, where the
    // resolved directory `unsafe` is group/other writable (0o777) and `leaf` is
    // safe (0o700). Under `SymlinkMode::RelativeWithinRoot` the confined
    // resolution must refuse the escaping symlink *before* a stage is allocated,
    // and the sentinel inside the unsafe tree must remain untouched.
    let tree = tempdir()?;
    let base = tree.path();
    let root_path = make_dir(base, "root")?;
    let unsafe_dir = make_dir(&root_path, "unsafe")?;
    let leaf = make_dir(&root_path, "unsafe/leaf")?;
    set_mode(base, 0o700)?;
    set_mode(&root_path, 0o700)?;
    set_mode(&unsafe_dir, 0o777)?;
    set_mode(&leaf, 0o700)?;

    let sentinel = write_file(&leaf.join("sentinel.bin"), b"original bytes")?;
    symlink("unsafe/leaf", root_path.join("link"))?;

    let root = open_root(&root_path)?;
    let target = parse_relative("link/sentinel.bin")?;

    // Rejected for a typed reason, before any staging descriptor exists. The
    // confined policy must not silently traverse the escape into the unsafe
    // group/other-writable directory.
    expect_rejected(begin_staged_create(
        &root,
        &target,
        SymlinkMode::RelativeWithinRoot,
    ))?;

    if read_file(&sentinel)? != b"original bytes" {
        return Err("sentinel bytes changed when the symlink escape was refused".into());
    }

    // The same holds for the prepared-target path used by the transfer worker.
    let prepared = resolve_upload_target(
        &root,
        Some(&target),
        &root_path,
        None,
        SymlinkMode::RelativeWithinRoot,
    );
    if let Ok(prepared) = prepared {
        expect_rejected(prepared.begin_stage())?;
    }

    if read_file(&sentinel)? != b"original bytes" {
        return Err("sentinel bytes changed on the prepared-target path".into());
    }
    Ok(())
}

#[test]
fn non_directory_ancestor_and_missing_parent_fail_closed() -> TestResult {
    // Defence in depth: a non-directory ancestor is refused with a typed error
    // (never a panic, never an unchecked fallback) before any stage exists.
    let tree = tempdir()?;
    let base = tree.path();
    set_mode(base, 0o700)?;
    let ancestor = write_file(&base.join("ancestor"), b"not a directory")?;

    let root = open_root(base)?;
    let target = parse_relative("ancestor/leaf/payload.bin")?;

    expect_rejected(begin_staged_create(&root, &target, refuse_symlinks()))?;

    if read_file(&ancestor)? != b"not a directory" {
        return Err("ancestor bytes changed on rejection".into());
    }

    // A missing parent is likewise a typed rejection, not a panic.
    let missing = parse_relative("absent/leaf/payload.bin")?;
    expect_rejected(begin_staged_create(&root, &missing, refuse_symlinks()))?;
    Ok(())
}
