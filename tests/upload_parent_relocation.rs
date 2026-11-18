use std::fs;
use std::io::Write;

use anyhow::Result;
use mender_connect_rust::limits_fs::{RelativePath, RootDir, SymlinkMode};
use mender_connect_rust::limits_fs_upload::{
    MetadataPlan, UploadError, begin_staged_create, resolve_upload_target,
};

#[test]
fn moved_parent_is_rejected_but_restored_parent_can_commit() -> Result<()> {
    let fixture = tempfile::tempdir()?;
    let root_path = fixture.path().join("root");
    let outside = fixture.path().join("outside");
    fs::create_dir(&root_path)?;
    fs::create_dir(&outside)?;
    fs::create_dir(root_path.join("parent"))?;
    fs::write(outside.join("sentinel"), b"unchanged")?;
    let root = RootDir::open(&root_path)?;
    let path = RelativePath::parse(b"parent/payload")?;
    let mut stage = begin_staged_create(&root, &path, SymlinkMode::RefuseAll)?;
    stage.write_all(b"probe")?;
    fs::rename(root_path.join("parent"), outside.join("moved"))?;
    assert_eq!(
        stage.commit_new(),
        Err(UploadError::ParentChangedAfterAdmission)
    );
    assert!(!outside.join("moved/payload").exists());
    assert_eq!(fs::read(outside.join("sentinel"))?, b"unchanged");
    fs::rename(outside.join("moved"), root_path.join("parent"))?;
    let mut restored = begin_staged_create(&root, &path, SymlinkMode::RefuseAll)?;
    restored.write_all(b"valid")?;
    restored.commit_new()?;
    assert_eq!(fs::read(root_path.join("parent/payload"))?, b"valid");
    Ok(())
}

#[test]
fn replacement_parent_substitution_is_rejected() -> Result<()> {
    let fixture = tempfile::tempdir()?;
    let root_path = fixture.path().join("root");
    fs::create_dir(&root_path)?;
    fs::create_dir(root_path.join("parent"))?;
    fs::write(root_path.join("parent/payload"), b"original")?;
    let root = RootDir::open(&root_path)?;
    let path = RelativePath::parse(b"parent/payload")?;
    let target =
        resolve_upload_target(&root, Some(&path), &root_path, None, SymlinkMode::RefuseAll)?;
    let mut stage = target.begin_stage()?;
    stage.write_all(b"replacement")?;
    fs::rename(root_path.join("parent"), fixture.path().join("moved"))?;
    fs::create_dir(root_path.join("parent"))?;
    fs::write(root_path.join("parent/payload"), b"sentinel")?;
    assert_eq!(
        stage.commit_with_metadata(MetadataPlan::none()),
        Err(UploadError::ParentChangedAfterAdmission)
    );
    assert_eq!(fs::read(root_path.join("parent/payload"))?, b"sentinel");
    assert_eq!(fs::read(fixture.path().join("moved/payload"))?, b"original");
    Ok(())
}

#[test]
fn directory_shorthand_detects_move_and_root_shorthand_works() -> Result<()> {
    let fixture = tempfile::tempdir()?;
    let root_path = fixture.path().join("root");
    fs::create_dir(&root_path)?;
    fs::create_dir(root_path.join("directory"))?;
    let root = RootDir::open(&root_path)?;
    let dir = RelativePath::parse(b"directory")?;
    let target = resolve_upload_target(
        &root,
        Some(&dir),
        &root_path,
        Some("input"),
        SymlinkMode::RefuseAll,
    )?;
    let mut stage = target.begin_stage()?;
    stage.write_all(b"data")?;
    fs::rename(root_path.join("directory"), fixture.path().join("moved"))?;
    assert_eq!(
        stage.commit_with_metadata(MetadataPlan::none()),
        Err(UploadError::ParentChangedAfterAdmission)
    );
    assert!(!fixture.path().join("moved/input").exists());
    let target = resolve_upload_target(
        &root,
        None,
        &root_path,
        Some("root-file"),
        SymlinkMode::RefuseAll,
    )?;
    let mut root_stage = target.begin_stage()?;
    root_stage.write_all(b"root")?;
    root_stage.commit_with_metadata(MetadataPlan::none())?;
    assert_eq!(fs::read(root_path.join("root-file"))?, b"root");
    Ok(())
}

#[test]
fn allowed_relative_symlink_retarget_is_detected() -> Result<()> {
    use std::os::unix::fs::symlink;
    let fixture = tempfile::tempdir()?;
    let root_path = fixture.path();
    fs::create_dir(root_path.join("first"))?;
    fs::create_dir(root_path.join("second"))?;
    symlink("first", root_path.join("link"))?;
    let root = RootDir::open(root_path)?;
    let path = RelativePath::parse(b"link/payload")?;
    let mut stage = begin_staged_create(&root, &path, SymlinkMode::RelativeWithinRoot)?;
    stage.write_all(b"data")?;
    fs::remove_file(root_path.join("link"))?;
    symlink("second", root_path.join("link"))?;
    assert_eq!(
        stage.commit_new(),
        Err(UploadError::ParentChangedAfterAdmission)
    );
    assert!(!root_path.join("first/payload").exists());
    assert!(!root_path.join("second/payload").exists());
    Ok(())
}

#[test]
fn same_staged_parent_restored_before_commit_succeeds() -> Result<()> {
    let fixture = tempfile::tempdir()?;
    let root_path = fixture.path().join("root");
    fs::create_dir(&root_path)?;
    fs::create_dir(root_path.join("parent"))?;
    let root = RootDir::open(&root_path)?;
    let path = RelativePath::parse(b"parent/file")?;
    let mut stage = begin_staged_create(&root, &path, SymlinkMode::RefuseAll)?;
    stage.write_all(b"data")?;
    fs::rename(root_path.join("parent"), fixture.path().join("moved"))?;
    fs::rename(fixture.path().join("moved"), root_path.join("parent"))?;
    stage.commit_new()?;
    assert_eq!(fs::read(root_path.join("parent/file"))?, b"data");
    Ok(())
}
