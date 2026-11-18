use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use mender_connect_rust::file_transfer_schema::{
    GetFile, StatFile, UploadRequest, required_path, source_basename, stat_file, timestamp_value,
    validate_requested_size,
};
use mender_connect_rust::protocol;

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let mut path = std::env::temp_dir();
        let unique = format!(
            "mender_ft_test_{}_{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        path.push(unique);
        fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn ext_bytes(value: &rmpv::Value) -> &[u8] {
    match value {
        rmpv::Value::Ext(-1, bytes) => bytes,
        other => panic!("expected Ext(-1, ..), got {other:?}"),
    }
}

#[test]
fn required_path_rejects_missing_empty_and_nul() {
    assert!(required_path(None).is_err());
    assert!(required_path(Some("")).is_err());
    assert!(required_path(Some("a\0b")).is_err());
    assert_eq!(required_path(Some("/tmp/x")).expect("valid path"), "/tmp/x");
}

#[test]
fn validate_requested_size_boundaries() {
    assert!(validate_requested_size(Some(-1)).is_err());
    assert!(validate_requested_size(Some(0)).is_ok());
    assert!(validate_requested_size(Some(i64::MAX)).is_ok());
    assert!(validate_requested_size(None).is_ok());
}

#[test]
fn source_basename_rules() {
    assert!(source_basename(".").is_err());
    assert!(source_basename("..").is_err());
    assert!(source_basename("/").is_err());
    assert_eq!(source_basename("/a/b/c.txt").expect("basename"), "c.txt");
}

#[test]
fn timestamp_epoch_is_four_bytes() {
    let value = timestamp_value(UNIX_EPOCH).expect("epoch");
    assert_eq!(ext_bytes(&value), &[0u8, 0, 0, 0][..]);
}

#[test]
fn timestamp_u32max_boundary_is_four_bytes() {
    let t = UNIX_EPOCH + Duration::from_secs(u64::from(u32::MAX));
    let value = timestamp_value(t).expect("u32max");
    assert_eq!(ext_bytes(&value), &[0xFF, 0xFF, 0xFF, 0xFF][..]);
}

#[test]
fn timestamp_above_u32max_is_64bit() {
    let secs = u64::from(u32::MAX) + 1;
    let t = UNIX_EPOCH + Duration::from_secs(secs);
    let value = timestamp_value(t).expect("64bit");
    let bytes = ext_bytes(&value);
    assert_eq!(bytes.len(), 8);
    assert_eq!(bytes, &secs.to_be_bytes()[..]);
}

#[test]
fn timestamp_nanoseconds_are_packed() {
    let t = UNIX_EPOCH + Duration::new(1, 500_000_000);
    let value = timestamp_value(t).expect("nanos");
    let bytes = ext_bytes(&value);
    assert_eq!(bytes.len(), 8);
    let expected = (500_000_000u64 << 34) | 1u64;
    assert_eq!(bytes, &expected.to_be_bytes()[..]);
}

#[test]
fn timestamp_large_secs_is_96bit() {
    let secs = 1u64 << 34;
    let t = UNIX_EPOCH + Duration::from_secs(secs);
    let value = timestamp_value(t).expect("96bit");
    let bytes = ext_bytes(&value);
    assert_eq!(bytes.len(), 12);
    let mut expected = Vec::new();
    expected.extend_from_slice(&0u32.to_be_bytes());
    expected.extend_from_slice(&secs.to_be_bytes());
    assert_eq!(bytes, expected.as_slice());
}

#[test]
fn timestamp_one_ns_before_epoch_is_96bit() {
    let t = UNIX_EPOCH - Duration::from_nanos(1);
    let value = timestamp_value(t).expect("pre-epoch");
    let bytes = ext_bytes(&value);
    assert_eq!(bytes.len(), 12);
    let mut expected = Vec::new();
    expected.extend_from_slice(&999_999_999u32.to_be_bytes());
    expected.extend_from_slice(&(-1i64).to_be_bytes());
    assert_eq!(bytes, expected.as_slice());
}

#[test]
fn protocol_roundtrip_preserves_ext() {
    let value = timestamp_value(UNIX_EPOCH + Duration::new(1, 500_000_000)).expect("ts");
    let encoded = protocol::encode(&value).expect("encode");
    let decoded: rmpv::Value = protocol::decode(&encoded).expect("decode");
    assert_eq!(decoded, value);
}

#[test]
fn stat_file_regular_file_reports_metadata() {
    let dir = TempDir::new();
    let file = dir.path.join("data.bin");
    fs::write(&file, b"hello world").expect("write");
    let mut perms = fs::metadata(&file).expect("meta").permissions();
    perms.set_mode(0o640);
    fs::set_permissions(&file, perms).expect("chmod");

    let info = stat_file(file.to_str().expect("utf8")).expect("stat");
    assert_eq!(info.size, Some(11));
    assert_eq!(info.mode.map(|m| m & 0o777), Some(0o640));

    let meta = fs::metadata(&file).expect("meta2");
    assert_eq!(info.uid, Some(meta.uid()));
    assert_eq!(info.gid, Some(meta.gid()));
    assert!(matches!(info.modtime, Some(rmpv::Value::Ext(-1, _))));
}

#[test]
fn stat_file_directory_has_mode_dir() {
    let dir = TempDir::new();
    let sub = dir.path.join("sub");
    fs::create_dir(&sub).expect("mkdir");
    let info = stat_file(sub.to_str().expect("utf8")).expect("stat dir");
    let mode = info.mode.expect("mode");
    assert_ne!(mode & (1 << 31), 0);
}

#[test]
fn stat_file_missing_path_errors() {
    let dir = TempDir::new();
    let missing = dir.path.join("nope");
    assert!(stat_file(missing.to_str().expect("utf8")).is_err());
}

#[test]
fn request_schemas_decode_missing_optional_fields() {
    let empty = rmpv::Value::Map(Vec::new());

    let get: GetFile = rmpv::ext::from_value(empty.clone()).expect("getfile");
    assert_eq!(get.path, None);

    let stat: StatFile = rmpv::ext::from_value(empty.clone()).expect("statfile");
    assert_eq!(stat.path, None);

    let upload: UploadRequest = rmpv::ext::from_value(empty).expect("upload");
    assert_eq!(upload.src_path, None);
    assert_eq!(upload.path, None);
    assert_eq!(upload.size, None);
    assert_eq!(upload.uid, None);
    assert_eq!(upload.gid, None);
    assert_eq!(upload.mode, None);
    assert_eq!(upload.modtime, None);
}
