use std::fmt;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileTransferError {
    InvalidPath(String),
    NegativeSize(i64),
    InvalidBasename(String),
    Io(String),
    SizeOverflow,
    TimestampOutOfRange,
}

impl fmt::Display for FileTransferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath(m) => write!(f, "invalid path: {m}"),
            Self::NegativeSize(s) => write!(f, "negative size: {s}"),
            Self::InvalidBasename(m) => write!(f, "invalid basename: {m}"),
            Self::Io(m) => write!(f, "io error: {m}"),
            Self::SizeOverflow => write!(f, "file size overflow"),
            Self::TimestampOutOfRange => write!(f, "timestamp out of range"),
        }
    }
}

impl std::error::Error for FileTransferError {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GetFile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatFile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UploadRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modtime: Option<rmpv::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileInfo {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modtime: Option<rmpv::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransferError {
    #[serde(rename = "err", skip_serializing_if = "Option::is_none")]
    pub err: Option<String>,
    #[serde(rename = "msgtype", skip_serializing_if = "Option::is_none")]
    pub msgtype: Option<String>,
    #[serde(rename = "msgid", skip_serializing_if = "Option::is_none")]
    pub msgid: Option<String>,
}

pub fn required_path(path: Option<&str>) -> Result<&str, FileTransferError> {
    let p = path.ok_or_else(|| FileTransferError::InvalidPath("missing path".to_string()))?;
    if p.is_empty() {
        return Err(FileTransferError::InvalidPath("empty path".to_string()));
    }
    if p.contains('\0') {
        return Err(FileTransferError::InvalidPath(
            "path contains NUL".to_string(),
        ));
    }
    Ok(p)
}

pub fn validate_requested_size(size: Option<i64>) -> Result<(), FileTransferError> {
    if let Some(s) = size
        && s < 0
    {
        return Err(FileTransferError::NegativeSize(s));
    }
    Ok(())
}

pub fn source_basename(src_path: &str) -> Result<&str, FileTransferError> {
    let base = std::path::Path::new(src_path)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| FileTransferError::InvalidBasename(src_path.to_string()))?;
    if base == "." || base == ".." {
        return Err(FileTransferError::InvalidBasename(base.to_string()));
    }
    Ok(base)
}

fn go_file_mode(meta: &fs::Metadata) -> u32 {
    let mode = meta.mode();
    let mut go: u32 = mode & 0o777;
    if mode & 0o4000 != 0 {
        go |= 1 << 23; // ModeSetuid
    }
    if mode & 0o2000 != 0 {
        go |= 1 << 22; // ModeSetgid
    }
    if mode & 0o1000 != 0 {
        go |= 1 << 20; // ModeSticky
    }
    match mode & 0o170000 {
        0o040000 => go |= 1 << 31,               // ModeDir
        0o120000 => go |= 1 << 27,               // ModeSymlink
        0o020000 => go |= (1 << 26) | (1 << 21), // ModeDevice | ModeCharDevice
        0o060000 => go |= 1 << 26,               // ModeDevice
        0o010000 => go |= 1 << 25,               // ModeNamedPipe
        0o140000 => go |= 1 << 24,               // ModeSocket
        _ => {}
    }
    go
}

pub fn stat_file(path: &str) -> Result<FileInfo, FileTransferError> {
    let p = required_path(Some(path))?;
    let meta = fs::metadata(p).map_err(|e| FileTransferError::Io(e.to_string()))?;
    let size = i64::try_from(meta.len()).map_err(|_| FileTransferError::SizeOverflow)?;
    let modtime = match meta.modified() {
        Ok(t) => Some(timestamp_value(t)?),
        Err(_) => None,
    };
    Ok(FileInfo {
        path: p.to_string(),
        size: Some(size),
        uid: Some(meta.uid()),
        gid: Some(meta.gid()),
        mode: Some(go_file_mode(&meta)),
        modtime,
    })
}

pub fn timestamp_value(t: SystemTime) -> Result<rmpv::Value, FileTransferError> {
    let (secs, nanos): (i64, u32) = match t.duration_since(UNIX_EPOCH) {
        Ok(d) => {
            let secs =
                i64::try_from(d.as_secs()).map_err(|_| FileTransferError::TimestampOutOfRange)?;
            (secs, d.subsec_nanos())
        }
        Err(e) => {
            let d = e.duration();
            let secs_u =
                i64::try_from(d.as_secs()).map_err(|_| FileTransferError::TimestampOutOfRange)?;
            let nanos = d.subsec_nanos();
            if nanos == 0 {
                let s = secs_u
                    .checked_neg()
                    .ok_or(FileTransferError::TimestampOutOfRange)?;
                (s, 0)
            } else {
                let s = secs_u
                    .checked_add(1)
                    .and_then(i64::checked_neg)
                    .ok_or(FileTransferError::TimestampOutOfRange)?;
                (s, 1_000_000_000 - nanos)
            }
        }
    };

    let bytes = if secs >= 0 && nanos == 0 && secs <= i64::from(u32::MAX) {
        let s = u32::try_from(secs).map_err(|_| FileTransferError::TimestampOutOfRange)?;
        s.to_be_bytes().to_vec()
    } else if secs >= 0 {
        let s = u64::try_from(secs).map_err(|_| FileTransferError::TimestampOutOfRange)?;
        if s < (1u64 << 34) {
            let packed = (u64::from(nanos) << 34) | s;
            packed.to_be_bytes().to_vec()
        } else {
            let mut v = Vec::with_capacity(12);
            v.extend_from_slice(&nanos.to_be_bytes());
            v.extend_from_slice(&secs.to_be_bytes());
            v
        }
    } else {
        let mut v = Vec::with_capacity(12);
        v.extend_from_slice(&nanos.to_be_bytes());
        v.extend_from_slice(&secs.to_be_bytes());
        v
    };

    Ok(rmpv::Value::Ext(-1, bytes))
}
