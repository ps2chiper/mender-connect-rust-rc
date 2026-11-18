//! Shell-policy validation for the remote terminal session.
//!
//! The configured shell command must be an exact line in `/etc/shells`. The
//! file is opened at a fixed path (no environment or configuration override),
//! is non-blocking and close-on-exec, must be a regular file and is read with a
//! hard size cap. Only a missing file permits the default fallback shell; any
//! other I/O failure denies the shell. This is intentionally stricter than the
//! Go implementation.
//!
//! Line handling mirrors Go's `bufio.ScanLines`: lines are split on `\n`, a
//! single trailing `\r` is stripped and no whitespace trimming or variable
//! expansion occurs. Blank lines and comments never match.

use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use nix::unistd::{User, getuid};

/// Fixed location of the authorised shell list.
pub const SHELLS_PATH: &str = "/etc/shells";

/// Shell allowed when `/etc/shells` is missing.
pub const DEFAULT_FALLBACK_SHELL: &str = "/bin/sh";

/// Maximum number of bytes accepted from the shell list.
pub const MAX_SHELLS_FILE_SIZE: u64 = 1024 * 1024;

/// Maximum accepted username length in bytes.
pub const MAX_USERNAME_LEN: usize = 256;

/// Typed failure for shell/user policy validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellPolicyError {
    EmptyUser,
    UserTooLong,
    UserContainsNul,
    UnknownUser(String),
    UserLookupFailed(String),
    InvalidIdentity(String),
    ShellNotListed(String),
    ShellListReadFailed(String),
    ShellListOversize,
    ShellListInvalidUtf8,
    ShellListNotRegularFile,
}

impl fmt::Display for ShellPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShellPolicyError::EmptyUser => {
                write!(formatter, "configuration User must be set and non-empty")
            }
            ShellPolicyError::UserTooLong => write!(
                formatter,
                "configuration User exceeds {MAX_USERNAME_LEN} bytes"
            ),
            ShellPolicyError::UserContainsNul => {
                write!(formatter, "configuration User contains a NUL byte")
            }
            ShellPolicyError::UnknownUser(user) => {
                write!(formatter, "configuration User is not known to NSS: {user}")
            }
            ShellPolicyError::UserLookupFailed(message) => {
                write!(formatter, "configuration User lookup failed: {message}")
            }
            ShellPolicyError::InvalidIdentity(message) => {
                write!(formatter, "configured identity is out of range: {message}")
            }
            ShellPolicyError::ShellNotListed(shell) => {
                write!(
                    formatter,
                    "ShellCommand is not listed in /etc/shells: {shell}"
                )
            }
            ShellPolicyError::ShellListReadFailed(message) => {
                write!(formatter, "/etc/shells cannot be read: {message}")
            }
            ShellPolicyError::ShellListOversize => write!(
                formatter,
                "/etc/shells exceeds {MAX_SHELLS_FILE_SIZE} bytes"
            ),
            ShellPolicyError::ShellListInvalidUtf8 => {
                write!(formatter, "/etc/shells is not valid UTF-8")
            }
            ShellPolicyError::ShellListNotRegularFile => {
                write!(formatter, "/etc/shells is not a regular file")
            }
        }
    }
}

impl std::error::Error for ShellPolicyError {}

/// Injected result of reading the shell list, used by pure unit tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellsRead {
    Missing,
    IoError(io::ErrorKind),
    NotRegular,
    Oversize,
    Bytes(Vec<u8>),
}

fn find_shell_line(text: &str, target: &str) -> bool {
    let mut remaining = text;
    loop {
        let (line, rest) = match remaining.find('\n') {
            Some(index) => remaining.split_at(index),
            None => {
                let candidate = remaining.strip_suffix('\r').unwrap_or(remaining);
                return candidate == target;
            }
        };
        let candidate = line.strip_suffix('\r').unwrap_or(line);
        if candidate == target {
            return true;
        }
        remaining = match rest.strip_prefix('\n') {
            Some(rest) => rest,
            None => return false,
        };
        if remaining.is_empty() {
            return false;
        }
    }
}

/// Parse raw shell-list bytes and report whether `target` appears as an exact line.
pub fn list_contains(bytes: &[u8], target: &str) -> Result<bool, ShellPolicyError> {
    match u64::try_from(bytes.len()) {
        Ok(len) if len <= MAX_SHELLS_FILE_SIZE => {}
        _ => return Err(ShellPolicyError::ShellListOversize),
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ShellPolicyError::ShellListInvalidUtf8)?;
    Ok(find_shell_line(text, target))
}

/// Apply the shell policy to an injected read outcome.
pub fn check_shell_from(shell_command: &str, outcome: ShellsRead) -> Result<(), ShellPolicyError> {
    match outcome {
        ShellsRead::Missing => {
            if shell_command == DEFAULT_FALLBACK_SHELL {
                Ok(())
            } else {
                Err(ShellPolicyError::ShellNotListed(shell_command.to_owned()))
            }
        }
        ShellsRead::IoError(kind) => {
            Err(ShellPolicyError::ShellListReadFailed(format!("{kind:?}")))
        }
        ShellsRead::NotRegular => Err(ShellPolicyError::ShellListNotRegularFile),
        ShellsRead::Oversize => Err(ShellPolicyError::ShellListOversize),
        ShellsRead::Bytes(bytes) => {
            if list_contains(&bytes, shell_command)? {
                Ok(())
            } else {
                Err(ShellPolicyError::ShellNotListed(shell_command.to_owned()))
            }
        }
    }
}

fn read_shells_file(path: &Path) -> ShellsRead {
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return ShellsRead::Missing,
        Err(error) => return ShellsRead::IoError(error.kind()),
    };

    match file.metadata() {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => return ShellsRead::NotRegular,
        Err(error) => return ShellsRead::IoError(error.kind()),
    }

    let mut data = Vec::new();
    let mut limited = file.take(MAX_SHELLS_FILE_SIZE + 1);
    if let Err(error) = limited.read_to_end(&mut data) {
        return ShellsRead::IoError(error.kind());
    }

    match u64::try_from(data.len()) {
        Ok(len) if len <= MAX_SHELLS_FILE_SIZE => ShellsRead::Bytes(data),
        _ => ShellsRead::Oversize,
    }
}

/// Validate the configured shell command against `/etc/shells`.
pub fn validate_shell_command(shell_command: &str) -> Result<(), ShellPolicyError> {
    check_shell_from(shell_command, read_shells_file(Path::new(SHELLS_PATH)))
}

/// Validate the configured user before it is used for a session.
pub fn validate_user(user: &str) -> Result<(), ShellPolicyError> {
    if user.trim().is_empty() {
        return Err(ShellPolicyError::EmptyUser);
    }
    if user.len() > MAX_USERNAME_LEN {
        return Err(ShellPolicyError::UserTooLong);
    }
    if user.as_bytes().contains(&0) {
        return Err(ShellPolicyError::UserContainsNul);
    }

    let entry = User::from_name(user)
        .map_err(|error| ShellPolicyError::UserLookupFailed(error.to_string()))?
        .ok_or_else(|| ShellPolicyError::UnknownUser(user.to_owned()))?;

    if entry.uid.as_raw() == u32::MAX {
        return Err(ShellPolicyError::InvalidIdentity(format!(
            "uid for {user} is reserved"
        )));
    }
    if entry.gid.as_raw() == u32::MAX {
        return Err(ShellPolicyError::InvalidIdentity(format!(
            "gid for {user} is reserved"
        )));
    }

    Ok(())
}

/// Resolve the name of the user running the current process.
pub fn current_user_name() -> Result<String, ShellPolicyError> {
    let uid = getuid();
    let entry = User::from_uid(uid)
        .map_err(|error| ShellPolicyError::UserLookupFailed(error.to_string()))?
        .ok_or_else(|| {
            ShellPolicyError::InvalidIdentity(format!("uid {} is unknown", uid.as_raw()))
        })?;
    Ok(entry.name)
}
