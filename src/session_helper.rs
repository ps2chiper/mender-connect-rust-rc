//! Parent-side foundation for the isolated credential-drop session helper.
//!
//! ROOT-ONLY. This module prepares a private Unix listener and validates the
//! trusted helper executable *before* the caller spawns the PTY child. After
//! the caller owns the unreaped child session (`OwnedSession`),
//! [`PreparedListener::complete`] performs the authenticated handshake, verifies
//! the helper's readiness proof, and distinguishes a successful same-PID `exec`
//! (clean EOF) from a bounded `exec_failed` response.
//!
//! This module never spawns, signals, reaps or otherwise manages process
//! lifetime. The caller MUST already own the unreaped child session and MUST
//! clean it up on every failure path. A helper `ready` message is *not*, by
//! itself, standalone proof of ownership: [`PreparedListener::complete`]
//! requires the caller's [`OwnedSession`] for the unreaped child and re-derives
//! the expected PID from its leader.

use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::unistd::{Uid, getresuid};
use serde::{Deserialize, Serialize};

use crate::session_process::OwnedSession;

const HELPER_PATH: &str = "/usr/libexec/mender-connect-session-helper";
const RUN_DIR: &str = "/run";
const MAX_FRAME: usize = 16 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_USERNAME: usize = 256;
const MAX_SHELL: usize = 4096;
const MAX_ARGUMENTS: usize = 64;
const MAX_ARGUMENT_TOTAL: usize = 8192;
const MAX_TERM: usize = 64;
const MAX_CHALLENGE: usize = 256;
const MAX_SUPPLEMENTARY_GROUPS: usize = 1024;
const MAX_KERNEL_GROUPS: usize = 1024;
const MAX_KERNEL_STATUS: usize = 64 * 1024;
const NONCE_BYTES: usize = 16;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecRequest {
    target_user: String,
    shell: String,
    arguments: Vec<String>,
    term: Option<String>,
    challenge: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityProof {
    effective_empty: bool,
    permitted_empty: bool,
    inheritable_empty: bool,
    ambient_empty: bool,
    keep_caps_clear: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadyResponse {
    status: String,
    challenge: Option<String>,
    pid: i32,
    sid: i32,
    pgid: i32,
    uid: u32,
    gid: u32,
    groups: Vec<u32>,
    capabilities: CapabilityProof,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecFailureResponse {
    status: String,
    error: String,
}

/// Credential target and shell request supplied by the caller.
#[derive(Debug, Clone)]
pub struct TargetRequest {
    pub user: String,
    pub uid: u32,
    pub gid: u32,
    pub shell: String,
    pub arguments: Vec<String>,
    pub term: Option<String>,
}

/// RAII owner of a fresh private directory under `/run`.
#[derive(Debug)]
struct PrivateDir {
    path: PathBuf,
}

impl PrivateDir {
    fn create() -> Result<Self> {
        verify_run_dir(Path::new(RUN_DIR))?;
        let name = format!("mender-connect-session-{}", read_nonce_hex(8)?);
        let path = Path::new(RUN_DIR).join(name);
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .context("failed to create session directory")?;
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(error) => {
                let _ = fs::remove_dir_all(&path);
                return Err(anyhow::Error::new(error).context("session directory metadata"));
            }
        };
        let facts = facts_from(&meta);
        let ok = !facts.is_symlink && facts.is_dir && facts.uid == 0 && facts.mode & 0o777 == 0o700;
        if !ok {
            let _ = fs::remove_dir_all(&path);
            bail!("session directory verification failed");
        }
        Ok(Self { path })
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// A root-prepared, RAII-scoped listener awaiting the helper handshake.
#[derive(Debug)]
pub struct PreparedListener {
    listener: UnixListener,
    _dir: PrivateDir,
    socket_path: PathBuf,
    expected_parent_pid: i32,
    nonce: String,
}

/// Verify ROOT (real/effective/saved) credentials.
fn require_root_credentials() -> Result<()> {
    let credentials = getresuid().context("root credential check failed")?;
    let root = Uid::from_raw(0);
    if credentials.real != root || credentials.effective != root || credentials.saved != root {
        bail!("root credentials required");
    }
    Ok(())
}

/// Prepare the private listener and validate the trusted helper executable.
///
/// Returns the socket path and expected parent PID the caller must pass to the
/// PTY `CommandBuilder`. Must be called *before* spawning the child.
pub fn prepare() -> Result<PreparedListener> {
    require_root_credentials()?;
    verify_trusted_command(Path::new(HELPER_PATH))?;
    let dir = PrivateDir::create()?;
    let socket_path = dir.path.join("session.sock");
    let listener = bind_listener(&socket_path)?;
    let expected_parent_pid = i32::try_from(std::process::id()).context("own pid out of range")?;
    let nonce = read_nonce_hex(NONCE_BYTES)?;
    Ok(PreparedListener {
        listener,
        _dir: dir,
        socket_path,
        expected_parent_pid,
        nonce,
    })
}

impl PreparedListener {
    /// Filesystem path of the private helper socket.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// PID the helper will verify as its parent (`getppid`).
    pub fn expected_parent_pid(&self) -> i32 {
        self.expected_parent_pid
    }

    /// Absolute path to the trusted helper executable.
    ///
    /// The trusted `CommandBuilder` uses this fixed path; there is no
    /// caller-supplied execution path, environment override, or arbitrary
    /// executable selection.
    pub fn helper_path(&self) -> &'static Path {
        Path::new(HELPER_PATH)
    }

    /// Complete the authenticated handshake for an owned, unreaped child.
    ///
    /// The caller MUST already own `session` (the [`OwnedSession`] whose leader
    /// is the unreaped helper child) and MUST clean up the child session on
    /// every failure path. The leader identity (PID + starttime + session) is
    /// re-verified before the handshake and again after the readiness/kernel
    /// proof, anchoring the captured starttime. This module neither spawns nor
    /// reaps the child.
    pub fn complete(self, session: &OwnedSession, target: &TargetRequest) -> Result<()> {
        let PreparedListener {
            listener,
            _dir,
            socket_path: _socket_path,
            expected_parent_pid: _expected_parent_pid,
            nonce,
        } = self;
        let leader = u32::try_from(session.leader()).context("child pid out of range")?;
        let child_pid = validate_expected_child_pid(leader)?;
        session
            .verify_leader_identity()
            .context("child session leader identity check")?;
        let payload = build_request(target, &nonce)?;
        let deadline = Instant::now() + IO_TIMEOUT;

        let stream = accept_peer(&listener, deadline)?;
        stream
            .set_nonblocking(false)
            .context("failed to restore blocking mode")?;
        verify_peer(&stream, child_pid)?;

        let mut io = DeadlineStream::new(stream, deadline);
        write_frame(&mut io, &payload).context("request send failure")?;
        let frame = read_frame_exact(&mut io)
            .context("ready read failure")?
            .ok_or_else(|| anyhow::anyhow!("helper closed before ready"))?;
        let ready: ReadyResponse = decode_bounded(&frame)?;
        validate_ready(&ready, child_pid, target, &nonce)?;
        verify_kernel_state(child_pid, target, &ready)?;
        session
            .verify_leader_identity()
            .context("child session leader identity recheck")?;

        match read_frame_exact(&mut io).context("post-ready read failure")? {
            None => Ok(()),
            Some(frame) => {
                let failure: ExecFailureResponse = decode_bounded(&frame)?;
                if failure.status == "exec-failed" || failure.status == "exec_failed" {
                    bail!("helper reported exec failure: {}", failure.error);
                }
                bail!("unexpected helper response after ready");
            }
        }
    }
}

fn validate_expected_child_pid(expected: u32) -> Result<i32> {
    if expected <= 1 {
        bail!("invalid expected child pid");
    }
    if expected == std::process::id() {
        bail!("expected child pid is our own pid");
    }
    i32::try_from(expected).context("expected child pid out of range")
}

fn accept_peer(listener: &UnixListener, deadline: Instant) -> Result<UnixStream> {
    loop {
        match listener.accept() {
            Ok((stream, _addr)) => return Ok(stream),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait_readable(listener, deadline)?;
            }
            Err(error) => return Err(anyhow::Error::new(error).context("accept failed")),
        }
    }
}

fn wait_readable(listener: &UnixListener, deadline: Instant) -> Result<()> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        bail!("accept deadline exceeded");
    }
    let clamped = remaining.as_millis().min(u128::from(u16::MAX));
    let millis = u16::try_from(clamped).map_err(|_| anyhow::anyhow!("poll timeout conversion"))?;
    if millis == 0 {
        bail!("accept deadline exceeded");
    }
    let mut fds = [PollFd::new(listener.as_fd(), PollFlags::POLLIN)];
    let ready = poll(&mut fds, PollTimeout::from(millis)).context("listener poll failed")?;
    if ready == 0 {
        bail!("accept deadline exceeded");
    }
    for descriptor in fds.iter() {
        if let Some(events) = descriptor.revents()
            && events.intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL)
        {
            bail!("listener poll error");
        }
    }
    Ok(())
}

fn verify_peer(stream: &UnixStream, expected_child_pid: i32) -> Result<()> {
    let credentials = getsockopt(stream, PeerCredentials).context("peer credential read")?;
    if credentials.uid() != 0 {
        bail!("untrusted helper peer uid");
    }
    if credentials.pid() != expected_child_pid {
        bail!("helper peer pid mismatch");
    }
    Ok(())
}

fn bind_listener(path: &Path) -> Result<UnixListener> {
    let listener = UnixListener::bind(path).context("failed to bind helper listener")?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .context("failed to set socket permissions")?;
    listener
        .set_nonblocking(true)
        .context("failed to set listener nonblocking")?;
    set_fd_cloexec(listener.as_raw_fd())?;
    let meta = fs::symlink_metadata(path).context("socket metadata read")?;
    if meta.file_type().is_symlink() {
        bail!("socket path became a symlink");
    }
    if meta.uid() != 0 || meta.mode() & 0o777 != 0o600 {
        bail!("socket permissions verification failed");
    }
    Ok(listener)
}

fn set_fd_cloexec(fd: RawFd) -> Result<()> {
    let flags = fcntl(fd, FcntlArg::F_GETFD).context("fd flag read failure")?;
    let flags = FdFlag::from_bits_retain(flags);
    if !flags.contains(FdFlag::FD_CLOEXEC) {
        fcntl(fd, FcntlArg::F_SETFD(flags | FdFlag::FD_CLOEXEC)).context("fd cloexec failure")?;
    }
    Ok(())
}

/// Trusted-file facts usable without touching the real filesystem.
#[derive(Debug, Clone, Copy)]
struct FileFacts {
    is_symlink: bool,
    is_dir: bool,
    is_file: bool,
    uid: u32,
    mode: u32,
}

fn facts_from(meta: &fs::Metadata) -> FileFacts {
    let ft = meta.file_type();
    FileFacts {
        is_symlink: ft.is_symlink(),
        is_dir: ft.is_dir(),
        is_file: ft.is_file(),
        uid: meta.uid(),
        mode: meta.mode(),
    }
}

fn check_facts(is_last: bool, facts: &FileFacts) -> Result<()> {
    if facts.is_symlink {
        bail!("trusted path component is a symlink");
    }
    if facts.uid != 0 {
        bail!("trusted path component is not root-owned");
    }
    if facts.mode & 0o022 != 0 {
        bail!("trusted path component is group/other writable");
    }
    if is_last {
        if !facts.is_file {
            bail!("trusted helper is not a regular file");
        }
        if facts.mode & 0o6000 != 0 {
            bail!("trusted helper must not be setuid/setgid");
        }
        if facts.mode & 0o111 == 0 {
            bail!("trusted helper is not executable");
        }
    } else if !facts.is_dir {
        bail!("trusted path component is not a directory");
    }
    Ok(())
}

fn verify_trusted_command(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("helper path must be absolute");
    }
    let components: Vec<Component> = path.components().collect();
    let last_index = components
        .len()
        .checked_sub(1)
        .ok_or_else(|| anyhow::anyhow!("empty helper path"))?;
    let mut current = PathBuf::new();
    for (index, component) in components.iter().enumerate() {
        match component {
            Component::RootDir => current.push("/"),
            Component::Normal(name) => {
                current.push(name);
                let meta = fs::symlink_metadata(&current)
                    .context("helper path component metadata failure")?;
                check_facts(index == last_index, &facts_from(&meta))?;
            }
            _ => bail!("invalid helper path component"),
        }
    }
    Ok(())
}

fn verify_run_dir(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path).context("run dir metadata failure")?;
    let facts = facts_from(&meta);
    if facts.is_symlink || !facts.is_dir {
        bail!("run dir is not a directory");
    }
    if facts.uid != 0 {
        bail!("run dir is not root-owned");
    }
    if facts.mode & 0o022 != 0 {
        bail!("run dir is group/other writable");
    }
    Ok(())
}

fn read_nonce_hex(byte_len: usize) -> Result<String> {
    let mut buffer = vec![0u8; byte_len];
    let mut file = fs::File::open("/dev/urandom").context("urandom open failure")?;
    file.read_exact(buffer.as_mut_slice())
        .context("urandom read failure")?;
    Ok(hex_encode(&buffer))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(hex_digit(*byte >> 4));
        out.push(hex_digit(*byte & 0x0f));
    }
    out
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0'.saturating_add(value)),
        _ => char::from(b'a'.saturating_add(value.saturating_sub(10))),
    }
}

fn build_request(target: &TargetRequest, nonce: &str) -> Result<Vec<u8>> {
    validate_target_user(&target.user)?;
    if target.uid == 0 || target.uid == u32::MAX {
        bail!("invalid target uid");
    }
    if target.gid == u32::MAX {
        bail!("invalid target gid");
    }
    validate_shell(&target.shell)?;
    validate_arguments(&target.arguments)?;
    let term = match &target.term {
        Some(value) => {
            validate_term(value)?;
            Some(value.clone())
        }
        None => None,
    };
    if nonce.is_empty() || nonce.len() > MAX_CHALLENGE {
        bail!("invalid request nonce");
    }
    let request = ExecRequest {
        target_user: target.user.clone(),
        shell: target.shell.clone(),
        arguments: target.arguments.clone(),
        term,
        challenge: Some(nonce.to_string()),
    };
    let payload = serde_json::to_vec(&request).context("request encode failure")?;
    if payload.len() > MAX_FRAME {
        bail!("request frame too large");
    }
    Ok(payload)
}

fn validate_target_user(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_USERNAME || value.contains('\0') {
        bail!("invalid target user");
    }
    Ok(())
}

fn validate_shell(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_SHELL
        || value.contains('\0')
        || !Path::new(value).is_absolute()
    {
        bail!("invalid shell");
    }
    Ok(())
}

fn validate_term(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_TERM {
        bail!("invalid term");
    }
    let valid = value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+'));
    if !valid {
        bail!("invalid term");
    }
    Ok(())
}

fn validate_arguments(args: &[String]) -> Result<()> {
    if args.len() > MAX_ARGUMENTS {
        bail!("too many arguments");
    }
    let mut total = 0usize;
    for arg in args {
        if arg.contains('\0') {
            bail!("invalid argument");
        }
        total = total
            .checked_add(arg.len())
            .ok_or_else(|| anyhow::anyhow!("argument size overflow"))?;
        if total > MAX_ARGUMENT_TOTAL {
            bail!("arguments too large");
        }
    }
    Ok(())
}

fn validate_ready(
    ready: &ReadyResponse,
    child_pid: i32,
    target: &TargetRequest,
    nonce: &str,
) -> Result<()> {
    if ready.status != "ready" {
        bail!("helper did not report ready");
    }
    if ready.challenge.as_deref() != Some(nonce) {
        bail!("helper challenge mismatch");
    }
    if ready.pid != child_pid {
        bail!("helper pid mismatch");
    }
    if ready.sid != child_pid {
        bail!("helper sid mismatch");
    }
    if ready.pgid != child_pid {
        bail!("helper pgid mismatch");
    }
    if ready.uid == 0 || ready.uid == u32::MAX {
        bail!("invalid helper uid proof");
    }
    if ready.gid == u32::MAX {
        bail!("invalid helper gid proof");
    }
    if ready.uid != target.uid {
        bail!("helper uid mismatch");
    }
    if ready.gid != target.gid {
        bail!("helper gid mismatch");
    }
    if ready.groups.len() > MAX_SUPPLEMENTARY_GROUPS {
        bail!("too many helper groups");
    }
    if ready.groups.contains(&u32::MAX) {
        bail!("invalid helper group");
    }
    let mut groups = ready.groups.clone();
    groups.sort_unstable();
    groups.dedup();
    if !groups.contains(&ready.gid) {
        bail!("helper groups missing primary gid");
    }
    let caps = &ready.capabilities;
    if !(caps.effective_empty
        && caps.permitted_empty
        && caps.inheritable_empty
        && caps.ambient_empty
        && caps.keep_caps_clear)
    {
        bail!("helper capability proof is incomplete");
    }
    Ok(())
}

fn verify_kernel_state(
    child_pid: i32,
    target: &TargetRequest,
    ready: &ReadyResponse,
) -> Result<()> {
    let stat = crate::session_process::read_stat(child_pid).context("child proc stat read")?;
    if stat.session != child_pid {
        bail!("child is not a session leader");
    }
    if stat.pgrp != child_pid {
        bail!("child is not a process group leader");
    }
    let file =
        fs::File::open(format!("/proc/{child_pid}/status")).context("child proc status open")?;
    let limit = u64::try_from(MAX_KERNEL_STATUS.saturating_add(1))
        .context("child proc status limit conversion")?;
    let mut limited = file.take(limit);
    let mut raw = Vec::new();
    limited
        .read_to_end(&mut raw)
        .context("child proc status read")?;
    let kernel_groups = parse_kernel_status(&raw, target)?;
    compare_groups(&kernel_groups, &ready.groups)?;
    Ok(())
}

/// Pure, bounded `/proc/<pid>/status` parser.
///
/// Requires exactly one `Uid`, `Gid`, `Groups`, `CapEff`, `CapPrm`, `CapInh`
/// and `CapAmb` field. The `Uid`/`Gid` fields must carry exactly four values,
/// all equal to the target UID/GID. Each capability field must contain exactly
/// one zero hexadecimal token. Returns the normalized (order-independent)
/// supplementary group set for comparison against the readiness proof.
fn parse_kernel_status(raw: &[u8], target: &TargetRequest) -> Result<Vec<u32>> {
    if raw.len() > MAX_KERNEL_STATUS {
        bail!("child proc status too large");
    }
    let text = std::str::from_utf8(raw).context("child proc status encoding")?;
    let mut uid_count = 0u32;
    let mut gid_count = 0u32;
    let mut cap_eff = 0u32;
    let mut cap_prm = 0u32;
    let mut cap_inh = 0u32;
    let mut cap_amb = 0u32;
    let mut groups_line: Option<&str> = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            uid_count = uid_count
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("uid line count overflow"))?;
            require_four_all(rest, target.uid, "uid")?;
        } else if let Some(rest) = line.strip_prefix("Gid:") {
            gid_count = gid_count
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("gid line count overflow"))?;
            require_four_all(rest, target.gid, "gid")?;
        } else if let Some(rest) = line.strip_prefix("Groups:") {
            if groups_line.is_some() {
                bail!("duplicate groups field");
            }
            groups_line = Some(rest);
        } else if let Some(rest) = line.strip_prefix("CapEff:") {
            cap_eff = cap_eff
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("capeff count overflow"))?;
            cap_zero(rest)?;
        } else if let Some(rest) = line.strip_prefix("CapPrm:") {
            cap_prm = cap_prm
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("capprm count overflow"))?;
            cap_zero(rest)?;
        } else if let Some(rest) = line.strip_prefix("CapInh:") {
            cap_inh = cap_inh
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("capinh count overflow"))?;
            cap_zero(rest)?;
        } else if let Some(rest) = line.strip_prefix("CapAmb:") {
            cap_amb = cap_amb
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("capamb count overflow"))?;
            cap_zero(rest)?;
        }
    }
    if uid_count != 1 {
        bail!("child proc status must contain exactly one Uid line");
    }
    if gid_count != 1 {
        bail!("child proc status must contain exactly one Gid line");
    }
    if cap_eff != 1 || cap_prm != 1 || cap_inh != 1 || cap_amb != 1 {
        bail!("child proc status must contain exactly one of each capability line");
    }
    let groups_rest =
        groups_line.ok_or_else(|| anyhow::anyhow!("child proc status missing Groups line"))?;
    parse_kernel_groups(groups_rest)
}

fn require_four_all(rest: &str, expected: u32, label: &str) -> Result<()> {
    let mut count = 0usize;
    for token in rest.split_whitespace() {
        let value: u32 = token
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid {label} field"))?;
        if value != expected {
            bail!("kernel {label} mismatch");
        }
        count = count
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("{label} count overflow"))?;
    }
    if count != 4 {
        bail!("kernel {label} must have exactly four values");
    }
    Ok(())
}

fn parse_kernel_groups(rest: &str) -> Result<Vec<u32>> {
    let mut groups = Vec::new();
    for token in rest.split_whitespace() {
        if groups.len() >= MAX_KERNEL_GROUPS {
            bail!("too many kernel groups");
        }
        let value: u32 = token
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid kernel group"))?;
        if value == u32::MAX {
            bail!("invalid kernel group sentinel");
        }
        groups.push(value);
    }
    Ok(groups)
}

fn compare_groups(kernel: &[u32], ready: &[u32]) -> Result<()> {
    let mut kernel = kernel.to_vec();
    kernel.sort_unstable();
    kernel.dedup();
    let mut ready = ready.to_vec();
    ready.sort_unstable();
    ready.dedup();
    if kernel != ready {
        bail!("kernel supplementary groups mismatch");
    }
    Ok(())
}

fn cap_zero(rest: &str) -> Result<()> {
    let mut tokens = rest.split_whitespace();
    let Some(token) = tokens.next() else {
        bail!("missing capability value");
    };
    if tokens.next().is_some() {
        bail!("trailing tokens in capability field");
    }
    let value =
        u64::from_str_radix(token, 16).map_err(|_| anyhow::anyhow!("invalid capability value"))?;
    if value != 0 {
        bail!("kernel capability set is not empty");
    }
    Ok(())
}

struct DeadlineStream {
    stream: UnixStream,
    deadline: Instant,
}

impl DeadlineStream {
    fn new(stream: UnixStream, deadline: Instant) -> Self {
        Self { stream, deadline }
    }

    fn remaining(&self) -> io::Result<Duration> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "io deadline exceeded",
            ))
        } else {
            Ok(remaining)
        }
    }

    fn normalize(error: io::Error) -> io::Error {
        match error.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                io::Error::new(io::ErrorKind::TimedOut, "io deadline exceeded")
            }
            _ => error,
        }
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.remaining()?;
        self.stream.set_read_timeout(Some(remaining))?;
        self.stream.read(buf).map_err(Self::normalize)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let remaining = self.remaining()?;
        self.stream.set_write_timeout(Some(remaining))?;
        self.stream.write(buf).map_err(Self::normalize)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0usize;
    while filled < buf.len() {
        let Some(rest) = buf.get_mut(filled..) else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "buffer range"));
        };
        match reader.read(rest) {
            Ok(0) => {
                if filled == 0 {
                    return Ok(false);
                }
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short frame"));
            }
            Ok(read) => {
                filled = filled
                    .checked_add(read)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "length overflow"))?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(true)
}

fn read_frame_exact<R: Read>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut length_bytes = [0u8; 4];
    if !read_exact_or_eof(reader, &mut length_bytes)? {
        return Ok(None);
    }
    let length_u32 = u32::from_be_bytes(length_bytes);
    let length = usize::try_from(length_u32)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame length overflow"))?;
    if length > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut payload = vec![0u8; length];
    reader.read_exact(payload.as_mut_slice())?;
    Ok(Some(payload))
}

fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame length overflow"))?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(payload)?;
    writer.flush()
}

fn decode_bounded<'a, T: Deserialize<'a>>(frame: &'a [u8]) -> Result<T> {
    serde_json::from_slice(frame).context("malformed helper frame")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn ready_fixture() -> ReadyResponse {
        ReadyResponse {
            status: String::from("ready"),
            challenge: Some(String::from("abc")),
            pid: 4242,
            sid: 4242,
            pgid: 4242,
            uid: 1000,
            gid: 1000,
            groups: vec![1000, 1001],
            capabilities: CapabilityProof {
                effective_empty: true,
                permitted_empty: true,
                inheritable_empty: true,
                ambient_empty: true,
                keep_caps_clear: true,
            },
        }
    }

    fn target_fixture() -> TargetRequest {
        TargetRequest {
            user: String::from("alice"),
            uid: 1000,
            gid: 1000,
            shell: String::from("/bin/sh"),
            arguments: vec![String::from("-c")],
            term: None,
        }
    }

    #[test]
    fn trusted_facts_reject_bad_components() {
        let root = FileFacts {
            is_symlink: false,
            is_dir: true,
            is_file: false,
            uid: 0,
            mode: 0o755,
        };
        assert!(check_facts(false, &root).is_ok());
        assert!(
            check_facts(
                false,
                &FileFacts {
                    is_symlink: true,
                    ..root
                }
            )
            .is_err()
        );
        assert!(check_facts(false, &FileFacts { uid: 1000, ..root }).is_err());
        assert!(
            check_facts(
                false,
                &FileFacts {
                    mode: 0o777,
                    ..root
                }
            )
            .is_err()
        );
        assert!(
            check_facts(
                false,
                &FileFacts {
                    is_dir: false,
                    ..root
                }
            )
            .is_err()
        );

        let leaf = FileFacts {
            is_symlink: false,
            is_dir: false,
            is_file: true,
            uid: 0,
            mode: 0o755,
        };
        assert!(check_facts(true, &leaf).is_ok());
        assert!(
            check_facts(
                true,
                &FileFacts {
                    mode: 0o4755,
                    ..leaf
                }
            )
            .is_err()
        );
        assert!(
            check_facts(
                true,
                &FileFacts {
                    mode: 0o644,
                    ..leaf
                }
            )
            .is_err()
        );
        assert!(
            check_facts(
                true,
                &FileFacts {
                    is_file: false,
                    is_dir: true,
                    ..leaf
                }
            )
            .is_err()
        );
    }

    #[test]
    fn trusted_command_rejects_relative_path() {
        assert!(verify_trusted_command(Path::new("relative/helper")).is_err());
    }

    #[test]
    fn expected_child_pid_is_typed_and_bounded() {
        assert!(validate_expected_child_pid(0).is_err());
        assert!(validate_expected_child_pid(1).is_err());
        assert!(validate_expected_child_pid(std::process::id()).is_err());
        if std::process::id() != 424242 {
            assert!(validate_expected_child_pid(424242).is_ok());
        }
    }

    #[test]
    fn ready_validation_accepts_consistent_proof() {
        let target = target_fixture();
        assert!(validate_ready(&ready_fixture(), 4242, &target, "abc").is_ok());
    }

    #[test]
    fn ready_validation_rejects_mismatches() {
        let target = target_fixture();
        assert!(validate_ready(&ready_fixture(), 4242, &target, "wrong").is_err());
        assert!(validate_ready(&ready_fixture(), 4343, &target, "abc").is_err());

        let mut bad_uid = ready_fixture();
        bad_uid.uid = 0;
        assert!(validate_ready(&bad_uid, 4242, &target, "abc").is_err());

        let mut bad_gid = ready_fixture();
        bad_gid.gid = 2000;
        assert!(validate_ready(&bad_gid, 4242, &target, "abc").is_err());

        let mut missing_primary = ready_fixture();
        missing_primary.groups = vec![1001];
        assert!(validate_ready(&missing_primary, 4242, &target, "abc").is_err());

        let mut sid = ready_fixture();
        sid.sid = 999;
        assert!(validate_ready(&sid, 4242, &target, "abc").is_err());

        let mut caps = ready_fixture();
        caps.capabilities.ambient_empty = false;
        assert!(validate_ready(&caps, 4242, &target, "abc").is_err());
    }

    #[test]
    fn request_validation_bounds_fields() {
        let ok = target_fixture();
        assert!(build_request(&ok, "nonce").is_ok());

        let mut bad_user = target_fixture();
        bad_user.user = String::new();
        assert!(build_request(&bad_user, "nonce").is_err());

        let mut bad_shell = target_fixture();
        bad_shell.shell = String::from("sh");
        assert!(build_request(&bad_shell, "nonce").is_err());

        let mut bad_term = target_fixture();
        bad_term.term = Some(String::from("xterm;rm"));
        assert!(build_request(&bad_term, "nonce").is_err());

        let mut too_many = target_fixture();
        too_many.arguments = vec![String::new(); MAX_ARGUMENTS + 1];
        assert!(build_request(&too_many, "nonce").is_err());

        assert!(build_request(&ok, "").is_err());
    }

    #[test]
    fn frame_reader_handles_eof_oversize_and_truncation() {
        let mut empty = Cursor::new(Vec::new());
        assert!(matches!(read_frame_exact(&mut empty), Ok(None)));

        let oversize_len: u32 = 16_385;
        let mut oversize = Cursor::new(oversize_len.to_be_bytes().to_vec());
        assert!(read_frame_exact(&mut oversize).is_err());

        let mut truncated = Cursor::new({
            let mut v = 8u32.to_be_bytes().to_vec();
            v.extend_from_slice(b"abcd");
            v
        });
        assert!(read_frame_exact(&mut truncated).is_err());
    }

    #[test]
    fn frame_write_roundtrip_and_bound() {
        let mut buffer: Vec<u8> = Vec::new();
        write_frame(&mut buffer, b"payload").expect("encode");
        let mut reader = Cursor::new(buffer);
        let frame = read_frame_exact(&mut reader).expect("read").expect("some");
        assert_eq!(frame, b"payload".to_vec());

        let mut big: Vec<u8> = Vec::new();
        let oversize = vec![0u8; MAX_FRAME + 1];
        assert!(write_frame(&mut big, &oversize).is_err());
    }

    #[test]
    fn decoder_rejects_unknown_trailing_and_malformed() {
        let unknown: Result<ExecFailureResponse> =
            decode_bounded(br#"{"status":"x","error":"y","extra":true}"#.as_slice());
        assert!(unknown.is_err());

        let ok: Result<ExecFailureResponse> =
            decode_bounded(br#"{"status":"exec-failed","error":"boom"}"#.as_slice());
        match ok {
            Ok(value) => assert_eq!(value.status, "exec-failed"),
            Err(_) => panic!("expected decode success"),
        }

        let trailing: Result<ExecFailureResponse> =
            decode_bounded(br#"{"status":"exec-failed","error":"boom"} x"#.as_slice());
        assert!(trailing.is_err());

        let malformed: Result<ExecFailureResponse> = decode_bounded(b"not json".as_slice());
        assert!(malformed.is_err());
    }

    #[test]
    fn deadline_stream_expires_despite_slow_drip() {
        let (reader, writer) = UnixStream::pair().expect("pair");
        let deadline = Instant::now() + Duration::from_millis(200);
        let mut stream = DeadlineStream::new(reader, deadline);

        // Keep the writer open and keep making progress well past the deadline
        // (64 * 20ms = 1280ms). The writer deliberately never closes the peer
        // before the deadline, so a clean EOF can only be observed if the peer
        // is gone -- it must never be mistaken for deadline expiry.
        let sender = std::thread::spawn(move || {
            let mut writer = writer;
            let _ = writer.set_write_timeout(Some(Duration::from_secs(1)));
            for _ in 0..64 {
                std::thread::sleep(Duration::from_millis(20));
                if writer.write_all(b"x").is_err() {
                    break;
                }
            }
        });

        let mut buffer = [0u8; 64];
        let mut total = 0usize;
        let started = Instant::now();
        let outcome = loop {
            match stream.read(&mut buffer) {
                Ok(0) => break None,
                Ok(read) => {
                    total = total.checked_add(read).expect("byte count overflow");
                    if total >= 64 {
                        break None;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => break Some(error),
            }
        };
        let elapsed = started.elapsed();

        // Drop the reader BEFORE joining the writer so the peer observes a
        // closed connection and finishes promptly instead of pacing out the
        // full drip (avoiding an unbounded ~1.28s join).
        drop(stream);
        let _ = sender.join();

        assert!(total > 0, "expected some progress before the deadline");
        let error = outcome.expect("deadline must terminate the slow drip, not a clean EOF");
        assert_eq!(
            error.kind(),
            io::ErrorKind::TimedOut,
            "deadline expiry must surface as TimedOut, never a clean EOF"
        );
        assert!(total < 64, "deadline must cut off the slow drip");
        assert!(
            elapsed < Duration::from_secs(1),
            "deadline must not be reset per read (elapsed {elapsed:?})"
        );
    }

    fn kernel_status_fixture() -> Vec<u8> {
        b"Name:\thelper\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nGroups:\t1000 1001\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapAmb:\t0000000000000000\n".to_vec()
    }

    #[test]
    fn kernel_status_accepts_valid_profile() {
        let target = target_fixture();
        let groups = parse_kernel_status(&kernel_status_fixture(), &target).expect("valid status");
        assert_eq!(groups, vec![1000, 1001]);
    }

    #[test]
    fn kernel_status_rejects_missing_capability() {
        let target = target_fixture();
        let stripped = String::from_utf8(kernel_status_fixture())
            .expect("utf8")
            .lines()
            .filter(|line| !line.starts_with("CapAmb:"))
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes();
        assert!(parse_kernel_status(&stripped, &target).is_err());
    }

    #[test]
    fn kernel_status_rejects_duplicate_fields() {
        let target = target_fixture();
        let mut dup_uid = kernel_status_fixture();
        dup_uid.extend_from_slice(b"Uid:\t1000\t1000\t1000\t1000\n");
        assert!(parse_kernel_status(&dup_uid, &target).is_err());

        let mut dup_cap = kernel_status_fixture();
        dup_cap.extend_from_slice(b"CapEff:\t0000000000000000\n");
        assert!(parse_kernel_status(&dup_cap, &target).is_err());
    }

    #[test]
    fn kernel_status_rejects_short_ids() {
        let target = target_fixture();
        let short = b"Uid:\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nGroups:\t1000\nCapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapAmb:\t0\n".to_vec();
        assert!(parse_kernel_status(&short, &target).is_err());
    }

    #[test]
    fn kernel_status_rejects_malformed_groups() {
        let target = target_fixture();
        let bad = String::from_utf8(kernel_status_fixture())
            .expect("utf8")
            .replace("Groups:\t1000 1001", "Groups:\t1000 notanumber")
            .into_bytes();
        assert!(parse_kernel_status(&bad, &target).is_err());
    }

    #[test]
    fn kernel_status_rejects_bad_capabilities() {
        let target = target_fixture();
        let nonzero = String::from_utf8(kernel_status_fixture())
            .expect("utf8")
            .replace("CapEff:\t0000000000000000", "CapEff:\t0000000000000001")
            .into_bytes();
        assert!(parse_kernel_status(&nonzero, &target).is_err());

        let trailing = String::from_utf8(kernel_status_fixture())
            .expect("utf8")
            .replace("CapAmb:\t0000000000000000", "CapAmb:\t0000000000000000 1")
            .into_bytes();
        assert!(parse_kernel_status(&trailing, &target).is_err());
    }

    #[test]
    fn kernel_status_rejects_oversize_input() {
        let target = target_fixture();
        let raw = vec![b'A'; MAX_KERNEL_STATUS + 1];
        assert!(parse_kernel_status(&raw, &target).is_err());
    }
}
