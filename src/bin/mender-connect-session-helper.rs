//! Isolated prototype credential-drop/exec helper.
//!
//! This is an ordinary Linux helper binary and must never be installed setuid.
//! It accepts one authenticated local parent connection, resolves a target
//! account through NSS, performs a verified credential transition, sends a
//! bounded readiness proof, and then replaces itself with the requested shell
//! without changing PID, SID or PGID.
//!
//! This is a credential transition helper, not a sandbox. The target user keeps
//! ordinary target-user execution semantics, including locally authorized
//! setuid tools. The capability bounding set and `no_new_privs` are deliberately
//! left as ordinary target-user execution requires.
//!
//! Ready-response plus CLOEXEC EOF is not proof that `exec` succeeded. The
//! parent must also inspect the status of the child it owns. If `exec` returns,
//! this helper sends a fixed failure response and exits unsuccessfully.

#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::as_conversions,
    clippy::indexing_slicing,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::dbg_macro
)]

use std::env;
use std::ffi::{CString, OsString};
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use nix::errno::Errno;
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::socket::{
    AddressFamily, SockFlag, SockType, UnixAddr, connect, getsockopt, socket,
    sockopt::{PeerCredentials, SocketError as SocketErrorOption},
};
use nix::unistd::{
    Gid, Uid, User, getgrouplist, getgroups, getpgrp, getppid, getresgid, getresuid, getsid,
    initgroups, setresgid, setresuid,
};
use rustix::thread::{
    CapabilitySet, CapabilitySets, capabilities, capability_is_in_ambient_set,
    clear_ambient_capability_set, get_keep_capabilities, set_capabilities, set_keep_capabilities,
};
use serde::{Deserialize, Serialize};

const MAX_FRAME: usize = 16 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_SOCKET_PATH: usize = 4096;
const MAX_USERNAME: usize = 256;
const MAX_SHELL: usize = 4096;
const MAX_ARGUMENTS: usize = 64;
const MAX_ARGUMENT_TOTAL: usize = 8192;
const MAX_TERM: usize = 64;
const MAX_CHALLENGE: usize = 256;
const MAX_SUPPLEMENTARY_GROUPS: usize = 1024;
const MAX_HOME: usize = 4096;
const MAX_SUPPORTED_CAPABILITY: u64 = 63;
const MAX_DESCRIPTOR_COUNT: usize = 4096;

#[derive(Debug)]
struct Args {
    socket: PathBuf,
    parent_pid: i32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecRequest {
    target_user: String,
    shell: String,
    arguments: Vec<String>,
    term: Option<String>,
    challenge: Option<String>,
}

#[derive(Debug)]
struct ValidatedRequest {
    target_user: String,
    shell: String,
    arguments: Vec<String>,
    term: String,
    challenge: Option<String>,
}

#[derive(Debug)]
struct CredentialPlan {
    uid: Uid,
    gid: Gid,
    groups: Vec<Gid>,
    home: PathBuf,
    user_cstr: CString,
}

#[derive(Debug, Serialize)]
struct CapabilityProof {
    effective_empty: bool,
    permitted_empty: bool,
    inheritable_empty: bool,
    ambient_empty: bool,
    keep_caps_clear: bool,
}

#[derive(Debug, Serialize)]
struct ReadyResponse {
    status: &'static str,
    challenge: Option<String>,
    pid: i32,
    sid: i32,
    pgid: i32,
    uid: u32,
    gid: u32,
    groups: Vec<u32>,
    capabilities: CapabilityProof,
}

#[derive(Debug, Serialize)]
struct ExecFailureResponse {
    status: &'static str,
    error: &'static str,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(2),
    }
}

fn run() -> Result<()> {
    // The root check is deliberately first: a non-root invocation must fail
    // before any socket, file or account access.
    require_root_credentials()?;

    let args = parse_args(env::args_os().skip(1))?;
    verify_expected_parent(args.parent_pid)?;
    verify_socket_directory(&args.socket)?;

    // The parent owns and listens on the private socket; this helper only
    // connects to it under a single bounded deadline.
    let stream = connect_stream(&args.socket).context("socket connect failure")?;

    set_fd_cloexec_required(raw_fd(&stream))?;
    verify_peer_credentials(&stream, args.parent_pid)?;

    // A single absolute deadline covers the whole framed request/response
    // exchange; partial reads and writes share it and can never extend it.
    let mut stream = DeadlineStream::new(stream, Instant::now() + IO_TIMEOUT);

    let frame = read_frame(&mut stream).context("request frame failure")?;
    let request: ExecRequest =
        serde_json::from_slice(&frame).map_err(|_| anyhow::anyhow!("malformed request"))?;
    let request = validate_request(request)?;

    // All account and supplementary-group NSS work is completed before the
    // credential transition and before the final descriptor sweep.
    let plan = resolve_credentials(&request.target_user)?;
    drop_privileges(&plan)?;

    // Choose the working directory only after the credential drop, keeping the
    // drop-before-chdir ordering. A genuinely missing home (NotFound) falls
    // back to `/`; permission and non-directory errors fail closed.
    let working_dir = select_working_directory(&plan.home)?;
    env::set_current_dir(&working_dir).context("target home directory failure")?;

    let ready = build_ready_response(&request, &plan)?;
    let ready_payload = serde_json::to_vec(&ready).context("ready response failure")?;
    if ready_payload.len() > MAX_FRAME {
        bail!("ready response is too large");
    }

    // Final descriptor sweep. It runs only after all NSS and capability work.
    // It relies on the trusted procfs mount namespace and on this process
    // having exactly one thread, both revalidated inside the sweep. The only
    // operations permitted after the sweep are bounded read-only self-checks
    // (a final single-thread confirmation) followed immediately by exec.
    ensure_all_descriptors_cloexec()?;

    write_frame(&mut stream, &ready_payload).context("ready response send failure")?;

    // Final single-thread confirmation immediately before exec. Only bounded
    // read-only self-checks run after the descriptor sweep.
    verify_single_threaded()?;

    let mut command = Command::new(&request.shell);
    command.args(&request.arguments);
    command.env_clear();
    command.env("HOME", &plan.home);
    command.env("USER", request.target_user.as_str());
    command.env("LOGNAME", request.target_user.as_str());
    command.env("TERM", request.term.as_str());
    command.env("PATH", "/usr/bin:/bin");
    command.env("LANG", "C.UTF-8");

    // CommandExt::exec preserves PID, SID and PGID. If it returns, no exec
    // happened; report a fixed failure and never claim success.
    let exec_error = command.exec();
    let failure = ExecFailureResponse {
        status: "exec-failed",
        error: "exec failed",
    };
    let failure_payload = serde_json::to_vec(&failure).context("failure response failure")?;
    match write_frame(&mut stream, &failure_payload) {
        Ok(()) => Err(anyhow::Error::new(exec_error).context("exec failed")),
        Err(send_error) => Err(anyhow::Error::new(send_error)
            .context("exec failed and failure response could not be sent")),
    }
}

fn require_root_credentials() -> Result<()> {
    let credentials = getresuid().context("real/effective/saved uid check failed")?;
    let root = Uid::from_raw(0);
    if credentials.real != root || credentials.effective != root || credentials.saved != root {
        bail!("root credentials required");
    }
    Ok(())
}

fn parse_args<I>(arguments: I) -> Result<Args>
where
    I: IntoIterator<Item = OsString>,
{
    let mut iter = arguments.into_iter();
    let mut socket: Option<PathBuf> = None;
    let mut parent_pid: Option<i32> = None;

    while let Some(argument) = iter.next() {
        let flag = argument
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("invalid argument"))?;
        match flag {
            "--socket" => {
                if socket.is_some() {
                    bail!("duplicate socket argument");
                }
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("missing socket argument"))?;
                let path = PathBuf::from(value);
                validate_socket_path(&path)?;
                socket = Some(path);
            }
            "--parent-pid" => {
                if parent_pid.is_some() {
                    bail!("duplicate parent pid argument");
                }
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("missing parent pid argument"))?;
                let text = value
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("invalid parent pid"))?;
                let parsed: i64 = text
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid parent pid"))?;
                let checked =
                    i32::try_from(parsed).map_err(|_| anyhow::anyhow!("invalid parent pid"))?;
                if checked <= 1 {
                    bail!("invalid parent pid");
                }
                parent_pid = Some(checked);
            }
            _ => bail!("unexpected argument"),
        }
    }

    let socket = socket.ok_or_else(|| anyhow::anyhow!("missing socket argument"))?;
    let parent_pid = parent_pid.ok_or_else(|| anyhow::anyhow!("missing parent pid argument"))?;
    Ok(Args { socket, parent_pid })
}

fn validate_socket_path(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("socket path must be absolute");
    }
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_SOCKET_PATH || bytes.contains(&0) {
        bail!("invalid socket path");
    }
    Ok(())
}

fn verify_expected_parent(expected: i32) -> Result<()> {
    let actual = getppid();
    if actual.as_raw() != expected || expected <= 1 {
        bail!("parent pid mismatch");
    }
    Ok(())
}

fn verify_socket_directory(socket: &Path) -> Result<()> {
    let parent = socket
        .parent()
        .ok_or_else(|| anyhow::anyhow!("socket has no parent directory"))?;
    if parent.as_os_str().is_empty() {
        bail!("socket has no parent directory");
    }
    let metadata = fs::symlink_metadata(parent).context("socket parent metadata failure")?;
    if metadata.file_type().is_symlink() {
        bail!("socket parent must not be a symlink");
    }
    if !metadata.is_dir() {
        bail!("socket parent is not a directory");
    }
    if metadata.uid() != 0 {
        bail!("socket parent is not root-owned");
    }
    if metadata.mode() & 0o777 != 0o700 {
        bail!("socket parent is not private");
    }
    Ok(())
}

fn verify_peer_credentials(stream: &UnixStream, expected_pid: i32) -> Result<()> {
    let credentials = getsockopt(stream, PeerCredentials).context("peer credential failure")?;
    if credentials.uid() != 0 || credentials.pid() != expected_pid {
        bail!("untrusted peer");
    }
    Ok(())
}

fn raw_fd<T: AsRawFd>(value: &T) -> RawFd {
    value.as_raw_fd()
}

// Nonblocking Unix connect bounded by one absolute deadline. No detached
// thread and no blocking accept are involved.
fn connect_stream(socket_path: &Path) -> Result<UnixStream> {
    let address = UnixAddr::new(socket_path).context("socket address failure")?;
    let owned = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .context("socket creation failure")?;

    match connect(owned.as_raw_fd(), &address) {
        Ok(()) => {}
        Err(Errno::EINPROGRESS) => wait_for_connect(&owned, &address)?,
        Err(error) => return Err(anyhow::Error::new(error).context("socket connect failure")),
    }

    verify_connect_error(&owned)?;

    let stream = UnixStream::from(owned);
    // Clearing nonblocking is required: `set_read_timeout` does not make a
    // nonblocking socket wait, so framed IO would fail instead of blocking.
    stream
        .set_nonblocking(false)
        .context("socket blocking mode failure")?;
    Ok(stream)
}

fn verify_connect_error(owned: &OwnedFd) -> Result<()> {
    let error: i32 =
        getsockopt(owned, SocketErrorOption).context("socket so_error read failure")?;
    if error != 0 {
        bail!("socket connect reported pending error");
    }
    Ok(())
}

fn wait_for_connect(owned: &OwnedFd, address: &UnixAddr) -> Result<()> {
    let deadline = Instant::now() + IO_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("socket connect deadline exceeded");
        }
        // `poll` accepts a bounded `PollTimeout` conversion rather than an
        // arbitrary `Duration`; clamp the remaining time to a checked, bounded
        // `u16` millisecond value (never exceeding the single 5s deadline).
        let remaining_millis = remaining.as_millis();
        let bounded_millis = std::cmp::min(remaining_millis, u128::from(u16::MAX));
        let millis = u16::try_from(bounded_millis)
            .map_err(|_| anyhow::anyhow!("socket connect poll timeout conversion failure"))?;
        if millis == 0 {
            bail!("socket connect deadline exceeded");
        }
        let mut descriptors = [PollFd::new(owned.as_fd(), PollFlags::POLLOUT)];
        let ready = poll(&mut descriptors, PollTimeout::from(millis))
            .context("socket connect poll failure")?;
        if ready == 0 {
            bail!("socket connect deadline exceeded");
        }
        let mut writable = false;
        for descriptor in descriptors.iter() {
            if let Some(events) = descriptor.revents() {
                if events.intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL)
                {
                    bail!("socket connect failed");
                }
                if events.contains(PollFlags::POLLOUT) {
                    writable = true;
                }
            }
        }
        if !writable {
            bail!("socket connect not writable");
        }
        match connect(owned.as_raw_fd(), address) {
            Ok(()) => return Ok(()),
            Err(Errno::EISCONN) => return Ok(()),
            Err(Errno::EALREADY) => continue,
            Err(error) => {
                return Err(anyhow::Error::new(error).context("socket connect failure"));
            }
        }
    }
}

fn read_frame<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut length_bytes = [0u8; 4];
    reader.read_exact(&mut length_bytes)?;
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
    reader.read_exact(&mut payload)?;
    Ok(payload)
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

// Deadline-aware adapter around the main `UnixStream`. A single absolute
// deadline governs the entire framed request/response exchange: before every
// underlying read or write the socket timeout is refreshed to the remaining
// duration, and once the deadline is exhausted every further call fails. Slow
// progress can never extend the deadline.
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
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "io deadline exceeded",
            ));
        }
        Ok(remaining)
    }

    fn normalize(error: io::Error) -> io::Error {
        match error.kind() {
            // Linux reports SO_RCVTIMEO/SO_SNDTIMEO expiry as either
            // WouldBlock or TimedOut; treat both as an exhausted deadline so
            // callers observe a single deterministic error kind.
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
        match self.stream.read(buf) {
            Ok(read) => Ok(read),
            Err(error) => Err(Self::normalize(error)),
        }
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let remaining = self.remaining()?;
        self.stream.set_write_timeout(Some(remaining))?;
        match self.stream.write(buf) {
            Ok(written) => Ok(written),
            Err(error) => Err(Self::normalize(error)),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

fn validate_request(request: ExecRequest) -> Result<ValidatedRequest> {
    validate_user_name(&request.target_user)?;
    validate_shell(&request.shell)?;

    if request.arguments.len() > MAX_ARGUMENTS {
        bail!("too many arguments");
    }
    let mut total = 0usize;
    for argument in &request.arguments {
        if argument.contains('\0') {
            bail!("invalid argument");
        }
        total = total
            .checked_add(argument.len())
            .ok_or_else(|| anyhow::anyhow!("argument size overflow"))?;
        if total > MAX_ARGUMENT_TOTAL {
            bail!("arguments too large");
        }
    }

    let term = request
        .term
        .unwrap_or_else(|| String::from("xterm-256color"));
    validate_term(&term)?;

    let challenge = match request.challenge {
        Some(value) => {
            if value.len() > MAX_CHALLENGE || value.contains('\0') {
                bail!("invalid challenge");
            }
            Some(value)
        }
        None => None,
    };

    Ok(ValidatedRequest {
        target_user: request.target_user,
        shell: request.shell,
        arguments: request.arguments,
        term,
        challenge,
    })
}

fn validate_user_name(value: &str) -> Result<()> {
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

fn resolve_credentials(target_user: &str) -> Result<CredentialPlan> {
    validate_user_name(target_user)?;
    let user_cstr =
        CString::new(target_user).map_err(|_| anyhow::anyhow!("invalid target user"))?;
    let user = User::from_name(target_user)
        .context("target account lookup failure")?
        .ok_or_else(|| anyhow::anyhow!("unknown target account"))?;

    let groups = getgrouplist(&user_cstr, user.gid).context("target group lookup failure")?;
    let group_ids: Vec<u32> = groups.iter().map(|group| group.as_raw()).collect();
    validate_credential_values(
        user.uid.as_raw(),
        user.gid.as_raw(),
        &group_ids,
        &user.dir,
        target_user,
    )?;

    Ok(CredentialPlan {
        uid: user.uid,
        gid: user.gid,
        groups,
        home: user.dir,
        user_cstr,
    })
}

fn validate_credential_values(
    uid: u32,
    gid: u32,
    groups: &[u32],
    home: &Path,
    username: &str,
) -> Result<()> {
    validate_user_name(username)?;
    if uid == 0 {
        bail!("root target needs no helper");
    }
    if uid == u32::MAX || gid == u32::MAX {
        bail!("invalid target credentials");
    }
    if groups.len() > MAX_SUPPLEMENTARY_GROUPS {
        bail!("too many supplementary groups");
    }
    if groups.contains(&u32::MAX) {
        bail!("invalid supplementary group");
    }
    if !home.is_absolute() {
        bail!("target home must be absolute");
    }
    let home_bytes = home.as_os_str().as_bytes();
    if home_bytes.is_empty() || home_bytes.len() > MAX_HOME || home_bytes.contains(&0) {
        bail!("invalid target home");
    }
    Ok(())
}

/// Outcome of inspecting the configured target home directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HomeStatus {
    Directory,
    Missing,
    NotDirectory,
    PermissionDenied,
    OtherError,
}

/// Inspect the home directory. Only a genuinely absent (`NotFound`) home is
/// treated as missing; every other inspection failure is classified so the
/// caller can fail closed.
fn home_status(home: &Path) -> HomeStatus {
    match fs::metadata(home) {
        Ok(metadata) => {
            if metadata.is_dir() {
                HomeStatus::Directory
            } else {
                HomeStatus::NotDirectory
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => HomeStatus::Missing,
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => HomeStatus::PermissionDenied,
        Err(_) => HomeStatus::OtherError,
    }
}

/// Pure working-directory decision. Only a missing home falls back to `/`; all
/// other failures propagate so the helper fails closed rather than executing in
/// an unexpected directory.
fn decide_working_directory(home: &Path, status: HomeStatus) -> Result<PathBuf> {
    match status {
        HomeStatus::Directory => Ok(home.to_path_buf()),
        HomeStatus::Missing => Ok(PathBuf::from("/")),
        HomeStatus::NotDirectory => bail!("target home is not a directory"),
        HomeStatus::PermissionDenied => bail!("target home permission denied"),
        HomeStatus::OtherError => bail!("target home directory check failure"),
    }
}

fn select_working_directory(home: &Path) -> Result<PathBuf> {
    decide_working_directory(home, home_status(home))
}

fn drop_privileges(plan: &CredentialPlan) -> Result<()> {
    set_keep_capabilities(false).context("keepcaps clear failure")?;
    clear_ambient_capability_set().context("ambient capability clear failure")?;

    initgroups(&plan.user_cstr, plan.gid).context("supplementary group transition failure")?;
    setresgid(plan.gid, plan.gid, plan.gid).context("gid transition failure")?;
    setresuid(plan.uid, plan.uid, plan.uid).context("uid transition failure")?;

    let empty = CapabilitySets {
        effective: CapabilitySet::empty(),
        permitted: CapabilitySet::empty(),
        inheritable: CapabilitySet::empty(),
    };
    let current = capabilities(None).context("capability read failure")?;
    if !current.effective.is_empty()
        || !current.permitted.is_empty()
        || !current.inheritable.is_empty()
    {
        set_capabilities(None, empty).context("capability clear failure")?;
    }

    verify_credential_transition(plan)
}

fn verify_credential_transition(plan: &CredentialPlan) -> Result<()> {
    let uid_state = getresuid().context("uid verification failure")?;
    if uid_state.real != plan.uid || uid_state.effective != plan.uid || uid_state.saved != plan.uid
    {
        bail!("uid transition verification failed");
    }

    let gid_state = getresgid().context("gid verification failure")?;
    if gid_state.real != plan.gid || gid_state.effective != plan.gid || gid_state.saved != plan.gid
    {
        bail!("gid transition verification failed");
    }

    let actual_groups = getgroups().context("supplementary group verification failure")?;
    if normalized_gids(&actual_groups) != normalized_gids(&plan.groups) {
        bail!("supplementary group verification failed");
    }

    let capability_sets = capabilities(None).context("capability verification failure")?;
    if !capability_sets.effective.is_empty()
        || !capability_sets.permitted.is_empty()
        || !capability_sets.inheritable.is_empty()
    {
        bail!("capability verification failed");
    }

    verify_ambient_capabilities_empty()?;

    if get_keep_capabilities().context("keepcaps verification failure")? {
        bail!("keepcaps verification failed");
    }

    Ok(())
}

fn normalized_gids(groups: &[Gid]) -> Vec<u32> {
    let mut values: Vec<u32> = groups.iter().map(|group| group.as_raw()).collect();
    values.sort_unstable();
    values.dedup();
    values
}

fn verify_ambient_capabilities_empty() -> Result<()> {
    let last = read_capability_limit()?;
    let mut bit: u64 = 1;
    for index in 0..=last {
        let set = CapabilitySet::from_bits_retain(bit);
        match capability_is_in_ambient_set(set) {
            Ok(false) => {}
            Ok(true) => bail!("ambient capability verification failed"),
            Err(_) => bail!("ambient capability query unsupported"),
        }
        if index < last {
            bit = bit
                .checked_shl(1)
                .ok_or_else(|| anyhow::anyhow!("ambient capability bit overflow"))?;
        }
    }
    Ok(())
}

fn read_capability_limit() -> Result<u64> {
    let text =
        fs::read_to_string("/proc/sys/kernel/cap_last_cap").context("cap_last_cap read failure")?;
    parse_capability_limit(text.trim())
}

fn parse_capability_limit(text: &str) -> Result<u64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("invalid cap_last_cap");
    }
    let value: u64 = text
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid cap_last_cap"))?;
    if value > MAX_SUPPORTED_CAPABILITY {
        bail!("unsupported capability range");
    }
    Ok(value)
}

fn build_ready_response(
    request: &ValidatedRequest,
    plan: &CredentialPlan,
) -> Result<ReadyResponse> {
    let pid = nix::unistd::getpid();
    let sid = getsid(None).context("session id lookup failure")?;
    let pgid = getpgrp();
    let groups = plan.groups.iter().map(|group| group.as_raw()).collect();

    Ok(ReadyResponse {
        status: "ready",
        challenge: request.challenge.clone(),
        pid: pid.as_raw(),
        sid: sid.as_raw(),
        pgid: pgid.as_raw(),
        uid: plan.uid.as_raw(),
        gid: plan.gid.as_raw(),
        groups,
        capabilities: CapabilityProof {
            effective_empty: true,
            permitted_empty: true,
            inheritable_empty: true,
            ambient_empty: true,
            keep_caps_clear: true,
        },
    })
}

fn set_fd_cloexec_required(fd: RawFd) -> Result<()> {
    let Some(flags) = read_fd_flags(fd)? else {
        bail!("handshake descriptor missing");
    };
    fcntl(fd, FcntlArg::F_SETFD(flags | FdFlag::FD_CLOEXEC))
        .context("descriptor cloexec failure")?;
    let Some(verified) = read_fd_flags(fd)? else {
        bail!("handshake descriptor closed during cloexec");
    };
    if !verified.contains(FdFlag::FD_CLOEXEC) {
        bail!("descriptor cloexec verification failed");
    }
    Ok(())
}

fn read_fd_flags(fd: RawFd) -> Result<Option<FdFlag>> {
    match fcntl(fd, FcntlArg::F_GETFD) {
        Ok(flags) => Ok(Some(FdFlag::from_bits_retain(flags))),
        Err(Errno::EBADF) => Ok(None),
        Err(error) => Err(anyhow::Error::new(error).context("descriptor flag read failure")),
    }
}

fn parse_fd_entry(text: &str) -> Result<RawFd> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("invalid descriptor entry");
    }
    let value: RawFd = text
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid descriptor entry"))?;
    if value < 0 {
        bail!("invalid descriptor entry");
    }
    Ok(value)
}

fn collect_descriptors() -> Result<Vec<RawFd>> {
    let entries = fs::read_dir("/proc/self/fd").context("descriptor enumeration failure")?;
    let mut descriptors: Vec<RawFd> = Vec::new();
    for entry in entries {
        let entry = entry.context("descriptor enumeration entry failure")?;
        let name = entry.file_name();
        let text = name
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("invalid descriptor entry"))?;
        let fd = parse_fd_entry(text)?;
        if fd >= 3 {
            if descriptors.len() >= MAX_DESCRIPTOR_COUNT {
                bail!("too many open descriptors");
            }
            descriptors.push(fd);
        }
    }
    Ok(descriptors)
}

fn verify_single_threaded() -> Result<()> {
    let entries = fs::read_dir("/proc/self/task").context("thread enumeration failure")?;
    let mut count = 0usize;
    for entry in entries {
        entry.context("thread enumeration entry failure")?;
        count += 1;
        if count > 1 {
            bail!("multiple threads detected");
        }
    }
    if count != 1 {
        bail!("thread enumeration mismatch");
    }
    Ok(())
}

fn mark_descriptor_cloexec(fd: RawFd) -> Result<()> {
    let Some(flags) = read_fd_flags(fd)? else {
        // The descriptor was closed since enumeration; a closed descriptor
        // cannot leak across exec.
        return Ok(());
    };
    if flags.contains(FdFlag::FD_CLOEXEC) {
        return Ok(());
    }
    fcntl(fd, FcntlArg::F_SETFD(flags | FdFlag::FD_CLOEXEC))
        .context("descriptor cloexec failure")?;
    let Some(verified) = read_fd_flags(fd)? else {
        bail!("descriptor closed during cloexec");
    };
    if !verified.contains(FdFlag::FD_CLOEXEC) {
        bail!("descriptor cloexec verification failed");
    }
    Ok(())
}

fn verify_descriptor_cloexec(fd: RawFd) -> Result<()> {
    match read_fd_flags(fd)? {
        Some(flags) => {
            if !flags.contains(FdFlag::FD_CLOEXEC) {
                bail!("descriptor cloexec recheck failed");
            }
            Ok(())
        }
        None => Ok(()),
    }
}

// Descriptor sanitation for the exec boundary. The trusted kernel procfs and
// its mount namespace are an EXTERNAL assumption: this sweep does not verify
// that /proc/self/fd and /proc/self/task reflect an untampered, private procfs
// mount. What is actually verified here is that this process has exactly one
// thread (both before and after the sweep) and that every enumerable
// descriptor carries FD_CLOEXEC after marking. The sweep fails closed if it
// cannot prove those properties; establishing a trusted procfs/mount namespace
// is the deployment environment's responsibility, not this helper's.
fn ensure_all_descriptors_cloexec() -> Result<()> {
    verify_single_threaded()?;
    let descriptors = collect_descriptors()?;
    for fd in &descriptors {
        mark_descriptor_cloexec(*fd)?;
    }
    let rechecked = collect_descriptors()?;
    for fd in &rechecked {
        verify_descriptor_cloexec(*fd)?;
    }
    verify_single_threaded()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::net::UnixListener;

    fn fixture_request() -> ExecRequest {
        ExecRequest {
            target_user: String::from("alice"),
            shell: String::from("/bin/sh"),
            arguments: vec![String::from("-c"), String::from("printf ok")],
            term: Some(String::from("xterm-256color")),
            challenge: Some(String::from("challenge-value")),
        }
    }

    fn decode(value: serde_json::Value) -> Result<ExecRequest> {
        serde_json::from_value(value).context("test request decode")
    }

    fn socket_pair() -> Result<(UnixStream, UnixStream)> {
        UnixStream::pair().context("test socket pair")
    }

    #[test]
    fn valid_request_passes_field_and_bound_validation() -> Result<()> {
        let validated = validate_request(fixture_request())?;
        assert_eq!(validated.target_user, "alice");
        assert_eq!(validated.shell, "/bin/sh");
        assert_eq!(validated.arguments.len(), 2);
        assert_eq!(validated.term, "xterm-256color");
        assert_eq!(validated.challenge.as_deref(), Some("challenge-value"));
        Ok(())
    }

    #[test]
    fn request_rejects_unknown_fields() -> Result<()> {
        let decoded = decode(json!({
            "target_user": "alice",
            "shell": "/bin/sh",
            "arguments": [],
            "extra": true
        }));
        assert!(decoded.is_err());
        Ok(())
    }

    #[test]
    fn request_rejects_bad_names_paths_and_terms() -> Result<()> {
        let mut missing_user = fixture_request();
        missing_user.target_user = String::new();
        assert!(validate_request(missing_user).is_err());

        let mut nul_user = fixture_request();
        nul_user.target_user = String::from("bad\0user");
        assert!(validate_request(nul_user).is_err());

        let mut relative_shell = fixture_request();
        relative_shell.shell = String::from("sh");
        assert!(validate_request(relative_shell).is_err());

        let mut bad_term = fixture_request();
        bad_term.term = Some(String::from("xterm;rm"));
        assert!(validate_request(bad_term).is_err());
        Ok(())
    }

    #[test]
    fn request_rejects_argument_count_total_and_nul() -> Result<()> {
        let mut too_many = fixture_request();
        too_many.arguments = vec![String::new(); MAX_ARGUMENTS + 1];
        assert!(validate_request(too_many).is_err());

        let mut too_large = fixture_request();
        too_large.arguments = vec![String::from("aaaaaaaaaa"); 820];
        assert!(validate_request(too_large).is_err());

        let mut nul_argument = fixture_request();
        nul_argument.arguments = vec![String::from("bad\0arg")];
        assert!(validate_request(nul_argument).is_err());
        Ok(())
    }

    #[test]
    fn synthetic_credential_plan_validation_is_strict() -> Result<()> {
        let home = Path::new("/home/alice");
        assert!(validate_credential_values(1000, 1000, &[1000, 1001], home, "alice").is_ok());
        assert!(validate_credential_values(0, 1000, &[0], home, "root").is_err());
        assert!(validate_credential_values(u32::MAX, 1000, &[1000], home, "alice").is_err());
        assert!(validate_credential_values(1000, u32::MAX, &[1000], home, "alice").is_err());
        assert!(validate_credential_values(1000, 1000, &[1000, u32::MAX], home, "alice").is_err());
        assert!(
            validate_credential_values(1000, 1000, &[1000], Path::new("relative"), "alice")
                .is_err()
        );
        assert!(
            validate_credential_values(1000, 1000, &[1000], Path::new("/home/\0bad"), "alice")
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn synthetic_group_bound_is_enforced() -> Result<()> {
        let mut groups = vec![1000u32; MAX_SUPPLEMENTARY_GROUPS + 1];
        let home = Path::new("/home/alice");
        assert!(validate_credential_values(1000, 1000, &groups, home, "alice").is_err());
        groups.truncate(MAX_SUPPLEMENTARY_GROUPS);
        assert!(validate_credential_values(1000, 1000, &groups, home, "alice").is_ok());
        Ok(())
    }

    #[test]
    fn working_directory_policy_falls_back_only_for_missing_home() -> Result<()> {
        let home = Path::new("/home/alice");
        assert_eq!(
            decide_working_directory(home, HomeStatus::Directory)?,
            home.to_path_buf()
        );
        assert_eq!(
            decide_working_directory(home, HomeStatus::Missing)?,
            PathBuf::from("/")
        );
        assert!(decide_working_directory(home, HomeStatus::NotDirectory).is_err());
        assert!(decide_working_directory(home, HomeStatus::PermissionDenied).is_err());
        assert!(decide_working_directory(home, HomeStatus::OtherError).is_err());
        Ok(())
    }

    #[test]
    fn user_name_validation_bounds_length_and_rejects_nul() -> Result<()> {
        assert!(validate_user_name("alice").is_ok());
        assert!(validate_user_name(&"a".repeat(MAX_USERNAME)).is_ok());
        assert!(validate_user_name(&"a".repeat(MAX_USERNAME + 1)).is_err());
        assert!(validate_user_name("").is_err());
        assert!(validate_user_name("bad\0user").is_err());
        Ok(())
    }

    #[test]
    fn frame_roundtrip_over_unix_stream_pair() -> Result<()> {
        let (mut reader, mut writer) = socket_pair()?;
        reader.set_read_timeout(Some(Duration::from_secs(1)))?;
        writer.set_write_timeout(Some(Duration::from_secs(1)))?;
        let payload = b"{\"hello\":true}".to_vec();
        let expected = payload.clone();

        let handle = std::thread::spawn(move || write_frame(&mut writer, &payload));
        let received_result = read_frame(&mut reader);
        let write_result = handle.join();
        let received = received_result?;
        assert_eq!(received, expected);

        match write_result {
            Ok(result) => result?,
            Err(_) => return Err(anyhow::anyhow!("frame writer thread panicked")),
        }
        Ok(())
    }

    #[test]
    fn frame_reader_rejects_truncated_payload() -> Result<()> {
        let (mut reader, mut writer) = socket_pair()?;
        reader.set_read_timeout(Some(Duration::from_secs(1)))?;
        writer.write_all(&8u32.to_be_bytes())?;
        writer.write_all(b"abcd")?;
        writer.shutdown(std::net::Shutdown::Write)?;
        assert!(read_frame(&mut reader).is_err());
        Ok(())
    }

    #[test]
    fn frame_reader_rejects_oversize_length() -> Result<()> {
        let (mut reader, mut writer) = socket_pair()?;
        reader.set_read_timeout(Some(Duration::from_secs(1)))?;
        let oversize = u32::try_from(MAX_FRAME)
            .map_err(|_| anyhow::anyhow!("test frame bound conversion"))?
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("test frame bound overflow"))?;
        writer.write_all(&oversize.to_be_bytes())?;
        assert!(read_frame(&mut reader).is_err());
        Ok(())
    }

    #[test]
    fn frame_reader_observes_read_deadline() -> Result<()> {
        let (mut reader, _writer) = socket_pair()?;
        reader.set_read_timeout(Some(Duration::from_millis(50)))?;
        assert!(read_frame(&mut reader).is_err());
        Ok(())
    }

    #[test]
    fn argument_parser_accepts_only_the_two_expected_options() -> Result<()> {
        let arguments = vec![
            OsString::from("--socket"),
            OsString::from("/run/helper/socket"),
            OsString::from("--parent-pid"),
            OsString::from("4242"),
        ];
        let parsed = parse_args(arguments)?;
        assert_eq!(parsed.parent_pid, 4242);
        assert_eq!(parsed.socket, PathBuf::from("/run/helper/socket"));

        let duplicate = vec![
            OsString::from("--socket"),
            OsString::from("/run/helper/a"),
            OsString::from("--socket"),
            OsString::from("/run/helper/b"),
        ];
        assert!(parse_args(duplicate).is_err());
        Ok(())
    }

    #[test]
    fn fd_entry_parser_is_strict() -> Result<()> {
        assert_eq!(parse_fd_entry("0")?, 0);
        assert_eq!(parse_fd_entry("3")?, 3);
        assert_eq!(parse_fd_entry("1024")?, 1024);
        assert!(parse_fd_entry("").is_err());
        assert!(parse_fd_entry("-1").is_err());
        assert!(parse_fd_entry("+4").is_err());
        assert!(parse_fd_entry("4x").is_err());
        assert!(parse_fd_entry(" 4").is_err());
        Ok(())
    }

    #[test]
    fn capability_limit_parser_is_bounded() -> Result<()> {
        assert_eq!(parse_capability_limit("0")?, 0);
        assert_eq!(parse_capability_limit("40")?, 40);
        assert_eq!(parse_capability_limit("63")?, 63);
        assert!(parse_capability_limit("64").is_err());
        assert!(parse_capability_limit("").is_err());
        assert!(parse_capability_limit("-1").is_err());
        assert!(parse_capability_limit("4a").is_err());
        Ok(())
    }

    // Unprivileged: exercises the real `connect_stream` over an owned temp
    // listener. The server delays its payload so a socket left SOCK_NONBLOCK
    // would fail immediately instead of waiting; a blocking stream reads it.
    #[test]
    fn connect_stream_clears_nonblocking_for_delayed_frame() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let socket_path = directory.path().join("helper.sock");
        let listener = UnixListener::bind(&socket_path)?;

        let server = std::thread::spawn(move || -> Result<()> {
            // Delay the payload so a still-nonblocking client would error out
            // immediately rather than waiting for the frame.
            std::thread::sleep(Duration::from_millis(100));
            let (mut connection, _addr) = listener.accept()?;
            connection.set_write_timeout(Some(Duration::from_secs(2)))?;
            write_frame(&mut connection, b"delayed-payload")?;
            Ok(())
        });

        let mut stream = connect_stream(&socket_path)?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        let received = read_frame(&mut stream);

        // Always join the finite server thread before propagating results.
        let joined = server.join();
        let frame = received?;
        assert_eq!(frame, b"delayed-payload".to_vec());
        match joined {
            Ok(result) => result?,
            Err(_) => return Err(anyhow::anyhow!("server thread panicked")),
        }
        Ok(())
    }

    // Unprivileged: proves the absolute deadline expires even though steady
    // progress arrives as a slow drip, and that the sender thread is joined on
    // every path.
    #[test]
    fn deadline_stream_expires_despite_slow_progress() -> Result<()> {
        let (reader, writer) = socket_pair()?;
        let deadline = Instant::now() + Duration::from_millis(200);
        let mut stream = DeadlineStream::new(reader, deadline);

        let sender = std::thread::spawn(move || -> Result<()> {
            let mut writer = writer;
            writer.set_write_timeout(Some(Duration::from_secs(1)))?;
            for _ in 0..8 {
                std::thread::sleep(Duration::from_millis(20));
                writer.write_all(b"x")?;
            }
            Ok(())
        });

        let mut buffer = [0u8; 64];
        let mut total = 0usize;
        let read_result = loop {
            match stream.read(&mut buffer) {
                Ok(0) => break Err(anyhow::anyhow!("unexpected end of stream")),
                Ok(read) => {
                    total = total
                        .checked_add(read)
                        .ok_or_else(|| anyhow::anyhow!("byte count overflow"))?;
                    if total >= 64 {
                        break Ok(());
                    }
                }
                Err(error) => break Err(anyhow::Error::new(error)),
            }
        };

        drop(stream);
        let joined = sender.join();
        match joined {
            Ok(result) => result?,
            Err(_) => return Err(anyhow::anyhow!("sender thread panicked")),
        }
        assert!(total > 0, "expected some progress before the deadline");
        assert!(
            read_result.is_err(),
            "expected the absolute deadline to expire despite progress"
        );
        Ok(())
    }
}
