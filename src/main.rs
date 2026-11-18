#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::as_conversions,
        clippy::indexing_slicing,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]

use std::future::pending;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use mender_connect_rust::auth::AuthClient;
use mender_connect_rust::config;
use mender_connect_rust::daemon;
use mender_connect_rust::logging;
use tokio::signal::unix::{SignalKind, signal};

#[derive(Debug, Parser)]
#[command(
    name = "mender-connect-rust",
    version,
    about = "Experimental Linux Rust rewrite of mender-connect"
)]
struct Cli {
    /// Primary configuration file.
    #[arg(long, short = 'c', global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Fallback configuration file, loaded before the primary file.
    #[arg(
        long = "fallback-config",
        short = 'b',
        global = true,
        value_name = "PATH"
    )]
    fallback_config: Option<PathBuf>,

    /// Set the diagnostic logging level to debug.
    #[arg(long, short = 'd', global = true)]
    debug: bool,

    /// Set the diagnostic logging level to trace (takes precedence over debug).
    #[arg(long, global = true)]
    trace: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Load and validate configuration without contacting any server.
    #[command(name = "config-check")]
    ConfigCheck,

    /// Run the supervised multi-session remote terminal daemon.
    ///
    /// Serves concurrent PTY shells, port forwarding, file transfer and
    /// Mender client commands over a websocket, with reconnect, heartbeat and
    /// idle-session supervision.
    Daemon {
        /// TEST ONLY: use the session D-Bus instead of the system bus.
        #[arg(long = "test-session-bus", hide = true)]
        test_session_bus: bool,
    },

    /// Show the version and runtime information of the binary build.
    Version,
}

/// Upper bound on Tokio's CPU-derived async worker threads.
///
/// This limits CPU-derived async worker overprovisioning on high-core hosts.
/// It does not bound Tokio's blocking pool or threads created by third-party
/// libraries, and it does not prove the historical 13-vs-12 thread-budget
/// issue is fixed.
const MAX_ASYNC_WORKERS: usize = 16;

/// Async worker count used when CPU detection is unavailable.
const FALLBACK_ASYNC_WORKERS: usize = 2;

/// Maps detected CPU parallelism to a bounded Tokio async worker count.
///
/// One detected CPU remains one worker; counts above [`MAX_ASYNC_WORKERS`] are
/// capped, and detection failure uses [`FALLBACK_ASYNC_WORKERS`].
fn async_worker_threads_from_parallelism(parallelism: Option<usize>) -> usize {
    parallelism.map_or(FALLBACK_ASYNC_WORKERS, |count| {
        count.clamp(1, MAX_ASYNC_WORKERS)
    })
}

fn detected_async_worker_threads() -> usize {
    async_worker_threads_from_parallelism(
        std::thread::available_parallelism()
            .ok()
            .map(|count| count.get()),
    )
}

fn main() -> Result<()> {
    let cli = Cli::parse_from(logging::normalize_args(std::env::args_os()));
    let primary = cli.config;
    let fallback_config = cli.fallback_config;
    let level = logging::level_from_flags(cli.debug, cli.trace);

    match cli.command {
        Command::ConfigCheck => {
            let loaded = load_and_validate(primary, fallback_config)?;
            print_config(&loaded).context("failed to write configuration output")?;
            let stderr = std::io::stderr();
            let mut locked = stderr.lock();
            writeln!(
                &mut locked,
                "note: this validates the experimental supported configuration; see README.md for scope"
            )
            .context("failed to write configuration note")?;
            Ok(())
        }
        Command::Version => {
            print_version().context("failed to write version information")?;
            Ok(())
        }
        Command::Daemon { test_session_bus } => {
            let loaded = load_and_validate(primary, fallback_config)?;
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(detected_async_worker_threads())
                .enable_all()
                .build()
                .context("failed to build the Tokio runtime")?;
            runtime.block_on(async move {
                log_event(
                    level,
                    logging::Level::Info,
                    logging::Event::Startup,
                    logging::STARTUP_MSG,
                );
                let mut sigint =
                    signal(SignalKind::interrupt()).context("failed to register SIGINT handler")?;
                let mut sigterm = signal(SignalKind::terminate())
                    .context("failed to register SIGTERM handler")?;
                let sigusr1 = signal(SignalKind::user_defined1())
                    .context("failed to register SIGUSR1 handler")?;

                let shutdown = async move {
                    let mut last_status: Option<Instant> = None;
                    let mut status_stream = Some(sigusr1);
                    loop {
                        tokio::select! {
                            biased;
                            _ = sigint.recv() => return,
                            _ = sigterm.recv() => return,
                            result = async {
                                match status_stream.as_mut() {
                                    Some(stream) => stream.recv().await,
                                    None => pending::<Option<()>>().await,
                                }
                            } => match result {
                                Some(()) => {
                                    let emit = match last_status {
                                        Some(at) => at.elapsed() >= Duration::from_secs(1),
                                        None => true,
                                    };
                                    if emit {
                                        last_status = Some(Instant::now());
                                        // Status output is best effort: a broken or full log
                                        // pipe must not terminate the daemon or skip cleanup.
                                        let _ = emit_status();
                                    }
                                    tokio::task::yield_now().await;
                                }
                                None => status_stream = None,
                            },
                        }
                    }
                };
                tokio::pin!(shutdown);

                let auth_fut = async {
                    if test_session_bus {
                        if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() {
                            bail!("--test-session-bus requires DBUS_SESSION_BUS_ADDRESS to be set");
                        }
                        let connection = zbus::Connection::session()
                            .await
                            .context("failed to connect to the session D-Bus")?;
                        Ok(AuthClient::from_connection(connection))
                    } else {
                        Ok(AuthClient::connect_system()
                            .await
                            .context("failed to connect to the system D-Bus")?)
                    }
                };

                let auth = tokio::select! {
                    biased;
                    _ = &mut shutdown => return Ok(()),
                    result = auth_fut => result?,
                };
                log_event(
                    level,
                    logging::Level::Debug,
                    logging::Event::Auth,
                    logging::AUTH_MSG,
                );
                log_event(
                    level,
                    logging::Level::Trace,
                    logging::Event::Detail,
                    logging::TRACE_DETAIL_MSG,
                );

                let (events, mut event_rx) = logging::RuntimeEvents::channel();
                let daemon_fut = daemon::run_with_events(loaded, auth, &mut shutdown, events);
                tokio::pin!(daemon_fut);

                // Drive the daemon alongside the bounded runtime-event receiver.
                // The daemon result is prioritised; each fixed event is written
                // best-effort through the existing private stderr helper. The
                // receiver branch is disabled once it closes to avoid a busy
                // loop. No awaits occur inside a single emission and no task is
                // spawned.
                let mut events_open = true;
                let result = loop {
                    tokio::select! {
                        biased;
                        result = &mut daemon_fut => break result,
                        maybe = event_rx.recv(), if events_open => {
                            match maybe {
                                Some(event) => {
                                    if let Some(line) = event.format(level) {
                                        let _ = write_stderr_line(&line);
                                    }
                                }
                                None => events_open = false,
                            }
                        }
                    }
                };

                // Drain at most the bounded capacity of already-queued events
                // without awaiting; events produced after completion are dropped.
                for _ in 0..logging::RUNTIME_EVENT_CAPACITY {
                    match event_rx.try_recv() {
                        Ok(event) => {
                            if let Some(line) = event.format(level) {
                                let _ = write_stderr_line(&line);
                            }
                        }
                        Err(_) => break,
                    }
                }

                log_event(
                    level,
                    logging::Level::Info,
                    logging::Event::Shutdown,
                    logging::SHUTDOWN_MSG,
                );
                result
            })
        }
    }
}

#[cfg(target_os = "linux")]
fn write_stderr_line(line: &str) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    // Reopening /proc/self/fd/2 can upgrade an inherited read-only descriptor into a
    // writable one. Check the original descriptor's access mode first and fail closed
    // so diagnostics never append to a file the daemon did not receive writable.
    let original_fd = std::io::stderr().as_raw_fd();
    let original_flags = nix::fcntl::fcntl(original_fd, nix::fcntl::FcntlArg::F_GETFL)
        .map_err(std::io::Error::from)?;
    let access_mode = original_flags & nix::libc::O_ACCMODE;
    if access_mode == nix::libc::O_RDONLY
        || original_flags & nix::libc::O_PATH != 0
        || (access_mode != nix::libc::O_WRONLY && access_mode != nix::libc::O_RDWR)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "inherited stderr descriptor is not writable",
        ));
    }

    // Reopen the inherited stderr descriptor through /proc so diagnostic writes use a
    // separate open file description. This avoids changing flags on the original
    // descriptor (which would be shared) and never falls back to blocking stderr if
    // the descriptor is unsupported, full, or otherwise not writable. The standard
    // OpenOptions CLOEXEC default is fine for this short-lived owned file.
    let mut status = OpenOptions::new()
        .append(true)
        .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_NOCTTY)
        .open("/proc/self/fd/2")?;

    writeln!(status, "{line}")
}

#[cfg(target_os = "linux")]
fn emit_status() -> std::io::Result<()> {
    write_stderr_line(&format!(
        "status: version={} pid={}",
        env!("CARGO_PKG_VERSION"),
        std::process::id()
    ))
}

#[cfg(not(target_os = "linux"))]
fn write_stderr_line(_line: &str) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "diagnostics require Linux /proc",
    ))
}

#[cfg(not(target_os = "linux"))]
fn emit_status() -> std::io::Result<()> {
    write_stderr_line("status: unsupported platform")
}

fn log_event(min: logging::Level, level: logging::Level, event: logging::Event, message: &str) {
    // Diagnostics are best effort: a broken, full or read-only stderr must never
    // abort daemon startup, shutdown or cleanup.
    if let Some(line) = logging::format_event(min, level, event, message) {
        let _ = write_stderr_line(&line);
    }
}

fn print_version() -> std::io::Result<()> {
    let stdout = std::io::stdout();
    let mut locked = stdout.lock();
    writeln!(
        &mut locked,
        "{} {}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    )?;
    writeln!(
        &mut locked,
        "runtime: rust platform={}/{} family={}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        std::env::consts::FAMILY
    )?;
    writeln!(
        &mut locked,
        "profile: {}",
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    )?;
    Ok(())
}

fn load_and_validate(
    primary: Option<PathBuf>,
    fallback_config: Option<PathBuf>,
) -> Result<config::Config> {
    let primary_config = primary.unwrap_or_else(config::default_primary_config_path);
    let fallback_config = fallback_config.unwrap_or_else(config::default_fallback_config_path);
    let loaded = config::load_config(&primary_config, &fallback_config)?;
    loaded.validate()?;
    Ok(loaded)
}

fn print_config(loaded: &config::Config) -> std::io::Result<()> {
    let stdout = std::io::stdout();
    let mut locked = stdout.lock();
    writeln!(&mut locked, "configuration OK")?;
    writeln!(&mut locked, "  User: {}", loaded.user)?;
    writeln!(&mut locked, "  ShellCommand: {}", loaded.shell_command)?;
    writeln!(
        &mut locked,
        "  ShellArguments: {:?}",
        loaded.shell_arguments
    )?;
    writeln!(
        &mut locked,
        "  Terminal: {}x{} (disable: {})",
        loaded.terminal.width, loaded.terminal.height, loaded.terminal.disable
    )?;
    writeln!(
        &mut locked,
        "  Sessions: stop_expired={} expire_after={} expire_after_idle={} max_per_user={}",
        loaded.sessions.stop_expired,
        loaded.sessions.expire_after,
        loaded.sessions.expire_after_idle,
        loaded.sessions.max_per_user
    )?;
    writeln!(
        &mut locked,
        "  Features: port_forward_disable={} file_transfer_disable={} mender_client_disable={}",
        loaded.port_forward.disable, loaded.file_transfer.disable, loaded.mender_client.disable
    )?;
    writeln!(&mut locked, "  Limits: enabled={}", loaded.limits_enabled)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{FALLBACK_ASYNC_WORKERS, MAX_ASYNC_WORKERS, async_worker_threads_from_parallelism};

    #[test]
    fn one_cpu_uses_one_worker() {
        assert_eq!(async_worker_threads_from_parallelism(Some(1)), 1);
    }

    #[test]
    fn low_cpu_counts_are_preserved() {
        assert_eq!(async_worker_threads_from_parallelism(Some(2)), 2);
        assert_eq!(async_worker_threads_from_parallelism(Some(4)), 4);
    }

    #[test]
    fn cpu_count_at_cap_is_preserved() {
        assert_eq!(
            async_worker_threads_from_parallelism(Some(MAX_ASYNC_WORKERS)),
            MAX_ASYNC_WORKERS
        );
    }

    #[test]
    fn cpu_counts_above_cap_are_limited() {
        assert_eq!(
            async_worker_threads_from_parallelism(Some(MAX_ASYNC_WORKERS + 1)),
            MAX_ASYNC_WORKERS
        );
        assert_eq!(
            async_worker_threads_from_parallelism(Some(32)),
            MAX_ASYNC_WORKERS
        );
    }

    #[test]
    fn unavailable_detection_uses_fallback() {
        assert_eq!(
            async_worker_threads_from_parallelism(None),
            FALLBACK_ASYNC_WORKERS
        );
    }
}
