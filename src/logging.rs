//! Small, safe diagnostic logging foundation for mender-connect-rust.
//!
//! The main/daemon runtime now also emits fixed, payload-free [`RuntimeEvent`]
//! values for auth and reconnect-loop transitions over a bounded 64-slot
//! channel using non-blocking `try_send`; they may be rendered to a
//! best-effort stderr sink. Startup/auth/shutdown messages and one trace detail
//! line remain constant and redacted. Arbitrary request, token, header or
//! payload data is intentionally never logged here.

use std::ffi::{OsStr, OsString};
use std::io::Write;

use tokio::sync::mpsc;

/// Diagnostic verbosity, ordered low to high so comparisons are meaningful.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Info,
    Debug,
    Trace,
}

impl Level {
    /// Short stable label used in diagnostic lines.
    pub fn label(self) -> &'static str {
        match self {
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
            Level::Trace => "TRACE",
        }
    }
}

/// Constant, redacted event kinds. No dynamic, user- or server-derived data is
/// ever associated with these events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Startup,
    Auth,
    Shutdown,
    Detail,
}

impl Event {
    /// Stable event code used in diagnostic lines.
    pub fn code(self) -> &'static str {
        match self {
            Event::Startup => "startup",
            Event::Auth => "auth",
            Event::Shutdown => "shutdown",
            Event::Detail => "detail",
        }
    }
}

/// Constant redacted messages for the fixed startup/auth/shutdown events.
pub const STARTUP_MSG: &str = "daemon startup";
pub const AUTH_MSG: &str = "authentication channel established";
pub const SHUTDOWN_MSG: &str = "daemon shutdown";
pub const TRACE_DETAIL_MSG: &str = "diagnostic trace detail enabled";

/// Select the effective level from the CLI flags. Trace takes precedence.
pub fn level_from_flags(debug: bool, trace: bool) -> Level {
    if trace {
        Level::Trace
    } else if debug {
        Level::Debug
    } else {
        Level::Info
    }
}

/// Normalise argv so the upstream `-dd` spelling maps onto `--trace`.
///
/// This is done deliberately: left untouched, clap would parse `-dd` as two
/// `-d` occurrences (debug) and the trace flag would be a silent no-op.
/// Legitimate standalone debug flags (`-d`) are left as-is.
pub fn normalize_args<I>(args: I) -> Vec<OsString>
where
    I: IntoIterator<Item = OsString>,
{
    let trace = OsStr::new("-dd");
    args.into_iter()
        .map(|arg| {
            if arg.as_os_str() == trace {
                OsString::from("--trace")
            } else {
                arg
            }
        })
        .collect()
}

/// Format a single diagnostic line, or `None` when filtered out at `min`.
pub fn format_event(min: Level, level: Level, event: Event, message: &str) -> Option<String> {
    if level > min {
        return None;
    }
    Some(format!(
        "level={} event={} msg={}",
        level.label(),
        event.code(),
        message
    ))
}

/// Capacity of the bounded runtime event channel.
pub const RUNTIME_EVENT_CAPACITY: usize = 64;

/// Fixed, redacted runtime event kinds. These carry no payload: no strings,
/// user data, tokens, paths or session identifiers are ever attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeEvent {
    AuthRetry,
    AuthChanged,
    Connecting,
    Connected,
    Disconnected,
    ProtocolRejected,
    ShellStarted,
    ShellStopped,
    CleanupFailed,
}

impl RuntimeEvent {
    /// Stable event code used in diagnostic lines.
    pub fn code(self) -> &'static str {
        match self {
            RuntimeEvent::AuthRetry => "auth_retry",
            RuntimeEvent::AuthChanged => "auth_changed",
            RuntimeEvent::Connecting => "connecting",
            RuntimeEvent::Connected => "connected",
            RuntimeEvent::Disconnected => "disconnected",
            RuntimeEvent::ProtocolRejected => "protocol_rejected",
            RuntimeEvent::ShellStarted => "shell_started",
            RuntimeEvent::ShellStopped => "shell_stopped",
            RuntimeEvent::CleanupFailed => "cleanup_failed",
        }
    }

    /// Constant, redacted, newline-free display message.
    pub fn message(self) -> &'static str {
        match self {
            RuntimeEvent::AuthRetry => "authentication retry scheduled",
            RuntimeEvent::AuthChanged => "authentication state changed",
            RuntimeEvent::Connecting => "connecting to server",
            RuntimeEvent::Connected => "connection established",
            RuntimeEvent::Disconnected => "connection closed",
            RuntimeEvent::ProtocolRejected => "protocol message rejected",
            RuntimeEvent::ShellStarted => "shell session started",
            RuntimeEvent::ShellStopped => "shell session stopped",
            RuntimeEvent::CleanupFailed => "cleanup step failed",
        }
    }

    /// Diagnostic level associated with the event.
    pub fn level(self) -> Level {
        match self {
            RuntimeEvent::ProtocolRejected | RuntimeEvent::CleanupFailed => Level::Info,
            RuntimeEvent::AuthRetry
            | RuntimeEvent::AuthChanged
            | RuntimeEvent::Connecting
            | RuntimeEvent::Connected
            | RuntimeEvent::Disconnected
            | RuntimeEvent::ShellStarted
            | RuntimeEvent::ShellStopped => Level::Debug,
        }
    }

    /// Format as a redacted diagnostic line when it passes the `min` filter.
    pub fn format(self, min: Level) -> Option<String> {
        let level = self.level();
        if level > min {
            return None;
        }
        Some(format!(
            "level={} event={} msg={}",
            level.label(),
            self.code(),
            self.message()
        ))
    }
}

/// Cloneable, non-blocking sender for runtime events.
///
/// A disabled sender owns no channel and drops events without any allocation.
/// [`RuntimeEvents::emit`] only uses `try_send`, so it never awaits or blocks;
/// events are dropped when the channel is full or the receiver is gone.
#[derive(Debug, Clone)]
pub struct RuntimeEvents {
    tx: Option<mpsc::Sender<RuntimeEvent>>,
}

impl RuntimeEvents {
    /// Disabled sink: every emitted event is dropped, no channel allocated.
    pub fn disabled() -> Self {
        RuntimeEvents { tx: None }
    }

    /// Bounded channel sink; returns the sender plus the receiver for `main`.
    pub fn channel() -> (Self, mpsc::Receiver<RuntimeEvent>) {
        let (tx, rx) = mpsc::channel(RUNTIME_EVENT_CAPACITY);
        (RuntimeEvents { tx: Some(tx) }, rx)
    }

    /// Whether this sender will actually deliver events.
    pub fn is_enabled(&self) -> bool {
        self.tx.is_some()
    }

    /// Non-blocking emit. Drops the event when disabled, full or closed.
    pub fn emit(&self, event: RuntimeEvent) {
        if let Some(tx) = &self.tx {
            let _ = tx.try_send(event);
        }
    }
}

impl Default for RuntimeEvents {
    fn default() -> Self {
        RuntimeEvents::disabled()
    }
}

/// Write a diagnostic line to `writer` if it passes the `min` filter.
pub fn record<W: Write>(
    writer: &mut W,
    min: Level,
    level: Level,
    event: Event,
    message: &str,
) -> std::io::Result<()> {
    match format_event(min, level, event, message) {
        Some(line) => writeln!(writer, "{line}"),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_takes_precedence() {
        assert_eq!(level_from_flags(false, false), Level::Info);
        assert_eq!(level_from_flags(true, false), Level::Debug);
        assert_eq!(level_from_flags(false, true), Level::Trace);
        assert_eq!(level_from_flags(true, true), Level::Trace);
    }

    #[test]
    fn double_d_maps_to_trace() {
        let args: Vec<OsString> = ["prog", "-dd", "daemon"]
            .iter()
            .map(OsString::from)
            .collect();
        let out = normalize_args(args);
        assert_eq!(
            out,
            vec![
                OsString::from("prog"),
                OsString::from("--trace"),
                OsString::from("daemon"),
            ]
        );
    }

    #[test]
    fn single_dash_d_is_unchanged() {
        let args: Vec<OsString> = ["prog", "-d"].iter().map(OsString::from).collect();
        let out = normalize_args(args);
        assert_eq!(out, vec![OsString::from("prog"), OsString::from("-d")]);
    }

    #[test]
    fn filtering_respects_min_level() {
        let mut buf: Vec<u8> = Vec::new();
        record(&mut buf, Level::Info, Level::Debug, Event::Auth, AUTH_MSG).unwrap();
        assert!(buf.is_empty(), "debug line must be filtered at info level");
        record(&mut buf, Level::Debug, Level::Debug, Event::Auth, AUTH_MSG).unwrap();
        assert!(!buf.is_empty(), "debug line must appear at debug level");
    }

    #[test]
    fn formatting_is_constant_and_redacted() {
        let line = format_event(Level::Trace, Level::Trace, Event::Startup, STARTUP_MSG).unwrap();
        assert_eq!(line, "level=TRACE event=startup msg=daemon startup");
    }

    const ALL_RUNTIME_EVENTS: [RuntimeEvent; 9] = [
        RuntimeEvent::AuthRetry,
        RuntimeEvent::AuthChanged,
        RuntimeEvent::Connecting,
        RuntimeEvent::Connected,
        RuntimeEvent::Disconnected,
        RuntimeEvent::ProtocolRejected,
        RuntimeEvent::ShellStarted,
        RuntimeEvent::ShellStopped,
        RuntimeEvent::CleanupFailed,
    ];

    #[test]
    fn runtime_metadata_is_fixed_bounded_and_newline_free() {
        for event in ALL_RUNTIME_EVENTS {
            let code = event.code();
            let message = event.message();
            assert!(!code.is_empty() && code.len() <= 32);
            assert!(!message.is_empty() && message.len() <= 64);
            assert!(!code.contains('\n') && !code.contains('\r'));
            assert!(!message.contains('\n') && !message.contains('\r'));
        }
    }

    #[test]
    fn runtime_metadata_codes_are_unique() {
        let mut codes: Vec<&str> = ALL_RUNTIME_EVENTS.iter().map(|e| e.code()).collect();
        codes.sort_unstable();
        let unique = {
            let mut u = codes.clone();
            u.dedup();
            u.len()
        };
        assert_eq!(unique, ALL_RUNTIME_EVENTS.len());
    }

    #[test]
    fn runtime_format_respects_level_filter() {
        for event in ALL_RUNTIME_EVENTS {
            let level = event.level();
            assert!(event.format(Level::Trace).is_some());
            assert!(event.format(level).is_some());
            if level > Level::Info {
                assert!(event.format(Level::Info).is_none());
            }
            let line = event.format(Level::Trace).unwrap_or_default();
            assert!(!line.contains('\n') && !line.contains('\r'));
        }
    }

    #[test]
    fn disabled_sink_drops_events() {
        let sink = RuntimeEvents::disabled();
        assert!(!sink.is_enabled());
        for event in ALL_RUNTIME_EVENTS {
            sink.emit(event);
        }
    }

    #[tokio::test]
    async fn channel_delivers_events_within_capacity() {
        let (tx, mut rx) = RuntimeEvents::channel();
        assert!(tx.is_enabled());
        tx.emit(RuntimeEvent::Connecting);
        tx.emit(RuntimeEvent::Connected);
        assert_eq!(rx.recv().await, Some(RuntimeEvent::Connecting));
        assert_eq!(rx.recv().await, Some(RuntimeEvent::Connected));
    }

    #[tokio::test]
    async fn full_channel_never_blocks() {
        let (tx, _rx) = RuntimeEvents::channel();
        for _ in 0..(RUNTIME_EVENT_CAPACITY + 8) {
            tx.emit(RuntimeEvent::Connecting);
        }
    }

    #[tokio::test]
    async fn closed_channel_never_blocks() {
        let (tx, rx) = RuntimeEvents::channel();
        drop(rx);
        for event in ALL_RUNTIME_EVENTS {
            tx.emit(event);
        }
    }

    #[tokio::test]
    async fn channel_emit_fills_capacity_then_drops() {
        let (tx, mut rx) = RuntimeEvents::channel();
        for _ in 0..(RUNTIME_EVENT_CAPACITY * 2) {
            tx.emit(RuntimeEvent::ShellStarted);
        }
        let mut seen = 0usize;
        while rx.try_recv().is_ok() {
            seen += 1;
        }
        assert_eq!(seen, RUNTIME_EVENT_CAPACITY);
    }
}
