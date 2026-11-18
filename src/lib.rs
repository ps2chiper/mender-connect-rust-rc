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
//! Experimental, Linux-only Rust foundation for a mender-connect rewrite.
//!
//! This milestone implements protocol framing, configuration loading, a typed
//! Authentication1 D-Bus client, websocket transport, a small PTY shell
//! building block and a single-session terminal daemon. It deliberately does
//! not implement reconnect supervision, file transfer or port forwarding yet.

pub mod auth;
pub mod backoff;
pub mod config;
pub mod daemon;
pub mod file_transfer_download;
pub mod file_transfer_schema;
pub mod file_transfer_upload;
pub mod limits;
pub mod limits_config;
pub mod limits_fs;
pub mod limits_fs_upload;
pub mod limits_rate;
pub mod logging;
pub mod port_forward;
pub mod port_forward_manager;
pub mod port_forward_worker;
pub mod protocol;
pub mod pty;
pub mod session_helper;
pub mod session_policy;
pub mod session_process;
pub mod session_router;
pub mod shell_policy;
pub mod transport;

pub mod file_transfer_manager;
mod file_transfer_task;
pub mod transfer_limits;

pub mod mender_command;

mod udp_inline;
