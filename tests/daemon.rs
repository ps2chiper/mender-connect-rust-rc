//! Local tests for the pure control-handshake helpers in `daemon`.

use std::time::Duration;

use mender_connect_rust::daemon::{
    SHELL_LIVENESS_TIMEOUT, SHELL_PING_INTERVAL, ShellHealthcheck, control_open, control_pong,
};
use mender_connect_rust::protocol::{
    Accept, Error as ControlError, Open, ProtoHdr, ProtoMsg, ProtoType, decode, encode,
};
use tokio::time::Instant;

fn open_message(sid: &str, versions: Vec<i64>) -> ProtoMsg {
    let body = encode(&Open { versions }).unwrap();
    ProtoMsg {
        header: ProtoHdr {
            proto: ProtoType::CONTROL,
            msg_type: "open".to_owned(),
            session_id: sid.to_owned(),
            properties: Default::default(),
        },
        body,
    }
}

#[test]
fn accepts_version_one_with_shell_protocol() {
    let response = control_open(&open_message("s1", vec![1]), false);
    assert_eq!(response.header.proto, ProtoType::CONTROL);
    assert_eq!(response.header.msg_type, "accept");
    assert_eq!(response.header.session_id, "s1");
    let accept: Accept = decode(&response.body).unwrap();
    assert_eq!(accept.version, 1);
    assert_eq!(accept.protocols, vec![ProtoType::SHELL]);
}

#[test]
fn accepts_version_one_with_no_protocols_when_terminal_disabled() {
    let response = control_open(&open_message("s1", vec![1]), true);
    assert_eq!(response.header.msg_type, "accept");
    let accept: Accept = decode(&response.body).unwrap();
    assert_eq!(accept.version, 1);
    assert!(accept.protocols.is_empty());
}

#[test]
fn rejects_unsupported_version_with_close_error() {
    let response = control_open(&open_message("s1", vec![99]), false);
    assert_eq!(response.header.proto, ProtoType::CONTROL);
    assert_eq!(response.header.msg_type, "error");
    assert_eq!(response.header.session_id, "s1");
    let error: ControlError = decode(&response.body).unwrap();
    assert!(error.close);
}

#[test]
fn rejects_missing_version_with_close_error() {
    let response = control_open(&open_message("s1", vec![]), false);
    assert_eq!(response.header.msg_type, "error");
    let error: ControlError = decode(&response.body).unwrap();
    assert!(error.close);
}

#[test]
fn pong_preserves_session_id() {
    let ping = ProtoMsg {
        header: ProtoHdr {
            proto: ProtoType::CONTROL,
            msg_type: "ping".to_owned(),
            session_id: "abc".to_owned(),
            properties: Default::default(),
        },
        body: Vec::new(),
    };
    let pong = control_pong(&ping);
    assert_eq!(pong.header.proto, ProtoType::CONTROL);
    assert_eq!(pong.header.msg_type, "pong");
    assert_eq!(pong.header.session_id, "abc");
    assert!(pong.body.is_empty());
}

#[test]
fn shell_healthcheck_deadline_boundaries() {
    let now = Instant::now();
    let health = ShellHealthcheck::new(now);
    assert_eq!(health.ping_deadline(), now + SHELL_PING_INTERVAL);
    assert_eq!(health.liveness_deadline(), now + SHELL_LIVENESS_TIMEOUT);
    assert!(!health.is_ping_due(now + SHELL_PING_INTERVAL - Duration::from_millis(1)));
    assert!(health.is_ping_due(now + SHELL_PING_INTERVAL));
    assert!(!health.is_liveness_expired(now + SHELL_LIVENESS_TIMEOUT - Duration::from_millis(1)));
    assert!(health.is_liveness_expired(now + SHELL_LIVENESS_TIMEOUT));
}

#[test]
fn shell_healthcheck_pong_extends_liveness_only() {
    let now = Instant::now();
    let mut health = ShellHealthcheck::new(now);
    let pong_at = now + Duration::from_secs(30);
    health.note_pong(pong_at);
    assert_eq!(health.ping_deadline(), now + SHELL_PING_INTERVAL);
    assert_eq!(health.liveness_deadline(), pong_at + SHELL_LIVENESS_TIMEOUT);
    assert!(!health.is_liveness_expired(now + SHELL_LIVENESS_TIMEOUT));
    assert!(health.is_liveness_expired(pong_at + SHELL_LIVENESS_TIMEOUT));
}

#[test]
fn shell_healthcheck_advance_ping_extends_ping_only() {
    let now = Instant::now();
    let mut health = ShellHealthcheck::new(now);
    let ping_at = now + SHELL_PING_INTERVAL;
    health.advance_ping(ping_at);
    assert_eq!(health.ping_deadline(), ping_at + SHELL_PING_INTERVAL);
    assert_eq!(health.liveness_deadline(), now + SHELL_LIVENESS_TIMEOUT);
}

#[test]
fn shell_healthcheck_fresh_state_resets_deadlines() {
    let first = Instant::now();
    let mut health = ShellHealthcheck::new(first);
    health.note_pong(first + Duration::from_secs(30));
    health.advance_ping(first + Duration::from_secs(60));

    let later = first + Duration::from_secs(120);
    let fresh = ShellHealthcheck::new(later);
    assert_eq!(fresh.ping_deadline(), later + SHELL_PING_INTERVAL);
    assert_eq!(fresh.liveness_deadline(), later + SHELL_LIVENESS_TIMEOUT);
    assert!(!fresh.is_liveness_expired(later + SHELL_LIVENESS_TIMEOUT - Duration::from_millis(1)));
}
