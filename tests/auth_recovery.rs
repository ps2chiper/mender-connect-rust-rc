//! Focused tests for `transport::is_unauthorized_error`.
//!
//! These tests exercise classification of typed tungstenite HTTP errors
//! without touching any bus or network resources.

use mender_connect_rust::transport::is_unauthorized_error;
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::{Error, http::Response};

/// Build an `anyhow::Error` wrapping a typed `Error::Http` response with the
/// given status code and optional body.
fn http_error(status_code: u16, body: Option<Vec<u8>>) -> anyhow::Error {
    let status = StatusCode::from_u16(status_code).expect("valid HTTP status code");
    let response: Response<Option<Vec<u8>>> = Response::builder()
        .status(status)
        .body(body)
        .expect("build http response");
    anyhow::Error::new(Error::Http(Box::new(response)))
}

#[test]
fn direct_401_is_unauthorized() {
    let err = http_error(401, None);
    assert!(
        is_unauthorized_error(&err),
        "bare typed 401 should be unauthorized"
    );
}

#[test]
fn direct_401_with_body_bytes_is_unauthorized() {
    let err = http_error(401, Some(b"Unauthorized".to_vec()));
    assert!(
        is_unauthorized_error(&err),
        "typed 401 with a body should still be unauthorized"
    );
}

#[test]
fn multiple_contexts_preserve_401() {
    let err = http_error(401, None)
        .context("opening websocket")
        .context("reconnecting client");
    assert!(
        is_unauthorized_error(&err),
        "typed 401 wrapped in contexts should remain unauthorized"
    );
}

#[test]
fn multiple_contexts_with_body_preserve_401() {
    let err = http_error(401, Some(b"token expired".to_vec()))
        .context("layer one")
        .context("layer two")
        .context("layer three");
    assert!(
        is_unauthorized_error(&err),
        "typed 401 with body and several contexts should remain unauthorized"
    );
}

#[test]
fn forbidden_403_is_not_unauthorized() {
    let err = http_error(403, None);
    assert!(
        !is_unauthorized_error(&err),
        "typed 403 must not be classified as unauthorized"
    );
}

#[test]
fn server_error_503_is_not_unauthorized() {
    let err = http_error(503, Some(b"unavailable".to_vec()));
    assert!(
        !is_unauthorized_error(&err),
        "typed 503 must not be classified as unauthorized"
    );
}

#[test]
fn plain_message_with_text_is_not_unauthorized() {
    let err = anyhow::anyhow!("request failed with 401 Unauthorized response");
    assert!(
        !is_unauthorized_error(&err),
        "a plain message mentioning 401 must not be classified as unauthorized"
    );
}

#[test]
fn io_error_with_text_is_not_unauthorized() {
    let io = std::io::Error::other("server said 401 Unauthorized");
    let err = anyhow::Error::new(io);
    assert!(
        !is_unauthorized_error(&err),
        "an io::Error mentioning 401 must not be classified as unauthorized"
    );
}

#[test]
fn connection_closed_is_not_unauthorized() {
    let err = anyhow::Error::new(Error::ConnectionClosed);
    assert!(
        !is_unauthorized_error(&err),
        "ConnectionClosed must not be classified as unauthorized"
    );
}
