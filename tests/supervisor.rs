//! Small policy tests for the reconnect supervisor.

use mender_connect_rust::daemon::is_authorized;

#[test]
fn authorization_requires_non_empty_token_and_server() {
    assert!(is_authorized("token", "https://server"));
    assert!(!is_authorized("", "https://server"));
    assert!(!is_authorized("token", ""));
    assert!(!is_authorized("   ", "https://server"));
    assert!(!is_authorized("token", "   "));
    assert!(!is_authorized("", ""));
}
