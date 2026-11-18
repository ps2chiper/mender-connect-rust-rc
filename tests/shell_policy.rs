use std::io;

use mender_connect_rust::shell_policy::{self, MAX_USERNAME_LEN, ShellPolicyError, ShellsRead};

#[test]
fn missing_shells_file_only_allows_default_shell() {
    assert!(shell_policy::check_shell_from("/bin/sh", ShellsRead::Missing).is_ok());
    assert!(shell_policy::check_shell_from("/usr/bin/zsh", ShellsRead::Missing).is_err());
}

#[test]
fn io_and_nonregular_and_oversize_fail_closed() {
    assert!(
        shell_policy::check_shell_from(
            "/bin/sh",
            ShellsRead::IoError(io::ErrorKind::PermissionDenied)
        )
        .is_err()
    );
    assert!(
        shell_policy::check_shell_from("/bin/sh", ShellsRead::IoError(io::ErrorKind::Other))
            .is_err()
    );
    assert!(shell_policy::check_shell_from("/bin/sh", ShellsRead::NotRegular).is_err());
    assert!(shell_policy::check_shell_from("/bin/sh", ShellsRead::Oversize).is_err());
}

#[test]
fn exact_line_matching() {
    assert!(shell_policy::list_contains(b"/bin/sh\n/bin/bash\n", "/bin/sh").unwrap());
    assert!(!shell_policy::list_contains(b"/bin/bash\n", "/bin/sh").unwrap());
    assert!(!shell_policy::list_contains(b"/bin/sh\n", "/bin/sh\r").unwrap());
}

#[test]
fn crlf_lines_are_accepted() {
    assert!(shell_policy::list_contains(b"/bin/sh\r\n/bin/bash\r\n", "/bin/sh").unwrap());
    assert!(shell_policy::list_contains(b"/bin/bash\r", "/bin/bash").unwrap());
}

#[test]
fn comments_blanks_and_whitespace_do_not_match() {
    assert!(!shell_policy::list_contains(b"# /bin/sh\n", "/bin/sh").unwrap());
    assert!(!shell_policy::list_contains(b"\n\n#comment\n", "/bin/sh").unwrap());
    assert!(!shell_policy::list_contains(b" /bin/sh \n", "/bin/sh").unwrap());
    assert!(!shell_policy::list_contains(b"/bin/sh \n", "/bin/sh").unwrap());
}

#[test]
fn malformed_utf8_is_rejected() {
    let error = shell_policy::list_contains(&[0xff, 0xfe], "/bin/sh").unwrap_err();
    assert!(matches!(error, ShellPolicyError::ShellListInvalidUtf8));
}

#[test]
fn oversize_outcome_is_rejected() {
    let error = shell_policy::check_shell_from("/bin/sh", ShellsRead::Oversize).unwrap_err();
    assert!(matches!(error, ShellPolicyError::ShellListOversize));
}

#[test]
fn injected_bytes_enforce_size_cap_at_boundary() {
    let limit = usize::try_from(shell_policy::MAX_SHELLS_FILE_SIZE).unwrap();

    let mut at_limit = b"/bin/sh\n".to_vec();
    at_limit.resize(limit, b'#');
    assert_eq!(at_limit.len(), limit);
    assert!(shell_policy::list_contains(&at_limit, "/bin/sh").unwrap());
    assert!(shell_policy::check_shell_from("/bin/sh", ShellsRead::Bytes(at_limit)).is_ok());

    let mut over_limit = b"/bin/sh\n".to_vec();
    over_limit.resize(limit + 1, b'#');
    assert_eq!(over_limit.len(), limit + 1);
    assert!(matches!(
        shell_policy::list_contains(&over_limit, "/bin/sh").unwrap_err(),
        ShellPolicyError::ShellListOversize
    ));
    assert!(matches!(
        shell_policy::check_shell_from("/bin/sh", ShellsRead::Bytes(over_limit)).unwrap_err(),
        ShellPolicyError::ShellListOversize
    ));
}

#[test]
fn user_prechecks_reject_before_lookup() {
    assert!(shell_policy::validate_user("").is_err());
    assert!(shell_policy::validate_user("   ").is_err());
    assert!(shell_policy::validate_user("bad\0name").is_err());
    let long = "a".repeat(MAX_USERNAME_LEN + 1);
    assert!(shell_policy::validate_user(&long).is_err());
    let current = shell_policy::current_user_name().unwrap();
    assert!(shell_policy::validate_user(&current).is_ok());
}
