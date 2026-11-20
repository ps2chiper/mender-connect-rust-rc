use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use mender_connect_rust::config;

struct TempDir {
    inner: tempfile::TempDir,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let inner = tempfile::Builder::new()
            .prefix(&format!("mender-connect-rust-test-{label}-"))
            .tempdir()
            .unwrap();
        Self { inner }
    }

    fn join(&self, name: &str) -> PathBuf {
        self.inner.path().join(name)
    }
}

fn write_json(directory: &TempDir, name: &str, contents: &str) -> PathBuf {
    let path = directory.join(name);
    fs::write(&path, contents).unwrap();
    path
}

fn current_test_user() -> String {
    mender_connect_rust::shell_policy::current_user_name()
        .expect("current process user must resolve through NSS")
}

#[test]
fn rejects_unknown_and_malformed_users() {
    let directory = TempDir::new("user-validation");

    let mut loaded = config::load_config(
        directory.join("missing-primary.json"),
        directory.join("missing-fallback.json"),
    )
    .unwrap();
    loaded.shell_command = config::DEFAULT_SHELL_COMMAND.to_owned();

    let unique = format!("mender-connect-nonexistent-user-{}", std::process::id());
    loaded.user = unique;
    let error = loaded.validate().unwrap_err();
    let message = format!("{:#}", error);
    assert!(
        message.contains("User"),
        "unknown user must be rejected: {message}"
    );

    loaded.user = "bad\0name".to_owned();
    assert!(loaded.validate().is_err());

    loaded.user = "a".repeat(mender_connect_rust::shell_policy::MAX_USERNAME_LEN + 1);
    assert!(loaded.validate().is_err());
}

#[test]
fn applies_go_compatible_defaults_when_files_are_missing() {
    let directory = TempDir::new("defaults");
    let loaded = config::load_config(
        directory.join("missing-primary.json"),
        directory.join("missing-fallback.json"),
    )
    .unwrap();

    assert!(loaded.user.is_empty());
    assert_eq!(loaded.shell_command, config::DEFAULT_SHELL_COMMAND);
    assert_eq!(loaded.shell_arguments, vec!["--login".to_owned()]);
    assert_eq!(loaded.terminal.width, config::DEFAULT_TERMINAL_WIDTH);
    assert_eq!(loaded.terminal.height, config::DEFAULT_TERMINAL_HEIGHT);
    assert!(!loaded.terminal.disable);
    assert!(loaded.sessions.stop_expired);
    assert_eq!(
        loaded.sessions.expire_after_idle,
        config::DEFAULT_EXPIRE_AFTER_IDLE
    );

    assert!(loaded.validate().is_err());
}

#[test]
fn fallback_is_loaded_before_primary_and_primary_overrides() {
    let directory = TempDir::new("merge");
    let fallback = directory.join("fallback.json");
    let primary = directory.join("primary.json");

    fs::write(
        &fallback,
        r#"{
            "User": "fallback-user",
            "ShellCommand": "/bin/sh",
            "ShellArguments": ["-c"],
            "Terminal": {"Width": 132, "Height": 43, "Disable": true},
            "Sessions": {"StopExpired": false, "MaxPerUser": 2}
        }"#,
    )
    .unwrap();
    fs::write(
        &primary,
        r#"{
            "User": "primary-user",
            "ShellArguments": [],
            "Terminal": {"Height": 50}
        }"#,
    )
    .unwrap();

    let loaded = config::load_config(&primary, &fallback).unwrap();

    assert_eq!(loaded.user, "primary-user");
    assert_eq!(loaded.shell_command, "/bin/sh");
    assert!(loaded.shell_arguments.is_empty());
    assert_eq!(loaded.terminal.width, 132);
    assert_eq!(loaded.terminal.height, 50);
    assert!(loaded.terminal.disable);
    assert!(!loaded.sessions.stop_expired);
    assert_eq!(loaded.sessions.expire_after, 0);
    assert_eq!(loaded.sessions.expire_after_idle, 0);
    assert_eq!(loaded.sessions.max_per_user, 2);
}

#[test]
fn malformed_primary_json_is_an_error_not_a_fallback() {
    let directory = TempDir::new("malformed");
    let fallback = directory.join("fallback.json");
    let primary = directory.join("primary.json");

    fs::write(
        &fallback,
        r#"{"User":"valid-fallback","ShellCommand":"/bin/sh"}"#,
    )
    .unwrap();
    fs::write(&primary, r#"{"User": "#).unwrap();

    let error = config::load_config(&primary, &fallback).unwrap_err();
    assert!(error.to_string().contains("failed to parse"));
}

#[test]
fn validates_user_and_shell_executable() {
    let directory = TempDir::new("validate");
    let mut loaded = config::load_config(
        directory.join("missing-primary.json"),
        directory.join("missing-fallback.json"),
    )
    .unwrap();

    loaded.user = current_test_user();
    loaded.shell_command = config::DEFAULT_SHELL_COMMAND.to_owned();
    loaded.validate().unwrap();

    loaded.user = "   ".to_owned();
    assert!(loaded.validate().is_err());

    loaded.user = current_test_user();
    loaded.shell_command = "relative/shell".to_owned();
    assert!(loaded.validate().is_err());

    loaded.shell_command = "/this/path/does/not/exist/for/mender-connect-rust".to_owned();
    assert!(loaded.validate().is_err());
}

#[test]
fn rejects_directory_as_shell_command() {
    let directory = TempDir::new("shell-directory");
    let shell_directory = directory.join("shell-directory");
    fs::create_dir(&shell_directory).unwrap();
    fs::set_permissions(&shell_directory, fs::Permissions::from_mode(0o755)).unwrap();

    let mut loaded = config::load_config(
        directory.join("missing-primary.json"),
        directory.join("missing-fallback.json"),
    )
    .unwrap();
    loaded.user = current_test_user();
    loaded.shell_command = shell_directory.to_string_lossy().into_owned();

    let error = loaded.validate().unwrap_err();
    assert!(error.to_string().contains("regular file"));
}

#[test]
fn feature_flags_default_to_enabled() {
    let directory = TempDir::new("features-default");
    let loaded = config::load_config(
        directory.join("missing-primary.json"),
        directory.join("missing-fallback.json"),
    )
    .unwrap();

    assert!(!loaded.port_forward.disable);
    assert!(!loaded.file_transfer.disable);
    assert!(!loaded.mender_client.disable);
    assert!(!loaded.limits_enabled);
}

#[test]
fn parses_pascal_case_feature_disable_flags() {
    let directory = TempDir::new("features-parse");
    let primary = directory.join("primary.json");
    fs::write(
        &primary,
        r#"{
            "PortForward": {"Disable": true},
            "FileTransfer": {"Disable": true},
            "MenderClient": {"Disable": true}
        }"#,
    )
    .unwrap();

    let loaded = config::load_config(&primary, directory.join("missing.json")).unwrap();
    assert!(loaded.port_forward.disable);
    assert!(loaded.file_transfer.disable);
    assert!(loaded.mender_client.disable);
}

#[test]
fn primary_false_overrides_fallback_true_per_feature() {
    let directory = TempDir::new("features-merge");
    let fallback = directory.join("fallback.json");
    let primary = directory.join("primary.json");
    fs::write(
        &fallback,
        r#"{
            "PortForward": {"Disable": true},
            "FileTransfer": {"Disable": true},
            "MenderClient": {"Disable": true}
        }"#,
    )
    .unwrap();
    fs::write(&primary, r#"{"PortForward": {"Disable": false}}"#).unwrap();

    let loaded = config::load_config(&primary, &fallback).unwrap();
    assert!(!loaded.port_forward.disable);
    assert!(loaded.file_transfer.disable);
    assert!(loaded.mender_client.disable);
}

#[test]
fn limits_enabled_true_accepts_valid_policy() {
    let directory = TempDir::new("limits-enabled");
    let root = directory.join("limits-root");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let primary = directory.join("primary.json");
    let document = serde_json::json!({
        "Limits": {
            "Enabled": true,
            "FileTransfer": {
                "Chroot": root.to_string_lossy(),
                "Umask": "0022",
                "MaxFileSize": 1048576,
                "Counters": {
                    "MaxBytesTxPerMinute": 1,
                    "MaxBytesRxPerMinute": 0
                }
            }
        }
    });
    fs::write(&primary, serde_json::to_vec(&document).unwrap()).unwrap();

    let mut loaded = config::load_config(&primary, directory.join("missing.json")).unwrap();
    assert!(loaded.limits_enabled);
    loaded.user = current_test_user();
    loaded.shell_command = config::DEFAULT_SHELL_COMMAND.to_owned();

    loaded.validate().unwrap();
}

#[test]
fn limits_enabled_false_is_accepted() {
    let directory = TempDir::new("limits-disabled");
    let primary = directory.join("primary.json");
    fs::write(&primary, r#"{"Limits": {"Enabled": false}}"#).unwrap();

    let mut loaded = config::load_config(&primary, directory.join("missing.json")).unwrap();
    assert!(!loaded.limits_enabled);
    loaded.user = current_test_user();
    loaded.shell_command = config::DEFAULT_SHELL_COMMAND.to_owned();
    loaded.validate().unwrap();
}

#[test]
fn rejects_configuration_files_over_the_size_limit() {
    let directory = TempDir::new("oversized");
    let primary = directory.join("primary.json");
    let data = vec![b' '; config::MAX_CONFIG_FILE_SIZE as usize + 1];
    fs::write(&primary, data).unwrap();

    let error = config::load_config(&primary, directory.join("missing.json")).unwrap_err();
    assert!(error.to_string().contains("exceeds"));
}

#[test]
fn accepts_lower_and_mixed_case_keys_at_all_levels() {
    let directory = TempDir::new("case-insensitive");
    let fallback = write_json(
        &directory,
        "fallback.json",
        r#"{
            "User": "fallback-user",
            "ShellCommand": "/bin/false",
            "Terminal": {"Width": 80, "Height": 40, "Disable": false},
            "Sessions": {"StopExpired": true, "ExpireAfterIdle": 600},
            "PortForward": {"Disable": false},
            "FileTransfer": {"Disable": false},
            "MenderClient": {"Disable": false}
        }"#,
    );
    let primary = write_json(
        &directory,
        "primary.json",
        r#"{
            "uSer": "primary-user",
            "shellcommand": "/bin/sh",
            "TERMINAL": {"wIdth": 120, "height": 50, "DISABLE": true},
            "sessions": {"stopexpired": false, "expireafteridle": 0},
            "portforward": {"disable": true},
            "fileTransfer": {"DISABLE": true},
            "menderclient": {"disable": true}
        }"#,
    );

    let loaded = config::load_config(&primary, &fallback).unwrap();
    assert_eq!(loaded.user, "primary-user");
    assert_eq!(loaded.shell_command, "/bin/sh");
    assert_eq!(loaded.terminal.width, 120);
    assert_eq!(loaded.terminal.height, 50);
    assert!(loaded.terminal.disable);
    assert!(!loaded.sessions.stop_expired);
    assert_eq!(loaded.sessions.expire_after, 0);
    assert_eq!(loaded.sessions.expire_after_idle, 0);
    assert!(loaded.port_forward.disable);
    assert!(loaded.file_transfer.disable);
    assert!(loaded.mender_client.disable);
}

#[test]
fn lowercase_limits_enabled_true_compiles_valid_policy() {
    let directory = TempDir::new("limits-lower-true");
    let root = directory.join("limits-root");
    fs::create_dir(&root).unwrap();
    let document = serde_json::json!({
        "limits": {
            "enabled": true,
            "fileTransfer": {
                "chroot": root.to_string_lossy(),
                "followSymLinks": true,
                "umask": "0027"
            }
        }
    });
    let primary = write_json(
        &directory,
        "primary.json",
        &serde_json::to_string(&document).unwrap(),
    );

    let mut loaded = config::load_config(&primary, directory.join("missing.json")).unwrap();
    assert!(loaded.limits_enabled);
    loaded.user = current_test_user();
    loaded.shell_command = config::DEFAULT_SHELL_COMMAND.to_owned();

    loaded.validate().unwrap();
}

#[test]
fn fallback_limits_enabled_true_primary_false_disables_gate() {
    let directory = TempDir::new("limits-override-false");
    let fallback = write_json(
        &directory,
        "fallback.json",
        r#"{"Limits": {"enabled": true}}"#,
    );
    let primary = write_json(
        &directory,
        "primary.json",
        r#"{"limits": {"enabled": false}}"#,
    );

    let mut loaded = config::load_config(&primary, &fallback).unwrap();
    assert!(!loaded.limits_enabled);
    loaded.user = current_test_user();
    loaded.shell_command = config::DEFAULT_SHELL_COMMAND.to_owned();
    loaded.validate().unwrap();
}

#[test]
fn unknown_fields_are_rejected() {
    let directory = TempDir::new("unknown-fields");
    let cases = [
        r#"{"Termnial": {}}"#,
        r#"{"Terminal": {"Disabel": true}}"#,
        r#"{"PortForward": {"Disabel": true}}"#,
        r#"{"FileTransfer": {"Disabel": true}}"#,
        r#"{"MenderClient": {"Disabel": true}}"#,
        r#"{"Sessions": {"StopExpird": true}}"#,
        r#"{"Limits": {"Enabeld": true}}"#,
        r#"{"Limits": {"Enabled": false, "FileTransfer": {"UnknownPolicy": true}}}"#,
        r#"{"Servers": [{"UnknownServerField": true}]}"#,
        r#"{"UnknownRoot": 1}"#,
        r#"{"PortForward": {"UnknownOption": true}}"#,
        r#"{"HttpsClient": {"Certficate": "x"}}"#,
    ];

    for (index, contents) in cases.into_iter().enumerate() {
        let primary = write_json(&directory, &format!("case-{index}.json"), contents);
        let error = config::load_config(&primary, directory.join("missing.json")).unwrap_err();
        assert!(
            format!("{:#}", error).contains("unknown field"),
            "case {index} did not report unknown field: {:#}",
            error
        );
    }
}

#[test]
fn duplicate_keys_are_rejected_even_with_case_variants() {
    let directory = TempDir::new("duplicates");
    let cases = [
        r#"{"User": "a", "User": "b"}"#,
        r#"{"User": "a", "user": "b"}"#,
        r#"{"User": "a", "\u0075ser": "b"}"#,
        r#"{"Terminal": {"Disable": true, "disable": false}}"#,
        r#"{"Terminal": {}, "terminal": {}}"#,
        r#"{"Servers": [{"ServerURL": "a", "serverurl": "b"}]}"#,
        r#"{"Limits": {"FileTransfer": {"Counters": {"MaxBytesTxPerMinute": 1, "maxbytestxperminute": 2}}}}"#,
        r#"{"TotallyUnknown": 1, "TotallyUnknown": 2}"#,
    ];

    for (index, contents) in cases.into_iter().enumerate() {
        let primary = write_json(&directory, &format!("dup-{index}.json"), contents);
        let error = config::load_config(&primary, directory.join("missing.json")).unwrap_err();
        assert!(
            format!("{:#}", error).contains("duplicate configuration key"),
            "case {index} did not report duplicate: {:#}",
            error
        );
    }
}

#[test]
fn same_key_in_distinct_objects_and_files_is_allowed() {
    let directory = TempDir::new("distinct-objects");
    let fallback = write_json(
        &directory,
        "fallback.json",
        r#"{"User": "fallback", "Terminal": {"Width": 90}}"#,
    );
    let primary = write_json(
        &directory,
        "primary.json",
        r#"{"User": "primary", "Sessions": {"StopExpired": true}, "PortForward": {"Disable": true}}"#,
    );

    let loaded = config::load_config(&primary, &fallback).unwrap();
    assert_eq!(loaded.user, "primary");
    assert_eq!(loaded.terminal.width, 90);
    assert!(loaded.port_forward.disable);
}

#[test]
fn deprecated_go_fields_are_accepted_and_ignored() {
    let directory = TempDir::new("deprecated");
    let primary = write_json(
        &directory,
        "primary.json",
        r#"{
            "ServerURL": "https://example.invalid",
            "Servers": [{"ServerURL": "https://a.invalid"}, null],
            "ClientProtocol": "https",
            "HttpsClient": {"Certificate": "dummy-cert", "Key": "dummy-key", "SSLEngine": "tls"},
            "SkipVerify": true,
            "ServerCertificate": "dummy-server-cert",
            "ReconnectIntervalSeconds": 123
        }"#,
    );

    let loaded = config::load_config(&primary, directory.join("missing.json")).unwrap();
    assert!(!loaded.port_forward.disable);
    assert!(!loaded.file_transfer.disable);
    assert!(!loaded.mender_client.disable);
    assert!(!loaded.limits_enabled);
    assert_eq!(loaded.shell_command, config::DEFAULT_SHELL_COMMAND);

    let servers_null = write_json(&directory, "servers-null.json", r#"{"Servers": [null]}"#);
    config::load_config(&servers_null, directory.join("missing.json")).unwrap();
}

#[test]
fn limits_disabled_accepts_full_go_file_transfer_policy() {
    let directory = TempDir::new("limits-disabled-full");
    let primary = write_json(
        &directory,
        "primary.json",
        r#"{
            "Limits": {
                "Enabled": false,
                "FileTransfer": {
                    "Chroot": "/srv",
                    "FollowSymLinks": true,
                    "AllowOverwrite": false,
                    "OwnerPut": "root",
                    "GroupPut": "root",
                    "OwnerGet": ["root", "user"],
                    "GroupGet": ["root"],
                    "Umask": "0022",
                    "MaxFileSize": 1048576,
                    "Counters": {"MaxBytesTxPerMinute": 1000, "MaxBytesRxPerMinute": 2000},
                    "AllowSuid": false,
                    "RegularFilesOnly": true,
                    "PreserveMode": true,
                    "PreserveOwner": true
                }
            }
        }"#,
    );

    let mut loaded = config::load_config(&primary, directory.join("missing.json")).unwrap();
    assert!(!loaded.limits_enabled);
    assert!(!loaded.port_forward.disable);
    assert!(!loaded.file_transfer.disable);
    assert!(!loaded.mender_client.disable);
    loaded.user = current_test_user();
    loaded.shell_command = config::DEFAULT_SHELL_COMMAND.to_owned();
    loaded.validate().unwrap();
}

#[test]
fn wrong_types_in_ignored_fields_are_rejected() {
    let directory = TempDir::new("wrong-types");
    let cases = [
        r#"{"ReconnectIntervalSeconds": "soon"}"#,
        r#"{"Servers": {}}"#,
        r#"{"HttpsClient": {"Key": 5}}"#,
        r#"{"Limits": {"Enabled": false, "FileTransfer": {"Counters": {"MaxBytesTxPerMinute": -1}}}}"#,
        r#"{"PortForward": {"IgnoredCompat": true}}"#,
    ];

    for (index, contents) in cases.into_iter().enumerate() {
        let primary = write_json(&directory, &format!("wrong-{index}.json"), contents);
        assert!(
            config::load_config(&primary, directory.join("missing.json")).is_err(),
            "case {index} should be rejected: {contents}"
        );
    }
}

#[test]
fn shell_arguments_null_and_empty_semantics() {
    let directory = TempDir::new("shell-args-null");
    let fallback = write_json(
        &directory,
        "fallback.json",
        r#"{"ShellArguments": ["-c", "echo"]}"#,
    );

    let primary_null = write_json(
        &directory,
        "primary-null.json",
        r#"{"ShellArguments": null}"#,
    );
    let loaded = config::load_config(&primary_null, &fallback).unwrap();
    assert_eq!(loaded.shell_arguments, vec!["--login".to_owned()]);

    let primary_empty = write_json(
        &directory,
        "primary-empty.json",
        r#"{"ShellArguments": []}"#,
    );
    let loaded = config::load_config(&primary_empty, &fallback).unwrap();
    assert!(loaded.shell_arguments.is_empty());

    let primary_missing = write_json(&directory, "primary-missing.json", r#"{"User": "x"}"#);
    let loaded = config::load_config(&primary_missing, &fallback).unwrap();
    assert_eq!(
        loaded.shell_arguments,
        vec!["-c".to_owned(), "echo".to_owned()]
    );

    let fallback_null = write_json(
        &directory,
        "fallback-null.json",
        r#"{"ShellArguments": null}"#,
    );
    let primary_user = write_json(&directory, "primary-user.json", r#"{"User": "x"}"#);
    let loaded = config::load_config(&primary_user, &fallback_null).unwrap();
    assert_eq!(loaded.shell_arguments, vec!["--login".to_owned()]);

    let primary_mixed = write_json(
        &directory,
        "primary-mixed.json",
        r#"{"shellarguments": null}"#,
    );
    let loaded = config::load_config(&primary_mixed, &fallback).unwrap();
    assert_eq!(loaded.shell_arguments, vec!["--login".to_owned()]);
}

#[test]
fn null_values_do_not_override_fallback() {
    let directory = TempDir::new("null-preserve");
    let fallback = write_json(
        &directory,
        "fallback.json",
        r#"{
            "User": "fallback-user",
            "Terminal": {"Width": 100, "Disable": true},
            "Sessions": {"StopExpired": false},
            "PortForward": {"Disable": true},
            "FileTransfer": {"Disable": true},
            "MenderClient": {"Disable": true}
        }"#,
    );
    let primary = write_json(
        &directory,
        "primary.json",
        r#"{
            "User": null,
            "Terminal": null,
            "Sessions": null,
            "PortForward": null,
            "FileTransfer": null,
            "MenderClient": null
        }"#,
    );

    let loaded = config::load_config(&primary, &fallback).unwrap();
    assert_eq!(loaded.user, "fallback-user");
    assert_eq!(loaded.terminal.width, 100);
    assert!(loaded.terminal.disable);
    assert!(!loaded.sessions.stop_expired);
    assert!(loaded.port_forward.disable);
    assert!(loaded.file_transfer.disable);
    assert!(loaded.mender_client.disable);
}

#[test]
fn top_level_null_primary_preserves_fallback() {
    let directory = TempDir::new("root-null");
    let fallback = write_json(
        &directory,
        "fallback.json",
        r#"{"User": "fallback-user", "Terminal": {"Width": 111}}"#,
    );
    let primary = write_json(&directory, "primary.json", "null");

    let loaded = config::load_config(&primary, &fallback).unwrap();
    assert_eq!(loaded.user, "fallback-user");
    assert_eq!(loaded.terminal.width, 111);
}

#[test]
fn invalid_shell_argument_types_are_rejected() {
    let directory = TempDir::new("shell-arg-types");
    let cases = [
        r#"{"ShellArguments": ["ok", 5]}"#,
        r#"{"ShellArguments": "/bin/sh"}"#,
    ];

    for (index, contents) in cases.into_iter().enumerate() {
        let primary = write_json(&directory, &format!("args-{index}.json"), contents);
        assert!(
            config::load_config(&primary, directory.join("missing.json")).is_err(),
            "case {index} should be rejected: {contents}"
        );
    }
}

#[test]
fn malformed_shapes_are_rejected() {
    let directory = TempDir::new("malformed-shapes");
    let cases = [
        r#"[]"#,
        r#"[{"User": "x"}]"#,
        r#"["user", "/bin/sh", [], null, null, null, null, null, null, null, null, null, null, null, null, null]"#,
        r#"{"Terminal": [80, 40, true]}"#,
        r#"{"Sessions": [false, 0, 0, 0]}"#,
        r#"{"PortForward": [true]}"#,
        r#"{"FileTransfer": [true]}"#,
        r#"{"MenderClient": [true]}"#,
        r#"{"Limits": [false, null]}"#,
        r#"{"HttpsClient": ["cert", "key", "engine"]}"#,
        r#"{"Limits": {"FileTransfer": {"Counters": [1, 2]}}}"#,
        r#"{"Servers": [["https://a"]]}"#,
    ];

    for (index, contents) in cases.into_iter().enumerate() {
        let primary = write_json(&directory, &format!("shape-{index}.json"), contents);
        assert!(
            config::load_config(&primary, directory.join("missing.json")).is_err(),
            "case {index} should be rejected: {contents}"
        );
    }
}

#[test]
fn accepts_file_at_exact_size_limit() {
    let directory = TempDir::new("size-boundary");
    let primary = directory.join("primary.json");

    let total = usize::try_from(config::MAX_CONFIG_FILE_SIZE).unwrap();
    let mut data = vec![b' '; total];
    data[0] = b'{';
    data[1] = b'}';
    assert_eq!(data.len(), total);
    fs::write(&primary, &data).unwrap();

    let loaded = config::load_config(&primary, directory.join("missing.json")).unwrap();
    assert_eq!(loaded.shell_command, config::DEFAULT_SHELL_COMMAND);
}

#[test]
fn trailing_tokens_are_rejected() {
    let directory = TempDir::new("trailing");
    let primary = write_json(&directory, "primary.json", r#"{"User": "x"} {"User": "y"}"#);

    let error = config::load_config(&primary, directory.join("missing.json")).unwrap_err();
    assert!(format!("{:#}", error).contains("trailing"));
}

#[test]
fn excessive_nesting_is_rejected() {
    let directory = TempDir::new("deep-nesting");
    let depth = 200;
    let mut nested = String::new();
    for _ in 0..depth {
        nested.push('[');
    }
    for _ in 0..depth {
        nested.push(']');
    }
    let primary = write_json(&directory, "primary.json", &nested);

    let error = config::load_config(&primary, directory.join("missing.json")).unwrap_err();
    let message = format!("{:#}", error);
    assert!(
        message.contains("nesting") || message.contains("recursion") || message.contains("depth"),
        "unexpected nesting error: {message}"
    );
}

#[test]
fn null_cannot_clear_fallback_security_switches() {
    let directory = TempDir::new("null-security");
    let fallback = write_json(
        &directory,
        "fallback.json",
        r#"{
        "Terminal":{"Disable":true},"PortForward":{"Disable":true},
        "FileTransfer":{"Disable":true},"MenderClient":{"Disable":true},
        "Limits":{"Enabled":true}
    }"#,
    );
    let cases = [
        r#"{"limits":null,"terminal":null,"portforward":null,"filetransfer":null,"menderclient":null}"#,
        r#"{"limits":{"enabled":null},"terminal":{"disable":null},"portforward":{"disable":null},"filetransfer":{"disable":null},"menderclient":{"disable":null}}"#,
    ];
    for (index, primary) in cases.into_iter().enumerate() {
        let path = write_json(&directory, &format!("primary-{index}.json"), primary);
        let loaded = config::load_config(path, &fallback).unwrap();
        assert!(loaded.terminal.disable);
        assert!(loaded.port_forward.disable);
        assert!(loaded.file_transfer.disable);
        assert!(loaded.mender_client.disable);
        assert!(loaded.limits_enabled);
        let error = loaded.validate().unwrap_err();
        assert!(
            error.to_string().contains("User"),
            "null override must not bypass enabled limits validation: {error:#}"
        );
        assert!(!error.to_string().contains("Limits"));
    }
}

#[test]
fn enabled_limits_reject_unknown_owner_and_group() {
    let directory = TempDir::new("limits-unknown-owner");
    let root = directory.join("limits-root");
    fs::create_dir(&root).unwrap();
    for (index, field) in ["OwnerPut", "GroupPut"].into_iter().enumerate() {
        let document = serde_json::json!({
            "Limits": {
                "Enabled": true,
                "FileTransfer": {
                    "Chroot": root.to_string_lossy(),
                    (field): "mender-connect-definitely-unknown-identity"
                }
            }
        });
        let primary = write_json(
            &directory,
            &format!("unknown-{index}.json"),
            &serde_json::to_string(&document).unwrap(),
        );
        let mut loaded = config::load_config(&primary, directory.join("missing.json")).unwrap();
        loaded.user = current_test_user();
        loaded.shell_command = config::DEFAULT_SHELL_COMMAND.to_owned();
        let error = loaded.validate().unwrap_err();
        let message = format!("{:#}", error);
        assert!(
            message.contains("owner") || message.contains("group"),
            "unexpected unknown identity error: {message}"
        );
    }
}

#[test]
fn enabled_limits_reject_unusable_root_and_bad_umask() {
    let directory = TempDir::new("limits-root-umask");
    let missing_root = directory.join("does-not-exist");
    let cases = [
        serde_json::json!({
            "Limits": {
                "Enabled": true,
                "FileTransfer": {"Chroot": missing_root.to_string_lossy()}
            }
        }),
        serde_json::json!({
            "Limits": {
                "Enabled": true,
                "FileTransfer": {"Chroot": "relative-root"}
            }
        }),
        serde_json::json!({
            "Limits": {
                "Enabled": true,
                "FileTransfer": {"Umask": "0899"}
            }
        }),
    ];
    for (index, document) in cases.into_iter().enumerate() {
        let primary = write_json(
            &directory,
            &format!("case-{index}.json"),
            &serde_json::to_string(&document).unwrap(),
        );
        let mut loaded = config::load_config(&primary, directory.join("missing.json")).unwrap();
        loaded.user = current_test_user();
        loaded.shell_command = config::DEFAULT_SHELL_COMMAND.to_owned();
        assert!(
            loaded.validate().is_err(),
            "case {index} must reject an unusable enabled limits policy"
        );
    }
}

#[test]
fn disabled_limits_do_not_resolve_nss_or_open_root() {
    let directory = TempDir::new("limits-disabled-no-work");
    let document = serde_json::json!({
        "Limits": {
            "Enabled": false,
            "FileTransfer": {
                "Chroot": "/definitely/missing/limits-root",
                "OwnerPut": "mender-connect-definitely-unknown-identity",
                "GroupPut": "mender-connect-definitely-unknown-group",
                "Umask": "not-octal"
            }
        }
    });
    let primary = write_json(
        &directory,
        "primary.json",
        &serde_json::to_string(&document).unwrap(),
    );
    let mut loaded = config::load_config(&primary, directory.join("missing.json")).unwrap();
    loaded.user = current_test_user();
    loaded.shell_command = config::DEFAULT_SHELL_COMMAND.to_owned();
    loaded.validate().unwrap();
}

// Append to an integration test module that imports config::load_config.
#[cfg(unix)]
#[test]
fn fifo_config_is_rejected_without_blocking() -> anyhow::Result<()> {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    const CHILD: &str = "MENDER_CONFIG_FIFO_CHILD";
    const MARKER: &str = "MENDER_CONFIG_FIFO_MARKER";
    const PRIMARY: &str = "MENDER_CONFIG_VALID_PRIMARY";
    if let Some(path) = std::env::var_os(CHILD) {
        let missing = std::path::Path::new(&path).with_extension("missing");
        let error = if let Some(primary) = std::env::var_os(PRIMARY) {
            mender_connect_rust::config::load_config(primary, &path)
                .expect_err("FIFO fallback rejected")
        } else {
            mender_connect_rust::config::load_config(&path, missing).expect_err("FIFO rejected")
        };
        assert!(format!("{error:#}").contains("not a regular file"));
        std::fs::write(
            std::env::var_os(MARKER).ok_or_else(|| anyhow::anyhow!("missing marker path"))?,
            b"completed",
        )?;
        return Ok(());
    }
    let dir = tempfile::tempdir()?;
    let fifo = dir.path().join("fifo");
    nix::unistd::mkfifo(
        &fifo,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )?;
    let fifo_link = dir.path().join("fifo-link");
    std::os::unix::fs::symlink(&fifo, &fifo_link)?;
    let valid = dir.path().join("valid.json");
    std::fs::write(&valid, br#"{"User":"fifo-test-user"}"#)?;
    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    for (index, (config, fallback)) in [
        (fifo.as_path(), false),
        (fifo.as_path(), true),
        (fifo_link.as_path(), false),
        (dir.path(), false),
    ]
    .into_iter()
    .enumerate()
    {
        let marker = dir.path().join(format!("completed-{index}"));
        let mut command = Command::new(std::env::current_exe()?);
        command.env_remove(PRIMARY);
        if fallback {
            command.env(PRIMARY, &valid);
        }
        let mut child = ChildGuard(
            command
                .args([
                    "--exact",
                    "fifo_config_is_rejected_without_blocking",
                    "--nocapture",
                ])
                .env(CHILD, config)
                .env(MARKER, &marker)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(status) = child.0.try_wait()? {
                assert!(status.success(), "FIFO child failed");
                assert_eq!(std::fs::read(&marker)?, b"completed");
                break;
            }
            if Instant::now() >= deadline {
                anyhow::bail!("FIFO config loading blocked");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let regular_link = dir.path().join("regular-link");
    std::os::unix::fs::symlink(&valid, &regular_link)?;
    let missing = dir.path().join("missing");
    assert_eq!(
        mender_connect_rust::config::load_config(&regular_link, &missing)?.user,
        "fifo-test-user"
    );
    let dangling = dir.path().join("dangling");
    std::os::unix::fs::symlink(&missing, &dangling)?;
    mender_connect_rust::config::load_config(&dangling, &missing)?;
    Ok(())
}

#[test]
fn port_forward_destination_lists_inherit_replace_and_reject_invalid_rules() {
    let dir = TempDir::new("forward-rules");
    let fallback = write_json(
        &dir,
        "fallback",
        r#"{"PortForward":{"AllowedDestinations":[{"Address":"::1","Protocol":"udp","Port":53}]}}"#,
    );
    let primary = write_json(&dir, "primary", r#"{"portforward":{"disable":false}}"#);
    let inherited = config::load_config(&primary, &fallback).unwrap();
    let rules = inherited.port_forward.allowed_destinations.unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].address, std::net::Ipv6Addr::LOCALHOST);
    assert_eq!(
        rules[0].protocol,
        mender_connect_rust::port_forward::Network::Udp
    );
    fs::write(&primary, r#"{"PortForward":{"AllowedDestinations":[]}}"#).unwrap();
    assert_eq!(
        config::load_config(&primary, &fallback)
            .unwrap()
            .port_forward
            .allowed_destinations,
        Some(vec![])
    );
    for invalid in [
        "null",
        r#"[{"Address":"localhost","Protocol":"tcp","Port":22}]"#,
        r#"[{"Address":"::1","Protocol":"tcp","Port":0}]"#,
        r#"[{"Address":"::1","Protocol":"any","Port":53}]"#,
    ] {
        fs::write(
            &primary,
            format!(r#"{{"PortForward":{{"AllowedDestinations":{invalid}}}}}"#),
        )
        .unwrap();
        assert!(
            config::load_config(&primary, &fallback).is_err(),
            "{invalid}"
        );
    }
}
