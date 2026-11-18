use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use mender_connect_rust::config;
use nix::unistd::{Uid, User};

struct Fixture {
    inner: tempfile::TempDir,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let inner = tempfile::Builder::new()
            .prefix(&format!("mender-connect-limits-activation-{label}-"))
            .tempdir()
            .unwrap();
        Self { inner }
    }

    fn path(&self) -> &Path {
        self.inner.path()
    }

    fn root(&self) -> PathBuf {
        let root = self.path().join("work");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        root
    }

    fn config_file(&self, name: &str, document: &serde_json::Value) -> PathBuf {
        let path = self.path().join(name);
        fs::write(&path, serde_json::to_vec(document).unwrap()).unwrap();
        path
    }
}

fn current_user_name() -> String {
    User::from_uid(Uid::effective())
        .unwrap()
        .expect("current effective uid must have a passwd entry")
        .name
}

fn base_config(username: &str) -> serde_json::Value {
    serde_json::json!({
        "User": username,
        "ShellCommand": config::DEFAULT_SHELL_COMMAND,
        "ShellArguments": [],
        "Terminal": {"Disable": true},
        "PortForward": {"Disable": true},
        "MenderClient": {"Disable": true},
        "FileTransfer": {"Disable": false}
    })
}

fn load(fixture: &Fixture, document: &serde_json::Value) -> config::Config {
    let primary = fixture.config_file("primary.json", document);
    config::load_config(primary, fixture.path().join("missing-fallback.json")).unwrap()
}

#[test]
fn enabled_limits_validate_owned_root_without_staging_writes() {
    let fixture = Fixture::new("owned-root");
    let root = fixture.root();
    let mut document = base_config(&current_user_name());
    document["Limits"] = serde_json::json!({
        "Enabled": true,
        "FileTransfer": {
            "Chroot": root.to_string_lossy(),
            "Umask": "0022",
            "MaxFileSize": 4096,
            "Counters": {"MaxBytesTxPerMinute": 1, "MaxBytesRxPerMinute": 0}
        }
    });

    let loaded = load(&fixture, &document);
    assert!(loaded.limits_enabled);
    loaded.validate().unwrap();
    assert!(
        fs::read_dir(&root).unwrap().next().is_none(),
        "startup validation must not create staging files"
    );
}

#[test]
fn enabled_limits_reject_missing_root_unknown_identity_and_umask() {
    let fixture = Fixture::new("enabled-errors");
    let root = fixture.root();
    let missing = fixture.path().join("missing-root");
    let cases = [
        serde_json::json!({
            "Enabled": true,
            "FileTransfer": {"Chroot": missing.to_string_lossy()}
        }),
        serde_json::json!({
            "Enabled": true,
            "FileTransfer": {
                "Chroot": root.to_string_lossy(),
                "OwnerPut": "mender-connect-definitely-unknown-owner"
            }
        }),
        serde_json::json!({
            "Enabled": true,
            "FileTransfer": {"Chroot": "relative-root"}
        }),
        serde_json::json!({
            "Enabled": true,
            "FileTransfer": {"Chroot": root.to_string_lossy(), "Umask": "0899"}
        }),
    ];

    for (index, limits) in cases.into_iter().enumerate() {
        let mut document = base_config(&current_user_name());
        document["Limits"] = limits;
        let loaded = load(&fixture, &document);
        assert!(
            loaded.validate().is_err(),
            "enabled limits case {index} must fail closed"
        );
    }
}

#[test]
fn disabled_limits_skip_policy_and_root_work() {
    let fixture = Fixture::new("disabled");
    let mut document = base_config(&current_user_name());
    document["Limits"] = serde_json::json!({
        "Enabled": false,
        "FileTransfer": {
            "Chroot": "/definitely/missing/limits-root",
            "OwnerPut": "mender-connect-definitely-unknown-owner",
            "GroupPut": "mender-connect-definitely-unknown-group",
            "Umask": "not-octal"
        }
    });

    let loaded = load(&fixture, &document);
    assert!(!loaded.limits_enabled);
    loaded.validate().unwrap();
}

#[test]
fn primary_disable_overrides_fallback_enabled_before_root_work() {
    let fixture = Fixture::new("override");
    let fallback = fixture.config_file(
        "fallback.json",
        &serde_json::json!({
            "Limits": {
                "Enabled": true,
                "FileTransfer": {"Chroot": "/definitely/missing/limits-root"}
            }
        }),
    );
    let primary = fixture.config_file(
        "primary.json",
        &serde_json::json!({"Limits": {"Enabled": false}}),
    );
    let mut loaded = config::load_config(primary, fallback).unwrap();
    loaded.user = current_user_name();
    loaded.shell_command = config::DEFAULT_SHELL_COMMAND.to_owned();
    loaded.validate().unwrap();
    assert!(!loaded.limits_enabled);
}

#[test]
fn enabled_limits_still_validate_when_file_transfer_handler_disabled() {
    let fixture = Fixture::new("disabled-handler");
    let mut document = base_config(&current_user_name());
    document["FileTransfer"] = serde_json::json!({"Disable": true});
    document["Limits"] = serde_json::json!({
        "Enabled": true,
        "FileTransfer": {"Chroot": "/definitely/missing/limits-root"}
    });

    let loaded = load(&fixture, &document);
    assert!(loaded.limits_enabled);
    assert!(loaded.file_transfer.disable);
    assert!(loaded.validate().is_err());
}
