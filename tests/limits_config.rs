use std::cell::Cell;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use mender_connect_rust::config;
use mender_connect_rust::limits::{DownloadInput, FileFacts, LimitsError, UploadInput};
use mender_connect_rust::limits_config::{
    ConfigLimitsError, NssResolver, RawFileTransferLimits, RawRateLimits, ResolverError,
    build_policy, resolve_peer_path,
};

/// Injected resolver used only by tests. It counts lookups so a disabled build
/// can be proven to perform no NSS work, and can be configured to fail.
#[derive(Default)]
struct TestResolver {
    users: HashMap<String, u32>,
    groups: HashMap<String, u32>,
    calls: Cell<usize>,
    fail: bool,
}

impl TestResolver {
    fn new() -> Self {
        Self::default()
    }

    fn user(mut self, name: &str, id: u32) -> Self {
        self.users.insert(name.to_owned(), id);
        self
    }

    fn group(mut self, name: &str, id: u32) -> Self {
        self.groups.insert(name.to_owned(), id);
        self
    }

    fn failing() -> Self {
        Self {
            fail: true,
            ..Default::default()
        }
    }

    fn calls(&self) -> usize {
        self.calls.get()
    }
}

impl NssResolver for TestResolver {
    fn lookup_user(&self, name: &str) -> Result<Option<u32>, ResolverError> {
        self.calls.set(self.calls.get() + 1);
        if self.fail {
            return Err(ResolverError::LookupFailed);
        }
        Ok(self.users.get(name).copied())
    }

    fn lookup_group(&self, name: &str) -> Result<Option<u32>, ResolverError> {
        self.calls.set(self.calls.get() + 1);
        if self.fail {
            return Err(ResolverError::LookupFailed);
        }
        Ok(self.groups.get(name).copied())
    }
}

fn facts(uid: u32, gid: u32, size: u64, is_regular: bool, is_symlink: bool) -> FileFacts {
    FileFacts {
        owner_uid: uid,
        owner_gid: gid,
        size,
        is_regular,
        is_symlink,
    }
}

#[test]
fn disabled_policy_skips_nss_lookups() {
    let resolver = TestResolver::failing();
    let raw = RawFileTransferLimits {
        owner_put: Some("root".to_owned()),
        group_put: Some("root".to_owned()),
        owner_get: Some(vec!["root".to_owned()]),
        ..Default::default()
    };
    let policy = build_policy(false, &raw, &resolver).expect("disabled policy compiles");
    assert!(!policy.is_enabled());
    assert_eq!(resolver.calls(), 0, "disabled build must not consult NSS");
}

#[test]
fn enabled_policy_reflects_fields_and_counters() {
    let resolver = TestResolver::new().user("alice", 1000).group("staff", 100);
    let raw = RawFileTransferLimits {
        chroot: None,
        follow_sym_links: Some(true),
        allow_overwrite: Some(true),
        owner_put: Some("alice".to_owned()),
        group_put: Some("staff".to_owned()),
        owner_get: Some(vec!["alice".to_owned()]),
        group_get: Some(vec!["staff".to_owned()]),
        umask: Some("0022".to_owned()),
        max_file_size: Some(1024),
        counters: Some(RawRateLimits {
            max_bytes_tx_per_minute: Some(1000),
            max_bytes_rx_per_minute: Some(2000),
        }),
        allow_suid: Some(false),
        regular_files_only: Some(true),
        preserve_mode: Some(false),
        preserve_owner: Some(false),
    };
    let policy = build_policy(true, &raw, &resolver).expect("enabled policy compiles");
    assert!(policy.is_enabled());
    assert_eq!(policy.max_bytes_tx_per_minute(), Some(1000));
    assert_eq!(policy.max_bytes_rx_per_minute(), Some(2000));
    assert!(resolver.calls() > 0);
}

#[test]
fn follow_symlinks_flag_is_reflected() {
    let resolver = TestResolver::new();
    let allow = RawFileTransferLimits {
        follow_sym_links: Some(true),
        ..Default::default()
    };
    let policy = build_policy(true, &allow, &resolver).expect("policy");
    let input = DownloadInput {
        source_path: "/x",
        facts: facts(0, 0, 0, true, true),
    };
    assert!(policy.check_download(&input).is_ok());

    let deny = RawFileTransferLimits {
        follow_sym_links: Some(false),
        ..Default::default()
    };
    let policy = build_policy(true, &deny, &resolver).expect("policy");
    assert_eq!(
        policy.check_download(&input),
        Err(LimitsError::FollowLinksForbidden)
    );
}

#[test]
fn overwrite_and_owner_put_are_reflected() {
    let resolver = TestResolver::new().user("alice", 1000);
    let raw = RawFileTransferLimits {
        allow_overwrite: Some(true),
        owner_put: Some("alice".to_owned()),
        ..Default::default()
    };
    let policy = build_policy(true, &raw, &resolver).expect("policy");
    let ok = UploadInput {
        target_path: "/x",
        declared_size: None,
        mode: None,
        requested_uid: None,
        requested_gid: None,
        existing: Some(facts(1000, 0, 10, true, false)),
    };
    assert!(policy.check_upload(&ok).is_ok());

    let mismatch = UploadInput {
        existing: Some(facts(2000, 0, 10, true, false)),
        ..ok.clone()
    };
    assert_eq!(
        policy.check_upload(&mismatch),
        Err(LimitsError::FileOwnerMismatch)
    );
}

#[test]
fn umask_is_applied_as_ceiling() {
    let resolver = TestResolver::new();
    let raw = RawFileTransferLimits {
        umask: Some("0022".to_owned()),
        ..Default::default()
    };
    let policy = build_policy(true, &raw, &resolver).expect("policy");
    let input = UploadInput {
        target_path: "/x",
        declared_size: None,
        mode: Some(0o777),
        requested_uid: None,
        requested_gid: None,
        existing: None,
    };
    let plan = policy.check_upload(&input).expect("upload accepted");
    assert_eq!(plan.mode, Some(0o755));
}

#[test]
fn explicit_false_preserve_is_forced_true() {
    let resolver = TestResolver::new();
    let raw = RawFileTransferLimits {
        preserve_mode: Some(false),
        preserve_owner: Some(false),
        ..Default::default()
    };
    // The raw value keeps the explicit `false` (observable).
    assert_eq!(raw.preserve_mode, Some(false));
    assert_eq!(raw.preserve_owner, Some(false));

    let policy = build_policy(true, &raw, &resolver).expect("policy");
    let input = UploadInput {
        target_path: "/x",
        declared_size: None,
        mode: Some(0o644),
        requested_uid: Some(1234),
        requested_gid: Some(5678),
        existing: None,
    };
    let plan = policy.check_upload(&input).expect("upload accepted");
    // Upstream `applyDefaults` forces PreserveMode/PreserveOwner true.
    assert_eq!(plan.mode, Some(0o644));
    assert_eq!(plan.ownership.uid, Some(1234));
    assert_eq!(plan.ownership.gid, Some(5678));
}

#[test]
fn allow_lists_and_regular_files_only_are_reflected() {
    let resolver = TestResolver::new().user("alice", 1000).group("staff", 100);
    let raw = RawFileTransferLimits {
        owner_get: Some(vec!["alice".to_owned()]),
        group_get: Some(vec!["staff".to_owned()]),
        regular_files_only: Some(true),
        ..Default::default()
    };
    let policy = build_policy(true, &raw, &resolver).expect("policy");
    let ok = DownloadInput {
        source_path: "/x",
        facts: facts(1000, 100, 0, true, false),
    };
    assert!(policy.check_download(&ok).is_ok());
    let bad_owner = DownloadInput {
        source_path: "/x",
        facts: facts(2000, 100, 0, true, false),
    };
    assert_eq!(
        policy.check_download(&bad_owner),
        Err(LimitsError::FileOwnerMismatch)
    );
    let not_regular = DownloadInput {
        source_path: "/x",
        facts: facts(1000, 100, 0, false, false),
    };
    assert_eq!(
        policy.check_download(&not_regular),
        Err(LimitsError::NotRegularFile)
    );
}

#[test]
fn allow_suid_is_reflected() {
    let resolver = TestResolver::new();
    let deny = RawFileTransferLimits {
        allow_suid: Some(false),
        ..Default::default()
    };
    let policy = build_policy(true, &deny, &resolver).expect("policy");
    let input = UploadInput {
        target_path: "/x",
        declared_size: None,
        mode: Some(0o4755),
        requested_uid: None,
        requested_gid: None,
        existing: None,
    };
    assert_eq!(
        policy.check_upload(&input),
        Err(LimitsError::SuidModeForbidden)
    );
}

#[test]
fn size_and_counter_limits() {
    let resolver = TestResolver::new();
    let raw = RawFileTransferLimits {
        max_file_size: Some(1024),
        counters: Some(RawRateLimits {
            max_bytes_tx_per_minute: Some(500),
            max_bytes_rx_per_minute: Some(600),
        }),
        ..Default::default()
    };
    let policy = build_policy(true, &raw, &resolver).expect("policy");
    assert!(policy.check_declared_size(1024).is_ok());
    assert_eq!(
        policy.check_declared_size(1025),
        Err(LimitsError::FileTooBig)
    );
    assert_eq!(policy.max_bytes_tx_per_minute(), Some(500));
    assert_eq!(policy.max_bytes_rx_per_minute(), Some(600));
}

#[test]
fn all_zero_is_unlimited_and_max_is_accepted() {
    let resolver = TestResolver::new();
    let zero = RawFileTransferLimits::default();
    let policy = build_policy(true, &zero, &resolver).expect("policy");
    assert!(policy.check_declared_size(u64::MAX).is_ok());
    assert_eq!(policy.max_bytes_tx_per_minute(), Some(0));

    let big = RawFileTransferLimits {
        max_file_size: Some(u64::MAX),
        counters: Some(RawRateLimits {
            max_bytes_tx_per_minute: Some(u64::MAX),
            max_bytes_rx_per_minute: Some(u64::MAX),
        }),
        ..Default::default()
    };
    let policy = build_policy(true, &big, &resolver).expect("policy");
    assert!(policy.check_declared_size(u64::MAX).is_ok());
    assert_eq!(policy.max_bytes_tx_per_minute(), Some(u64::MAX));
}

#[test]
fn unknown_names_are_explicit_errors() {
    let resolver = TestResolver::new().user("alice", 1000).group("staff", 100);
    let missing_user = RawFileTransferLimits {
        owner_put: Some("bob".to_owned()),
        ..Default::default()
    };
    assert_eq!(
        build_policy(true, &missing_user, &resolver).unwrap_err(),
        ConfigLimitsError::UnknownOwner
    );
    let missing_group = RawFileTransferLimits {
        group_put: Some("nogroup".to_owned()),
        ..Default::default()
    };
    assert_eq!(
        build_policy(true, &missing_group, &resolver).unwrap_err(),
        ConfigLimitsError::UnknownGroup
    );
    let missing_in_list = RawFileTransferLimits {
        owner_get: Some(vec!["bob".to_owned()]),
        ..Default::default()
    };
    assert_eq!(
        build_policy(true, &missing_in_list, &resolver).unwrap_err(),
        ConfigLimitsError::UnknownOwner
    );
}

#[test]
fn sentinel_id_is_rejected() {
    let resolver = TestResolver::new()
        .user("max", u32::MAX)
        .group("maxg", u32::MAX);
    let user = RawFileTransferLimits {
        owner_put: Some("max".to_owned()),
        ..Default::default()
    };
    assert_eq!(
        build_policy(true, &user, &resolver).unwrap_err(),
        ConfigLimitsError::InvalidUidGid
    );
    let group = RawFileTransferLimits {
        group_put: Some("maxg".to_owned()),
        ..Default::default()
    };
    assert_eq!(
        build_policy(true, &group, &resolver).unwrap_err(),
        ConfigLimitsError::InvalidUidGid
    );
}

#[test]
fn overlong_and_nul_names_are_rejected() {
    let resolver = TestResolver::new();
    let long = "a".repeat(257);
    let raw = RawFileTransferLimits {
        owner_put: Some(long),
        ..Default::default()
    };
    assert_eq!(
        build_policy(true, &raw, &resolver).unwrap_err(),
        ConfigLimitsError::NameTooLong
    );
    let nul = RawFileTransferLimits {
        group_put: Some("a\u{0}b".to_owned()),
        ..Default::default()
    };
    assert_eq!(
        build_policy(true, &nul, &resolver).unwrap_err(),
        ConfigLimitsError::NameContainsNul
    );
}

#[test]
fn list_overflow_is_rejected() {
    let resolver = TestResolver::new().user("alice", 1000);
    let names = vec!["alice".to_owned(); 257];
    let raw = RawFileTransferLimits {
        owner_get: Some(names),
        ..Default::default()
    };
    assert_eq!(
        build_policy(true, &raw, &resolver).unwrap_err(),
        ConfigLimitsError::ListTooLong
    );
}

#[test]
fn empty_allowlist_entries_are_rejected() {
    let resolver = TestResolver::new().user("alice", 1000).group("staff", 100);
    let empty_owner = RawFileTransferLimits {
        owner_get: Some(vec![String::new()]),
        ..Default::default()
    };
    assert_eq!(
        build_policy(true, &empty_owner, &resolver).unwrap_err(),
        ConfigLimitsError::EmptyName
    );
    assert_eq!(
        resolver.calls(),
        0,
        "empty entries rejected before any NSS lookup"
    );
    let empty_group = RawFileTransferLimits {
        group_get: Some(vec![String::new()]),
        ..Default::default()
    };
    assert_eq!(
        build_policy(true, &empty_group, &resolver).unwrap_err(),
        ConfigLimitsError::EmptyName
    );
    let mixed_owner = RawFileTransferLimits {
        owner_get: Some(vec!["alice".to_owned(), String::new()]),
        ..Default::default()
    };
    assert_eq!(
        build_policy(true, &mixed_owner, &resolver).unwrap_err(),
        ConfigLimitsError::EmptyName
    );
    let mixed_group = RawFileTransferLimits {
        group_get: Some(vec![String::new(), "staff".to_owned()]),
        ..Default::default()
    };
    assert_eq!(
        build_policy(true, &mixed_group, &resolver).unwrap_err(),
        ConfigLimitsError::EmptyName
    );
}

#[test]
fn chroot_and_root_reject_parent_components() {
    let resolver = TestResolver::new();
    let chroot_parent = RawFileTransferLimits {
        chroot: Some("/srv/../etc".to_owned()),
        ..Default::default()
    };
    assert_eq!(
        build_policy(true, &chroot_parent, &resolver).unwrap_err(),
        ConfigLimitsError::ChrootHasParent
    );
    let bad_root = Path::new("/work/../outside");
    assert_eq!(
        resolve_peer_path(bad_root, "/etc/passwd").unwrap_err(),
        ConfigLimitsError::RootHasParent
    );
}

#[test]
fn umask_validation() {
    let resolver = TestResolver::new();
    for ok in ["0000", "0022", "0777", ""] {
        let raw = RawFileTransferLimits {
            umask: Some(ok.to_owned()),
            ..Default::default()
        };
        assert!(build_policy(true, &raw, &resolver).is_ok(), "accept {ok}");
    }
    for bad in ["0o22", "+22", "089", "1000", "1777777", "abc", " 22", "22 "] {
        let raw = RawFileTransferLimits {
            umask: Some(bad.to_owned()),
            ..Default::default()
        };
        assert_eq!(
            build_policy(true, &raw, &resolver).unwrap_err(),
            ConfigLimitsError::InvalidUmask,
            "reject {bad:?}"
        );
    }
}

#[test]
fn chroot_validation() {
    let resolver = TestResolver::new();
    let ok = RawFileTransferLimits {
        chroot: Some("/srv".to_owned()),
        ..Default::default()
    };
    assert!(build_policy(true, &ok, &resolver).is_ok());
    let empty = RawFileTransferLimits {
        chroot: Some(String::new()),
        ..Default::default()
    };
    assert!(build_policy(true, &empty, &resolver).is_ok());
    let relative = RawFileTransferLimits {
        chroot: Some("srv".to_owned()),
        ..Default::default()
    };
    assert_eq!(
        build_policy(true, &relative, &resolver).unwrap_err(),
        ConfigLimitsError::ChrootNotAbsolute
    );
    let nul = RawFileTransferLimits {
        chroot: Some("/srv\u{0}".to_owned()),
        ..Default::default()
    };
    assert_eq!(
        build_policy(true, &nul, &resolver).unwrap_err(),
        ConfigLimitsError::ChrootContainsNul
    );
    let long = RawFileTransferLimits {
        chroot: Some(format!("/{}", "a".repeat(4096))),
        ..Default::default()
    };
    assert_eq!(
        build_policy(true, &long, &resolver).unwrap_err(),
        ConfigLimitsError::ChrootTooLong
    );
}

#[test]
fn resolve_peer_path_maps_beneath_root() {
    let root = Path::new("/work");
    assert!(resolve_peer_path(root, "/work/dir/file").is_ok());
    assert_eq!(
        resolve_peer_path(root, "/work").unwrap_err(),
        ConfigLimitsError::PathIsRoot
    );
    assert_eq!(
        resolve_peer_path(root, "/work-other/x").unwrap_err(),
        ConfigLimitsError::PathNotBeneathRoot
    );
    assert_eq!(
        resolve_peer_path(root, "relative/path").unwrap_err(),
        ConfigLimitsError::PathNotAbsolute
    );
    assert_eq!(
        resolve_peer_path(root, "/work/../etc").unwrap_err(),
        ConfigLimitsError::PathHasParent
    );
    assert_eq!(
        resolve_peer_path(root, "").unwrap_err(),
        ConfigLimitsError::PathEmpty
    );
    assert_eq!(
        resolve_peer_path(root, "/work/a\u{0}b").unwrap_err(),
        ConfigLimitsError::PathContainsNul
    );
    let long = format!("/{}", "a".repeat(4096));
    assert_eq!(
        resolve_peer_path(root, &long).unwrap_err(),
        ConfigLimitsError::PathTooLong
    );
}

#[test]
fn resolve_peer_path_rejects_bad_root() {
    let root = Path::new("relative");
    assert_eq!(
        resolve_peer_path(root, "/relative/x").unwrap_err(),
        ConfigLimitsError::RootNotAbsolute
    );
}

#[test]
fn fallback_nested_limits_merge() {
    let dir = tempfile::tempdir().expect("temp dir");
    let fallback = dir.path().join("fallback.json");
    let primary = dir.path().join("primary.json");
    fs::write(
        &fallback,
        r#"{"Limits":{"Enabled":false,"FileTransfer":{"FollowSymLinks":true,"MaxFileSize":100,"Counters":{"MaxBytesTxPerMinute":1000}}}}"#,
    )
    .expect("write fallback");
    fs::write(
        &primary,
        r#"{"Limits":{"FileTransfer":{"Counters":{"MaxBytesRxPerMinute":2000},"Umask":"0022"}}}"#,
    )
    .expect("write primary");

    let loaded = config::load_config(&primary, &fallback).expect("load config");
    assert!(!loaded.limits_enabled);
    assert_eq!(loaded.limits.follow_sym_links, Some(true));
    assert_eq!(loaded.limits.max_file_size, Some(100));
    assert_eq!(loaded.limits.umask.as_deref(), Some("0022"));
    let counters = loaded.limits.counters.expect("counters merged");
    assert_eq!(counters.max_bytes_tx_per_minute, Some(1000));
    assert_eq!(counters.max_bytes_rx_per_minute, Some(2000));
}
