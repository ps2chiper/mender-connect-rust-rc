//! Public-API tests for the pure file-transfer limits policy foundation.
//!
//! These tests exercise only the public surface of `mender_connect_rust::limits`;
//! no private helper is mirrored here.

use std::path::PathBuf;

use mender_connect_rust::limits::{
    CommitPlan, DownloadInput, FileFacts, LimitsError, LimitsOptions, LimitsPolicy, MAX_CHROOT_LEN,
    MAX_ID_ALLOWLIST, UploadInput,
};

/// Go `os.FileMode` setuid bit.
const GO_SUID: u32 = 1 << 23;

fn base_options() -> LimitsOptions {
    LimitsOptions {
        enabled: true,
        preserve_mode: true,
        preserve_owner: true,
        ..LimitsOptions::default()
    }
}

fn enabled(options: LimitsOptions) -> LimitsPolicy {
    LimitsPolicy::from_options(options).expect("valid policy options")
}

fn facts(owner_uid: u32, owner_gid: u32, size: u64, regular: bool, symlink: bool) -> FileFacts {
    FileFacts {
        owner_uid,
        owner_gid,
        size,
        is_regular: regular,
        is_symlink: symlink,
    }
}

fn upload<'a>(target_path: &'a str) -> UploadInput<'a> {
    UploadInput {
        target_path,
        declared_size: None,
        mode: None,
        requested_uid: None,
        requested_gid: None,
        existing: None,
    }
}

#[test]
fn default_policy_is_disabled() {
    assert!(!LimitsPolicy::default().is_enabled());
    assert!(!LimitsPolicy::disabled().is_enabled());
    let disabled_opt = LimitsOptions {
        enabled: false,
        ..base_options()
    };
    assert!(!enabled(disabled_opt).is_enabled());
}

#[test]
fn disabled_policy_allows_everything() {
    let policy = LimitsPolicy::disabled();
    // A suid mode that an enabled policy would reject is accepted.
    let mut input = upload("/anywhere");
    input.mode = Some(GO_SUID | 0o777);
    input.declared_size = Some(u64::MAX);
    input.existing = Some(facts(1, 1, 10, true, true));
    assert_eq!(policy.check_upload(&input), Ok(CommitPlan::default()));

    let download = DownloadInput {
        source_path: "/outside",
        facts: facts(1, 1, u64::MAX, false, true),
    };
    assert_eq!(policy.check_download(&download), Ok(()));
    assert_eq!(policy.check_declared_size(u64::MAX), Ok(()));
    assert_eq!(policy.check_progress_size(u64::MAX), Ok(()));
}

#[test]
fn download_owner_match_and_mismatch() {
    let mut options = base_options();
    options.owner_get = vec![10, 20];
    let policy = enabled(options);

    let matched = DownloadInput {
        source_path: "/f",
        facts: facts(20, 99, 1, true, false),
    };
    assert_eq!(policy.check_download(&matched), Ok(()));

    let mismatched = DownloadInput {
        source_path: "/f",
        facts: facts(30, 99, 1, true, false),
    };
    assert_eq!(
        policy.check_download(&mismatched),
        Err(LimitsError::FileOwnerMismatch)
    );
}

#[test]
fn download_group_match_and_mismatch() {
    let mut options = base_options();
    options.group_get = vec![10, 20];
    let policy = enabled(options);

    let matched = DownloadInput {
        source_path: "/f",
        facts: facts(99, 10, 1, true, false),
    };
    assert_eq!(policy.check_download(&matched), Ok(()));

    let mismatched = DownloadInput {
        source_path: "/f",
        facts: facts(99, 30, 1, true, false),
    };
    assert_eq!(
        policy.check_download(&mismatched),
        Err(LimitsError::FileGroupMismatch)
    );
}

#[test]
fn upload_overwrite_existing_forbidden() {
    let options = base_options();
    let policy = enabled(options);
    let mut input = upload("/f");
    input.existing = Some(facts(1, 1, 1, true, false));
    assert_eq!(
        policy.check_upload(&input),
        Err(LimitsError::ForbiddenToOverwrite)
    );
}

#[test]
fn upload_overwrite_existing_allowed() {
    let mut options = base_options();
    options.overwrite = true;
    let policy = enabled(options);
    let mut input = upload("/f");
    input.existing = Some(facts(1, 1, 1, true, false));
    assert!(policy.check_upload(&input).is_ok());
}

#[test]
fn upload_absent_target_allowed() {
    let options = base_options();
    let policy = enabled(options);
    assert!(policy.check_upload(&upload("/f")).is_ok());
}

#[test]
fn upload_overwrite_owner_filter() {
    let mut options = base_options();
    options.overwrite = true;
    options.owner_put = Some(7);
    let policy = enabled(options);

    let mut matched = upload("/f");
    matched.existing = Some(facts(7, 1, 1, true, false));
    assert!(policy.check_upload(&matched).is_ok());

    let mut mismatched = upload("/f");
    mismatched.existing = Some(facts(8, 1, 1, true, false));
    assert_eq!(
        policy.check_upload(&mismatched),
        Err(LimitsError::FileOwnerMismatch)
    );
}

#[test]
fn upload_overwrite_group_filter() {
    let mut options = base_options();
    options.overwrite = true;
    options.group_put = Some(9);
    let policy = enabled(options);

    let mut matched = upload("/f");
    matched.existing = Some(facts(1, 9, 1, true, false));
    assert!(policy.check_upload(&matched).is_ok());

    let mut mismatched = upload("/f");
    mismatched.existing = Some(facts(1, 10, 1, true, false));
    assert_eq!(
        policy.check_upload(&mismatched),
        Err(LimitsError::FileGroupMismatch)
    );
}

#[test]
fn download_regular_files_only() {
    let mut options = base_options();
    options.regular_files_only = true;
    let policy = enabled(options);

    let regular = DownloadInput {
        source_path: "/f",
        facts: facts(1, 1, 1, true, false),
    };
    assert_eq!(policy.check_download(&regular), Ok(()));

    let special = DownloadInput {
        source_path: "/f",
        facts: facts(1, 1, 1, false, false),
    };
    assert_eq!(
        policy.check_download(&special),
        Err(LimitsError::NotRegularFile)
    );
}

#[test]
fn download_follow_links_forbidden() {
    let options = base_options();
    let policy = enabled(options);
    let link = DownloadInput {
        source_path: "/f",
        facts: facts(1, 1, 1, true, true),
    };
    assert_eq!(
        policy.check_download(&link),
        Err(LimitsError::FollowLinksForbidden)
    );

    let mut follow = base_options();
    follow.follow_symlinks = true;
    let policy = enabled(follow);
    assert_eq!(policy.check_download(&link), Ok(()));
}

#[test]
fn upload_existing_symlink_follow_rules() {
    let options = base_options();
    let policy = enabled(options);
    let mut input = upload("/f");
    input.existing = Some(facts(1, 1, 1, true, true));
    assert_eq!(
        policy.check_upload(&input),
        Err(LimitsError::FollowLinksForbidden)
    );

    let mut follow = base_options();
    follow.follow_symlinks = true;
    follow.overwrite = true;
    let policy = enabled(follow);
    assert!(policy.check_upload(&input).is_ok());
}

#[test]
fn chroot_lexical_boundary() {
    let mut options = base_options();
    options.chroot = Some(PathBuf::from("/srv/files"));
    let policy = enabled(options);

    assert!(policy.check_upload(&upload("/srv/files/a/b.txt")).is_ok());
    assert!(policy.check_upload(&upload("/srv/files")).is_ok());

    assert_eq!(
        policy.check_upload(&upload("/srv/other.txt")),
        Err(LimitsError::ChrootViolation)
    );
    // A sibling sharing the chroot prefix must not be accepted.
    assert_eq!(
        policy.check_upload(&upload("/srv/files-escape/x")),
        Err(LimitsError::ChrootViolation)
    );
}

#[test]
fn chroot_rejects_relative_target() {
    let mut options = base_options();
    options.chroot = Some(PathBuf::from("/srv/files"));
    let policy = enabled(options);
    assert_eq!(
        policy.check_upload(&upload("relative/path")),
        Err(LimitsError::ChrootViolation)
    );
}

#[test]
fn chroot_rejects_dotdot_escape() {
    let mut options = base_options();
    options.chroot = Some(PathBuf::from("/srv/files"));
    let policy = enabled(options);
    assert_eq!(
        policy.check_upload(&upload("/srv/files/../../etc/passwd")),
        Err(LimitsError::ChrootViolation)
    );
}

#[test]
fn chroot_rejects_relative_config() {
    let mut options = base_options();
    options.chroot = Some(PathBuf::from("srv/files"));
    assert_eq!(
        LimitsPolicy::from_options(options).err(),
        Some(LimitsError::ChrootNotAbsolute)
    );
}

#[test]
fn chroot_nul_byte_rejected() {
    let mut options = base_options();
    options.chroot = Some(PathBuf::from("/srv/files\0escape"));
    assert_eq!(
        LimitsPolicy::from_options(options).err(),
        Some(LimitsError::PathContainsNul)
    );
}

#[test]
fn target_path_nul_rejected_before_lexical_decision() {
    let mut options = base_options();
    options.chroot = Some(PathBuf::from("/srv/files"));
    let policy = enabled(options);
    assert_eq!(
        policy.check_upload(&upload("/srv/files/ok\0bad")),
        Err(LimitsError::PathContainsNul)
    );

    let download = DownloadInput {
        source_path: "/srv/files/ok\0bad",
        facts: facts(1, 1, 1, true, false),
    };
    assert_eq!(
        policy.check_download(&download),
        Err(LimitsError::PathContainsNul)
    );
}

#[test]
fn target_path_nul_rejected_without_chroot() {
    let policy = enabled(base_options());
    assert_eq!(
        policy.check_upload(&upload("/f\0bad")),
        Err(LimitsError::PathContainsNul)
    );
}

#[test]
fn chroot_too_long_rejected() {
    let mut options = base_options();
    let long = format!("/{}", "a".repeat(MAX_CHROOT_LEN));
    options.chroot = Some(PathBuf::from(long));
    assert_eq!(
        LimitsPolicy::from_options(options).err(),
        Some(LimitsError::ChrootTooLong)
    );
}

#[test]
fn umask_out_of_range_rejected() {
    let mut options = base_options();
    options.umask = 0o1000;
    assert_eq!(
        LimitsPolicy::from_options(options).err(),
        Some(LimitsError::UmaskOutOfRange)
    );
}

#[test]
fn umask_is_a_ceiling() {
    let options = base_options();
    let policy = enabled(options);
    let mut input = upload("/f");
    input.mode = Some(0o777);
    assert_eq!(policy.check_upload(&input).map(|p| p.mode), Ok(Some(0o777)));

    let mut masked = base_options();
    masked.umask = 0o022;
    let policy = enabled(masked);
    assert_eq!(policy.check_upload(&input).map(|p| p.mode), Ok(Some(0o755)));
}

#[test]
fn umask_never_adds_permissions() {
    // A request for a single owner bit must never be widened, even with a zero
    // umask (which would add nothing on a correct implementation but reveal an
    // upstream-style overwrite bug if present).
    let options = base_options();
    let policy = enabled(options);
    let mut input = upload("/f");
    input.mode = Some(0o400);
    assert_eq!(policy.check_upload(&input).map(|p| p.mode), Ok(Some(0o400)));

    // A permissive umask still may not grant unrequested bits.
    let mut masked = base_options();
    masked.umask = 0o000;
    let policy = enabled(masked);
    let mut zero = upload("/f");
    zero.mode = Some(0o000);
    assert_eq!(policy.check_upload(&zero).map(|p| p.mode), Ok(Some(0o000)));
}

#[test]
fn absent_mode_applies_umask_ceiling() {
    // With no wire mode the private staging default `0o600` is the base; the
    // configured umask removes bits but never adds any.
    let policy = enabled(base_options());
    assert_eq!(
        policy.check_upload(&upload("/f")).map(|p| p.mode),
        Ok(Some(0o600))
    );

    let mut owner_group = base_options();
    owner_group.umask = 0o077;
    let policy = enabled(owner_group);
    assert_eq!(
        policy.check_upload(&upload("/f")).map(|p| p.mode),
        Ok(Some(0o600))
    );

    let mut closed = base_options();
    closed.umask = 0o777;
    let policy = enabled(closed);
    assert_eq!(
        policy.check_upload(&upload("/f")).map(|p| p.mode),
        Ok(Some(0o000))
    );
}

#[test]
fn explicit_mode_full_umask_clears_all_bits() {
    let mut options = base_options();
    options.umask = 0o777;
    let policy = enabled(options);
    let mut input = upload("/f");
    input.mode = Some(0o777);
    assert_eq!(policy.check_upload(&input).map(|p| p.mode), Ok(Some(0o000)));
}

#[test]
fn go_suid_bit_rejected_when_disallowed() {
    let options = base_options();
    let policy = enabled(options);
    let mut input = upload("/f");
    input.mode = Some(GO_SUID | 0o755);
    assert_eq!(
        policy.check_upload(&input),
        Err(LimitsError::SuidModeForbidden)
    );
}

#[test]
fn posix_suid_alias_rejected_when_disallowed() {
    let options = base_options();
    let policy = enabled(options);
    let mut input = upload("/f");
    input.mode = Some(0o4755);
    assert_eq!(
        policy.check_upload(&input),
        Err(LimitsError::SuidModeForbidden)
    );
}

#[test]
fn ambiguous_setuid_aliases_rejected() {
    let mut options = base_options();
    options.allow_suid = true;
    let policy = enabled(options);
    let mut input = upload("/f");
    input.mode = Some(GO_SUID | 0o4000 | 0o755);
    assert_eq!(
        policy.check_upload(&input),
        Err(LimitsError::AmbiguousModeEncoding)
    );
}

#[test]
fn suid_allowed_and_converted_to_posix_bit() {
    let mut options = base_options();
    options.allow_suid = true;
    let policy = enabled(options);

    let mut go = upload("/f");
    go.mode = Some(GO_SUID | 0o755);
    assert_eq!(policy.check_upload(&go).map(|p| p.mode), Ok(Some(0o4755)));

    let mut posix = upload("/f");
    posix.mode = Some(0o4755);
    assert_eq!(
        policy.check_upload(&posix).map(|p| p.mode),
        Ok(Some(0o4755))
    );
}

#[test]
fn unsupported_posix_setgid_rejected() {
    let options = base_options();
    let policy = enabled(options);
    let mut input = upload("/f");
    input.mode = Some(0o2000 | 0o755);
    assert_eq!(
        policy.check_upload(&input),
        Err(LimitsError::UnsupportedModeBits)
    );
}

#[test]
fn unsupported_go_type_bits_rejected() {
    let options = base_options();
    let policy = enabled(options);
    let mut input = upload("/f");
    // Go setgid bit and a Go type bit (ModeDir) must both fail closed.
    input.mode = Some((1 << 22) | 0o755);
    assert_eq!(
        policy.check_upload(&input),
        Err(LimitsError::UnsupportedModeBits)
    );
    input.mode = Some((1 << 31) | 0o755);
    assert_eq!(
        policy.check_upload(&input),
        Err(LimitsError::UnsupportedModeBits)
    );
}

#[test]
fn declared_size_boundaries() {
    let mut options = base_options();
    options.max_file_size = 100;
    let policy = enabled(options);

    assert_eq!(policy.check_declared_size(0), Ok(()));
    assert_eq!(policy.check_declared_size(100), Ok(()));
    assert_eq!(
        policy.check_declared_size(101),
        Err(LimitsError::FileTooBig)
    );
    assert_eq!(
        policy.check_declared_size(u64::MAX),
        Err(LimitsError::FileTooBig)
    );
}

#[test]
fn progress_size_boundaries() {
    let mut options = base_options();
    options.max_file_size = 4096;
    let policy = enabled(options);

    assert_eq!(policy.check_progress_size(0), Ok(()));
    assert_eq!(policy.check_progress_size(4096), Ok(()));
    assert_eq!(
        policy.check_progress_size(4097),
        Err(LimitsError::FileTooBig)
    );
    assert_eq!(
        policy.check_progress_size(u64::MAX),
        Err(LimitsError::FileTooBig)
    );
}

#[test]
fn size_unlimited_when_zero() {
    let options = base_options();
    let policy = enabled(options);
    assert_eq!(policy.check_declared_size(u64::MAX), Ok(()));
    assert_eq!(policy.check_progress_size(u64::MAX), Ok(()));

    let download = DownloadInput {
        source_path: "/f",
        facts: facts(1, 1, u64::MAX, true, false),
    };
    assert_eq!(policy.check_download(&download), Ok(()));
}

#[test]
fn upload_declared_size_checked() {
    let mut options = base_options();
    options.max_file_size = 10;
    let policy = enabled(options);
    let mut input = upload("/f");
    input.declared_size = Some(11);
    assert_eq!(policy.check_upload(&input), Err(LimitsError::FileTooBig));
    input.declared_size = Some(10);
    assert!(policy.check_upload(&input).is_ok());
}

#[test]
fn owner_preservation_forced_override() {
    let mut options = base_options();
    options.overwrite = true;
    options.owner_put = Some(50);
    let policy = enabled(options);
    let mut input = upload("/f");
    input.requested_uid = Some(5);
    input.requested_gid = Some(6);
    // Existing owner must match the owner_put filter (50).
    input.existing = Some(facts(50, 1, 1, true, false));
    let plan = policy.check_upload(&input).expect("admissible");
    assert_eq!(plan.ownership.uid, Some(50));
    // gid is preserved from the request because group_put is unset.
    assert_eq!(plan.ownership.gid, Some(6));
}

#[test]
fn owner_forced_even_without_preservation() {
    let mut options = base_options();
    options.preserve_owner = false;
    options.owner_put = Some(50);
    options.group_put = Some(60);
    let policy = enabled(options);
    let mut input = upload("/f");
    input.requested_uid = Some(5);
    input.requested_gid = Some(6);
    let plan = policy.check_upload(&input).expect("admissible");
    assert_eq!(plan.ownership.uid, Some(50));
    assert_eq!(plan.ownership.gid, Some(60));
}

#[test]
fn ownership_not_preserved_when_disabled_flag() {
    let mut options = base_options();
    options.preserve_owner = false;
    let policy = enabled(options);
    let mut input = upload("/f");
    input.requested_uid = Some(5);
    input.requested_gid = Some(6);
    let plan = policy.check_upload(&input).expect("admissible");
    assert_eq!(plan.ownership.uid, None);
    assert_eq!(plan.ownership.gid, None);
}

#[test]
fn preserve_disabled_uses_safe_default_masked_by_umask() {
    // A direct (non-config) `preserve_mode = false` request must not ignore the
    // configured ceiling: the private staging default is planned with the
    // umask applied instead of leaving the raw default untouched.
    let mut options = base_options();
    options.preserve_mode = false;
    let policy = enabled(options);
    let mut input = upload("/f");
    input.mode = Some(0o755);
    let plan = policy.check_upload(&input).expect("admissible");
    assert_eq!(plan.mode, Some(0o600));

    let mut masked = base_options();
    masked.preserve_mode = false;
    masked.umask = 0o777;
    let policy = enabled(masked);
    let plan = policy.check_upload(&input).expect("admissible");
    assert_eq!(plan.mode, Some(0o000));
}

#[test]
fn config_list_bounds() {
    let mut options = base_options();
    options.owner_get = vec![1; MAX_ID_ALLOWLIST + 1];
    assert_eq!(
        LimitsPolicy::from_options(options).err(),
        Some(LimitsError::TooManyOwnerGetEntries)
    );

    let mut options = base_options();
    options.group_get = vec![1; MAX_ID_ALLOWLIST + 1];
    assert_eq!(
        LimitsPolicy::from_options(options).err(),
        Some(LimitsError::TooManyGroupGetEntries)
    );
}

#[test]
fn typed_errors_display_constant_messages() {
    assert_eq!(
        LimitsError::ChrootViolation.to_string(),
        "the target file path is outside chroot"
    );
    assert_eq!(
        LimitsError::SuidModeForbidden.to_string(),
        "the set uid mode is forbidden"
    );
    assert_eq!(
        LimitsError::UnsupportedModeBits.to_string(),
        "the requested mode contains unsupported bits"
    );
    // The error type is a std::error::Error.
    let _boxed: Box<dyn std::error::Error> = Box::new(LimitsError::FileTooBig);
}
