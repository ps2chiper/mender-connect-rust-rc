# Deployment notes (review-only)

This directory holds **prepared packaging artifacts**, not an installer. Nothing
here is installed, enabled or started by this repository, and it has not been
tested under a production boot. Any real deployment is a separate,
explicitly authorized step that must first check packages, paths and
configuration. There are no install/enable/start scripts, no hooks, and no
secrets, example passwords or real server values anywhere in these files.

## Verification status

Native Ubuntu 24.04 WSL2 x86-64 is the only qualified scope; QEMU and hardware
are excluded. The latest native release binary has SHA-256
`1b352bc4e0402208e56605438b2cdd2f95f59af3fd3b78a004c1edd2d9d7dae8`. Strict
all-target Clippy, the full all-target Rust suite (175 library tests plus all
integration suites) and the release build passed. Current-hash mender-cli and
terminal-soak reports are saved at
`reports/mender-rust-mender-cli-x64/candidate-cli-x64-20261114192707.json`,
`reports/mender-rust-signoff/terminal-soak-x64-20261114.json`, and
`reports/mender-rust-signoff/mixed-soak-x64-20261114.json`; the dependency review
is at `reports/mender-rust-signoff/dependency-review-x64-20261114.json`.
The current-hash Clippy, full-test and release-build logs are indexed in
reports/mender-rust-signoff/candidate-checks-20261114/. The older 32-check
native x64 mender-cli run passed in 78.071 seconds with Limits enabled and
included the negative upload confinement check; QEMU was not used. Port
forwarding and Mender commands were disabled in that run. A separate 30-check
live feature run passed in 9.54 seconds on the same hash: TCP/UDP mender-cli
echoes passed, the server returned 202 for send-inventory and check-update, and
both reached a harmless guest stub. Limits were disabled and no real updater
ran. The 17-check systemd run exercised the candidate in a transient unit with
a private session bus and passed start, restart, on-failure restart and stop.
It was not an installed service test. The reports are reports/mender-rust-mender-cli-x64/cli-feature-x64-20261115012329.json and reports/mender-rust-signoff/systemd-transient-qualification-20261114-final2.json.

The 30-minute isolated terminal and mixed-forwarding soaks passed on local
peers; neither exercises the real server or installed service. The historical
baseline-plus-four thread-growth test failed at 13 versus a 12-thread
threshold; the current mixed harness enforces a 32-thread absolute ceiling
but observes relative thread growth without enforcing it. Real system-bus
policy, installed paths, production boot/shutdown, longer real-server
stability, real updater execution and broader real-server protocol coverage
remain unqualified. Dependency checks are recorded below; duplicate-version
follow-up and legal approval of a permanent license policy remain outstanding.
Nothing here is installed, enabled or started.

## Dependency checks

cargo-audit v0.23.0 scanned 180 lockfile dependencies and reported no
advisories. cargo-deny v0.20.2 passed advisories, bans, licenses and sources for
`x86_64-unknown-linux-gnu` using a temporary explicit allowlist of the permissive
license IDs present in the Linux graph. The default cargo-deny run failed because
this project has no license policy config and defaults to rejecting every
license; that is not a dependency license failure. Duplicate-version warnings
for several transitive crates remain a follow-up.

## Installed layout to prepare

| Path | Kind | Ownership and mode |
| --- | --- | --- |
| `/usr/bin/mender-connect-rust` | main daemon binary | `root:root`, `0755` |
| `/usr/libexec/mender-connect-session-helper` | session helper | `root:root`, `0755`, **never SUID/SGID** |
| `/etc/mender/mender-connect.conf` | configuration | `root:root`, not group/other writable |
| `/etc/systemd/system/mender-connect-rust.service` | systemd unit (`support/mender-connect-rust.service`) | `root:root`, `0644` |

Additional requirements:

- Every path ancestor of the binary and the helper must be a real directory
  (not a symlink) owned by root and not group- or other-writable.
- The helper must remain an ordinary fixed path. It must never be marked
  setuid or setgid, and it is invoked only when an already-root parent drops to
  a different UID; the same-UID direct path needs no helper.
- The example unit runs as `root` for the foreign-UID transition and the
  common Auth permissions; this is a packaging choice, not a universal runtime
  constraint. The Authentication1 API itself does not require root, and an
  unprivileged daemon is possible if the existing system-bus policy permits it.
  The unit adds no capability grants and no setuid. It also adds no
  `NoNewPrivileges=`/`CapabilityBoundingSet=` hardening, which could break the
  target's normal SUID semantics.

## Configuration (`examples/mender-connect.conf`)

The shipped example is a reviewable terminal-only configuration:

- `User: "nobody"`, `ShellCommand: "/bin/sh"`, `ShellArguments: []`.
- `Terminal` enabled (`Disable: false`).
- `FileTransfer`, `PortForward` and `MenderClient` explicitly disabled
  (`Disable: true`).

Administrators may enable the other features, but the example keeps them off so
the artifact is minimal and easy to review.

Target-user rules:

- The configured user must exist in NSS.
- The configured shell must be listed in `/etc/shells`; only the default shell
  is accepted when the list file is missing.
- A configured user with no home directory is supported via a `/` fallback
  while the original `HOME` value is preserved.

Optional features:

- `Limits.Enabled` enables descriptor-verified regular-file read/stat,
  `O_TMPFILE` create/overwrite and directory targets with metadata checks. Keep
  it off unless the target supports `openat2`, procfs and `O_TMPFILE`; the code
  fails closed with no fallback.
- File-transfer paths must lie beneath the configured `Chroot` component
  prefix, and that prefix must be provisioned by the administrator. Relative
  symlinks are containment-checked only.

## D-Bus compatibility

The application is a **client** of the existing system-bus service, not a new
service:

- Service `io.mender.AuthenticationManager`
- Object `/io/mender/AuthenticationManager`
- Interface `io.mender.Authentication1`

No new permissive system-bus policy file is needed, and none is provided; do
not add an allow-everyone policy. The existing Mender Auth service and its
installed policy are required. A child running as the target user needs neither
a bus permission nor a JWT. Intended stdio/PTY descriptors 0, 1 and 2 remain;
the foreign-UID helper verifies that any extra descriptors are CLOEXEC before
exec, so the target does not receive extra file descriptors.

The hidden `--test-session-bus` flag is for local fixtures only and requires
`DBUS_SESSION_BUS_ADDRESS`; it is never for real deployments.

## Stop and cleanup semantics

The unit uses `Restart=on-failure` with `RestartSec=5`, `KillMode=mixed` and
`TimeoutStopSec=180`. On stop the main daemon runs its owned-session cleanup
first, then the remaining members of the whole cgroup are killed after the
180-second bound.
