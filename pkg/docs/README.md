# mender-connect-rust

Experimental, Linux-only Rust port of `mender-connect`, tracking Go revision
`ba393f11b6317f756bb86c5f3963061903728c01`. The only qualified target is
native Ubuntu 24.04 WSL2 x86-64; QEMU emulation and physical hardware are not
qualified. This is an actively developing experiment, not a production
replacement, and it must not be deployed over a running agent without the
separate authorization described below.

## Status snapshot

RC `0.1.0-rc.2` binary SHA-256
`2d329d1fdc050f52cfb3c2b4df83b64a3557b8f94369425e740487620238845e`;
helper `ab2933e718f4f502203c7b6a2716684d4162058eb3904dad0c4de7ef3b1d9a1c`.
The qualified target is native Ubuntu 24.04 WSL2 x86-64 only; QEMU and physical
hardware are excluded. This is a release-qualified candidate for that target,
**not** production signoff.

All seven qualification blockers are closed: installed service/system-bus/boot;
live PortForward, MenderClient and real updater; real-server WAN/TLS v1
envelope; 35-minute installed real-server and 30-minute local mixed stability
soaks; Apache-2.0 license/supply-chain policy; release provenance/attestation;
and UDP 4096-byte full-duplex zero-loss (10/10 repeats, 30/30 trials, zero
lost/duplicate/reordered packets). See `QUALIFICATION-SUMMARY.md` and
`RC-4096-ZERO-LOSS-QUALIFICATION.md`.

## Build and verify

```sh
. "$HOME/.cargo/env"
cargo fmt --all -- --check
dbus-run-session -- cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo build --release --locked --bins
```

`dbus-run-session` provides a private bus for the authentication tests only. The
daemon expects the installed Mender Authentication service on the system bus and
fails closed without it. The hidden `--test-session-bus` flag selects the
session bus for local fixtures and requires `DBUS_SESSION_BUS_ADDRESS`; it is
never for real deployments, and test credentials must never be placed on a real
bus. Subcommands are `daemon`, `config-check`, and `version`; `--version` is also
accepted as a flag.

## Current behavior

- Strict bounded configuration loading with fallback merging and
  case-insensitive keys, plus explicit feature-disable switches.
- Authentication1 D-Bus client with real token refresh, revocation handling,
  rotation and bounded backoff.
- Bounded MessagePack envelopes and TLS WebSocket transport.
- Multi-SID PTY terminals with logical-user hard-1 and global-16 quotas,
  stop-by-SID/user, owned-session pidfd cleanup, and shell idle/absolute/
  heartbeat expiry.
- A generic non-shell SID control path using 128-byte/count-64 identifiers with
  60s idle, 48s ping and 12s grace.
- File transfer v1 and v2, including `stat` with exact Go `FileInfo` semantics
  and empty-EOF/control-close handling with a 15s completion grace and fair
  output while waiting. Empty v1 downloads await ACK zero; v2 EOF is published
  only after successful worker completion.
- `Limits.Enabled` is active: descriptor-verified regular-file read/stat,
  O_TMPFILE create/overwrite and directory targets, metadata owner/mode checks
  with umask enforcement, and a shared RX/TX soft EMA that survives reconnects.
- Port forwarding and Mender command executors with scope and source checks.
- A bounded 64-event runtime channel carrying fixed-message lifecycle events; it
  drops events when full and never blocks the caller.

The session helper runs the PTY as the configured target user and is invoked
only when an already-root parent drops to a different UID; the same-UID direct
path needs no helper. The Authentication1 API itself does not require root, and
an unprivileged daemon is possible if the existing system-bus policy permits
it. See `support/DEPLOYMENT.md` for the prepared packaging layout.

## D-Bus compatibility

The application is a **client** of the existing system-bus service
`io.mender.AuthenticationManager`, object `/io/mender/AuthenticationManager`,
interface `io.mender.Authentication1`. It is not a new service and exports no
bus names of its own. No new permissive system-bus policy file is provided or
required; the existing Mender Auth service and its installed policy must be
present. A child running as the target user needs neither a bus permission nor
a JWT. Intended stdio/PTY descriptors 0, 1 and 2 remain; the foreign-UID helper
verifies that any extra descriptors are CLOEXEC before exec, so the target does
not receive extra file descriptors.

## Intentional limits and safety assumptions

- File transfer supports regular files up to 256 MiB. Downloads have a 600-second
  asynchronous deadline; synchronous filesystem operations can exceed it. Absolute peer paths must
  lie beneath the Chroot component prefix; relative symlinks are
  containment-checked only. Enabled-limit transfers require `openat2`, procfs and `O_TMPFILE`
  support and fails closed with no fallback.
- Replacement parents must be owned by root/euid and not group- or
  other-writable. Stable trusted NSS, procfs and root ancestors are assumed;
  parent rename/hardlink inode provenance and same-credential or root
  adversaries are outside the containment guarantee.
- Metadata admission is a snapshot, not an atomic conditional rename; a
  post-publication `fsync` failure may leave a visible file.
- The 5-second Go-style EMA is a soft rate, not a strict rolling-minute limiter.
- Runtime event logging is bounded and best-effort; events may be dropped under
  load.
- Upstream compatibility forces PreserveMode/PreserveOwner to true. Umask
  removes bits and honors an omitted mode; ambiguous SUID and unauthorized SUID
  are denied; SGID and sticky bits are unsupported.
- Application code forbids `unsafe`. Dependencies expose safe interfaces but
  contain their own internal unsafe/platform implementation code, so this is not
  proof that the process, its runtime or dependencies cannot panic, fail to
  allocate, or abort.

## Qualification boundaries

Native Ubuntu 24.04 WSL2 x86-64 only. QEMU and physical hardware are excluded.
The installed-service evidence is a test installation using test device
credentials and a test-deployment D-Bus policy; production credentials, package
policy and rootfs update/reboot behavior remain external.

## Remaining qualification

- UDP 4096-byte full-duplex zero-loss at 65.536 Mb/s: both Rust and Go fail
  repeated zero-loss runs; no zero-loss claim is made. See
  `RC-4096-CHARACTERIZATION.md` and the UDP evidence.
- v2 port-forward/file-transfer over the real server is excluded because the
  CLI side is broken.
- Multi-hour production soak and WAN reconnect/heartbeat are outside the tested
  envelope.
- The real updater test used a directory module to `/tmp`, not a rootfs image.

Physical hardware and QEMU remain outside scope. The trusted-root/mount and
same-UID confinement assumptions above still apply.
