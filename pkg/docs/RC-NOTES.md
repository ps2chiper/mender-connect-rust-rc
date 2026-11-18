# mender-connect-rust 0.1.0-rc.1 — Release Candidate Notes

Built: 2026-11-17T04:51:51Z
Source snapshot: `/home/jason/.local/share/duo-aider/mender-rust-trial/prototypes/confinement-invariant`
Base code: latest prototype tree (UDP inline-ACK line); `Cargo.toml` and `Cargo.lock` version bumped to `0.1.0-rc.1`.
The README status snapshot describes the prior prototype build; the hashes and verification in this file apply to this candidate.

## Candidate status

**Release candidate artifact built; functional parity passes.** The only failed
gate — v1 4096 full-duplex zero-loss at 65.536 Mb/s — is also failed by the Go
reference in a 10-repeat control (Go 7/10 failed, Rust 5/10). The zero-loss claim
at this profile is therefore not supported for either implementation on this
host; it is a gate/environment limitation, not an RC-specific regression. This
is not production signoff: installed-service, real-server and other gates remain
unqualified.

## Verification performed for this candidate

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --all-targets --locked -- -D warnings` | PASS |
| `dbus-run-session -- cargo test --all-targets --locked` | PASS — 56 suites, 644 passed, 0 failed |
| `cargo build --release --locked --bins` | PASS |
| `mender-connect-rust config-check -c examples/mender-connect.conf` | PASS — `configuration OK` |
| `mender-connect-rust --version` / `version` | `0.1.0-rc.1` |
| Go functional side-by-side (same peer) | Rust 38/38, Go 38/38, identical asserted checks |
| UDP 3 x 5 s screen, 12 profiles | PASS both implementations, zero loss |
| UDP 3 x 60 s gate, 12 profiles | 11/12 profiles pass; v1 4096 full-duplex is **inconclusive** — Rust 5/10 repeats, Go 3/10 repeats |

Artifacts:

| Artifact | SHA-256 |
|---|---|
| `mender-connect-rust` | `21e54ac08c5453261b5ba61ec6c1f70132ee83e717163d6e9ff0e2050cfe8ee4` |
| `mender-connect-session-helper` | `64fd1f8411af61a1d3491da8a00f6c83d5ef2aaa1af2ccde08dc411922691a11` |

Source tree manifest: `SOURCE_SHA256SUMS`, manifest SHA-256
`43a39353a952125c645d36066866c60e507e61b514e92a45e6c439a4905ca5cd`.

Toolchain: rustc 1.99.1 (58cf8f9c3 2026-10-13), cargo 1.99.1, target
`x86_64-unknown-linux-gnu`.

## Go comparison

The frozen Go reference daemon (`364fc12f…`, Go 1.22.2) and this RC were run
separately against the same independent Go protocol peer and test-only
Authentication1 mock on a private session bus. Both passed all 38 asserted
functional checks; the asserted check maps are identical. One non-asserted
difference was observed: Go recorded `shell_trailing_output = 1`, Rust did not.

The UDP 5 s screen passed for all twelve profile/rate points for both
implementations with zero loss. The 60 s gate initially failed on the RC at:

- v1 1400 full-duplex, 33.6 Mb/s: from-device loss 275/727/849 packets (0.15–0.47%) across three trials.
- v1 4096 full-duplex, 65.536 Mb/s: from-device loss 0/39/33 packets (0–0.03%) across three trials.

A later rerun of the two initially failing RC profiles, followed by a 10-repeat
control on v1 4096 full-duplex, changed the interpretation:

- v1 1400 full-duplex passed 3/3 clean. The initial failure was not reproducible;
  combined with the predecessor's 2/3 failure, this profile is intermittent, not
  a deterministic RC regression.
- v1 4096 full-duplex is **not reproducible for either implementation**. Ten
  repeats of three 60 s trials each gave: Rust RC 5/10 repeats failed (7/30
  trials, 2,390 lost packets, median 32, max 2,217); Go reference 7/10 repeats
  failed (14/30 trials, 2,569 lost packets, median 79, max 1,431). All loss was
  from-device; to-device lost zero in all 60 trials. The Go reference is worse in
  this sample, so this is not an RC-specific regression.

The zero-loss claim at v1 4096 full-duplex, 65.536 Mb/s is therefore
unsupported for both implementations on this host. The gate is environment-
limited at this rate; it would need a lower declared rate or a more isolated
host before either implementation can claim it. The full evidence is in
`RC-GO-COMPARISON.md` and `RC-4096-CHARACTERIZATION.md`.

## Qualification scope

Qualified target: native Ubuntu 24.04 WSL2 x86-64 only. QEMU emulation and physical
hardware are not qualified. All checks ran natively on that target.

Prior evidence in the reports workspace covers local disposable-server CLI checks,
30-minute local terminal and mixed soaks, RustSec advisory scanning, and local UDP
Go-parity at fixed rates for the predecessor binary `26eaacbbb7ade5a370d42f11a98cecc11e1a39d3974894c2b744c3d0d67d1380`.
Those results do not transfer to this version-bumped RC; the RC UDP gate was
rerun, and its only non-passing profile is inconclusive for both implementations
as described above.

## Not qualified / outstanding

- **UDP v1 4096 full-duplex zero-loss parity** at 65.536 Mb/s — inconclusive: Rust 5/10 repeats failed, Go 7/10 repeats failed; all loss from-device. The rate is not reproducible for either implementation on this host. The v1 1400 full-duplex profile is intermittent (failed initially, passed rerun) and needs more repeats before any claim.
- Installed systemd service, real system D-Bus `io.mender.AuthenticationManager`, production boot and shutdown.
- Live-server PortForward, MenderClient commands, and update workflows with a real updater.
- Real-server/WAN protocol matrix, authenticated/encrypted WebSocket, TLS v1/v2 forwarding and file transfer, paced UDP beyond local loopback.
- Longer real-server stability and resource budgets; historical baseline-plus-four thread-growth failure (13 threads vs a 12-thread threshold) remains unresolved.
- Permanent dependency-license policy and legal approval; the cargo-deny allowlist is temporary. Duplicate transitive dependency versions remain a follow-up.
- The 4096-byte WSL loopback raw-UDP failure and higher-rate v1 loss above approved points remain open or must be formally scoped.
- ACK tail-latency attribution and TCP v2 throughput variability are unresolved.

## Scope and safety

- Linux-only experimental port, tracking Go revision `ba393f11b6317f756bb86c5f3963061903728c01`.
- Do not deploy over a running Mender agent without separate authorization.
- Packaging under `support/` and `examples/` is prepared, not installed, enabled, or started.
- File-transfer path, Limits, trusted-root/mount, and same-UID confinement assumptions remain as documented in `README.md`.

## Reproduce

```sh
. "$HOME/.cargo/env"
cargo fmt --all -- --check
dbus-run-session -- cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo build --release --locked --bins
./target/release/mender-connect-rust config-check -c examples/mender-connect.conf
```