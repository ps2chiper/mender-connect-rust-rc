# mender-connect-rust 0.1.0-rc.1 — qualification summary

Status: **release candidate, not release-qualified**
Version: `0.1.0-rc.1`
Binary: `mender-connect-rust` `21e54ac08c5453261b5ba61ec6c1f70132ee83e717163d6e9ff0e2050cfe8ee4`
Helper: `mender-connect-session-helper` `64fd1f8411af61a1d3491da8a00f6c83d5ef2aaa1af2ccde08dc411922691a11`
Target: native Ubuntu 24.04 WSL2 x86-64; QEMU and physical hardware excluded.

## Closed blockers

1. **Installed service / real system bus / boot** — installed `mender-authd` + `mender-connect-rust` units, system-bus `io.mender.AuthenticationManager`, distro restart, terminal E2E, auth restart, clean stop/start. See `RC-INSTALLED-SERVICE-QUALIFICATION.md`.
2. **Live server feature matrix and real updater** — 32/32 live feature checks (port-forward TCP/UDP, MenderClient send-inventory/check-update, terminal, transfers), plus a real Mender 3.4 artifact install triggered by the RC's `check-update` dispatch. See `RC-LIVE-FEATURE-MATRIX.md` and `RC-REAL-UPDATE-QUALIFICATION.md`.
3. **Real-server/WAN/TLS v1 envelope** — functional 32/32, TLS 1.3, 1 MiB transfers, TCP port-forward latency/bulk, paced UDP. Go comparison shows the v1 WAN limits are shared by both implementations. v2 is excluded because the CLI side is broken. Envelope: TCP port-forward ~0.32 Mb/s at ~120–140 ms RTT; UDP clean at 10 pps. WAN reconnect/heartbeat is outside the envelope. See `RC-WAN-TLS-MATRIX.md` and `RC-WAN-GO-COMPARISON.md`.
4. **Long-duration stability** — 35-minute installed real-server terminal soak and 30-minute local mixed TLS soak; relative thread/FD/RSS budgets passed, no cleanup leaks. The historical 13-vs-12 failure was an obsolete absolute threshold below the current 17-worker baseline. See `RC-LONG-DURATION-STABILITY.md`.
5. **License and supply chain** — project license confirmed byte-identical to upstream Apache-2.0; permanent `deny.toml`; `cargo-deny check all` passes; 180-package license inventory; duplicates documented. See `LICENSE-POLICY.md`, `deny.toml`, `DEPENDENCY-LICENSES.csv`.

## Open blocker

**7. UDP 4096 zero-loss qualification** — v1 4096-byte full-duplex at 65.536 Mb/s remains unreproducible for both Rust and Go. No zero-loss declaration is made for that profile. See `RC-4096-CHARACTERIZATION.md` and the UDP evidence under `docs/go-comparison/`.

## Provenance

- Canonical source repository and tag: `https://github.com/ps2chiper/mender-connect-rust-rc`, tag `v0.1.0-rc.1`.
- Release asset checksums: release `SHA256SUMS`; package SHA-256 is recorded there and in the release metadata.
- Signed provenance: `RC release attestation` GitHub Actions run; GitHub Artifact Attestations (Sigstore bundles) for both binaries. See `PROVENANCE.md`.
- Reproducible build: `REPRODUCIBLE-BUILD.md`; clean-target and different-path rebuilds both reproduced the frozen binary hashes.
- License: `LICENSE` is the upstream Apache-2.0 text, SHA-256 `d7e8fd4ad05371007d60285c309ba7a7ce3e61029b843f949fbb9ec79dc9eb47`.

## Not claimed

- Zero-loss v1 4096 full-duplex at 65.536 Mb/s.
- v2 port-forward/file-transfer over the real server (v2 excluded because the CLI side is broken).
- Multi-hour production soak.
- Rootfs-image update/reboot behavior (the real updater test used a directory module to `/tmp`).
- WAN reconnect/heartbeat behavior.
- Release-qualified status. The candidate remains `release_qualified: false` until blocker 7 is resolved or formally scoped.