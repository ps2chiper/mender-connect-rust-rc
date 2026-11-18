# mender-connect-rust 0.1.0-rc.2 — qualification summary

Status: **release-qualified for native Ubuntu 24.04 WSL2 x86-64; not production signoff**
Version: `0.1.0-rc.2`
Binary: `mender-connect-rust` `2d329d1fdc050f52cfb3c2b4df83b64a3557b8f94369425e740487620238845e`
Helper: `mender-connect-session-helper` `ab2933e718f4f502203c7b6a2716684d4162058eb3904dad0c4de7ef3b1d9a1c`
Target: native Ubuntu 24.04 WSL2 x86-64; QEMU and physical hardware excluded.

## Closed blockers

1. **Installed service / real system bus / boot** — installed `mender-authd` + `mender-connect-rust` units, system-bus `io.mender.AuthenticationManager`, distro restart, terminal E2E, auth restart, clean stop/start. See `RC-INSTALLED-SERVICE-QUALIFICATION.md`.
2. **Live server feature matrix and real updater** — 32/32 live feature checks (port-forward TCP/UDP, MenderClient send-inventory/check-update, terminal, transfers), plus a real Mender 3.4 artifact install triggered by the RC's `check-update` dispatch. See `RC-LIVE-FEATURE-MATRIX.md` and `RC-REAL-UPDATE-QUALIFICATION.md`.
3. **Real-server/WAN/TLS v1 envelope** — functional 32/32, TLS 1.3, 1 MiB transfers, TCP port-forward latency/bulk, paced UDP. Go comparison shows the v1 WAN limits are shared by both implementations. v2 is excluded because the CLI side is broken. See `RC-WAN-TLS-MATRIX.md` and `RC-WAN-GO-COMPARISON.md`.
4. **Long-duration stability** — 35-minute installed real-server terminal soak and 30-minute local mixed TLS soak; relative thread/FD/RSS budgets passed, no cleanup leaks. See `RC-LONG-DURATION-STABILITY.md`.
5. **License and supply chain** — project license confirmed byte-identical to upstream Apache-2.0; permanent `deny.toml`; `cargo-deny check all` passes; 180-package license inventory; duplicates documented. See `LICENSE-POLICY.md`, `deny.toml`, `DEPENDENCY-LICENSES.csv`.
6. **Release provenance and signing** — public repository and tag, CycloneDX SBOM, clean-target/different-path reproducible builds, and signed GitHub Artifact Attestations for the release package and both binaries. See `PROVENANCE.md` and `ATTESTATION.md`.
7. **UDP 4096 zero-loss** — 10/10 independent repeats, 30/30 trials, 60/60 per-direction measurements with zero lost, duplicate and reordered packets at 4096-byte full duplex and 65.536 Mb/s per direction. Fixed by a bounded v1 ACK window in Rust plus the Go CLI and test peer. See `RC-4096-ZERO-LOSS-QUALIFICATION.md` and `RC-UDP-ACK-WINDOW.md`.

## Provenance

- Canonical source repository and tag: see the GitHub release for this version; tag `v0.1.0-rc.2`.
- Release asset checksums: release `SHA256SUMS`; package SHA-256 is recorded there and in the release metadata.
- Signed provenance: GitHub Actions `RC release attestation`; GitHub Artifact Attestations (Sigstore bundles) for the package and both binaries. See `ATTESTATION.md`.
- Reproducible build: `REPRODUCIBLE-BUILD.md`.
- License: `LICENSE` is the upstream Apache-2.0 text, SHA-256 `d7e8fd4ad05371007d60285c309ba7a7ce3e61029b843f949fbb9ec79dc9eb47`.

## Not claimed

- Production signoff, physical hardware, QEMU, or rootfs-image update/reboot behavior.
- v2 port-forward/file-transfer over the real server (excluded because the CLI side is broken).
- Multi-hour production soak and WAN reconnect/heartbeat.
- IPv4 loopback UDP 4096 on this WSL host; the qualification target is IPv6 local loopback.
- The real updater test used a directory module to `/tmp`, not a rootfs image.