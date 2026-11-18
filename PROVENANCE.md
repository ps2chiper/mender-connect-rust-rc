# Release provenance — mender-connect-rust 0.1.0-rc.2

## Canonical source

- Repository: `https://github.com/ps2chiper/mender-connect-rust-rc`
- Release tag: `v0.1.0-rc.2`
- Qualified target: native Ubuntu 24.04 WSL2 x86-64
- License: Apache-2.0, upstream text SHA-256 `d7e8fd4ad05371007d60285c309ba7a7ce3e61029b843f949fbb9ec79dc9eb47`

## Release

- Release: `https://github.com/ps2chiper/mender-connect-rust-rc/releases/tag/v0.1.0-rc.2`
- Prerelease: yes
- Package: `mender-connect-rust-0.1.0-rc.2-x86_64-linux.tar.gz`
- Package SHA-256: `7042782dc5b3b5778aded859c4aacdd322b78d1c3de0e285dfa756c50c948ed2`
- `mender-connect-rust`: `2d329d1fdc050f52cfb3c2b4df83b64a3557b8f94369425e740487620238845e`
- `mender-connect-session-helper`: `ab2933e718f4f502203c7b6a2716684d4162058eb3904dad0c4de7ef3b1d9a1c`

## Build attestation

GitHub Actions run: `https://github.com/ps2chiper/mender-connect-rust-rc/actions/runs/44266895500`

The `RC release attestation` workflow downloads the published release tarball,
verifies its `SHA256SUMS`, verifies the package contents, and generates signed
GitHub Artifact Attestations (Sigstore bundles) for the package and both
binaries. The GitHub API reports one attestation for each subject:

```text
package  sha256:7042782d… -> 1
daemon   sha256:2d329d1f… -> 1
helper   sha256:ab2933e7… -> 1
```

This is a GitHub OIDC/Sigstore attestation, not a locally generated GPG
signature. No local private signing key was used.

## SBOM and reproducibility

- `SBOM.cdx.json`: CycloneDX 1.5, root plus 179 dependency components,
  SHA-256 `d6644d20cfbc60e52dcab5a80facf1ab1c0ab6de771114404ccc237ff1fb29de`.
- `REPRODUCIBLE-BUILD.md`: clean source-copy rebuild reproduced both frozen
  binary hashes.
- All `cargo test --all-targets --locked` targets passed.
- UDP 4096 full-duplex zero-loss: 10/10 repeats, 30/30 trials, 60/60
  per-direction measurements with zero loss; see
  `RC-4096-ZERO-LOSS-QUALIFICATION.md`.
- Go CLI patch: `mender-cli-udp-window.patch` (commit `060a594`), with a passing
  bounded-window unit test.