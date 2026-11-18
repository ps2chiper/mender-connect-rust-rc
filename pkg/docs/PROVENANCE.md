# Release provenance — mender-connect-rust 0.1.0-rc.1

## Canonical source

- Repository: `https://github.com/ps2chiper/mender-connect-rust-rc`
- Release tag: `v0.1.0-rc.1` (resolve the exact tag commit with `git rev-parse v0.1.0-rc.1^{}`)
- Attestation source commit: `c921d28deea86d2a92776515d801c6712a7d3cf6`
- License: Apache-2.0, upstream text SHA-256 `d7e8fd4ad05371007d60285c309ba7a7ce3e61029b843f949fbb9ec79dc9eb47`

## Release

- Release: `https://github.com/ps2chiper/mender-connect-rust-rc/releases/tag/v0.1.0-rc.1`
- Prerelease: yes
- Package: `mender-connect-rust-0.1.0-rc.1-x86_64-linux.tar.gz`
- Package SHA-256: published in the release `SHA256SUMS` asset (the package
  contains the binaries and docs; its hash is not embedded in the docs to avoid
  a self-referential checksum).
- `mender-connect-rust`: `21e54ac08c5453261b5ba61ec6c1f70132ee83e717163d6e9ff0e2050cfe8ee4`
- `mender-connect-session-helper`: `64fd1f8411af61a1d3491da8a00f6c83d5ef2aaa1af2ccde08dc411922691a11`

## Build attestation

GitHub Actions run: `https://github.com/ps2chiper/mender-connect-rust-rc/actions/runs/44250024617`

The `RC release attestation` workflow downloads the published release tarball, verifies its
`SHA256SUMS`, verifies the binary hashes, and generates signed GitHub Artifact Attestations
(Sigstore bundles) for both binaries. Verification through the GitHub API reports one
attestation for each subject:

```text
GET /repos/ps2chiper/mender-connect-rust-rc/attestations/sha256:21e54ac0…  -> 1
GET /repos/ps2chiper/mender-connect-rust-rc/attestations/sha256:64fd1f84…  -> 1
```

The bundle media type is `application/vnd.dev.sigstore.bundle.v0.3+json`.

This is a GitHub OIDC/Sigstore build-and-release attestation, not a locally generated GPG
signature. No local private signing key was available or used.

## SBOM and reproducibility

- `SBOM.cdx.json`: CycloneDX 1.5, root plus 179 dependency components, SHA-256 `824af17100201fde1d6b9a2211eb11b5e0b5d187fcdf32d80fd378bb5c258144`.
- `REPRODUCIBLE-BUILD.md`: clean-target and different-path rebuilds both reproduced both frozen binary hashes.
- `LICENSE-POLICY.md`: project license confirmed byte-identical to upstream Apache-2.0; `cargo-deny check all` passed with documented duplicate warnings.