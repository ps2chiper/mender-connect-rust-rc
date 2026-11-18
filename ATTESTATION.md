# GitHub Artifact Attestation — mender-connect-rust 0.1.0-rc.1

Latest attestation run: `https://github.com/ps2chiper/mender-connect-rust-rc/actions/runs/44251073883`

The `RC release attestation` workflow downloaded the published release assets,
verified `SHA256SUMS`, verified the package contents, and generated signed
GitHub Artifact Attestations (Sigstore bundles) for the package and both
binaries.

| Subject | SHA-256 | Attestations via GitHub API |
|---|---|---|
| `mender-connect-rust-0.1.0-rc.1-x86_64-linux.tar.gz` | `9507068c95552700ec001b56f154d8b6d30e68ec502dcfd220e88d815978147d` | 1 |
| `mender-connect-rust` | `21e54ac08c5453261b5ba61ec6c1f70132ee83e717163d6e9ff0e2050cfe8ee4` | 3 |
| `mender-connect-session-helper` | `64fd1f8411af61a1d3491da8a00f6c83d5ef2aaa1af2ccde08dc411922691a11` | 3 |

Verify a subject with the GitHub REST API:

```text
GET /repos/ps2chiper/mender-connect-rust-rc/attestations/sha256:<digest>
```

Bundle media type: `application/vnd.dev.sigstore.bundle.v0.3+json`. This is a
GitHub OIDC/Sigstore attestation, not a locally generated GPG signature.