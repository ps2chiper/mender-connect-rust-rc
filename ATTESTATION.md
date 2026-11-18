# GitHub Artifact Attestation — mender-connect-rust 0.1.0-rc.2

Attestation run: `https://github.com/ps2chiper/mender-connect-rust-rc/actions/runs/44266895500`

The `RC release attestation` workflow downloaded the published rc.2 release
assets, verified `SHA256SUMS`, verified the package contents, and generated
signed GitHub Artifact Attestations (Sigstore bundles) for the package and both
binaries.

| Subject | SHA-256 | Attestations via GitHub API |
|---|---|---|
| `mender-connect-rust-0.1.0-rc.2-x86_64-linux.tar.gz` | `7042782dc5b3b5778aded859c4aacdd322b78d1c3de0e285dfa756c50c948ed2` | 1 |
| `mender-connect-rust` | `2d329d1fdc050f52cfb3c2b4df83b64a3557b8f94369425e740487620238845e` | 1 |
| `mender-connect-session-helper` | `ab2933e718f4f502203c7b6a2716684d4162058eb3904dad0c4de7ef3b1d9a1c` | 1 |

Verify a subject with the GitHub REST API:

```text
GET /repos/ps2chiper/mender-connect-rust-rc/attestations/sha256:<digest>
```

Bundle media type: `application/vnd.dev.sigstore.bundle.v0.3+json`. This is a
GitHub OIDC/Sigstore attestation, not a locally generated GPG signature.