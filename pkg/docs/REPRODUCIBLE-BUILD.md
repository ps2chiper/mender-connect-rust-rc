# Reproducible build — mender-connect-rust 0.1.0-rc.2

Date: 2026-11-18 (America/New_York)
Toolchain: rustc `1.99.1 (58cf8f9c3 2026-10-13)`, cargo `1.99.1 (5f94df478 2026-08-27)`
Target: `x86_64-unknown-linux-gnu`
Command: `cargo build --release --locked --offline --bins`

## Frozen release binaries

| Artifact | SHA-256 |
|---|---|
| `mender-connect-rust` | `2d329d1fdc050f52cfb3c2b4df83b64a3557b8f94369425e740487620238845e` |
| `mender-connect-session-helper` | `ab2933e718f4f502203c7b6a2716684d4162058eb3904dad0c4de7ef3b1d9a1c` |

## Clean source-copy rebuild

The source was copied from `/home/jason/mender-udp-window` to
`/home/jason/rebuild-rc2-src`, excluding `target/`, `pkg/bin/`, `pkg/libexec/`
and the packaged source copy, then built with a fresh target directory:

```text
cd /home/jason/rebuild-rc2-src
CARGO_TARGET_DIR=/home/jason/rebuild-rc2-target \
  cargo build --release --locked --bins
```

Result: both binaries matched the frozen hashes exactly. Build time 20.29 s.
This demonstrates path-independent, clean-target reproducibility for the
qualified Linux target from the frozen source and lockfile.

## SBOM

`SBOM.cdx.json` is CycloneDX 1.5 with the root application plus 179 dependency
components, generated from the frozen `cargo metadata` graph. See the release
asset for its current SHA-256.

## Signature status

The GitHub repository and release provide the canonical tag and asset checksums.
The `RC release attestation` workflow verifies the published package checksums
and binary hashes and generates signed GitHub Artifact Attestations (Sigstore
bundles) for the package and both binaries. See `PROVENANCE.md` and
`ATTESTATION.md`. This is GitHub OIDC/Sigstore attestation, not a locally
generated GPG signature; no local private signing key was used.