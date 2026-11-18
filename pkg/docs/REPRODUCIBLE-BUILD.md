# Reproducible build — mender-connect-rust 0.1.0-rc.1

Date: 2026-11-17 (America/New_York)
Toolchain: rustc `1.99.1 (58cf8f9c3 2026-10-13)`, cargo `1.99.1 (5f94df478 2026-08-27)`
Target: `x86_64-unknown-linux-gnu`
Command: `cargo build --release --locked --offline --bins`

## Frozen release binary

| Artifact | SHA-256 |
|---|---|
| `mender-connect-rust` | `21e54ac08c5453261b5ba61ec6c1f70132ee83e717163d6e9ff0e2050cfe8ee4` |
| `mender-connect-session-helper` | `64fd1f8411af61a1d3491da8a00f6c83d5ef2aaa1af2ccde08dc411922691a11` |

## Rebuild 1 — clean target directory, original source path

```text
cd /home/jason/releases/mender-connect-rust-0.1.0-rc.1
CARGO_TARGET_DIR=/home/jason/rebuild-target-rc \
  cargo build --release --locked --offline --bins
```

Result: both binaries matched the frozen hashes exactly. Build time 20.46 s.

## Rebuild 2 — clean source copy at a different path

The source was copied to `/home/jason/rebuild-src-rc` excluding `target/`,
`pkg/bin/`, and `pkg/libexec/`, then built with a fresh target directory:

```text
cd /home/jason/rebuild-src-rc
CARGO_TARGET_DIR=/home/jason/rebuild-target-rc2 \
  cargo build --release --locked --offline --bins
```

Result: both binaries again matched the frozen hashes exactly. Build time 20.44 s.

This demonstrates path-independent, clean-target reproducibility for the qualified
Linux target from the frozen source and lockfile. It does not prove reproducibility
across a different compiler version, libc version, or target triple.

## SBOM

`SBOM.cdx.json` is CycloneDX 1.5 with the root application plus 179 dependency
components, generated from the frozen `cargo metadata` graph. SHA-256:
`824af17100201fde1d6b9a2211eb11b5e0b5d187fcdf32d80fd378bb5c258144`.

## Signature status

The GitHub repository and release provide a canonical tag and asset checksums.
No local private signing key is available in this environment; if GitHub Actions
attestation is enabled, the build provenance attestation is the signed
provenance record. Local GPG/cosign signing requires a trusted key supplied by
the release owner.