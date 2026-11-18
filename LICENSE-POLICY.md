# License and supply-chain policy — mender-connect-rust 0.1.0-rc.1

Status: **closed — upstream Apache-2.0 provenance confirmed; permissive dependency policy accepted**
Date: 2026-11-17 (America/New_York)
Scope: native `x86_64-unknown-linux-gnu` only. The qualified target is the frozen RC dependency graph.

## Upstream license provenance

The original project license is confirmed from `https://github.com/mendersoftware/mender-connect`:

- Upstream `LICENSE` SHA-256: `d7e8fd4ad05371007d60285c309ba7a7ce3e61029b843f949fbb9ec79dc9eb47`
- RC `LICENSE` SHA-256: **the same hash**
- The RC `LICENSE` is byte-identical to the upstream Apache-2.0 text, including `Copyright 2026 Northern.tech AS`.
- The project remains **Apache-2.0**, with no relicensing and no added exception.

The project-license question is therefore settled by the upstream original. The dependency policy below accepts only permissive licenses compatible with Apache-2.0 distribution.

## Files

- `deny.toml` — permanent cargo-deny policy, SHA-256 `c4ae43d561b1e0e78c15db53f238f4dd993f681a3b13d2ee2048801d8562ae4a`.
- `DEPENDENCY-LICENSES.csv` — 180-package inventory, SHA-256 `76c5c84ce015c8f7163b7d36cd39879bf1676b40cb9d300d89644a82bdd90544`.
- `deny-all.log` — full `cargo-deny check all` output.

## Accepted license set

Only permissive licenses present in the Linux graph are accepted:

`MIT`, `Apache-2.0`, `Apache-2.0 WITH LLVM-exception`, `Unicode-3.0`, `ISC`, `BSD-2-Clause`, `BSD-3-Clause`, `Unlicense`.

No copyleft license is accepted as a required license. Notes:

- `r-efi` offers `MIT OR Apache-2.0 OR LGPL-2.1-or-later`; the MIT/Apache alternatives are selected, so no LGPL obligation is accepted.
- `unicode-ident` is `(MIT OR Apache-2.0) AND Unicode-3.0`; both accepted components are required.
- `ring` is `Apache-2.0 AND ISC`; both are accepted.
- `memchr` offers `Unlicense OR MIT`; accepted.
- `rustls`, `rustls-native-certs`, and `serial2` provide permissive alternatives; no copyleft alternative is selected.

The full distribution by declaration is: 100 `MIT OR Apache-2.0`, 31 `MIT`, 18 `Unicode-3.0`, 10 `Apache-2.0 OR MIT`, 6 `MIT/Apache-2.0`, and the remaining permissive combinations listed in the CSV.

## Duplicate versions

`cargo-deny` reports six duplicate-version warnings in the x86_64 graph:

| Crate | Versions | Policy |
|---|---|---|
| `cfg_aliases` | 0.1.1, 0.2.2 | Accepted transitive difference |
| `getrandom` | 0.2.17, 0.4.3 | Accepted transitive difference |
| `nix` | 0.28.0, 0.29.0, 0.31.3 | Direct 0.29; `nix_spawn` 0.31.3; 0.28 transitive |
| `syn` | 2.0.119, 3.0.10 | Derive-macro generation split |
| `thiserror` | 1.0.69, 2.0.21 | `portable-pty` vs `tungstenite` |
| `thiserror-impl` | 1.0.69, 2.0.21 | Follows `thiserror` |

The metadata graph also contains `bitflags` 1.3.2/2.13.2 and `windows-sys` 0.52.0/0.61.2; these are outside the selected Linux target graph or not reported by the target-pruned check. Reduction plan: upgrade `portable-pty`/`filedescriptor` and `nix_spawn` when upstream supports the newer generations; do not force upgrades without retesting forwarding, PTY, and file-transfer behavior. Duplicate warnings are intentionally visible, not suppressed with `skip`.

## Verification result

Command:

```text
env PATH=/home/jason/.cargo/bin:/usr/bin:/bin \
  /home/jason/.cargo/bin/cargo-deny \
  --metadata-path /tmp/rc-metadata.json check all
```

Result:

```text
advisories ok, bans ok, licenses ok, sources ok
```

Exit code: **0**. Six duplicate-version warnings are emitted as policy-visible warnings; no errors.

The prior `cargo-audit` run scanned the same 180 lockfile dependencies and reported no advisories. The cargo-deny advisory check also returned `advisories ok`; its only warnings were inability to query the local crates.io index for yanked-crate status because the offline environment has no registry index.

## Signoff

The project license is the upstream original **Apache-2.0**, confirmed byte-for-byte. The dependency policy accepts only permissive licenses compatible with Apache-2.0 distribution, and `cargo-deny check all` passes with only documented duplicate-version warnings.

This closes the license and supply-chain blocker. No license text was modified, and the project’s own `LICENSE` remains the upstream Apache-2.0 file. If a separate legal memo on third-party dependencies is required by the release process, it is a process artifact rather than an unresolved license incompatibility.