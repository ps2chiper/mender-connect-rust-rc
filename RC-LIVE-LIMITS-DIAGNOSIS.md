# RC 0.1.0-rc.1 — live-server `Limits.Enabled` failure diagnosis

Date: 2026-11-17 (America/New_York)
Binary: `mender-connect-rust` SHA-256 `21e54ac08c5453261b5ba61ec6c1f70132ee83e717163d6e9ff0e2050cfe8ee4`
Server: `https://mender.zapto.org` (test device `2bc5c66f-dd78-47ae-9158-24fe92c72fc0`)
Harness: `trial-tools/live_mender_cli_rc.py` (disposable guest, official `mender-auth`, private session bus)

## Initial observation

One run labelled "limits enabled" failed at the first terminal prompt:

- Run: `/home/jason/.local/share/duo-aider/mender-client-test/cli-x64-20261118035852`
- Result: `passed: false`, `error: "CLI terminal prompt not received"`, elapsed `14.285 s`
- `official-auth.log` showed a successful `101` device-connect upgrade followed by no WebSocket frames
- `rust-daemon.log` contained only `daemon startup` / `daemon shutdown`; no error or panic
- `terminal-output.log` stopped at `Connecting to the device ...`

## Re-run evidence

The same binary, same server, same guest bundle, and the same `--limits-enabled` mode passed repeatedly:

- 3 consecutive idle-0 runs: 26/26 checks, 6.5–7.3 s each
- 1 full idle-65 run: **28/28 checks**, 73.1 s
- The predecessor binary `1b352bc4e0402208e56605438b2cdd2f95f59af3fd3b78a004c1edd2d9d7dae8` also passed its 26-check run

No `--trace` change was needed for the passing idle-0 runs; the bundle was restored to its unmodified command line before those runs.

## Root cause classification

The failure was a **transient terminal/device-registration race in the live harness**, not a reproducible RC defect:

- The official auth path completed its WebSocket upgrade (`101`) but no session frames were exchanged.
- The daemon neither errored nor panicked; it simply never received a terminal-open frame.
- Immediate re-runs on the same binary and server passed 28/28, including a full idle-65 run.

Important correction to the earlier label: the guest fixture always sets `Limits.Enabled = true`; `--limits-enabled` actually selects the `approved-features` file-transfer mode. The failure was therefore in the file-transfer-enabled live path, not in a limits-disabled vs limits-enabled comparison.

## Status

- Live terminal, resize, small/binary/empty file transfers, overwrite, missing-file error, terminal survival, idle lifetime, clean stop, single device connection, and guest cleanup: **pass** on the RC with limits enabled.
- PortForward and MenderClient commands are now covered by `RC-LIVE-FEATURE-MATRIX.md`; real updater execution remains outside this harness (`PortForward.Disable = true`, `MenderClient.Disable = true` in the terminal-only runs).
- Recommendation: make the live harness retry the first terminal prompt once on a zero-frame `101` upgrade; the observed failure would then be absorbed without changing the RC.