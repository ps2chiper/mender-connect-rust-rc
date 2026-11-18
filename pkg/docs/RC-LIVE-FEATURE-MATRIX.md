# RC 0.1.0-rc.1 — live-server feature matrix

Date: 2026-11-17 (America/New_York)
Binary: `mender-connect-rust` SHA-256 `21e54ac08c5453261b5ba61ec6c1f70132ee83e717163d6e9ff0e2050cfe8ee4`
Server: `https://mender.zapto.org` (test device `2bc5c66f-dd78-47ae-9158-24fe92c72fc0`)
Harness: `trial-tools/live_mender_cli_features_rc.py` (private session bus, official `mender-auth`, disposable guest)

## Result

Two full runs:

| Mode | Checks | Result | Report |
|---|---:|---|---|
| Limits disabled | 32 | **32/32 pass** | `reports/mender-rust-mender-cli-x64/cli-x64-20261118043222.json` |
| Limits enabled | 31 | **31/31 pass** | `reports/mender-rust-mender-cli-x64/cli-x64-20261118043243.json` |

## Newly exercised workflows

- **PortForward TCP echo:** `mender-cli port-forward <device> tcp/38080:38080` reached a loopback echo server in the guest; payload arrived byte-for-byte.
- **PortForward UDP echo:** `mender-cli port-forward <device> udp/38081:38081` reached a loopback UDP echo server; payload arrived byte-for-byte.
- **MenderClient send-inventory:** management API `POST /api/management/v1/deviceconnect/devices/<id>/send-inventory` returned **HTTP 202**.
- **MenderClient check-update:** management API `POST /api/management/v1/deviceconnect/devices/<id>/check-update` returned **HTTP 202**.
- **MenderClient command dispatch:** both commands reached the guest command fixture; `/work/mender-command.log` recorded `send-inventory` and `check-update`.

Terminal, resize, binary/empty uploads and downloads, overwrite, missing-file error, terminal survival, idle lifetime, clean stop, single device connection, guest isolation, and cleanup all continued to pass in the same runs.

## Important scope boundary

The guest uses a **logging command fixture** at `/usr/bin/mender` (SHA-256 `99061a903585c90138ee10f812cd71e1f3a04332d6cede986984c4910f400416`, `trial-tools/mender_stub.sh`), not a real Mender updater. It was installed temporarily for the run and removed afterward. The isolated guest intentionally has no external network, so a real `mender` daemon cannot reach the Mender server from inside it. The RC's own responsibility in this path is to validate the command and dispatch it to the configured updater binary; that dispatch is now verified end-to-end through the real server.

**Real updater execution and an actual artifact installation are still not exercised.** That belongs to a separate Mender client/update-module qualification on an authorized disposable VM or device, not to `mender-connect`'s command-dispatch path. No deployment or update was created against this device.

## Verdict

Blocker 2's RC-owned live-server workflows — **PortForward and MenderClient commands** — are now qualified. The only remaining sub-item is real updater/update-install execution, which remains explicitly out of this RC's tested scope.