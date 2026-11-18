# RC 0.1.0-rc.1 — real updater and artifact-install qualification

Date: 2026-11-17 (America/New_York)
RC binary: `mender-connect-rust` SHA-256 `21e54ac08c5453261b5ba61ec6c1f70132ee83e717163d6e9ff0e2050cfe8ee4`
Real Mender client: `mender` 3.4.0+ds1-5ubuntu0.24.04.3, SHA-256 `ea023922ac8ed7e583268054b800997a7ec2f766edf2a9a00532af4b713a1fc2`
Server: `https://mender.zapto.org`; test device `2bc5c66f-dd78-47ae-9158-24fe92c72fc0`

## What was exercised

A real Mender client daemon was installed and run on the test host, and a real Mender artifact was uploaded and deployed to the test device. The artifact used the `directory` update module with:

- Artifact: `rc-directory-host-test-2`
- Artifact SHA-256: `4fae1157a251ebdef2adbb01fb9718082304e40e5396c650b1366d6c2b8d83fc`
- Destination: `/tmp/mender-update-target`
- Payload marker: `rc-triggered-update-marker`

The RC's installed `mender-connect-rust.service` was configured with `MenderClient.Disable=false`, connected through the system-bus Authentication1 service, while the real Mender daemon was running.

## Trigger path

1. Deployment `rc-triggered-directory-test-2` was created with the management API; it returned `201` and initially reported one pending device.
2. A management API call to `POST /api/management/v1/deviceconnect/devices/<id>/check-update` returned **202**.
3. The RC received the MenderClient `check-update` command and dispatched it to the real `/usr/bin/mender check-update`.
4. The real Mender daemon performed the update check, downloaded the artifact, ran `ArtifactInstall`, and committed it.
5. Deployment status changed from one pending device to **`finished`** with **`success: 1`**.
6. The installed marker file `/tmp/mender-update-target/marker.txt` contained `rc-triggered-update-marker` (SHA-256 `69ac8de602d38bf3f56af1711399562d6e266795a2c3e29fdccce2c2103db6ea`).

Mender daemon log showed the transitions:

```text
update-check -> update-fetch -> update-store -> update-install [ArtifactInstall]
-> update-commit [ArtifactCommit_Enter] -> cleanup -> update-status-report -> idle
```

## Scope and caveats

- This is a **real artifact install** through the real server and real Mender client, but the payload is a `directory` module writing to `/tmp/mender-update-target`, not a rootfs-image update. Rootfs replacement and reboot semantics remain outside this test.
- Test device credentials and a test deployment were used. The Mender client/updater is a separate component from `mender-connect`; this test verifies the RC's command dispatch plus the complete live update path.
- After evidence collection, `mender-client.service` was stopped and disabled, and `/etc/mender/mender-connect.conf` was restored to `MenderClient.Disable=true`. The installed `mender-authd.service` and `mender-connect-rust.service` remain active.
- The test artifacts/deployments remain on the disposable Mender test server as evidence; they are not production artifacts.

## Verdict

**Blocker 2 is closed.** The RC has now been exercised with:

- PortForward TCP/UDP through the real server.
- MenderClient `send-inventory` and `check-update` through the real server.
- A real Mender client updater executing an artifact installation triggered by the RC's `check-update` dispatch.
- Terminal and file-transfer workflows through the installed system-bus service and real server.

No real rootfs update or reboot sequence was attempted.