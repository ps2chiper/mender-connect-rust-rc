# RC 0.1.0-rc.1 — installed-service, system-bus, and boot qualification

Date: 2026-11-17 (America/New_York)
Scope: native Ubuntu 24.04.5 LTS WSL2, x86-64. No QEMU, no physical hardware, no production credentials.
Status: **installed, enabled, boot-tested, and exercised end-to-end through the real server on the system bus.**

## Installed artifacts

| Path | SHA-256 | Mode / owner |
|---|---|---|
| `/usr/bin/mender-connect-rust` | `21e54ac08c5453261b5ba61ec6c1f70132ee83e717163d6e9ff0e2050cfe8ee4` | `0755 root:root` |
| `/usr/libexec/mender-connect-session-helper` | `64fd1f8411af61a1d3491da8a00f6c83d5ef2aaa1af2ccde08dc411922691a11` | `0755 root:root`, not SUID/SGID |
| `/etc/mender/mender-connect.conf` | `3e1d499061fecf955f1fefe1f34320f9cfba2bfab6c7b4b9f945b678b386ca7c` | `0644 root:root` |
| `/etc/systemd/system/mender-connect-rust.service` | `91f1e1afb94ee3c1ff98ebbba575457d7f8578baeac2c8ebacae1d379181e709` | `0644 root:root` |
| `/usr/bin/mender-auth` (official, `017743f`) | `20494766ead4485be0719f14398031324ca4f3492bade1975f1415c179f958e3` | `0755 root:root` |
| `/etc/systemd/system/mender-authd.service` | `01036ee2192c4e3d253d9d49fff26e12954b5c4cc2808281d9cb1b4787d3aa8c` | `0644 root:root` |
| `/etc/dbus-1/system.d/io.mender.AuthenticationManager.conf` | `af6c6bda700206052fd86de558e7f9db252483b86cad810f2ef9ef1cb13bacd9` | `0644 root:root` |
| `/etc/mender/mender.conf` | `5c3b4794148e42e2f278acd8a7607a67750d7c4d994efd7ea9b5323e765c0802` | `0600 root:root` |

The installed configuration is the packaged terminal-only profile: `User=nobody`, `ShellCommand=/bin/sh`, terminal enabled, FileTransfer/PortForward/MenderClient disabled.

## Authentication setup

- Official Mender Auth daemon `017743f`, using the existing test device credentials for device `2bc5c66f-dd78-47ae-9158-24fe92c72fc0` and `https://mender.zapto.org`.
- `mender-authd.service` owns `io.mender.AuthenticationManager` on the **system bus**.
- A system-bus policy allows root to own that name and allows the default context to send/receive. This is a test-deployment policy, not a claim about the upstream Mender package policy.
- Identity script installed at `/usr/share/mender/identity/mender-device-identity`; auth logs show `Successfully received new authorization data from server 'https://mender.zapto.org'`.

## Boot and service checks

Commands:

```text
wsl.exe --terminate Ubuntu-24.04
wsl.exe -d Ubuntu-24.04 -u root -- systemctl is-system-running
wsl.exe -d Ubuntu-24.04 -u root -- systemctl is-active mender-authd.service mender-connect-rust.service
wsl.exe -d Ubuntu-24.04 -u root -- busctl --system list
```

Observed after the distro restart:

```text
systemctl is-system-running: running
mender-authd.service: active (running), enabled, MainPID 223
mender-connect-rust.service: active (running), enabled, MainPID 224
io.mender.AuthenticationManager  223  mender-auth  root  mender-authd.service
```

The Rust daemon reuses the system-bus auth service and has no private-session-bus flag.

## End-to-end through the installed service

A real `mender-cli terminal` session against the server reached the installed daemon:

```text
$ echo BOOT_SERVICE_OK
BOOT_SERVICE_OK
```

After `systemctl restart mender-authd.service`, the Rust daemon stayed active on the same PID and a second terminal session returned:

```text
$ echo AUTH_RESTART_OK
AUTH_RESTART_OK
```

This exercises the installed helper for the root -> `nobody` transition, the system-bus Authentication1 client path, and the server-side device connection.

## Stop/start and cleanup

```text
systemctl stop mender-connect-rust.service
# after: ActiveState=inactive, SubState=dead, no /usr/bin/mender-connect-rust daemon process
systemctl start mender-connect-rust.service
# after: ActiveState=active, SubState=running
```

The unit's `KillMode=mixed` and `TimeoutStopSec=180` remain unchanged. No warning-level journal entries were recorded for either unit.

## Remaining caveats

- Uses **test device credentials** and a test-deployment D-Bus policy; production must use the real Mender Auth package/config/policy.
- The packaged Rust unit still lists `mender-client.service` as a `Wants=`/`After=` dependency; that service is absent in this WSL image and the Rust unit starts without it. A production image with a Mender Client should reconcile that dependency.
- Boot was a WSL distro terminate/start, not a full Windows host reboot.
- PortForward, MenderClient commands, real updater execution, and production credential rotation remain outside this installed-service check.
- The package's own unit comments still describe it as review-only packaging; this installation is a test qualification, not a formal release promotion.